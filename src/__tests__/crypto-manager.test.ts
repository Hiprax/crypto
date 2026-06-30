import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
  jest,
} from '@jest/globals';
import { CryptoManager, SECURITY_THRESHOLDS } from '../crypto-manager';
import { CryptoError, CryptoErrorType, SecurityLevel } from '../types';
import {
  HEADER_LENGTH,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  MAGIC_BYTES,
  packHeader,
  parseHeader,
  hasMagic,
  FORMAT_VERSION,
  MAX_ARGON2_MEMORY_COST,
  MAX_ARGON2_TIME_COST,
  MAX_ARGON2_PARALLELISM,
  MAX_PBKDF2_ITERATIONS,
} from '../format';
import { writeFile, unlink, readFile } from 'node:fs/promises';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  unlinkSync,
  openSync,
  closeSync,
  readSync,
  writeSync,
  statSync,
  readdirSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import argon2Module from 'argon2';
import nodeCrypto from 'node:crypto';

// Unique per-suite scratch directory so concurrent jest workers / repeated
// runs cannot collide on file paths (Task 21). Created once in beforeAll
// and torn down in afterAll; every per-test directory join still uses
// `tempDir` as before so the rest of the test code is unchanged.
const TEST_DIR = path.join(
  os.tmpdir(),
  `hiprax-crypto-${nodeCrypto.randomBytes(8).toString('hex')}`
);

describe('CryptoManager', () => {
  let crypto: CryptoManager;
  const testPassword = 'MySecureP@ssw0rd123!';
  const testText = 'Hello, World! This is a test message.';
  const tempDir = TEST_DIR;

  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  beforeEach(() => {
    crypto = new CryptoManager();
  });

  describe('Constructor', () => {
    it('should create instance with default options', () => {
      expect(crypto).toBeInstanceOf(CryptoManager);
      const params = crypto.getParameters();
      expect(params.algorithm).toBe('aes-256-gcm');
      expect(params.keyLength).toBe(32);
      expect(params.ivLength).toBe(12);
      expect(params.saltLength).toBe(32);
      expect(params.tagLength).toBe(16);
    });

    it('should default Argon2 parameters to the post-Task-18 HIGH tier (mem=2^17, time=3, parallelism=1)', () => {
      // Lock in the bumped default. Pre-Task-18 this was 2^16 (64 MiB);
      // Task 18 raised it to 2^17 (128 MiB) so the library's out-of-the-box
      // configuration matches the OWASP 2026 first-choice tier for
      // Argon2id. Resource-constrained callers can opt back into the old
      // value via `memoryCost: 2 ** 16`.
      const params = crypto.getParameters();
      expect(params.argon2Options.memoryCost).toBe(2 ** 17);
      expect(params.argon2Options.timeCost).toBe(3);
      expect(params.argon2Options.parallelism).toBe(1);
    });

    it('should create instance with custom options', () => {
      const customCrypto = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 2,
        parallelism: 2,
        aad: 'custom-aad',
      });
      const params = customCrypto.getParameters();
      expect(params.argon2Options.memoryCost).toBe(2 ** 14);
      expect(params.argon2Options.timeCost).toBe(2);
      expect(params.argon2Options.parallelism).toBe(2);
    });

    it('should create instance with default passphrase', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      expect(cryptoWithDefault.hasDefaultPassphrase()).toBe(true);
    });

    it('should not have default passphrase when not provided', () => {
      expect(crypto.hasDefaultPassphrase()).toBe(false);
    });

    it('should throw error for invalid memoryCost', () => {
      expect(() => new CryptoManager({ memoryCost: -1 })).toThrow(CryptoError);
      expect(() => new CryptoManager({ memoryCost: 0 })).toThrow(CryptoError);
      expect(() => new CryptoManager({ memoryCost: 1.5 })).toThrow(
        CryptoError
      );
    });

    it('should throw error for invalid timeCost', () => {
      expect(() => new CryptoManager({ timeCost: -1 })).toThrow(CryptoError);
      expect(() => new CryptoManager({ timeCost: 0 })).toThrow(CryptoError);
      expect(() => new CryptoManager({ timeCost: 1.5 })).toThrow(CryptoError);
    });

    it('should throw error for invalid parallelism', () => {
      expect(() => new CryptoManager({ parallelism: -1 })).toThrow(
        CryptoError
      );
      expect(() => new CryptoManager({ parallelism: 0 })).toThrow(CryptoError);
      expect(() => new CryptoManager({ parallelism: 1.5 })).toThrow(
        CryptoError
      );
    });

    it('should throw MEMORY_COST_TOO_LARGE when memoryCost exceeds wire-format cap', () => {
      let caught: CryptoError | undefined;
      try {
        new CryptoManager({ memoryCost: MAX_ARGON2_MEMORY_COST + 1 });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MEMORY_COST_TOO_LARGE');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw TIME_COST_TOO_LARGE when timeCost exceeds wire-format cap', () => {
      let caught: CryptoError | undefined;
      try {
        new CryptoManager({ timeCost: MAX_ARGON2_TIME_COST + 1 });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('TIME_COST_TOO_LARGE');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw PARALLELISM_TOO_LARGE when parallelism exceeds wire-format cap', () => {
      let caught: CryptoError | undefined;
      try {
        new CryptoManager({ parallelism: MAX_ARGON2_PARALLELISM + 1 });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('PARALLELISM_TOO_LARGE');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw PBKDF2_ITERATIONS_TOO_LARGE when pbkdf2Iterations exceeds wire-format cap', () => {
      let caught: CryptoError | undefined;
      try {
        new CryptoManager({ pbkdf2Iterations: MAX_PBKDF2_ITERATIONS + 1 });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('PBKDF2_ITERATIONS_TOO_LARGE');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw LEGACY_PBKDF2_ITERATIONS_TOO_LARGE when legacyPbkdf2Iterations exceeds cap', () => {
      let caught: CryptoError | undefined;
      try {
        new CryptoManager({
          legacyPbkdf2Iterations: MAX_PBKDF2_ITERATIONS + 1,
        });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('LEGACY_PBKDF2_ITERATIONS_TOO_LARGE');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should accept KDF params at exactly the wire-format cap (boundary construction)', () => {
      // At exactly the cap, construction must succeed — the cap is inclusive.
      expect(() =>
        new CryptoManager({
          memoryCost: MAX_ARGON2_MEMORY_COST,
          timeCost: MAX_ARGON2_TIME_COST,
          parallelism: MAX_ARGON2_PARALLELISM,
        })
      ).not.toThrow();
      expect(() =>
        new CryptoManager({ pbkdf2Iterations: MAX_PBKDF2_ITERATIONS })
      ).not.toThrow();
      expect(() =>
        new CryptoManager({ legacyPbkdf2Iterations: MAX_PBKDF2_ITERATIONS })
      ).not.toThrow();
    });

    it('should accept below-cap KDF params (sanity check)', () => {
      expect(() =>
        new CryptoManager({
          memoryCost: 2 ** 12,
          timeCost: 1,
          parallelism: 1,
          pbkdf2Iterations: 1000,
          legacyPbkdf2Iterations: 1000,
        })
      ).not.toThrow();
    });

    it('should round-trip encryptTextSync/decryptTextSync at boundary PBKDF2 params (regression: nothing constructable is undecryptable)', () => {
      // Verifies that a constructable config actually produces decryptable
      // ciphertext — catches any future regression where cap enforcement
      // diverges from what parseHeader accepts.
      const cm = new CryptoManager({ pbkdf2Iterations: 1000 }); // small for speed
      const password = 'TestPassphrase20chars!';
      const plaintext = 'sync boundary round-trip';

      const encrypted = cm.encryptTextSync(plaintext, password);
      const decrypted = cm.decryptTextSync(encrypted, password);
      expect(decrypted).toBe(plaintext);
    });

    it('should round-trip encryptText/decryptText with Argon2 timeCost at cap and tiny memoryCost', async () => {
      // timeCost:100 at memoryCost:2^12 (4 MiB) is comparable in total
      // memory work to the default (128 MiB × 3), so this should complete
      // in well under a second on any reasonable hardware.
      const cm = new CryptoManager({
        memoryCost: 2 ** 12, // 4 MiB — tiny but valid
        timeCost: MAX_ARGON2_TIME_COST, // 100 — exactly at cap
        parallelism: 1,
      });
      const password = 'TestPassphrase20chars!';
      const plaintext = 'argon2 cap boundary round-trip';

      const encrypted = await cm.encryptText(plaintext, password);
      const decrypted = await cm.decryptText(encrypted, password);
      expect(decrypted).toBe(plaintext);
    }, 30_000);

    it('should throw MEMORY_COST_TOO_SMALL when memoryCost < 8 * parallelism (under-boundary)', () => {
      // p=1: Argon2id floor is 8*1=8; mc=7 is one below
      let caught: CryptoError | undefined;
      try {
        new CryptoManager({ memoryCost: 7, parallelism: 1 });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MEMORY_COST_TOO_SMALL');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
      expect(caught?.message).toContain('8 × 1');

      // p=2: floor is 8*2=16; mc=15 is one below
      caught = undefined;
      try {
        new CryptoManager({ memoryCost: 15, parallelism: 2 });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MEMORY_COST_TOO_SMALL');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
      expect(caught?.message).toContain('8 × 2');
    });

    it('should accept memoryCost >= 8 * parallelism (at boundary and defaults)', () => {
      // Exactly at the floor — must NOT throw
      expect(() =>
        new CryptoManager({ memoryCost: 8, parallelism: 1 })
      ).not.toThrow();
      expect(() =>
        new CryptoManager({ memoryCost: 16, parallelism: 2 })
      ).not.toThrow();
      // Default constructor (mc=2^17, p=1) trivially satisfies the floor
      expect(() => new CryptoManager()).not.toThrow();
    });

    it('should throw INVALID_AAD when aad is a number or plain object', () => {
      let caught: CryptoError | undefined;

      // number — Buffer.from(123) throws a raw Node TypeError without the fix
      try {
        new CryptoManager({ aad: 123 as unknown as string });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_AAD');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);

      // plain object
      caught = undefined;
      try {
        new CryptoManager({ aad: {} as unknown as string });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_AAD');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw INVALID_AAD when aad is an array (silent-coercion regression)', () => {
      // Before this fix, Buffer.from([72, 73], 'utf8') silently produced the
      // two-byte AAD "HI" instead of rejecting the misconfiguration.
      let caught: CryptoError | undefined;
      try {
        new CryptoManager({ aad: [72, 73] as unknown as string });
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_AAD');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should accept a valid string aad without throwing', () => {
      expect(() =>
        new CryptoManager({ aad: 'my-app-context-v1' })
      ).not.toThrow();
    });
  });

  describe('generateSecureRandom', () => {
    it('should generate random bytes of specified length', () => {
      const length = 32;
      const random = crypto.generateSecureRandom(length);
      expect(Buffer.isBuffer(random)).toBe(true);
      expect(random.length).toBe(length);
    });

    it('should throw error for invalid length', () => {
      expect(() => crypto.generateSecureRandom(0)).toThrow(CryptoError);
      expect(() => crypto.generateSecureRandom(-1)).toThrow(CryptoError);
      expect(() => crypto.generateSecureRandom(1025)).toThrow(CryptoError);
    });
  });

  describe('deriveKey', () => {
    it('should derive key successfully', async () => {
      const salt = crypto.generateSecureRandom(32);
      const key = await crypto.deriveKey(testPassword, salt);
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });

    it('should throw error for invalid password', async () => {
      const salt = crypto.generateSecureRandom(32);
      await expect(crypto.deriveKey('', salt)).rejects.toThrow(CryptoError);
      await expect(
        crypto.deriveKey(null as unknown as string, salt)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for invalid salt', async () => {
      const invalidSalt = Buffer.alloc(16); // Wrong length
      await expect(crypto.deriveKey(testPassword, invalidSalt)).rejects.toThrow(
        CryptoError
      );
      await expect(
        crypto.deriveKey(testPassword, null as unknown as Buffer)
      ).rejects.toThrow(CryptoError);
    });

    it('should handle argon2 hash errors', async () => {
      // This test would require mocking argon2.hash to throw an error
      // For now, we'll test with a very weak password that might cause issues
      const salt = crypto.generateSecureRandom(32);
      const weakPassword = 'a'.repeat(1000); // Very long password might cause issues

      // This should either succeed or throw a CryptoError
      try {
        await crypto.deriveKey(weakPassword, salt);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
      }
    });
  });

  describe('encryptData', () => {
    it('should encrypt data successfully', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const result = crypto.encryptData(data, key, iv);
      expect(result.encrypted).toBeDefined();
      expect(result.tag).toBeDefined();
      expect(Buffer.isBuffer(result.encrypted)).toBe(true);
      expect(Buffer.isBuffer(result.tag)).toBe(true);
    });

    it('should throw error for invalid data', () => {
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      expect(() =>
        crypto.encryptData(null as unknown as Buffer, key, iv)
      ).toThrow(CryptoError);
      expect(() =>
        crypto.encryptData('string' as unknown as Buffer, key, iv)
      ).toThrow(CryptoError);
    });

    it('should throw error for invalid key', () => {
      const data = Buffer.from('test data');
      const iv = crypto.generateSecureRandom(12);

      expect(() => crypto.encryptData(data, Buffer.alloc(16), iv)).toThrow(
        CryptoError
      );
      expect(() =>
        crypto.encryptData(data, null as unknown as Buffer, iv)
      ).toThrow(CryptoError);
    });

    it('should throw error for invalid IV', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);

      expect(() => crypto.encryptData(data, key, Buffer.alloc(8))).toThrow(
        CryptoError
      );
      expect(() =>
        crypto.encryptData(data, key, null as unknown as Buffer)
      ).toThrow(CryptoError);
    });

    it('should throw INVALID_AAD when aadOverride is not a Buffer (audit #11)', () => {
      // Production guard: aadOverride !== undefined && !Buffer.isBuffer(aadOverride)
      // throws CryptoError(INVALID_INPUT, 'INVALID_AAD'). This branch was previously
      // untested — a non-Buffer aadOverride would have silently coerced or crashed.
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      let caught: CryptoError | undefined;
      try {
        crypto.encryptData(data, key, iv, 'not-a-buffer' as unknown as Buffer);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_AAD');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });
  });

  describe('decryptData', () => {
    it('should decrypt data successfully', async () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const encrypted = crypto.encryptData(data, key, iv);
      const decrypted = crypto.decryptData(
        encrypted.encrypted,
        key,
        iv,
        encrypted.tag
      );
      expect(decrypted).toEqual(data);
    });

    it('should throw error for invalid encrypted data', () => {
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);
      const tag = crypto.generateSecureRandom(16);

      expect(() =>
        crypto.decryptData(null as unknown as Buffer, key, iv, tag)
      ).toThrow(CryptoError);
      expect(() =>
        crypto.decryptData('string' as unknown as Buffer, key, iv, tag)
      ).toThrow(CryptoError);
    });

    it('should throw error for invalid key', () => {
      const encryptedData = Buffer.from('encrypted');
      const iv = crypto.generateSecureRandom(12);
      const tag = crypto.generateSecureRandom(16);

      expect(() =>
        crypto.decryptData(encryptedData, Buffer.alloc(16), iv, tag)
      ).toThrow(CryptoError);
      expect(() =>
        crypto.decryptData(encryptedData, null as unknown as Buffer, iv, tag)
      ).toThrow(CryptoError);
    });

    it('should throw error for invalid IV', () => {
      const encryptedData = Buffer.from('encrypted');
      const key = crypto.generateSecureRandom(32);
      const tag = crypto.generateSecureRandom(16);

      expect(() =>
        crypto.decryptData(encryptedData, key, Buffer.alloc(8), tag)
      ).toThrow(CryptoError);
      expect(() =>
        crypto.decryptData(encryptedData, key, null as unknown as Buffer, tag)
      ).toThrow(CryptoError);
    });

    it('should throw error for invalid tag', () => {
      const encryptedData = Buffer.from('encrypted');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      expect(() =>
        crypto.decryptData(encryptedData, key, iv, Buffer.alloc(8))
      ).toThrow(CryptoError);
      expect(() =>
        crypto.decryptData(encryptedData, key, iv, null as unknown as Buffer)
      ).toThrow(CryptoError);
    });

    it('should handle decryption errors with invalid data', () => {
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);
      const tag = crypto.generateSecureRandom(16);

      // Try to decrypt invalid data that should cause a crypto error
      const invalidData = Buffer.from('invalid encrypted data');

      expect(() => crypto.decryptData(invalidData, key, iv, tag)).toThrow(
        CryptoError
      );
    });

    it('should throw INVALID_AAD when aadOverride is not a Buffer (audit #11)', () => {
      // Mirror of the encryptData INVALID_AAD test — pins the matching guard in
      // decryptData (src/crypto-manager.ts). Previously untested.
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);
      const { encrypted, tag } = crypto.encryptData(data, key, iv);

      let caught: CryptoError | undefined;
      try {
        crypto.decryptData(
          encrypted,
          key,
          iv,
          tag,
          'not-a-buffer' as unknown as Buffer
        );
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_AAD');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });
  });

  describe('encryptText', () => {
    it('should encrypt text successfully', async () => {
      const result = await crypto.encryptText(testText, testPassword);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toBe(testText);
    });

    it('should encrypt text with default passphrase when no password provided', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      const result = await cryptoWithDefault.encryptText(testText);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toBe(testText);
    });

    it('should use provided password over default passphrase', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      const result = await cryptoWithDefault.encryptText(
        testText,
        testPassword
      );
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toBe(testText);
    });

    it('should throw INVALID_TEXT for null/undefined text', async () => {
      let caught: CryptoError | undefined;
      try {
        await crypto.encryptText(null as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_TEXT');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);

      caught = undefined;
      try {
        await crypto.encryptText(undefined as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_TEXT');
    });

    it('should encrypt and round-trip the empty string', async () => {
      const enc = await crypto.encryptText('', testPassword);
      expect(typeof enc).toBe('string');
      expect(enc.length).toBeGreaterThan(0);
      const dec = await crypto.decryptText(enc, testPassword);
      expect(dec).toBe('');
    });

    it('should throw error for invalid password', async () => {
      await expect(crypto.encryptText(testText, '')).rejects.toThrow(
        CryptoError
      );
      await expect(
        crypto.encryptText(testText, null as unknown as string)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error when no password provided and no default passphrase set', async () => {
      await expect(crypto.encryptText(testText)).rejects.toThrow(CryptoError);
    });
  });

  describe('decryptText', () => {
    it('should decrypt text successfully', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      const decrypted = await crypto.decryptText(encrypted, testPassword);
      expect(decrypted).toBe(testText);
    });

    it('should decrypt text with default passphrase when no password provided', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      const encrypted = await cryptoWithDefault.encryptText(testText);
      const decrypted = await cryptoWithDefault.decryptText(encrypted);
      expect(decrypted).toBe(testText);
    });

    it('should use provided password over default passphrase for decryption', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      const encrypted = await crypto.encryptText(testText, testPassword);
      const decrypted = await cryptoWithDefault.decryptText(
        encrypted,
        testPassword
      );
      expect(decrypted).toBe(testText);
    });

    it('should throw error for invalid encrypted text', async () => {
      await expect(crypto.decryptText('', testPassword)).rejects.toThrow(
        CryptoError
      );
      await expect(
        crypto.decryptText(null as unknown as string, testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for invalid password', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      await expect(crypto.decryptText(encrypted, '')).rejects.toThrow(
        CryptoError
      );
      await expect(
        crypto.decryptText(encrypted, null as unknown as string)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for encrypted data too small', async () => {
      await expect(crypto.decryptText('invalid', testPassword)).rejects.toThrow(
        CryptoError
      );
    });

    it('should throw error when no password provided and no default passphrase set', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      await expect(crypto.decryptText(encrypted)).rejects.toThrow(CryptoError);
    });
  });

  describe('encryptFile', () => {
    const testFilePath = path.join(tempDir, 'test-encrypt.txt');
    const encryptedFilePath = path.join(tempDir, 'test-encrypted.bin');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should encrypt file successfully', async () => {
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
      expect(existsSync(encryptedFilePath)).toBe(true);

      const stats = await readFile(encryptedFilePath);
      expect(stats.length).toBeGreaterThan(testText.length);
    });

    it('should encrypt file with default passphrase when no password provided', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      await cryptoWithDefault.encryptFile(testFilePath, encryptedFilePath);
      expect(existsSync(encryptedFilePath)).toBe(true);

      const stats = await readFile(encryptedFilePath);
      expect(stats.length).toBeGreaterThan(testText.length);
    });

    it('should use provided password over default passphrase for file encryption', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      await cryptoWithDefault.encryptFile(
        testFilePath,
        encryptedFilePath,
        testPassword
      );
      expect(existsSync(encryptedFilePath)).toBe(true);

      const stats = await readFile(encryptedFilePath);
      expect(stats.length).toBeGreaterThan(testText.length);
    });

    it('should throw error for missing parameters', async () => {
      await expect(
        crypto.encryptFile('', encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.encryptFile(testFilePath, '', testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError for non-string path arguments', async () => {
      let caught: CryptoError | undefined;
      try {
        await crypto.encryptFile(5 as unknown as string, encryptedFilePath, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);

      caught = undefined;
      try {
        await crypto.encryptFile(testFilePath, {} as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw error for weak password', async () => {
      await expect(
        crypto.encryptFile(testFilePath, encryptedFilePath, 'weak')
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for non-existent input file', async () => {
      await expect(
        crypto.encryptFile('non-existent.txt', encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error when no password provided and no default passphrase set', async () => {
      await expect(
        crypto.encryptFile(testFilePath, encryptedFilePath)
      ).rejects.toThrow(CryptoError);
    });

    it('should create output directory if it does not exist', async () => {
      const nestedDir = path.join(tempDir, 'nested', 'dir');
      const nestedOutputPath = path.join(nestedDir, 'encrypted.bin');

      await crypto.encryptFile(testFilePath, nestedOutputPath, testPassword);
      expect(existsSync(nestedOutputPath)).toBe(true);

      // Cleanup
      await unlink(nestedOutputPath);
    });
  });

  describe('decryptFile', () => {
    const testFilePath = path.join(tempDir, 'test-decrypt.txt');
    const encryptedFilePath = path.join(tempDir, 'test-encrypted.bin');
    const decryptedFilePath = path.join(tempDir, 'test-decrypted.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should decrypt file successfully', async () => {
      await crypto.decryptFile(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(existsSync(decryptedFilePath)).toBe(true);

      const decryptedContent = await readFile(decryptedFilePath, 'utf8');
      expect(decryptedContent).toBe(testText);
    });

    it('should decrypt file with default passphrase when no password provided', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      await cryptoWithDefault.decryptFile(encryptedFilePath, decryptedFilePath);
      expect(existsSync(decryptedFilePath)).toBe(true);

      const decryptedContent = await readFile(decryptedFilePath, 'utf8');
      expect(decryptedContent).toBe(testText);
    });

    it('should use provided password over default passphrase for file decryption', async () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      await cryptoWithDefault.decryptFile(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(existsSync(decryptedFilePath)).toBe(true);

      const decryptedContent = await readFile(decryptedFilePath, 'utf8');
      expect(decryptedContent).toBe(testText);
    });

    it('should throw error for missing parameters', async () => {
      await expect(
        crypto.decryptFile('', decryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.decryptFile(encryptedFilePath, '', testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError for non-string path arguments', async () => {
      let caught: CryptoError | undefined;
      try {
        await crypto.decryptFile(5 as unknown as string, decryptedFilePath, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);

      caught = undefined;
      try {
        await crypto.decryptFile(encryptedFilePath, {} as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw error for non-existent input file', async () => {
      await expect(
        crypto.decryptFile('non-existent.bin', decryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for file too small', async () => {
      const smallFile = path.join(tempDir, 'small.bin');
      await writeFile(smallFile, Buffer.alloc(10)); // Too small

      await expect(
        crypto.decryptFile(smallFile, decryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);

      // Cleanup
      await unlink(smallFile);
    });

    it('should throw error when no password provided and no default passphrase set', async () => {
      await expect(
        crypto.decryptFile(encryptedFilePath, decryptedFilePath)
      ).rejects.toThrow(CryptoError);
    });

    it('should create output directory if it does not exist', async () => {
      const nestedDir = path.join(tempDir, 'nested', 'dir');
      const nestedOutputPath = path.join(nestedDir, 'decrypted.txt');

      await crypto.decryptFile(
        encryptedFilePath,
        nestedOutputPath,
        testPassword
      );
      expect(existsSync(nestedOutputPath)).toBe(true);

      // Cleanup
      await unlink(nestedOutputPath);
    });
  });

  describe('secureClear', () => {
    it('should clear buffer contents', () => {
      const buffer = Buffer.from('sensitive data');
      crypto.secureClear(buffer);
      expect(buffer.toString()).toBe('\x00'.repeat(buffer.length));
    });

    it('should handle null/undefined buffer', () => {
      expect(() => crypto.secureClear(null as unknown as Buffer)).not.toThrow();
      expect(() =>
        crypto.secureClear(undefined as unknown as Buffer)
      ).not.toThrow();
    });

    it('should handle non-buffer input', () => {
      expect(() =>
        crypto.secureClear('not a buffer' as unknown as Buffer)
      ).not.toThrow();
    });
  });

  describe('validatePassword', () => {
    it('should validate strong passwords', () => {
      expect(crypto.validatePassword('StrongP@ss1')).toBe(true);
      expect(crypto.validatePassword('Complex!Pass2')).toBe(true);
    });

    it('should reject weak passwords', () => {
      expect(crypto.validatePassword('weak')).toBe(false);
      expect(crypto.validatePassword('')).toBe(false);
      expect(crypto.validatePassword(null as unknown as string)).toBe(false);
      expect(crypto.validatePassword('NoSpecialChar1')).toBe(false);
      expect(crypto.validatePassword('nouppercase1!')).toBe(false);
      expect(crypto.validatePassword('NOLOWERCASE1!')).toBe(false);
      expect(crypto.validatePassword('NoNumbers!')).toBe(false);
    });

    // -----------------------------------------------------------------------
    // Task 13: extended acceptance rules — long passphrases bypass character
    // categories, and "special character" now means any non-alphanumeric.
    // -----------------------------------------------------------------------

    it('should accept XKCD-style passphrases >= 20 chars without categories', () => {
      // Classic XKCD example, no upper/digit/special; length alone qualifies.
      expect(
        crypto.validatePassword('correct horse battery staple longer')
      ).toBe(true);
      expect(
        crypto.validatePassword('aaaaaaaaaaaaaaaaaaaa') // 20 lowercase only
      ).toBe(true);
    });

    it('should accept passphrases at exactly 20 characters', () => {
      // 20 chars, all lowercase, no digit/special — category rules
      // intentionally bypassed by length.
      const twenty = 'abcdefghijklmnopqrst';
      expect(twenty.length).toBe(20);
      expect(crypto.validatePassword(twenty)).toBe(true);
    });

    it('should still reject 19-char passwords lacking categories', () => {
      const nineteen = 'abcdefghijklmnopqrs';
      expect(nineteen.length).toBe(19);
      expect(crypto.validatePassword(nineteen)).toBe(false);
    });

    it('should accept short passwords with broadened special chars', () => {
      // `_` was previously rejected (not in `[!@#$%^&*(),.?":{}|<>]`); now
      // counts as "special" because it is non-alphanumeric.
      expect(crypto.validatePassword('Aa1_aaaa')).toBe(true);
      expect(crypto.validatePassword('Aa1-aaaa')).toBe(true);
      expect(crypto.validatePassword('Aa1+aaaa')).toBe(true);
      expect(crypto.validatePassword('Aa1=aaaa')).toBe(true);
      expect(crypto.validatePassword('Aa1[aaaa')).toBe(true);
      expect(crypto.validatePassword('Aa1]aaaa')).toBe(true);
      expect(crypto.validatePassword("Aa1'aaaa")).toBe(true);
      expect(crypto.validatePassword('Aa1`aaaa')).toBe(true);
      expect(crypto.validatePassword('Aa1\\aaaa')).toBe(true);
      // Non-ASCII punctuation also counts.
      expect(crypto.validatePassword('Aa1¶aaaa')).toBe(true);
    });

    it('should still preserve the historical narrow specials too', () => {
      // The old allow-list characters obviously still pass under the
      // broader rule; documenting the back-compat invariant here.
      expect(crypto.validatePassword('Test1234!')).toBe(true);
      expect(crypto.validatePassword('Test1234@')).toBe(true);
      expect(crypto.validatePassword('Test1234#')).toBe(true);
      expect(crypto.validatePassword('Test1234$')).toBe(true);
      expect(crypto.validatePassword('Test1234%')).toBe(true);
    });
  });

  describe('getParameters', () => {
    it('should return current parameters', () => {
      const params = crypto.getParameters();
      expect(params.algorithm).toBe('aes-256-gcm');
      expect(params.keyLength).toBe(32);
      expect(params.ivLength).toBe(12);
      expect(params.saltLength).toBe(32);
      expect(params.tagLength).toBe(16);
      expect(params.argon2Options).toBeDefined();
    });

    it('should return a copy of argon2Options', () => {
      const params = crypto.getParameters();
      const originalOptions = params.argon2Options;

      // Modify the returned options
      originalOptions.memoryCost = 999;

      // Get parameters again - should be unchanged
      const newParams = crypto.getParameters();
      expect(newParams.argon2Options.memoryCost).not.toBe(999);
    });
  });

  describe('getSecurityLevel', () => {
    it('should return ULTRA at the post-Task-18 threshold (mem=2^19, time=4)', () => {
      const ultraCrypto = new CryptoManager({
        memoryCost: 2 ** 19,
        timeCost: 4,
      });
      expect(ultraCrypto.getSecurityLevel()).toBe(SecurityLevel.ULTRA);
    });

    it('should return HIGH at the post-Task-18 threshold (mem=2^17, time=3)', () => {
      const highCrypto = new CryptoManager({
        memoryCost: 2 ** 17,
        timeCost: 3,
      });
      expect(highCrypto.getSecurityLevel()).toBe(SecurityLevel.HIGH);
    });

    it('should return MEDIUM for moderate settings', () => {
      const mediumCrypto = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 2,
      });
      expect(mediumCrypto.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
    });

    it('should return HIGH for default settings', () => {
      // The default after Task 18 is memoryCost=2^17 (128 MiB), timeCost=3,
      // which classifies as HIGH (the OWASP first-choice tier).
      expect(crypto.getSecurityLevel()).toBe(SecurityLevel.HIGH);
    });

    it('should return MEDIUM for the pre-Task-18 default (mem=2^16, time=3)', () => {
      // Bumping the HIGH threshold from 2^16 → 2^17 means the old 64 MiB
      // default is now classified as MEDIUM. Lock this in so the threshold
      // change is regression-tested.
      const oldDefaultCrypto = new CryptoManager({
        memoryCost: 2 ** 16,
        timeCost: 3,
      });
      expect(oldDefaultCrypto.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
    });

    it('should return HIGH for the pre-Task-18 ULTRA settings (mem=2^18, time=4)', () => {
      // Bumping the ULTRA threshold from 2^18 → 2^19 means the previous
      // ULTRA configuration falls back to HIGH. This is the documented perf
      // / security trade-off — callers who want ULTRA must now provision
      // 512 MiB instead of 256 MiB.
      const oldUltraCrypto = new CryptoManager({
        memoryCost: 2 ** 18,
        timeCost: 4,
      });
      expect(oldUltraCrypto.getSecurityLevel()).toBe(SecurityLevel.HIGH);
    });

    it('should return LOW for low settings', () => {
      const lowCrypto = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
      });
      expect(lowCrypto.getSecurityLevel()).toBe(SecurityLevel.LOW);
    });
  });

  describe('hasDefaultPassphrase', () => {
    it('should return true when default passphrase is set', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      expect(cryptoWithDefault.hasDefaultPassphrase()).toBe(true);
    });

    it('should return false when no default passphrase is set', () => {
      expect(crypto.hasDefaultPassphrase()).toBe(false);
    });

    it('should return false when default passphrase is empty string', () => {
      const cryptoWithEmpty = new CryptoManager({
        defaultPassphrase: '',
      });
      expect(cryptoWithEmpty.hasDefaultPassphrase()).toBe(false);
    });
  });

  describe('deriveKeySync', () => {
    it('should derive key successfully', () => {
      const salt = crypto.generateSecureRandom(32);
      const key = crypto.deriveKeySync(testPassword, salt);
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });

    it('should throw error for invalid password', () => {
      const salt = crypto.generateSecureRandom(32);
      expect(() => crypto.deriveKeySync('', salt)).toThrow(CryptoError);
      expect(() =>
        crypto.deriveKeySync(null as unknown as string, salt)
      ).toThrow(CryptoError);
    });

    it('should throw error for invalid salt', () => {
      const invalidSalt = Buffer.alloc(16); // Wrong length
      expect(() => crypto.deriveKeySync(testPassword, invalidSalt)).toThrow(
        CryptoError
      );
      expect(() =>
        crypto.deriveKeySync(testPassword, null as unknown as Buffer)
      ).toThrow(CryptoError);
    });
  });

  describe('encryptTextSync', () => {
    it('should encrypt text successfully', () => {
      const result = crypto.encryptTextSync(testText, testPassword);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toBe(testText);
    });

    it('should encrypt text with default passphrase when no password provided', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      const result = cryptoWithDefault.encryptTextSync(testText);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toBe(testText);
    });

    it('should use provided password over default passphrase', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      const result = cryptoWithDefault.encryptTextSync(testText, testPassword);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toBe(testText);
    });

    it('should throw INVALID_TEXT for null/undefined text', () => {
      let caught: CryptoError | undefined;
      try {
        crypto.encryptTextSync(null as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_TEXT');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);

      caught = undefined;
      try {
        crypto.encryptTextSync(undefined as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('INVALID_TEXT');
    });

    it('should encrypt and round-trip the empty string (sync)', () => {
      const enc = crypto.encryptTextSync('', testPassword);
      expect(typeof enc).toBe('string');
      expect(enc.length).toBeGreaterThan(0);
      const dec = crypto.decryptTextSync(enc, testPassword);
      expect(dec).toBe('');
    });

    it('should throw error for invalid password', () => {
      expect(() => crypto.encryptTextSync(testText, '')).toThrow(CryptoError);
      expect(() =>
        crypto.encryptTextSync(testText, null as unknown as string)
      ).toThrow(CryptoError);
    });

    it('should throw error when no password provided and no default passphrase set', () => {
      expect(() => crypto.encryptTextSync(testText)).toThrow(CryptoError);
    });
  });

  describe('decryptTextSync', () => {
    it('should decrypt text successfully', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      const decrypted = crypto.decryptTextSync(encrypted, testPassword);
      expect(decrypted).toBe(testText);
    });

    it('should decrypt text with default passphrase when no password provided', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      const encrypted = cryptoWithDefault.encryptTextSync(testText);
      const decrypted = cryptoWithDefault.decryptTextSync(encrypted);
      expect(decrypted).toBe(testText);
    });

    it('should use provided password over default passphrase for decryption', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      const decrypted = cryptoWithDefault.decryptTextSync(
        encrypted,
        testPassword
      );
      expect(decrypted).toBe(testText);
    });

    it('should throw error for invalid encrypted text', () => {
      expect(() => crypto.decryptTextSync('', testPassword)).toThrow(
        CryptoError
      );
      expect(() =>
        crypto.decryptTextSync(null as unknown as string, testPassword)
      ).toThrow(CryptoError);
    });

    it('should throw error for invalid password', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      expect(() => crypto.decryptTextSync(encrypted, '')).toThrow(CryptoError);
      expect(() =>
        crypto.decryptTextSync(encrypted, null as unknown as string)
      ).toThrow(CryptoError);
    });

    it('should throw error for encrypted data too small', () => {
      expect(() => crypto.decryptTextSync('invalid', testPassword)).toThrow(
        CryptoError
      );
    });

    it('should throw error when no password provided and no default passphrase set', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      expect(() => crypto.decryptTextSync(encrypted)).toThrow(CryptoError);
    });
  });

  describe('encryptFileSync', () => {
    const testFilePath = path.join(tempDir, 'test-encrypt-sync.txt');
    const encryptedFilePath = path.join(tempDir, 'test-encrypted-sync.bin');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should encrypt file successfully', () => {
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
      expect(existsSync(encryptedFilePath)).toBe(true);

      const stats = readFileSync(encryptedFilePath);
      expect(stats.length).toBeGreaterThan(testText.length);
    });

    it('should encrypt file with default passphrase when no password provided', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      cryptoWithDefault.encryptFileSync(testFilePath, encryptedFilePath);
      expect(existsSync(encryptedFilePath)).toBe(true);

      const stats = readFileSync(encryptedFilePath);
      expect(stats.length).toBeGreaterThan(testText.length);
    });

    it('should use provided password over default passphrase for file encryption', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      cryptoWithDefault.encryptFileSync(
        testFilePath,
        encryptedFilePath,
        testPassword
      );
      expect(existsSync(encryptedFilePath)).toBe(true);

      const stats = readFileSync(encryptedFilePath);
      expect(stats.length).toBeGreaterThan(testText.length);
    });

    it('should throw error for missing parameters', () => {
      expect(() =>
        crypto.encryptFileSync('', encryptedFilePath, testPassword)
      ).toThrow(CryptoError);
      expect(() =>
        crypto.encryptFileSync(testFilePath, '', testPassword)
      ).toThrow(CryptoError);
    });

    it('should throw CryptoError for non-string path arguments', () => {
      let caught: CryptoError | undefined;
      try {
        crypto.encryptFileSync(5 as unknown as string, encryptedFilePath, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);

      caught = undefined;
      try {
        crypto.encryptFileSync(testFilePath, {} as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw error for weak password', () => {
      expect(() =>
        crypto.encryptFileSync(testFilePath, encryptedFilePath, 'weak')
      ).toThrow(CryptoError);
    });

    it('should throw error for non-existent input file', () => {
      expect(() =>
        crypto.encryptFileSync(
          'non-existent.txt',
          encryptedFilePath,
          testPassword
        )
      ).toThrow(CryptoError);
    });

    it('should throw error when no password provided and no default passphrase set', () => {
      expect(() =>
        crypto.encryptFileSync(testFilePath, encryptedFilePath)
      ).toThrow(CryptoError);
    });

    it('should create output directory if it does not exist', () => {
      const nestedDir = path.join(tempDir, 'nested', 'dir');
      const nestedOutputPath = path.join(nestedDir, 'encrypted-sync.bin');

      crypto.encryptFileSync(testFilePath, nestedOutputPath, testPassword);
      expect(existsSync(nestedOutputPath)).toBe(true);

      // Cleanup
      unlinkSync(nestedOutputPath);
    });
  });

  describe('decryptFileSync', () => {
    const testFilePath = path.join(tempDir, 'test-decrypt-sync.txt');
    const encryptedFilePath = path.join(tempDir, 'test-encrypted-sync.bin');
    const decryptedFilePath = path.join(tempDir, 'test-decrypted-sync.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should decrypt file successfully', () => {
      crypto.decryptFileSync(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(existsSync(decryptedFilePath)).toBe(true);

      const decryptedContent = readFileSync(decryptedFilePath, 'utf8');
      expect(decryptedContent).toBe(testText);
    });

    it('should decrypt file with default passphrase when no password provided', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: testPassword,
      });
      cryptoWithDefault.decryptFileSync(encryptedFilePath, decryptedFilePath);
      expect(existsSync(decryptedFilePath)).toBe(true);

      const decryptedContent = readFileSync(decryptedFilePath, 'utf8');
      expect(decryptedContent).toBe(testText);
    });

    it('should use provided password over default passphrase for file decryption', () => {
      const cryptoWithDefault = new CryptoManager({
        defaultPassphrase: 'DifferentP@ssw0rd123!',
      });
      cryptoWithDefault.decryptFileSync(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(existsSync(decryptedFilePath)).toBe(true);

      const decryptedContent = readFileSync(decryptedFilePath, 'utf8');
      expect(decryptedContent).toBe(testText);
    });

    it('should throw error for missing parameters', () => {
      expect(() =>
        crypto.decryptFileSync('', decryptedFilePath, testPassword)
      ).toThrow(CryptoError);
      expect(() =>
        crypto.decryptFileSync(encryptedFilePath, '', testPassword)
      ).toThrow(CryptoError);
    });

    it('should throw CryptoError for non-string path arguments', () => {
      let caught: CryptoError | undefined;
      try {
        crypto.decryptFileSync(5 as unknown as string, decryptedFilePath, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);

      caught = undefined;
      try {
        crypto.decryptFileSync(encryptedFilePath, {} as unknown as string, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('MISSING_REQUIRED_PARAMS');
      expect(caught?.type).toBe(CryptoErrorType.INVALID_INPUT);
    });

    it('should throw error for non-existent input file', () => {
      expect(() =>
        crypto.decryptFileSync(
          'non-existent.bin',
          decryptedFilePath,
          testPassword
        )
      ).toThrow(CryptoError);
    });

    it('should throw error for file too small', () => {
      const smallFile = path.join(tempDir, 'small-sync.bin');
      writeFileSync(smallFile, Buffer.alloc(10)); // Too small

      expect(() =>
        crypto.decryptFileSync(smallFile, decryptedFilePath, testPassword)
      ).toThrow(CryptoError);

      // Cleanup
      unlinkSync(smallFile);
    });

    it('should throw error when no password provided and no default passphrase set', () => {
      expect(() =>
        crypto.decryptFileSync(encryptedFilePath, decryptedFilePath)
      ).toThrow(CryptoError);
    });

    it('should create output directory if it does not exist', () => {
      const nestedDir = path.join(tempDir, 'nested', 'dir');
      const nestedOutputPath = path.join(nestedDir, 'decrypted-sync.txt');

      crypto.decryptFileSync(encryptedFilePath, nestedOutputPath, testPassword);
      expect(existsSync(nestedOutputPath)).toBe(true);

      // Cleanup
      unlinkSync(nestedOutputPath);
    });
  });

  describe('CryptoError', () => {
    it('should use default type and code when not provided', () => {
      const error = new CryptoError('test error');
      expect(error.message).toBe('test error');
      expect(error.type).toBe(CryptoErrorType.VALIDATION_ERROR);
      expect(error.code).toBe('CRYPTO_ERROR');
      expect(error.name).toBe('CryptoError');
    });

    it('should use default code when only type provided', () => {
      const error = new CryptoError(
        'test error',
        CryptoErrorType.ENCRYPTION_FAILED
      );
      expect(error.type).toBe(CryptoErrorType.ENCRYPTION_FAILED);
      expect(error.code).toBe('CRYPTO_ERROR');
    });

    it('should use all custom params', () => {
      const error = new CryptoError(
        'custom msg',
        CryptoErrorType.FILE_ERROR,
        'CUSTOM_CODE'
      );
      expect(error.message).toBe('custom msg');
      expect(error.type).toBe(CryptoErrorType.FILE_ERROR);
      expect(error.code).toBe('CUSTOM_CODE');
    });

    it('should be an instance of Error', () => {
      const error = new CryptoError('test');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(CryptoError);
    });
  });

  describe('encryptText - weak password', () => {
    it('should throw WEAK_PASSWORD for password without special chars', async () => {
      await expect(
        crypto.encryptText(testText, 'WeakPassword1')
      ).rejects.toThrow(CryptoError);
      try {
        await crypto.encryptText(testText, 'WeakPassword1');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('WEAK_PASSWORD');
      }
    });

    it('should throw WEAK_PASSWORD for password without uppercase', async () => {
      await expect(
        crypto.encryptText(testText, 'weakpassword1!')
      ).rejects.toThrow(CryptoError);
    });

    it('should throw WEAK_PASSWORD for password without lowercase', async () => {
      await expect(
        crypto.encryptText(testText, 'WEAKPASSWORD1!')
      ).rejects.toThrow(CryptoError);
    });

    it('should throw WEAK_PASSWORD for password without digits', async () => {
      await expect(
        crypto.encryptText(testText, 'WeakPassword!')
      ).rejects.toThrow(CryptoError);
    });

    it('should throw WEAK_PASSWORD for short password', async () => {
      await expect(crypto.encryptText(testText, 'Ab1!')).rejects.toThrow(
        CryptoError
      );
    });
  });

  describe('encryptTextSync - weak password', () => {
    it('should throw WEAK_PASSWORD for password without special chars', () => {
      expect(() => crypto.encryptTextSync(testText, 'WeakPassword1')).toThrow(
        CryptoError
      );
      try {
        crypto.encryptTextSync(testText, 'WeakPassword1');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('WEAK_PASSWORD');
      }
    });

    it('should throw WEAK_PASSWORD for password without uppercase', () => {
      expect(() =>
        crypto.encryptTextSync(testText, 'weakpassword1!')
      ).toThrow(CryptoError);
    });
  });

  describe('encryptFile - weak password', () => {
    const testFilePath = path.join(tempDir, 'test-weak-pw.txt');
    const encryptedFilePath = path.join(tempDir, 'test-weak-pw.bin');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw WEAK_PASSWORD for password without special chars', async () => {
      await expect(
        crypto.encryptFile(testFilePath, encryptedFilePath, 'WeakPassword1')
      ).rejects.toThrow(CryptoError);
    });
  });

  describe('encryptFileSync - weak password', () => {
    const testFilePath = path.join(tempDir, 'test-weak-pw-sync.txt');
    const encryptedFilePath = path.join(tempDir, 'test-weak-pw-sync.bin');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw WEAK_PASSWORD for password without special chars', () => {
      expect(() =>
        crypto.encryptFileSync(testFilePath, encryptedFilePath, 'WeakPassword1')
      ).toThrow(CryptoError);
    });
  });

  describe('decryptText - wrong password', () => {
    it('should throw CryptoError when decrypting with wrong password', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      let caught: CryptoError | undefined;
      try {
        await crypto.decryptText(encrypted, 'WrongP@ssw0rd123!');
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });
  });

  describe('decryptTextSync - wrong password', () => {
    it('should throw CryptoError when decrypting with wrong password', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      let caught: CryptoError | undefined;
      try {
        crypto.decryptTextSync(encrypted, 'WrongP@ssw0rd123!');
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });
  });

  describe('decryptFile - wrong password', () => {
    const testFilePath = path.join(tempDir, 'test-wrong-pw-dec.txt');
    const encryptedFilePath = path.join(tempDir, 'test-wrong-pw-enc.bin');
    const decryptedFilePath = path.join(tempDir, 'test-wrong-pw-out.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw CryptoError when decrypting with wrong password', async () => {
      let caught: CryptoError | undefined;
      try {
        await crypto.decryptFile(
          encryptedFilePath,
          decryptedFilePath,
          'WrongP@ssw0rd123!'
        );
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('FILE_DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
      // Output file should be cleaned up (deleted)
      expect(existsSync(decryptedFilePath)).toBe(false);
    });

    it('should throw CryptoError for tampered encrypted file', async () => {
      // Tamper with the encrypted file (flip last byte of the auth tag)
      const data = await readFile(encryptedFilePath);
      data[data.length - 1] = (data[data.length - 1] ?? 0) ^ 0xff;
      await writeFile(encryptedFilePath, data);

      let caught: CryptoError | undefined;
      try {
        await crypto.decryptFile(encryptedFilePath, decryptedFilePath, testPassword);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('FILE_DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });
  });

  describe('decryptFileSync - wrong password', () => {
    const testFilePath = path.join(tempDir, 'test-wrong-pw-dec-sync.txt');
    const encryptedFilePath = path.join(tempDir, 'test-wrong-pw-enc-sync.bin');
    const decryptedFilePath = path.join(tempDir, 'test-wrong-pw-out-sync.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw CryptoError when decrypting with wrong password', () => {
      let caught: CryptoError | undefined;
      try {
        crypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          'WrongP@ssw0rd123!'
        );
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('SYNC_FILE_DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
      // Output file should be cleaned up (deleted)
      expect(existsSync(decryptedFilePath)).toBe(false);
    });

    it('should throw CryptoError for tampered encrypted file', () => {
      const data = readFileSync(encryptedFilePath);
      data[data.length - 1] = (data[data.length - 1] ?? 0) ^ 0xff;
      writeFileSync(encryptedFilePath, data);

      let caught: CryptoError | undefined;
      try {
        crypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        );
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('SYNC_FILE_DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });
  });

  describe('encryptText - error handling', () => {
    it('should wrap non-CryptoError exceptions', async () => {
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'generateSecureRandom').mockImplementation(() => {
        throw new Error('Random generation hardware failure');
      });

      try {
        await mockCrypto.encryptText(testText, testPassword);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('TEXT_ENCRYPTION_FAILED');
      }

      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError from inside try block', async () => {
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKey').mockRejectedValue(
        new CryptoError(
          'Mock key derivation failure',
          CryptoErrorType.ENCRYPTION_FAILED,
          'MOCK_KEY_ERROR'
        )
      );

      try {
        await mockCrypto.encryptText(testText, testPassword);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('MOCK_KEY_ERROR');
      }

      jest.restoreAllMocks();
    });
  });

  describe('encryptTextSync - error handling', () => {
    it('should wrap non-CryptoError exceptions', () => {
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'generateSecureRandom').mockImplementation(() => {
        throw new Error('Random generation hardware failure');
      });

      try {
        mockCrypto.encryptTextSync(testText, testPassword);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'SYNC_TEXT_ENCRYPTION_FAILED'
        );
      }

      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError from inside try block', () => {
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new CryptoError(
          'Mock key derivation failure',
          CryptoErrorType.ENCRYPTION_FAILED,
          'MOCK_KEY_ERROR'
        );
      });

      try {
        mockCrypto.encryptTextSync(testText, testPassword);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('MOCK_KEY_ERROR');
      }

      jest.restoreAllMocks();
    });
  });

  describe('decryptText - non-CryptoError wrapping', () => {
    it('should wrap non-CryptoError exceptions', async () => {
      const mockCrypto = new CryptoManager();
      // Encrypt first with real implementation
      const encrypted = await mockCrypto.encryptText(testText, testPassword);

      // Now mock deriveKey to throw generic error
      jest.spyOn(mockCrypto, 'deriveKey').mockRejectedValue(
        new Error('Key derivation hardware failure')
      );

      try {
        await mockCrypto.decryptText(encrypted, testPassword);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('TEXT_DECRYPTION_FAILED');
      }

      jest.restoreAllMocks();
    });
  });

  describe('decryptTextSync - non-CryptoError wrapping', () => {
    it('should wrap non-CryptoError exceptions', () => {
      const mockCrypto = new CryptoManager();
      const encrypted = mockCrypto.encryptTextSync(testText, testPassword);

      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new Error('Key derivation hardware failure');
      });

      try {
        mockCrypto.decryptTextSync(encrypted, testPassword);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'SYNC_TEXT_DECRYPTION_FAILED'
        );
      }

      jest.restoreAllMocks();
    });
  });

  describe('encryptFile - non-CryptoError wrapping', () => {
    const testFilePath = path.join(tempDir, 'test-enc-wrap.txt');
    const encryptedFilePath = path.join(tempDir, 'test-enc-wrap.bin');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should wrap non-CryptoError exceptions and clean up output', async () => {
      const mockCrypto = new CryptoManager();
      // Mock deriveKey to throw a generic Error
      jest.spyOn(mockCrypto, 'deriveKey').mockRejectedValue(
        new Error('Key derivation hardware failure')
      );

      try {
        await mockCrypto.encryptFile(
          testFilePath,
          encryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('FILE_ENCRYPTION_FAILED');
      }
      // Output file should be cleaned up
      expect(existsSync(encryptedFilePath)).toBe(false);

      jest.restoreAllMocks();
    });
  });

  describe('decryptFile - non-CryptoError wrapping', () => {
    const testFilePath = path.join(tempDir, 'test-dec-wrap.txt');
    const encryptedFilePath = path.join(tempDir, 'test-dec-wrap.bin');
    const decryptedFilePath = path.join(tempDir, 'test-dec-wrap-out.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should wrap non-CryptoError exceptions', async () => {
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKey').mockRejectedValue(
        new Error('Key derivation hardware failure')
      );

      try {
        await mockCrypto.decryptFile(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('FILE_DECRYPTION_FAILED');
      }

      jest.restoreAllMocks();
    });
  });

  describe('encryptFileSync - non-CryptoError wrapping', () => {
    const testFilePath = path.join(tempDir, 'test-enc-wrap-sync.txt');
    const encryptedFilePath = path.join(tempDir, 'test-enc-wrap-sync.bin');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should wrap non-CryptoError exceptions and clean up output', () => {
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new Error('Key derivation hardware failure');
      });

      try {
        mockCrypto.encryptFileSync(
          testFilePath,
          encryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'SYNC_FILE_ENCRYPTION_FAILED'
        );
      }
      // Output file should be cleaned up
      expect(existsSync(encryptedFilePath)).toBe(false);

      jest.restoreAllMocks();
    });
  });

  describe('decryptFileSync - non-CryptoError wrapping', () => {
    const testFilePath = path.join(tempDir, 'test-dec-wrap-sync.txt');
    const encryptedFilePath = path.join(tempDir, 'test-dec-wrap-sync.bin');
    const decryptedFilePath = path.join(tempDir, 'test-dec-wrap-sync-out.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should wrap non-CryptoError exceptions', () => {
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new Error('Key derivation hardware failure');
      });

      try {
        mockCrypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'SYNC_FILE_DECRYPTION_FAILED'
        );
      }

      jest.restoreAllMocks();
    });
  });

  describe('encrypt/decrypt roundtrip edge cases', () => {
    it('should handle unicode text', async () => {
      const unicodeText = 'こんにちは世界 🌍 مرحبا بالعالم';
      const encrypted = await crypto.encryptText(unicodeText, testPassword);
      const decrypted = await crypto.decryptText(encrypted, testPassword);
      expect(decrypted).toBe(unicodeText);
    });

    it('should handle very long text', async () => {
      const longText = 'A'.repeat(100000);
      const encrypted = await crypto.encryptText(longText, testPassword);
      const decrypted = await crypto.decryptText(encrypted, testPassword);
      expect(decrypted).toBe(longText);
    });

    it('should produce different ciphertext each time', async () => {
      const enc1 = await crypto.encryptText(testText, testPassword);
      const enc2 = await crypto.encryptText(testText, testPassword);
      expect(enc1).not.toBe(enc2);
    });

    it('should handle unicode text sync', () => {
      const unicodeText = 'Ünïcödé Têxt ñ é ü ö';
      const encrypted = crypto.encryptTextSync(unicodeText, testPassword);
      const decrypted = crypto.decryptTextSync(encrypted, testPassword);
      expect(decrypted).toBe(unicodeText);
    });

    it('should produce different ciphertext each time sync', () => {
      const enc1 = crypto.encryptTextSync(testText, testPassword);
      const enc2 = crypto.encryptTextSync(testText, testPassword);
      expect(enc1).not.toBe(enc2);
    });
  });

  describe('file encrypt/decrypt roundtrip edge cases', () => {
    const testFilePath = path.join(tempDir, 'test-roundtrip.txt');
    const encryptedFilePath = path.join(tempDir, 'test-roundtrip.bin');
    const decryptedFilePath = path.join(tempDir, 'test-roundtrip-out.txt');

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should handle binary file content', async () => {
      const binaryData = Buffer.from(
        Array.from({ length: 256 }, (_, i) => i)
      );
      await writeFile(testFilePath, binaryData);

      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
      await crypto.decryptFile(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );

      const decryptedData = await readFile(decryptedFilePath);
      expect(decryptedData).toEqual(binaryData);
    });

    it('should handle binary file content sync', async () => {
      const binaryData = Buffer.from(
        Array.from({ length: 256 }, (_, i) => i)
      );
      await writeFile(testFilePath, binaryData);

      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
      crypto.decryptFileSync(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );

      const decryptedData = readFileSync(decryptedFilePath);
      expect(decryptedData).toEqual(binaryData);
    });

    it('should handle empty-ish file', async () => {
      await writeFile(testFilePath, 'x');
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
      await crypto.decryptFile(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      const content = await readFile(decryptedFilePath, 'utf8');
      expect(content).toBe('x');
    });
  });

  describe('cross-instance compatibility', () => {
    it('should decrypt with same configuration async', async () => {
      const crypto1 = new CryptoManager({ aad: 'app-v1' });
      const crypto2 = new CryptoManager({ aad: 'app-v1' });

      const encrypted = await crypto1.encryptText(testText, testPassword);
      const decrypted = await crypto2.decryptText(encrypted, testPassword);
      expect(decrypted).toBe(testText);
    });

    it('should fail with different AAD', async () => {
      const crypto1 = new CryptoManager({ aad: 'app-v1' });
      const crypto2 = new CryptoManager({ aad: 'app-v2' });

      const encrypted = await crypto1.encryptText(testText, testPassword);
      await expect(
        crypto2.decryptText(encrypted, testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should decrypt with same configuration sync', () => {
      const crypto1 = new CryptoManager({ aad: 'app-v1' });
      const crypto2 = new CryptoManager({ aad: 'app-v1' });

      const encrypted = crypto1.encryptTextSync(testText, testPassword);
      const decrypted = crypto2.decryptTextSync(encrypted, testPassword);
      expect(decrypted).toBe(testText);
    });

    it('should fail with different AAD sync', () => {
      const crypto1 = new CryptoManager({ aad: 'app-v1' });
      const crypto2 = new CryptoManager({ aad: 'app-v2' });

      const encrypted = crypto1.encryptTextSync(testText, testPassword);
      expect(() =>
        crypto2.decryptTextSync(encrypted, testPassword)
      ).toThrow(CryptoError);
    });
  });

  describe('Constructor - additional validation', () => {
    it('should accept valid custom memoryCost', () => {
      const cm = new CryptoManager({ memoryCost: 2 ** 14 });
      const params = cm.getParameters();
      expect(params.argon2Options.memoryCost).toBe(2 ** 14);
    });

    it('should accept valid custom timeCost', () => {
      const cm = new CryptoManager({ timeCost: 5 });
      const params = cm.getParameters();
      expect(params.argon2Options.timeCost).toBe(5);
    });

    it('should accept valid custom parallelism', () => {
      const cm = new CryptoManager({ parallelism: 2 });
      const params = cm.getParameters();
      expect(params.argon2Options.parallelism).toBe(2);
    });

    it('should reject NaN memoryCost', () => {
      expect(() => new CryptoManager({ memoryCost: NaN })).toThrow(
        CryptoError
      );
    });

    it('should reject NaN timeCost', () => {
      expect(() => new CryptoManager({ timeCost: NaN })).toThrow(CryptoError);
    });

    it('should reject NaN parallelism', () => {
      expect(() => new CryptoManager({ parallelism: NaN })).toThrow(
        CryptoError
      );
    });

    it('should reject negative memoryCost', () => {
      expect(() => new CryptoManager({ memoryCost: -100 })).toThrow(
        CryptoError
      );
    });

    it('should reject float timeCost', () => {
      expect(() => new CryptoManager({ timeCost: 2.5 })).toThrow(CryptoError);
    });

    it('should reject float parallelism', () => {
      expect(() => new CryptoManager({ parallelism: 1.5 })).toThrow(
        CryptoError
      );
    });

    it('should not store empty string as default passphrase', () => {
      const cm = new CryptoManager({ defaultPassphrase: '' });
      expect(cm.hasDefaultPassphrase()).toBe(false);
    });
  });

  describe('generateSecureRandom - additional edge cases', () => {
    it('should generate 1 byte', () => {
      const random = crypto.generateSecureRandom(1);
      expect(random.length).toBe(1);
    });

    it('should generate max 1024 bytes', () => {
      const random = crypto.generateSecureRandom(1024);
      expect(random.length).toBe(1024);
    });

    it('should throw for non-integer', () => {
      expect(() => crypto.generateSecureRandom(1.5)).toThrow(CryptoError);
      expect(() => crypto.generateSecureRandom(NaN)).toThrow(CryptoError);
    });

    it('should produce unique bytes', () => {
      const a = crypto.generateSecureRandom(32);
      const b = crypto.generateSecureRandom(32);
      expect(a.equals(b)).toBe(false);
    });
  });

  describe('deriveKey - consistent output', () => {
    it('should produce same key for same password and salt', async () => {
      const salt = crypto.generateSecureRandom(32);
      const key1 = await crypto.deriveKey(testPassword, salt);
      const key2 = await crypto.deriveKey(testPassword, salt);
      expect(key1.equals(key2)).toBe(true);
    });

    it('should produce different keys for different salts', async () => {
      const salt1 = crypto.generateSecureRandom(32);
      const salt2 = crypto.generateSecureRandom(32);
      const key1 = await crypto.deriveKey(testPassword, salt1);
      const key2 = await crypto.deriveKey(testPassword, salt2);
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('deriveKeySync - consistent output', () => {
    it('should produce same key for same password and salt', () => {
      const salt = crypto.generateSecureRandom(32);
      const key1 = crypto.deriveKeySync(testPassword, salt);
      const key2 = crypto.deriveKeySync(testPassword, salt);
      expect(key1.equals(key2)).toBe(true);
    });

    it('should produce different keys for different passwords', () => {
      const salt = crypto.generateSecureRandom(32);
      const key1 = crypto.deriveKeySync(testPassword, salt);
      const key2 = crypto.deriveKeySync('DifferentP@ssw0rd123!', salt);
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('encryptData/decryptData roundtrip', () => {
    it('should handle empty buffer', () => {
      const data = Buffer.alloc(0);
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv);
      const decrypted = crypto.decryptData(encrypted, key, iv, tag);
      expect(decrypted).toEqual(data);
    });

    it('should handle large buffer', () => {
      const data = crypto.generateSecureRandom(1024);
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv);
      const decrypted = crypto.decryptData(encrypted, key, iv, tag);
      expect(decrypted).toEqual(data);
    });

    it('should fail with wrong key', () => {
      const data = Buffer.from('test data');
      const key1 = crypto.generateSecureRandom(32);
      const key2 = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key1, iv);
      let caught: CryptoError | undefined;
      try {
        crypto.decryptData(encrypted, key2, iv, tag);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });

    it('should fail with wrong iv', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv1 = crypto.generateSecureRandom(12);
      const iv2 = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv1);
      let caught: CryptoError | undefined;
      try {
        crypto.decryptData(encrypted, key, iv2, tag);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });

    it('should fail with tampered ciphertext', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv);
      encrypted[0] = (encrypted[0] ?? 0) ^ 0xff;
      let caught: CryptoError | undefined;
      try {
        crypto.decryptData(encrypted, key, iv, tag);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });

    it('should fail with tampered tag', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv);
      tag[0] = (tag[0] ?? 0) ^ 0xff;
      let caught: CryptoError | undefined;
      try {
        crypto.decryptData(encrypted, key, iv, tag);
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('DECRYPTION_FAILED');
      expect(caught?.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
    });

    it('encryptData with reused (key, iv) is deterministic — security boundary documentation (Task 17 / M17)', () => {
      // SECURITY DOCUMENTATION TEST.
      //
      // This test deliberately encrypts the SAME plaintext twice with the
      // SAME key AND the SAME iv, and asserts that the resulting ciphertext
      // and authentication tag are byte-identical. It is NOT a "feature"
      // test — it exists to lock in, and to make visible, the property of
      // AES-GCM that motivates the @security warning on `encryptData`:
      //
      //   AES-GCM is a deterministic stream cipher under any fixed
      //   `(key, iv)` pair. Therefore reusing a `(key, iv)` pair to encrypt
      //   two DIFFERENT plaintexts is catastrophic: an observer can XOR
      //   the two ciphertexts to recover the XOR of the plaintexts (the
      //   keystream cancels), and additionally the GCM authentication
      //   subkey leaks, which means the attacker can forge authenticated
      //   ciphertexts under that key.
      //
      // The high-level methods (`encryptText`/`encryptFile` and their
      // `Sync` siblings) avoid this hazard by generating a fresh random IV
      // per message AND deriving a fresh key from a fresh per-message
      // salt. Direct callers of the low-level `encryptData` API take on
      // the IV-uniqueness obligation themselves; if you ever find yourself
      // about to call `encryptData` with a fixed `(key, iv)`, STOP —
      // generate a new IV first via `generateSecureRandom(12)`.
      //
      // If a future refactor changes this property (e.g. somehow injects
      // randomness into `encryptData`), this test will fail loudly and
      // force a deliberate review of the new behaviour rather than
      // silently changing a documented security boundary.
      const data = Buffer.from(
        'plaintext-that-must-not-be-encrypted-twice-with-the-same-key-and-iv'
      );
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const first = crypto.encryptData(data, key, iv);
      const second = crypto.encryptData(data, key, iv);

      // Same `(plaintext, key, iv, aad)` => identical ciphertext and tag.
      expect(first.encrypted.equals(second.encrypted)).toBe(true);
      expect(first.tag.equals(second.tag)).toBe(true);

      // Sanity check: changing JUST the plaintext (still the same key+iv —
      // the dangerous setup the @security warning is about) leaks the
      // plaintext-XOR. We assert the keystream-cancellation invariant
      // explicitly so a future refactor that breaks GCM determinism is
      // caught.
      const data2 = Buffer.from(
        'plaintext-that-must-not-be-encrypted-twice-with-THE-SAME-KEY-AND-IV'
      );
      const third = crypto.encryptData(data2, key, iv);
      // Ciphertext lengths match plaintext lengths in GCM (no padding).
      expect(third.encrypted.length).toBe(data.length);
      expect(first.encrypted.length).toBe(data.length);
      // The two ciphertexts XORed equals the two plaintexts XORed — the
      // textbook "two-time pad" leak that motivates the @security warning.
      // We assert it here to make the leak experimentally observable; in
      // production, callers MUST use a fresh IV per message to make this
      // attack impossible.
      const xorCiphertexts = Buffer.alloc(data.length);
      const xorPlaintexts = Buffer.alloc(data.length);
      for (let i = 0; i < data.length; i++) {
        xorCiphertexts[i] =
          (first.encrypted[i] ?? 0) ^ (third.encrypted[i] ?? 0);
        xorPlaintexts[i] = (data[i] ?? 0) ^ (data2[i] ?? 0);
      }
      expect(xorCiphertexts.equals(xorPlaintexts)).toBe(true);
    });
  });

  describe('getSecurityLevel - boundary conditions', () => {
    it('should return LOW when memoryCost is high but timeCost is low', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 19,
        timeCost: 1,
      });
      expect(cm.getSecurityLevel()).toBe(SecurityLevel.LOW);
    });

    it('should return MEDIUM at exact boundary', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 2,
      });
      expect(cm.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
    });

    it('should return MEDIUM when memoryCost is low but timeCost is high', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 10,
      });
      expect(cm.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
    });

    it('should return HIGH (not ULTRA) when memoryCost meets ULTRA threshold but timeCost is short', () => {
      // memoryCost meets ULTRA but timeCost only meets HIGH → HIGH wins.
      const cm = new CryptoManager({
        memoryCost: 2 ** 19,
        timeCost: 3,
      });
      expect(cm.getSecurityLevel()).toBe(SecurityLevel.HIGH);
    });

    it('should return MEDIUM (not HIGH) when timeCost meets HIGH threshold but memoryCost is short', () => {
      // timeCost meets HIGH but memoryCost only meets MEDIUM → MEDIUM wins.
      const cm = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 3,
      });
      expect(cm.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
    });
  });

  describe('SECURITY_THRESHOLDS (Task 28)', () => {
    it('should expose the post-Task-18 ULTRA threshold (mem=2^19, time=4)', () => {
      expect(SECURITY_THRESHOLDS.ULTRA.memoryCost).toBe(2 ** 19);
      expect(SECURITY_THRESHOLDS.ULTRA.timeCost).toBe(4);
    });

    it('should expose the post-Task-18 HIGH threshold (mem=2^17, time=3)', () => {
      expect(SECURITY_THRESHOLDS.HIGH.memoryCost).toBe(2 ** 17);
      expect(SECURITY_THRESHOLDS.HIGH.timeCost).toBe(3);
    });

    it('should expose the MEDIUM threshold (mem=2^14, time=2)', () => {
      expect(SECURITY_THRESHOLDS.MEDIUM.memoryCost).toBe(2 ** 14);
      expect(SECURITY_THRESHOLDS.MEDIUM.timeCost).toBe(2);
    });

    it('should match the value getSecurityLevel uses for each tier', () => {
      // Round-trip the constants through actual classifications so any
      // future drift between the table and the classifier is caught here.
      const ultra = new CryptoManager({
        memoryCost: SECURITY_THRESHOLDS.ULTRA.memoryCost,
        timeCost: SECURITY_THRESHOLDS.ULTRA.timeCost,
      });
      expect(ultra.getSecurityLevel()).toBe(SecurityLevel.ULTRA);

      const high = new CryptoManager({
        memoryCost: SECURITY_THRESHOLDS.HIGH.memoryCost,
        timeCost: SECURITY_THRESHOLDS.HIGH.timeCost,
      });
      expect(high.getSecurityLevel()).toBe(SecurityLevel.HIGH);

      const medium = new CryptoManager({
        memoryCost: SECURITY_THRESHOLDS.MEDIUM.memoryCost,
        timeCost: SECURITY_THRESHOLDS.MEDIUM.timeCost,
      });
      expect(medium.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
    });

    it('should match the default CryptoManager configuration to the HIGH tier exactly', () => {
      // Default constructor (no overrides) uses SECURITY_THRESHOLDS.HIGH
      // for both memoryCost and timeCost, so a fresh instance reports HIGH
      // and its parameters match the HIGH constant byte-for-byte.
      const defaults = new CryptoManager();
      const params = defaults.getParameters();
      expect(params.argon2Options.memoryCost).toBe(
        SECURITY_THRESHOLDS.HIGH.memoryCost
      );
      expect(params.argon2Options.timeCost).toBe(
        SECURITY_THRESHOLDS.HIGH.timeCost
      );
      expect(defaults.getSecurityLevel()).toBe(SecurityLevel.HIGH);
    });

    it('should be deeply readonly (mutation attempts must not weaken thresholds)', () => {
      // `as const` gives us a deep-readonly type so consumers cannot widen
      // (e.g.) the HIGH bar to 0 in order to claim a higher reported tier
      // for a weak configuration. We can't directly type-check `readonly`
      // at runtime, but we CAN observe that any (TypeScript-rejected,
      // runtime-attempted) mutation through a typed cast does not propagate
      // back into getSecurityLevel's behaviour for the next instance.
      const before = SECURITY_THRESHOLDS.HIGH.memoryCost;
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (SECURITY_THRESHOLDS as any).HIGH.memoryCost = 1;
      } catch {
        // In strict mode this throws; in sloppy mode it silently no-ops on
        // a frozen object. Either is acceptable — we only care that the
        // subsequent classification uses the original value.
      }
      const cm = new CryptoManager({
        memoryCost: before,
        timeCost: SECURITY_THRESHOLDS.HIGH.timeCost,
      });
      expect(cm.getSecurityLevel()).toBe(SecurityLevel.HIGH);
      // And the value is still the original.
      expect(SECURITY_THRESHOLDS.HIGH.memoryCost).toBe(before);
    });
  });

  describe('encryptFile - atomic output (pre-existing target)', () => {
    const testFilePath = path.join(tempDir, 'test-cleanup-enc.txt');
    const encryptedFilePath = path.join(tempDir, 'test-cleanup-enc.bin');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
      // Clean up any stray .tmp files in tempDir that match our pattern.
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      for (const entry of entries) {
        if (
          entry.startsWith('test-cleanup-enc.bin.') &&
          entry.endsWith('.tmp')
        ) {
          await unlink(path.join(tempDir, entry));
        }
      }
    });

    it('should preserve pre-existing output file on error and leave no temp file', async () => {
      const original = 'pre-existing content';
      await writeFile(encryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest
        .spyOn(mockCrypto, 'deriveKey')
        .mockRejectedValue(new Error('Key failure'));

      await expect(
        mockCrypto.encryptFile(testFilePath, encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);

      // The pre-existing file MUST remain untouched (atomic-rename
      // contract: the canonical outputPath is only updated on success).
      expect(existsSync(encryptedFilePath)).toBe(true);
      expect(await readFile(encryptedFilePath, 'utf8')).toBe(original);
      // No lingering temp file.
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-enc.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError without touching the pre-existing output', async () => {
      const original = 'pre-existing content';
      await writeFile(encryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKey').mockRejectedValue(
        new CryptoError(
          'Mock failure',
          CryptoErrorType.ENCRYPTION_FAILED,
          'MOCK_ERROR'
        )
      );

      try {
        await mockCrypto.encryptFile(
          testFilePath,
          encryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('MOCK_ERROR');
      }
      expect(existsSync(encryptedFilePath)).toBe(true);
      expect(await readFile(encryptedFilePath, 'utf8')).toBe(original);
      jest.restoreAllMocks();
    });

    it('should not create outputPath when no pre-existing output and encryption errors', async () => {
      // Ensure no pre-existing output file.
      if (existsSync(encryptedFilePath)) {
        await unlink(encryptedFilePath);
      }

      const mockCrypto = new CryptoManager();
      jest
        .spyOn(mockCrypto, 'deriveKey')
        .mockRejectedValue(new Error('Key failure'));

      await expect(
        mockCrypto.encryptFile(testFilePath, encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);

      // No file at outputPath (it was never created, and the temp file was
      // unlinked in the catch block).
      expect(existsSync(encryptedFilePath)).toBe(false);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-enc.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
      jest.restoreAllMocks();
    });

    it('should leave no temp file behind on a successful encryption', async () => {
      await crypto.encryptFile(
        testFilePath,
        encryptedFilePath,
        testPassword
      );
      expect(existsSync(encryptedFilePath)).toBe(true);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-enc.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    });
  });

  describe('decryptFile - atomic output (pre-existing target)', () => {
    const testFilePath = path.join(tempDir, 'test-cleanup-dec.txt');
    const encryptedFilePath = path.join(tempDir, 'test-cleanup-dec.bin');
    const decryptedFilePath = path.join(tempDir, 'test-cleanup-dec-out.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      for (const entry of entries) {
        if (
          entry.startsWith('test-cleanup-dec-out.txt.') &&
          entry.endsWith('.tmp')
        ) {
          await unlink(path.join(tempDir, entry));
        }
      }
    });

    it('should preserve pre-existing output file on error and leave no temp file', async () => {
      const original = 'pre-existing content';
      await writeFile(decryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest
        .spyOn(mockCrypto, 'deriveKey')
        .mockRejectedValue(new Error('Key failure'));

      await expect(
        mockCrypto.decryptFile(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        )
      ).rejects.toThrow(CryptoError);
      expect(existsSync(decryptedFilePath)).toBe(true);
      expect(await readFile(decryptedFilePath, 'utf8')).toBe(original);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-dec-out.txt.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError without touching the pre-existing output', async () => {
      const original = 'pre-existing content';
      await writeFile(decryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKey').mockRejectedValue(
        new CryptoError(
          'Mock failure',
          CryptoErrorType.DECRYPTION_FAILED,
          'MOCK_ERROR'
        )
      );

      try {
        await mockCrypto.decryptFile(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('MOCK_ERROR');
      }
      expect(existsSync(decryptedFilePath)).toBe(true);
      expect(await readFile(decryptedFilePath, 'utf8')).toBe(original);
      jest.restoreAllMocks();
    });

    it('should not create outputPath when no pre-existing output and decryption errors with wrong password', async () => {
      if (existsSync(decryptedFilePath)) {
        await unlink(decryptedFilePath);
      }
      await expect(
        crypto.decryptFile(
          encryptedFilePath,
          decryptedFilePath,
          'WrongP@ssw0rd123!'
        )
      ).rejects.toThrow(CryptoError);
      expect(existsSync(decryptedFilePath)).toBe(false);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-dec-out.txt.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    });

    it('should leave no temp file behind on a successful decryption', async () => {
      await crypto.decryptFile(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(existsSync(decryptedFilePath)).toBe(true);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-dec-out.txt.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    });
  });

  describe('encryptFileSync - atomic output (pre-existing target)', () => {
    const testFilePath = path.join(tempDir, 'test-cleanup-enc-sync.txt');
    const encryptedFilePath = path.join(
      tempDir,
      'test-cleanup-enc-sync.bin'
    );

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      for (const entry of entries) {
        if (
          entry.startsWith('test-cleanup-enc-sync.bin.') &&
          entry.endsWith('.tmp')
        ) {
          await unlink(path.join(tempDir, entry));
        }
      }
    });

    it('should preserve pre-existing output file on error and leave no temp file', async () => {
      const original = 'pre-existing content';
      writeFileSync(encryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new Error('Key failure');
      });

      expect(() =>
        mockCrypto.encryptFileSync(
          testFilePath,
          encryptedFilePath,
          testPassword
        )
      ).toThrow(CryptoError);
      expect(existsSync(encryptedFilePath)).toBe(true);
      expect(readFileSync(encryptedFilePath, 'utf8')).toBe(original);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-enc-sync.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError without touching the pre-existing output', () => {
      const original = 'pre-existing content';
      writeFileSync(encryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new CryptoError(
          'Mock failure',
          CryptoErrorType.ENCRYPTION_FAILED,
          'MOCK_ERROR'
        );
      });

      try {
        mockCrypto.encryptFileSync(
          testFilePath,
          encryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('MOCK_ERROR');
      }
      expect(existsSync(encryptedFilePath)).toBe(true);
      expect(readFileSync(encryptedFilePath, 'utf8')).toBe(original);
      jest.restoreAllMocks();
    });

    it('should not create outputPath when no pre-existing output and encryption errors', async () => {
      if (existsSync(encryptedFilePath)) {
        unlinkSync(encryptedFilePath);
      }
      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new Error('Key failure');
      });
      expect(() =>
        mockCrypto.encryptFileSync(
          testFilePath,
          encryptedFilePath,
          testPassword
        )
      ).toThrow(CryptoError);
      expect(existsSync(encryptedFilePath)).toBe(false);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-enc-sync.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
      jest.restoreAllMocks();
    });

    it('should leave no temp file behind on a successful encryption', async () => {
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
      expect(existsSync(encryptedFilePath)).toBe(true);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-enc-sync.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    });
  });

  describe('decryptFileSync - atomic output (pre-existing target)', () => {
    const testFilePath = path.join(tempDir, 'test-cleanup-dec-sync.txt');
    const encryptedFilePath = path.join(
      tempDir,
      'test-cleanup-dec-sync.bin'
    );
    const decryptedFilePath = path.join(
      tempDir,
      'test-cleanup-dec-sync-out.txt'
    );

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, decryptedFilePath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      for (const entry of entries) {
        if (
          entry.startsWith('test-cleanup-dec-sync-out.txt.') &&
          entry.endsWith('.tmp')
        ) {
          await unlink(path.join(tempDir, entry));
        }
      }
    });

    it('should preserve pre-existing output file on error and leave no temp file', async () => {
      const original = 'pre-existing content';
      writeFileSync(decryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new Error('Key failure');
      });

      expect(() =>
        mockCrypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        )
      ).toThrow(CryptoError);
      expect(existsSync(decryptedFilePath)).toBe(true);
      expect(readFileSync(decryptedFilePath, 'utf8')).toBe(original);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-dec-sync-out.txt.') &&
          e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError without touching the pre-existing output', () => {
      const original = 'pre-existing content';
      writeFileSync(decryptedFilePath, original);

      const mockCrypto = new CryptoManager();
      jest.spyOn(mockCrypto, 'deriveKeySync').mockImplementation(() => {
        throw new CryptoError(
          'Mock failure',
          CryptoErrorType.DECRYPTION_FAILED,
          'MOCK_ERROR'
        );
      });

      try {
        mockCrypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('MOCK_ERROR');
      }
      expect(existsSync(decryptedFilePath)).toBe(true);
      expect(readFileSync(decryptedFilePath, 'utf8')).toBe(original);
      jest.restoreAllMocks();
    });

    it('should not create outputPath when no pre-existing output and decryption errors with wrong password', async () => {
      if (existsSync(decryptedFilePath)) {
        unlinkSync(decryptedFilePath);
      }
      expect(() =>
        crypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          'WrongP@ssw0rd123!'
        )
      ).toThrow(CryptoError);
      expect(existsSync(decryptedFilePath)).toBe(false);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-dec-sync-out.txt.') &&
          e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    });

    it('should leave no temp file behind on a successful decryption', async () => {
      crypto.decryptFileSync(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(existsSync(decryptedFilePath)).toBe(true);
      const fs = await import('node:fs/promises');
      const entries = await fs.readdir(tempDir);
      const stray = entries.filter(
        (e) =>
          e.startsWith('test-cleanup-dec-sync-out.txt.') &&
          e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    });
  });

  describe('encryptFile - mkdir error', () => {
    const testFilePath = path.join(tempDir, 'test-mkdir-enc.txt');
    const blockingFile = path.join(tempDir, 'blocking-file-enc');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      // Create a regular file that blocks directory creation
      await writeFile(blockingFile, 'I am a file, not a directory');
    });

    afterEach(async () => {
      for (const file of [testFilePath, blockingFile]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw when output directory cannot be created', async () => {
      // Try to write output inside a regular file (not a directory)
      const invalidOutputPath = path.join(
        blockingFile,
        'subdir',
        'output.bin'
      );

      try {
        await crypto.encryptFile(
          testFilePath,
          invalidOutputPath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'OUTPUT_DIR_CREATION_FAILED'
        );
      }
    });
  });

  describe('decryptFile - mkdir error', () => {
    const testFilePath = path.join(tempDir, 'test-mkdir-dec.txt');
    const encryptedFilePath = path.join(tempDir, 'test-mkdir-dec.bin');
    const blockingFile = path.join(tempDir, 'blocking-file-dec');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
      await writeFile(blockingFile, 'I am a file, not a directory');
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, blockingFile]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw when output directory cannot be created', async () => {
      const invalidOutputPath = path.join(
        blockingFile,
        'subdir',
        'output.txt'
      );

      try {
        await crypto.decryptFile(
          encryptedFilePath,
          invalidOutputPath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'OUTPUT_DIR_CREATION_FAILED'
        );
      }
    });
  });

  describe('encryptFileSync - mkdir error', () => {
    const testFilePath = path.join(tempDir, 'test-mkdir-enc-sync.txt');
    const blockingFile = path.join(tempDir, 'blocking-file-enc-sync');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      await writeFile(blockingFile, 'I am a file, not a directory');
    });

    afterEach(async () => {
      for (const file of [testFilePath, blockingFile]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw when output directory cannot be created', () => {
      const invalidOutputPath = path.join(
        blockingFile,
        'subdir',
        'output.bin'
      );

      try {
        crypto.encryptFileSync(testFilePath, invalidOutputPath, testPassword);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'OUTPUT_DIR_CREATION_FAILED'
        );
      }
    });
  });

  describe('decryptFileSync - mkdir error', () => {
    const testFilePath = path.join(tempDir, 'test-mkdir-dec-sync.txt');
    const encryptedFilePath = path.join(tempDir, 'test-mkdir-dec-sync.bin');
    const blockingFile = path.join(tempDir, 'blocking-file-dec-sync');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
      await writeFile(blockingFile, 'I am a file, not a directory');
    });

    afterEach(async () => {
      for (const file of [testFilePath, encryptedFilePath, blockingFile]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should throw when output directory cannot be created', () => {
      const invalidOutputPath = path.join(
        blockingFile,
        'subdir',
        'output.txt'
      );

      try {
        crypto.decryptFileSync(
          encryptedFilePath,
          invalidOutputPath,
          testPassword
        );
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'OUTPUT_DIR_CREATION_FAILED'
        );
      }
    });
  });

  describe('deriveKey - internal error wrapping', () => {
    it('should wrap argon2 errors', async () => {
      jest
        .spyOn(argon2Module, 'hash')
        .mockRejectedValue(new Error('Argon2 internal failure'));

      const salt = crypto.generateSecureRandom(32);
      try {
        await crypto.deriveKey(testPassword, salt);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('KEY_DERIVATION_FAILED');
      }

      jest.restoreAllMocks();
    });
  });

  describe('deriveKeySync - internal error wrapping', () => {
    // Use jest.spyOn + jest.restoreAllMocks in afterEach (Task 22) so the
    // mock is automatically rolled back even if an assertion throws — and
    // so concurrent jest workers cannot observe each other's stub of the
    // shared `node:crypto` namespace. Direct property mutation
    // (the previous approach) was racy under parallel execution.
    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should wrap pbkdf2Sync errors', () => {
      jest.spyOn(nodeCrypto, 'pbkdf2Sync').mockImplementation(((): never => {
        throw new Error('PBKDF2 internal failure');
      }) as unknown as typeof nodeCrypto.pbkdf2Sync);

      const salt = crypto.generateSecureRandom(32);
      try {
        crypto.deriveKeySync(testPassword, salt);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'SYNC_KEY_DERIVATION_FAILED'
        );
      }
    });
  });

  describe('encryptData - internal error wrapping', () => {
    // Same Task 22 rationale as the deriveKeySync block above.
    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should wrap cipher errors', () => {
      jest
        .spyOn(nodeCrypto, 'createCipheriv')
        .mockImplementation(((): never => {
          throw new Error('Cipher creation failure');
        }) as unknown as typeof nodeCrypto.createCipheriv);

      const data = Buffer.from('test');
      const key = Buffer.alloc(32);
      const iv = Buffer.alloc(12);

      try {
        crypto.encryptData(data, key, iv);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
      }
    });
  });

  describe('validatePassword - edge cases', () => {
    it('should accept password at exactly 8 characters', () => {
      expect(crypto.validatePassword('Ab1!cdef')).toBe(true);
    });

    it('should reject password at 7 characters', () => {
      expect(crypto.validatePassword('Ab1!cde')).toBe(false);
    });

    it('should handle number input', () => {
      expect(crypto.validatePassword(12345678 as unknown as string)).toBe(
        false
      );
    });

    it('should handle undefined input', () => {
      expect(crypto.validatePassword(undefined as unknown as string)).toBe(
        false
      );
    });
  });

  // ==========================================================================
  // Versioned ciphertext format (Task 2)
  // ==========================================================================

  describe('format helpers (packHeader / parseHeader)', () => {
    it('should pack and parse an Argon2id header', () => {
      const buf = packHeader(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        memoryCost: 2 ** 16,
        timeCost: 3,
        parallelism: 1,
      });
      expect(buf.length).toBe(HEADER_LENGTH);
      expect(hasMagic(buf)).toBe(true);

      const parsed = parseHeader(buf);
      expect(parsed.version).toBe(FORMAT_VERSION);
      expect(parsed.kdfId).toBe(KDF_ID_ARGON2ID);
      expect(parsed.headerLen).toBe(HEADER_LENGTH);
      expect(parsed.params.kind).toBe('argon2id');
      if (parsed.params.kind === 'argon2id') {
        expect(parsed.params.memoryCost).toBe(2 ** 16);
        expect(parsed.params.timeCost).toBe(3);
        expect(parsed.params.parallelism).toBe(1);
      }
    });

    it('should pack and parse a PBKDF2 header', () => {
      const buf = packHeader(KDF_ID_PBKDF2_SHA256, {
        kind: 'pbkdf2-sha256',
        iterations: 100000,
      });
      expect(buf.length).toBe(HEADER_LENGTH);

      const parsed = parseHeader(buf);
      expect(parsed.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
      expect(parsed.params.kind).toBe('pbkdf2-sha256');
      if (parsed.params.kind === 'pbkdf2-sha256') {
        expect(parsed.params.iterations).toBe(100000);
      }
    });

    it('should zero-fill reserved bytes in Argon2id header', () => {
      const buf = packHeader(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        memoryCost: 1,
        timeCost: 1,
        parallelism: 1,
      });
      // Argon2id occupies first 4+4+2 = 10 bytes of params; remaining 6 must be zero.
      const paramsStart = 6; // 4 magic + 1 ver + 1 kdfId
      for (let i = paramsStart + 10; i < paramsStart + 16; i++) {
        expect(buf[i]).toBe(0);
      }
    });

    it('should zero-fill reserved bytes in PBKDF2 header', () => {
      const buf = packHeader(KDF_ID_PBKDF2_SHA256, {
        kind: 'pbkdf2-sha256',
        iterations: 1,
      });
      // PBKDF2 occupies first 4 bytes of params; remaining 12 must be zero.
      const paramsStart = 6;
      for (let i = paramsStart + 4; i < paramsStart + 16; i++) {
        expect(buf[i]).toBe(0);
      }
    });

    it('should reject mismatched kdfId/params kind', () => {
      expect(() =>
        packHeader(KDF_ID_ARGON2ID, {
          kind: 'pbkdf2-sha256',
          iterations: 1,
        })
      ).toThrow(CryptoError);
      expect(() =>
        packHeader(KDF_ID_PBKDF2_SHA256, {
          kind: 'argon2id',
          memoryCost: 1,
          timeCost: 1,
          parallelism: 1,
        })
      ).toThrow(CryptoError);
    });

    it('should reject out-of-range u32 fields', () => {
      expect(() =>
        packHeader(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 0xffffffff + 1,
          timeCost: 3,
          parallelism: 1,
        })
      ).toThrow(CryptoError);
    });

    it('should reject out-of-range u16 parallelism', () => {
      expect(() =>
        packHeader(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 1,
          timeCost: 1,
          parallelism: 0x10000,
        })
      ).toThrow(CryptoError);
    });

    it('should throw on truncated header', () => {
      const short = Buffer.from('HPCR', 'ascii');
      expect(() => parseHeader(short)).toThrow(CryptoError);
      try {
        parseHeader(short);
      } catch (error) {
        expect((error as CryptoError).code).toBe('TRUNCATED_HEADER');
      }
    });

    it('should throw on missing magic', () => {
      const buf = Buffer.alloc(HEADER_LENGTH);
      expect(() => parseHeader(buf)).toThrow(CryptoError);
      try {
        parseHeader(buf);
      } catch (error) {
        expect((error as CryptoError).code).toBe('INVALID_MAGIC');
      }
    });

    it('should throw on unsupported version', () => {
      const buf = Buffer.alloc(HEADER_LENGTH);
      MAGIC_BYTES.copy(buf, 0);
      buf.writeUInt8(0x99, 4); // bogus version
      buf.writeUInt8(KDF_ID_ARGON2ID, 5);
      // params: minimal valid Argon2id
      buf.writeUInt32BE(1, 6);
      buf.writeUInt32BE(1, 10);
      buf.writeUInt16BE(1, 14);
      try {
        parseHeader(buf);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('UNSUPPORTED_VERSION');
      }
    });

    it('should throw on unknown KDF id', () => {
      const buf = Buffer.alloc(HEADER_LENGTH);
      MAGIC_BYTES.copy(buf, 0);
      buf.writeUInt8(FORMAT_VERSION, 4);
      buf.writeUInt8(0x77, 5); // unknown kdf
      try {
        parseHeader(buf);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('UNSUPPORTED_KDF');
      }
    });

    it('should throw on zero parameters in v1 header', () => {
      const buf = Buffer.alloc(HEADER_LENGTH);
      MAGIC_BYTES.copy(buf, 0);
      buf.writeUInt8(FORMAT_VERSION, 4);
      buf.writeUInt8(KDF_ID_ARGON2ID, 5);
      // All param bytes zero -> memory/time/parallelism = 0
      try {
        parseHeader(buf);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('INVALID_HEADER_PARAM');
      }
    });

    it('hasMagic should reject too-short buffers', () => {
      expect(hasMagic(Buffer.alloc(0))).toBe(false);
      expect(hasMagic(Buffer.from('HPC'))).toBe(false);
      expect(hasMagic(Buffer.from('HPCR'))).toBe(true);
      expect(hasMagic(Buffer.from('XXXX'))).toBe(false);
    });
  });

  describe('inspectHeader', () => {
    it('should return parsed v1 header for async-encrypted text', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      const parsed = crypto.inspectHeader(encrypted);
      expect(parsed).not.toBeNull();
      expect(parsed?.version).toBe(FORMAT_VERSION);
      expect(parsed?.kdfId).toBe(KDF_ID_ARGON2ID);
      expect(parsed?.params.kind).toBe('argon2id');
    });

    it('should return parsed v1 header for sync-encrypted text', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      const parsed = crypto.inspectHeader(encrypted);
      expect(parsed).not.toBeNull();
      expect(parsed?.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
      expect(parsed?.params.kind).toBe('pbkdf2-sha256');
    });

    it('should return parsed v1 header from a Buffer', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      const buf = Buffer.from(encrypted, 'base64url');
      const parsed = crypto.inspectHeader(buf);
      expect(parsed).not.toBeNull();
      expect(parsed?.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
    });

    it('should return null for legacy v0 ciphertext', () => {
      // Build a buffer that does NOT start with HPCR but is otherwise large.
      const fake = Buffer.alloc(64);
      fake.write('NOTM', 0, 'ascii');
      const b64 = fake.toString('base64url');
      expect(crypto.inspectHeader(b64)).toBeNull();
      expect(crypto.inspectHeader(fake)).toBeNull();
    });

    it('should reject empty string input', () => {
      expect(() => crypto.inspectHeader('')).toThrow(CryptoError);
    });

    it('should reject non-Buffer non-string input', () => {
      expect(() =>
        crypto.inspectHeader(123 as unknown as string)
      ).toThrow(CryptoError);
    });

    // Task 8 — base64url validation. Without the precondition,
    // `Buffer.from(input, 'base64url')` silently coerces invalid
    // characters to an empty buffer, making malformed input look like
    // a v0 ciphertext (returning `null`). The validator now rejects
    // malformed strings up-front with INVALID_BASE64URL.
    describe('base64url validation (Task 8)', () => {
      it('should throw INVALID_BASE64URL for input with disallowed characters', () => {
        // '!' is not in the base64url alphabet
        const malformed = '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!';
        expect(() => crypto.inspectHeader(malformed)).toThrow(CryptoError);
        try {
          crypto.inspectHeader(malformed);
        } catch (err) {
          expect(err).toBeInstanceOf(CryptoError);
          expect((err as CryptoError).code).toBe('INVALID_BASE64URL');
          expect((err as CryptoError).type).toBe(
            CryptoErrorType.INVALID_INPUT
          );
        }
      });

      it('should throw INVALID_BASE64URL for input mixed with invalid characters', () => {
        const malformed = 'AAAA[non-base64-chars]AAAA';
        expect(() => crypto.inspectHeader(malformed)).toThrow(CryptoError);
        try {
          crypto.inspectHeader(malformed);
        } catch (err) {
          expect(err).toBeInstanceOf(CryptoError);
          expect((err as CryptoError).code).toBe('INVALID_BASE64URL');
        }
      });

      it('should throw INVALID_BASE64URL for input using standard base64 padding', () => {
        // base64 with '=' padding is NOT valid base64url (which is
        // unpadded). `Buffer.from('abc=', 'base64url')` accepts the
        // input but the round-trip mismatch is what isValidBase64Url
        // checks for.
        const padded = 'YWJj'; // valid base64url for 'abc'
        const padded2 = 'YWJj=='; // padded version — NOT valid base64url
        expect(() => crypto.inspectHeader(padded2)).toThrow(CryptoError);
        try {
          crypto.inspectHeader(padded2);
        } catch (err) {
          expect((err as CryptoError).code).toBe('INVALID_BASE64URL');
        }
        // Sanity: the unpadded version is well-formed base64url and
        // does NOT throw INVALID_BASE64URL (it returns null because
        // the buffer doesn't start with the v1 magic).
        expect(crypto.inspectHeader(padded)).toBeNull();
      });

      it('should throw INVALID_BASE64URL for input containing standard base64 + or / characters', () => {
        // '+' and '/' are valid base64 but NOT base64url (which uses
        // '-' and '_' instead).
        const standardBase64 = 'AAAA+AAA/AAA';
        expect(() => crypto.inspectHeader(standardBase64)).toThrow(
          CryptoError
        );
        try {
          crypto.inspectHeader(standardBase64);
        } catch (err) {
          expect((err as CryptoError).code).toBe('INVALID_BASE64URL');
        }
      });

      it('should accept valid base64url input that doesn\'t carry v1 magic (returns null)', () => {
        // A well-formed base64url string that decodes to a buffer
        // without the HPCR magic still returns `null` (legacy v0
        // contract). Only malformed encoding throws.
        const validNoMagic = Buffer.from('NOTM', 'ascii').toString(
          'base64url'
        );
        expect(crypto.inspectHeader(validNoMagic)).toBeNull();
      });

      it('should NOT validate Buffer inputs as base64url (Buffer is read as-is)', () => {
        // Buffers skip the base64url precondition entirely — they're
        // raw bytes, not encoded text. A buffer without the magic
        // returns null as before.
        const buf = Buffer.from('not base64url at all');
        expect(crypto.inspectHeader(buf)).toBeNull();
      });
    });
  });

  describe('versioned format - text v1 round-trip', () => {
    it('should round-trip async with v1 header', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      // First decoded byte should be the magic
      const buf = Buffer.from(encrypted, 'base64url');
      expect(hasMagic(buf)).toBe(true);
      const decrypted = await crypto.decryptText(encrypted, testPassword);
      expect(decrypted).toBe(testText);
    });

    it('should round-trip sync with v1 header', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      const buf = Buffer.from(encrypted, 'base64url');
      expect(hasMagic(buf)).toBe(true);
      const decrypted = crypto.decryptTextSync(encrypted, testPassword);
      expect(decrypted).toBe(testText);
    });

    it('should embed parameters that match the encrypting instance (async)', async () => {
      const customCrypto = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 2,
        parallelism: 2,
      });
      const encrypted = await customCrypto.encryptText(testText, testPassword);
      const header = customCrypto.inspectHeader(encrypted);
      expect(header?.params.kind).toBe('argon2id');
      if (header?.params.kind === 'argon2id') {
        expect(header.params.memoryCost).toBe(2 ** 14);
        expect(header.params.timeCost).toBe(2);
        expect(header.params.parallelism).toBe(2);
      }
    });
  });

  describe('versioned format - file v1 round-trip', () => {
    const testFilePath = path.join(tempDir, 'v1-rt-input.txt');
    const encryptedFilePath = path.join(tempDir, 'v1-rt-encrypted.bin');
    const decryptedFilePath = path.join(tempDir, 'v1-rt-decrypted.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      for (const file of [
        testFilePath,
        encryptedFilePath,
        decryptedFilePath,
      ]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    it('should round-trip async file with v1 header', async () => {
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
      const fileBuf = await readFile(encryptedFilePath);
      expect(hasMagic(fileBuf)).toBe(true);
      // Header KDF should be Argon2id for async file encryption.
      const parsed = crypto.inspectHeader(fileBuf);
      expect(parsed?.kdfId).toBe(KDF_ID_ARGON2ID);

      await crypto.decryptFile(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(await readFile(decryptedFilePath, 'utf8')).toBe(testText);
    });

    it('should round-trip sync file with v1 header', () => {
      crypto.encryptFileSync(testFilePath, encryptedFilePath, testPassword);
      const fileBuf = readFileSync(encryptedFilePath);
      expect(hasMagic(fileBuf)).toBe(true);
      const parsed = crypto.inspectHeader(fileBuf);
      expect(parsed?.kdfId).toBe(KDF_ID_PBKDF2_SHA256);

      crypto.decryptFileSync(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(readFileSync(decryptedFilePath, 'utf8')).toBe(testText);
    });
  });

  describe('versioned format - legacy v0 ciphertexts', () => {
    /**
     * Build a v0-format text ciphertext (the layout used before this task
     * was implemented). Layout: base64url([salt][iv][tag][ciphertext]).
     */
    async function buildLegacyV0Text(
      cm: CryptoManager,
      text: string,
      password: string
    ): Promise<string> {
      const salt = cm.generateSecureRandom(32);
      const iv = cm.generateSecureRandom(12);
      const key = await cm.deriveKey(password, salt);
      const { encrypted, tag } = cm.encryptData(
        Buffer.from(text, 'utf8'),
        key,
        iv
      );
      return Buffer.concat([salt, iv, tag, encrypted]).toString('base64url');
    }

    /**
     * Build a v0-format sync text ciphertext using the historical 100000
     * PBKDF2 iteration count that v0 sync ciphertexts were always encoded
     * with (the format had no embedded iteration count). The decrypt path
     * will read the iteration count from `legacyPbkdf2Iterations`, which
     * also defaults to 100000.
     */
    function buildLegacyV0TextSync(
      cm: CryptoManager,
      text: string,
      password: string
    ): string {
      const salt = cm.generateSecureRandom(32);
      const iv = cm.generateSecureRandom(12);
      const key = cm.deriveKeySync(password, salt, 100000);
      const { encrypted, tag } = cm.encryptData(
        Buffer.from(text, 'utf8'),
        key,
        iv
      );
      return Buffer.concat([salt, iv, tag, encrypted]).toString('base64url');
    }

    /**
     * Build a v0-format file ciphertext.
     * Layout: [salt][iv][ciphertext][tag]
     */
    async function buildLegacyV0File(
      cm: CryptoManager,
      content: Buffer,
      password: string,
      outputPath: string
    ): Promise<void> {
      const salt = cm.generateSecureRandom(32);
      const iv = cm.generateSecureRandom(12);
      const key = await cm.deriveKey(password, salt);
      const { encrypted, tag } = cm.encryptData(content, key, iv);
      await writeFile(outputPath, Buffer.concat([salt, iv, encrypted, tag]));
    }

    /**
     * Build a v0-format sync file ciphertext using the historical 100000
     * PBKDF2 iteration count.
     */
    function buildLegacyV0FileSync(
      cm: CryptoManager,
      content: Buffer,
      password: string,
      outputPath: string
    ): void {
      const salt = cm.generateSecureRandom(32);
      const iv = cm.generateSecureRandom(12);
      const key = cm.deriveKeySync(password, salt, 100000);
      const { encrypted, tag } = cm.encryptData(content, key, iv);
      writeFileSync(outputPath, Buffer.concat([salt, iv, encrypted, tag]));
    }

    describe('legacyMode = auto (default)', () => {
      it('should decrypt v0 async text', async () => {
        const v0 = await buildLegacyV0Text(crypto, testText, testPassword);
        // Sanity: should not start with magic.
        expect(hasMagic(Buffer.from(v0, 'base64url'))).toBe(false);
        const result = await crypto.decryptText(v0, testPassword);
        expect(result).toBe(testText);
      });

      it('should decrypt v0 sync text', () => {
        const v0 = buildLegacyV0TextSync(crypto, testText, testPassword);
        expect(hasMagic(Buffer.from(v0, 'base64url'))).toBe(false);
        const result = crypto.decryptTextSync(v0, testPassword);
        expect(result).toBe(testText);
      });

      it('should decrypt v0 async file', async () => {
        const filePath = path.join(tempDir, 'v0-async.bin');
        const outPath = path.join(tempDir, 'v0-async-out.txt');
        try {
          await buildLegacyV0File(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          // Sanity: not starting with magic
          const fileBuf = await readFile(filePath);
          expect(hasMagic(fileBuf)).toBe(false);

          await crypto.decryptFile(filePath, outPath, testPassword);
          expect(await readFile(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) await unlink(f);
          }
        }
      });

      it('should decrypt v0 sync file', () => {
        const filePath = path.join(tempDir, 'v0-sync.bin');
        const outPath = path.join(tempDir, 'v0-sync-out.txt');
        try {
          buildLegacyV0FileSync(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          const fileBuf = readFileSync(filePath);
          expect(hasMagic(fileBuf)).toBe(false);

          crypto.decryptFileSync(filePath, outPath, testPassword);
          expect(readFileSync(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });
    });

    describe('legacyMode = strict', () => {
      it('should reject v0 async text with LEGACY_FORMAT_REJECTED', async () => {
        const v0 = await buildLegacyV0Text(crypto, testText, testPassword);
        const strict = new CryptoManager({ legacyMode: 'strict' });
        await expect(strict.decryptText(v0, testPassword)).rejects.toThrow(
          CryptoError
        );
        try {
          await strict.decryptText(v0, testPassword);
        } catch (error) {
          expect(error).toBeInstanceOf(CryptoError);
          expect((error as CryptoError).code).toBe('LEGACY_FORMAT_REJECTED');
        }
      });

      it('should reject v0 sync text with LEGACY_FORMAT_REJECTED', () => {
        const v0 = buildLegacyV0TextSync(crypto, testText, testPassword);
        const strict = new CryptoManager({ legacyMode: 'strict' });
        try {
          strict.decryptTextSync(v0, testPassword);
        } catch (error) {
          expect(error).toBeInstanceOf(CryptoError);
          expect((error as CryptoError).code).toBe('LEGACY_FORMAT_REJECTED');
        }
      });

      it('should reject v0 async file with LEGACY_FORMAT_REJECTED', async () => {
        const filePath = path.join(tempDir, 'v0-strict-async.bin');
        const outPath = path.join(tempDir, 'v0-strict-async-out.txt');
        try {
          await buildLegacyV0File(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          const strict = new CryptoManager({ legacyMode: 'strict' });
          try {
            await strict.decryptFile(filePath, outPath, testPassword);
            throw new Error('Expected throw');
          } catch (error) {
            expect(error).toBeInstanceOf(CryptoError);
            expect((error as CryptoError).code).toBe('LEGACY_FORMAT_REJECTED');
          }
          expect(existsSync(outPath)).toBe(false);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) await unlink(f);
          }
        }
      });

      it('should still accept v1 async text in strict mode', async () => {
        const strict = new CryptoManager({ legacyMode: 'strict' });
        const encrypted = await strict.encryptText(testText, testPassword);
        const decrypted = await strict.decryptText(encrypted, testPassword);
        expect(decrypted).toBe(testText);
      });
    });

    describe('legacyMode = reject', () => {
      it('should reject v0 async text with UNSUPPORTED_FORMAT', async () => {
        const v0 = await buildLegacyV0Text(crypto, testText, testPassword);
        const rejected = new CryptoManager({ legacyMode: 'reject' });
        try {
          await rejected.decryptText(v0, testPassword);
          throw new Error('Expected throw');
        } catch (error) {
          expect(error).toBeInstanceOf(CryptoError);
          expect((error as CryptoError).code).toBe('UNSUPPORTED_FORMAT');
        }
      });

      it('should reject v0 sync file with UNSUPPORTED_FORMAT', () => {
        const filePath = path.join(tempDir, 'v0-reject-sync.bin');
        const outPath = path.join(tempDir, 'v0-reject-sync-out.txt');
        try {
          buildLegacyV0FileSync(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          const rejected = new CryptoManager({ legacyMode: 'reject' });
          try {
            rejected.decryptFileSync(filePath, outPath, testPassword);
            throw new Error('Expected throw');
          } catch (error) {
            expect(error).toBeInstanceOf(CryptoError);
            expect((error as CryptoError).code).toBe('UNSUPPORTED_FORMAT');
          }
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });

      it('should still accept v1 sync text in reject mode', () => {
        const rejected = new CryptoManager({ legacyMode: 'reject' });
        const encrypted = rejected.encryptTextSync(testText, testPassword);
        const decrypted = rejected.decryptTextSync(encrypted, testPassword);
        expect(decrypted).toBe(testText);
      });
    });

    describe('magic-collision recovery (v0 salt begins with "HPCR")', () => {
      /**
       * Build a colliding v0 async text ciphertext: standard v0 layout
       * [salt][iv][tag][ciphertext], but the first 4 bytes of the salt are
       * forced to "HPCR". Before the fix, hasMagic() returned true on such a
       * blob and parseHeader threw on the random salt bytes, making it
       * permanently undecryptable.
       */
      async function buildCollidingV0Text(
        cm: CryptoManager,
        text: string,
        password: string
      ): Promise<string> {
        const salt = cm.generateSecureRandom(32);
        Buffer.from('HPCR', 'ascii').copy(salt, 0);
        const iv = cm.generateSecureRandom(12);
        const key = await cm.deriveKey(password, salt);
        const { encrypted, tag } = cm.encryptData(
          Buffer.from(text, 'utf8'),
          key,
          iv
        );
        return Buffer.concat([salt, iv, tag, encrypted]).toString('base64url');
      }

      /** Sync variant (PBKDF2, 100k iterations — the historical v0 count). */
      function buildCollidingV0TextSync(
        cm: CryptoManager,
        text: string,
        password: string
      ): string {
        const salt = cm.generateSecureRandom(32);
        Buffer.from('HPCR', 'ascii').copy(salt, 0);
        const iv = cm.generateSecureRandom(12);
        const key = cm.deriveKeySync(password, salt, 100000);
        const { encrypted, tag } = cm.encryptData(
          Buffer.from(text, 'utf8'),
          key,
          iv
        );
        return Buffer.concat([salt, iv, tag, encrypted]).toString('base64url');
      }

      /**
       * Build a colliding v0 async file ciphertext: [salt][iv][ciphertext][tag].
       */
      async function buildCollidingV0File(
        cm: CryptoManager,
        content: Buffer,
        password: string,
        outputPath: string
      ): Promise<void> {
        const salt = cm.generateSecureRandom(32);
        Buffer.from('HPCR', 'ascii').copy(salt, 0);
        const iv = cm.generateSecureRandom(12);
        const key = await cm.deriveKey(password, salt);
        const { encrypted, tag } = cm.encryptData(content, key, iv);
        await writeFile(outputPath, Buffer.concat([salt, iv, encrypted, tag]));
      }

      /** Sync file variant (PBKDF2, 100k iterations). */
      function buildCollidingV0FileSync(
        cm: CryptoManager,
        content: Buffer,
        password: string,
        outputPath: string
      ): void {
        const salt = cm.generateSecureRandom(32);
        Buffer.from('HPCR', 'ascii').copy(salt, 0);
        const iv = cm.generateSecureRandom(12);
        const key = cm.deriveKeySync(password, salt, 100000);
        const { encrypted, tag } = cm.encryptData(content, key, iv);
        writeFileSync(outputPath, Buffer.concat([salt, iv, encrypted, tag]));
      }

      it('round-trips a colliding v0 async text in auto mode', async () => {
        const v0 = await buildCollidingV0Text(crypto, testText, testPassword);
        // Guard: hasMagic must be true so we are testing the collision path.
        expect(hasMagic(Buffer.from(v0, 'base64url'))).toBe(true);
        const result = await crypto.decryptText(v0, testPassword);
        expect(result).toBe(testText);
      });

      it('round-trips a colliding v0 sync text in auto mode', () => {
        const v0 = buildCollidingV0TextSync(crypto, testText, testPassword);
        expect(hasMagic(Buffer.from(v0, 'base64url'))).toBe(true);
        const result = crypto.decryptTextSync(v0, testPassword);
        expect(result).toBe(testText);
      });

      it('round-trips a colliding v0 async file in auto mode', async () => {
        const filePath = path.join(tempDir, 'v0-collision-async.bin');
        const outPath = path.join(tempDir, 'v0-collision-async-out.txt');
        try {
          await buildCollidingV0File(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          expect(hasMagic(readFileSync(filePath))).toBe(true);
          await crypto.decryptFile(filePath, outPath, testPassword);
          expect(await readFile(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) await unlink(f);
          }
        }
      });

      it('round-trips a colliding v0 sync file in auto mode', () => {
        const filePath = path.join(tempDir, 'v0-collision-sync.bin');
        const outPath = path.join(tempDir, 'v0-collision-sync-out.txt');
        try {
          buildCollidingV0FileSync(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          expect(hasMagic(readFileSync(filePath))).toBe(true);
          crypto.decryptFileSync(filePath, outPath, testPassword);
          expect(readFileSync(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });

      it('rejects a colliding v0 async text in strict mode (original parse error preserved)', async () => {
        const v0 = await buildCollidingV0Text(crypto, testText, testPassword);
        const strict = new CryptoManager({ legacyMode: 'strict' });
        await expect(
          strict.decryptText(v0, testPassword)
        ).rejects.toBeInstanceOf(CryptoError);
      });

      it('rejects a colliding v0 sync text in reject mode (original parse error preserved)', () => {
        const v0 = buildCollidingV0TextSync(crypto, testText, testPassword);
        const rejected = new CryptoManager({ legacyMode: 'reject' });
        expect(() => rejected.decryptTextSync(v0, testPassword)).toThrow(
          CryptoError
        );
      });

      it('rejects a colliding v0 async file in strict mode (original parse error preserved)', async () => {
        const filePath = path.join(tempDir, 'v0-collision-strict-async.bin');
        const outPath = path.join(tempDir, 'v0-collision-strict-async-out.txt');
        try {
          await buildCollidingV0File(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          const strict = new CryptoManager({ legacyMode: 'strict' });
          await expect(
            strict.decryptFile(filePath, outPath, testPassword)
          ).rejects.toBeInstanceOf(CryptoError);
          expect(existsSync(outPath)).toBe(false);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) await unlink(f);
          }
        }
      });

      it('rejects a colliding v0 sync file in reject mode (original parse error preserved)', () => {
        const filePath = path.join(tempDir, 'v0-collision-reject-sync.bin');
        const outPath = path.join(tempDir, 'v0-collision-reject-sync-out.txt');
        try {
          buildCollidingV0FileSync(
            crypto,
            Buffer.from(testText, 'utf8'),
            testPassword,
            filePath
          );
          const rejected = new CryptoManager({ legacyMode: 'reject' });
          expect(() =>
            rejected.decryptFileSync(filePath, outPath, testPassword)
          ).toThrow(CryptoError);
          expect(existsSync(outPath)).toBe(false);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });

      it('still throws on a v1 ciphertext with corrupted version byte (fallback to v0 → GCM auth fails)', async () => {
        // Valid magic + bad version → parseHeader throws UNSUPPORTED_VERSION
        // → auto fallback → wrong salt/key → decipher.final() tag mismatch
        const encrypted = await crypto.encryptText(testText, testPassword);
        const buf = Buffer.from(encrypted, 'base64url');
        buf[4] = 0x99; // byte 4 is the version byte (after 4-byte magic)
        const corrupt = buf.toString('base64url');
        await expect(
          crypto.decryptText(corrupt, testPassword)
        ).rejects.toBeInstanceOf(CryptoError);
      });

      // ───────────────────────────────────────────────────────────────────
      // Zero-KDF-param magic collision (pins the unified auto-mode contract).
      //
      // A v0 salt may collide not just on the 4-byte "HPCR" magic but also
      // form a structurally-recognised v1 header whose KDF parameter field is
      // zero, so parseHeader throws INVALID_HEADER_PARAM (rather than the more
      // common UNSUPPORTED_VERSION). The documented contract (CLAUDE.md
      // legacyMode, the CHANGELOG magic-collision entry, and decryptText's own
      // in-catch comment) names ONLY KDF_PARAMS_OUT_OF_BOUNDS as the
      // always-re-thrown DoS exception in auto mode — every other structural
      // parse failure, INVALID_HEADER_PARAM included, must be caught and
      // recovered as v0. Earlier, three of the four paths (decryptText,
      // decryptTextSync, decryptFileSync) re-threw INVALID_HEADER_PARAM and so
      // could NOT recover such a blob, while decryptFile alone fell back; these
      // tests force that exact collision and assert uniform recovery across all
      // four paths. GCM authentication still guards correctness — a wrong key
      // from the v0 fallback would fail decipher.final().

      /**
       * Stamp `salt` so that, read as a v1 header, it is structurally valid up
       * to a ZERO Argon2id memoryCost → parseHeader throws INVALID_HEADER_PARAM.
       * Layout: [0..3]="HPCR", [4]=version 0x01, [5]=kdfId 0x00 (Argon2id),
       * [6..9]=memoryCost u32 forced to 0. Remaining bytes stay random so the
       * derived key is still unpredictable.
       */
      function stampZeroParamHeader(salt: Buffer): void {
        Buffer.from('HPCR', 'ascii').copy(salt, 0);
        salt[4] = FORMAT_VERSION; // 0x01
        salt[5] = KDF_ID_ARGON2ID; // 0x00
        salt.fill(0, 6, 10); // memoryCost u32 = 0 → INVALID_HEADER_PARAM
      }

      /** Assert the assembled blob really exercises the INVALID_HEADER_PARAM path. */
      function expectInvalidHeaderParam(buf: Buffer): void {
        expect(hasMagic(buf)).toBe(true);
        let code: string | undefined;
        try {
          parseHeader(buf);
        } catch (e) {
          code = (e as CryptoError).code;
        }
        expect(code).toBe('INVALID_HEADER_PARAM');
      }

      it('recovers a colliding v0 async text whose header would throw INVALID_HEADER_PARAM (auto)', async () => {
        const salt = crypto.generateSecureRandom(32);
        stampZeroParamHeader(salt);
        const iv = crypto.generateSecureRandom(12);
        const key = await crypto.deriveKey(testPassword, salt);
        const { encrypted, tag } = crypto.encryptData(
          Buffer.from(testText, 'utf8'),
          key,
          iv
        );
        const v0 = Buffer.concat([salt, iv, tag, encrypted]).toString(
          'base64url'
        );
        expectInvalidHeaderParam(Buffer.from(v0, 'base64url'));
        expect(await crypto.decryptText(v0, testPassword)).toBe(testText);
      });

      it('recovers a colliding v0 sync text whose header would throw INVALID_HEADER_PARAM (auto)', () => {
        const salt = crypto.generateSecureRandom(32);
        stampZeroParamHeader(salt);
        const iv = crypto.generateSecureRandom(12);
        const key = crypto.deriveKeySync(testPassword, salt, 100000);
        const { encrypted, tag } = crypto.encryptData(
          Buffer.from(testText, 'utf8'),
          key,
          iv
        );
        const v0 = Buffer.concat([salt, iv, tag, encrypted]).toString(
          'base64url'
        );
        expectInvalidHeaderParam(Buffer.from(v0, 'base64url'));
        expect(crypto.decryptTextSync(v0, testPassword)).toBe(testText);
      });

      it('recovers a colliding v0 async file whose header would throw INVALID_HEADER_PARAM (auto)', async () => {
        const filePath = path.join(tempDir, 'v0-zeroparam-async.bin');
        const outPath = path.join(tempDir, 'v0-zeroparam-async-out.txt');
        try {
          const salt = crypto.generateSecureRandom(32);
          stampZeroParamHeader(salt);
          const iv = crypto.generateSecureRandom(12);
          const key = await crypto.deriveKey(testPassword, salt);
          const { encrypted, tag } = crypto.encryptData(
            Buffer.from(testText, 'utf8'),
            key,
            iv
          );
          await writeFile(filePath, Buffer.concat([salt, iv, encrypted, tag]));
          expectInvalidHeaderParam(readFileSync(filePath));
          await crypto.decryptFile(filePath, outPath, testPassword);
          expect(await readFile(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) await unlink(f);
          }
        }
      });

      it('recovers a colliding v0 sync file whose header would throw INVALID_HEADER_PARAM (auto)', () => {
        const filePath = path.join(tempDir, 'v0-zeroparam-sync.bin');
        const outPath = path.join(tempDir, 'v0-zeroparam-sync-out.txt');
        try {
          const salt = crypto.generateSecureRandom(32);
          stampZeroParamHeader(salt);
          const iv = crypto.generateSecureRandom(12);
          const key = crypto.deriveKeySync(testPassword, salt, 100000);
          const { encrypted, tag } = crypto.encryptData(
            Buffer.from(testText, 'utf8'),
            key,
            iv
          );
          writeFileSync(filePath, Buffer.concat([salt, iv, encrypted, tag]));
          expectInvalidHeaderParam(readFileSync(filePath));
          crypto.decryptFileSync(filePath, outPath, testPassword);
          expect(readFileSync(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });

      // Corrupt-v1 "still throws" smoke tests for the three paths PLAN 6.2 left
      // uncovered (decryptText already has one above). A genuine v1 ciphertext
      // with a corrupted version byte parses as UNSUPPORTED_VERSION → auto
      // fallback to v0 → wrong key → decipher.final() tag mismatch → CryptoError.
      it('still throws on a v1 ciphertext with corrupted version byte — sync text (auto)', () => {
        const encrypted = crypto.encryptTextSync(testText, testPassword);
        const buf = Buffer.from(encrypted, 'base64url');
        buf[4] = 0x99; // version byte
        expect(() =>
          crypto.decryptTextSync(buf.toString('base64url'), testPassword)
        ).toThrow(CryptoError);
      });

      it('still throws on a v1 ciphertext with corrupted version byte — async file (auto)', async () => {
        const inPath = path.join(tempDir, 'corrupt-v1-async-in.bin');
        const encPath = path.join(tempDir, 'corrupt-v1-async-enc.bin');
        const outPath = path.join(tempDir, 'corrupt-v1-async-out.txt');
        try {
          writeFileSync(inPath, Buffer.from(testText, 'utf8'));
          await crypto.encryptFile(inPath, encPath, testPassword);
          const enc = readFileSync(encPath);
          enc[4] = 0x99; // version byte (after 4-byte magic)
          writeFileSync(encPath, enc);
          await expect(
            crypto.decryptFile(encPath, outPath, testPassword)
          ).rejects.toBeInstanceOf(CryptoError);
          expect(existsSync(outPath)).toBe(false);
        } finally {
          for (const f of [inPath, encPath, outPath]) {
            if (existsSync(f)) await unlink(f);
          }
        }
      });

      it('still throws on a v1 ciphertext with corrupted version byte — sync file (auto)', () => {
        const inPath = path.join(tempDir, 'corrupt-v1-sync-in.bin');
        const encPath = path.join(tempDir, 'corrupt-v1-sync-enc.bin');
        const outPath = path.join(tempDir, 'corrupt-v1-sync-out.txt');
        try {
          writeFileSync(inPath, Buffer.from(testText, 'utf8'));
          crypto.encryptFileSync(inPath, encPath, testPassword);
          const enc = readFileSync(encPath);
          enc[4] = 0x99; // version byte (after 4-byte magic)
          writeFileSync(encPath, enc);
          expect(() =>
            crypto.decryptFileSync(encPath, outPath, testPassword)
          ).toThrow(CryptoError);
          expect(existsSync(outPath)).toBe(false);
        } finally {
          for (const f of [inPath, encPath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });
    });
  });

  describe('versioned format - tampering & malformed input', () => {
    it('should reject tampered magic byte (text async)', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      const buf = Buffer.from(encrypted, 'base64url');
      buf[0] = (buf[0] ?? 0) ^ 0xff; // corrupt magic
      const tampered = buf.toString('base64url');
      // After magic is corrupted, the decoder treats this as legacy v0 (auto)
      // which will fail decryption with a tag-mismatch DECRYPTION_FAILED.
      try {
        await crypto.decryptText(tampered, testPassword);
        throw new Error('Expected throw');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).type).toBe(
          CryptoErrorType.DECRYPTION_FAILED
        );
      }
    });

    it('should reject tampered version byte (auto mode: v0 fallback → GCM auth failure)', async () => {
      // In auto mode, a bad version byte triggers the magic-collision recovery
      // path (parseHeader throws → v0 fallback → wrong key → DECRYPTION_FAILED).
      // In strict mode, the original UNSUPPORTED_VERSION error is preserved.
      const encrypted = await crypto.encryptText(testText, testPassword);
      const buf = Buffer.from(encrypted, 'base64url');
      buf[4] = 0x99; // corrupt version (still after intact magic)
      const tampered = buf.toString('base64url');
      await expect(crypto.decryptText(tampered, testPassword)).rejects.toBeInstanceOf(CryptoError);
      // strict mode preserves the original parse error code
      const strict = new CryptoManager({ legacyMode: 'strict' });
      try {
        await strict.decryptText(tampered, testPassword);
        throw new Error('Expected throw');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('UNSUPPORTED_VERSION');
      }
    });

    it('should reject tampered KDF id (auto mode: v0 fallback → GCM auth failure)', async () => {
      // Same rationale as the version-byte test above.
      const encrypted = await crypto.encryptText(testText, testPassword);
      const buf = Buffer.from(encrypted, 'base64url');
      buf[5] = 0x77; // corrupt kdfId
      const tampered = buf.toString('base64url');
      await expect(crypto.decryptText(tampered, testPassword)).rejects.toBeInstanceOf(CryptoError);
      // strict mode preserves the original parse error code
      const strict = new CryptoManager({ legacyMode: 'strict' });
      try {
        await strict.decryptText(tampered, testPassword);
        throw new Error('Expected throw');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('UNSUPPORTED_KDF');
      }
    });

    it('should reject KDF mismatch (sync ciphertext given to async decrypt)', async () => {
      // In auto mode, KDF_MISMATCH is caught → v0 fallback → wrong key → DECRYPTION_FAILED.
      // Strict mode re-throws the original KDF_MISMATCH.
      const cm = new CryptoManager();
      const encrypted = cm.encryptTextSync(testText, testPassword);
      // auto mode
      await expect(cm.decryptText(encrypted, testPassword)).rejects.toBeInstanceOf(CryptoError);
      // strict mode preserves KDF_MISMATCH
      const strict = new CryptoManager({ legacyMode: 'strict' });
      try {
        await strict.decryptText(encrypted, testPassword);
        throw new Error('Expected throw');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('KDF_MISMATCH');
      }
    });

    it('should reject async ciphertext given to sync decrypt (auto mode: v0 fallback → GCM auth failure)', async () => {
      // In auto mode, KDF_MISMATCH → v0 fallback → DECRYPTION_FAILED.
      const cm = new CryptoManager();
      const encrypted = await cm.encryptText(testText, testPassword);
      expect(() => cm.decryptTextSync(encrypted, testPassword)).toThrow(CryptoError);
      // strict mode preserves KDF_MISMATCH
      const strict = new CryptoManager({ legacyMode: 'strict' });
      try {
        strict.decryptTextSync(encrypted, testPassword);
        throw new Error('Expected throw');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('KDF_MISMATCH');
      }
    });

    it('should reject truncated v1 file (header followed by truncated body)', async () => {
      const filePath = path.join(tempDir, 'v1-truncated.bin');
      const outPath = path.join(tempDir, 'v1-truncated-out.txt');
      try {
        await crypto.encryptFile(
          path.join(tempDir, '__non_existent_input_should_not_be_read.txt'),
          filePath,
          testPassword
        ).catch(() => {
          /* expected to fail; we will manufacture the file ourselves */
        });
        // Manufacture a file with valid v1 header but only a few extra bytes.
        const header = packHeader(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 2 ** 16,
          timeCost: 3,
          parallelism: 1,
        });
        // header (22) + 5 bytes of "salt" — far short of needed 32 + 12 + 16
        await writeFile(filePath, Buffer.concat([header, Buffer.alloc(5)]));

        try {
          await crypto.decryptFile(filePath, outPath, testPassword);
          throw new Error('Expected throw');
        } catch (error) {
          expect(error).toBeInstanceOf(CryptoError);
          expect((error as CryptoError).code).toBe(
            'INVALID_ENCRYPTED_FILE_SIZE'
          );
        }
      } finally {
        for (const f of [filePath, outPath]) {
          if (existsSync(f)) await unlink(f);
        }
      }
    });

    it('should reject v1 text whose body is too short', async () => {
      // header only, no body
      const header = packHeader(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        memoryCost: 2 ** 16,
        timeCost: 3,
        parallelism: 1,
      });
      const malformed = header.toString('base64url');
      try {
        await crypto.decryptText(malformed, testPassword);
        throw new Error('Expected throw');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'INVALID_ENCRYPTED_DATA_SIZE'
        );
      }
    });
  });

  describe('versioned format - cross-instance parameter interop', () => {
    it('should decrypt v1 text encrypted with different memoryCost (async)', async () => {
      const enc = new CryptoManager({
        memoryCost: 2 ** 16,
        timeCost: 3,
        parallelism: 1,
      });
      const dec = new CryptoManager({
        memoryCost: 2 ** 17, // different default
        timeCost: 4,
        parallelism: 2,
      });
      const ciphertext = await enc.encryptText(testText, testPassword);
      const result = await dec.decryptText(ciphertext, testPassword);
      expect(result).toBe(testText);
    });

    it('should preserve embedded parameters across round-trip (async)', async () => {
      const enc = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 5,
        parallelism: 3,
      });
      const ciphertext = await enc.encryptText(testText, testPassword);
      const header = enc.inspectHeader(ciphertext);
      expect(header?.params.kind).toBe('argon2id');
      if (header?.params.kind === 'argon2id') {
        expect(header.params.memoryCost).toBe(2 ** 14);
        expect(header.params.timeCost).toBe(5);
        expect(header.params.parallelism).toBe(3);
      }

      // Decrypt with another instance whose defaults differ.
      const dec = new CryptoManager({
        memoryCost: 2 ** 16,
        timeCost: 3,
        parallelism: 1,
      });
      const out = await dec.decryptText(ciphertext, testPassword);
      expect(out).toBe(testText);
      // Two Argon2id derivations with timeCost=5, parallelism=3 add up on
      // shared CI runners (especially under memory pressure from the rest
      // of the suite, which now uses the bumped 128 MiB default). 30s is a
      // generous ceiling that still catches a true regression.
    }, 30000);

    it('should decrypt v1 file encrypted with different parameters (async)', async () => {
      const enc = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 2,
        parallelism: 1,
      });
      const dec = new CryptoManager({
        memoryCost: 2 ** 16,
        timeCost: 4,
        parallelism: 2,
      });
      const inputPath = path.join(tempDir, 'cross-param-in.txt');
      const encryptedPath = path.join(tempDir, 'cross-param-enc.bin');
      const decryptedPath = path.join(tempDir, 'cross-param-out.txt');
      try {
        await writeFile(inputPath, testText);
        await enc.encryptFile(inputPath, encryptedPath, testPassword);
        await dec.decryptFile(encryptedPath, decryptedPath, testPassword);
        expect(await readFile(decryptedPath, 'utf8')).toBe(testText);
      } finally {
        for (const f of [inputPath, encryptedPath, decryptedPath]) {
          if (existsSync(f)) await unlink(f);
        }
      }
    });
  });

  describe('Constructor - legacyMode validation', () => {
    it('should default legacyMode to "auto"', () => {
      const cm = new CryptoManager();
      expect(cm.getLegacyMode()).toBe('auto');
    });

    it('should accept legacyMode = "auto"', () => {
      const cm = new CryptoManager({ legacyMode: 'auto' });
      expect(cm.getLegacyMode()).toBe('auto');
    });

    it('should accept legacyMode = "strict"', () => {
      const cm = new CryptoManager({ legacyMode: 'strict' });
      expect(cm.getLegacyMode()).toBe('strict');
    });

    it('should accept legacyMode = "reject"', () => {
      const cm = new CryptoManager({ legacyMode: 'reject' });
      expect(cm.getLegacyMode()).toBe('reject');
    });

    it('should reject invalid legacyMode', () => {
      expect(
        () =>
          new CryptoManager({
            legacyMode: 'banana' as unknown as 'auto',
          })
      ).toThrow(CryptoError);
      try {
        new CryptoManager({
          legacyMode: 'banana' as unknown as 'auto',
        });
      } catch (error) {
        expect((error as CryptoError).code).toBe('INVALID_LEGACY_MODE');
      }
    });
  });

  // ==========================================================================
  // PBKDF2 iteration count (Task 1)
  // ==========================================================================

  describe('PBKDF2 iteration count', () => {
    describe('Constructor validation', () => {
      it('should default pbkdf2Iterations to 600000', () => {
        const cm = new CryptoManager();
        const encrypted = cm.encryptTextSync(testText, testPassword);
        const parsed = cm.inspectHeader(encrypted);
        expect(parsed?.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
        if (parsed?.params.kind === 'pbkdf2-sha256') {
          expect(parsed.params.iterations).toBe(600000);
        }
      });

      it('should default legacyPbkdf2Iterations to 100000 (no public getter — verified via decrypt round-trip below)', () => {
        // No direct public observable. Verified via the v0 round-trip tests
        // that use 100000 iterations to build legacy ciphertexts.
        const cm = new CryptoManager();
        expect(cm).toBeInstanceOf(CryptoManager);
      });

      it('should accept custom pbkdf2Iterations', () => {
        const cm = new CryptoManager({ pbkdf2Iterations: 1000000 });
        const encrypted = cm.encryptTextSync(testText, testPassword);
        const parsed = cm.inspectHeader(encrypted);
        if (parsed?.params.kind === 'pbkdf2-sha256') {
          expect(parsed.params.iterations).toBe(1000000);
        }
      });

      it('should accept custom legacyPbkdf2Iterations', () => {
        const cm = new CryptoManager({ legacyPbkdf2Iterations: 50000 });
        expect(cm).toBeInstanceOf(CryptoManager);
      });

      it('should reject negative pbkdf2Iterations', () => {
        expect(() => new CryptoManager({ pbkdf2Iterations: -1 })).toThrow(
          CryptoError
        );
        try {
          new CryptoManager({ pbkdf2Iterations: -1 });
        } catch (error) {
          expect((error as CryptoError).code).toBe(
            'INVALID_PBKDF2_ITERATIONS'
          );
        }
      });

      it('should reject zero pbkdf2Iterations', () => {
        expect(() => new CryptoManager({ pbkdf2Iterations: 0 })).toThrow(
          CryptoError
        );
      });

      it('should reject non-integer pbkdf2Iterations', () => {
        expect(() => new CryptoManager({ pbkdf2Iterations: 1.5 })).toThrow(
          CryptoError
        );
        expect(() => new CryptoManager({ pbkdf2Iterations: NaN })).toThrow(
          CryptoError
        );
      });

      it('should reject negative legacyPbkdf2Iterations', () => {
        expect(
          () => new CryptoManager({ legacyPbkdf2Iterations: -1 })
        ).toThrow(CryptoError);
        try {
          new CryptoManager({ legacyPbkdf2Iterations: -1 });
        } catch (error) {
          expect((error as CryptoError).code).toBe(
            'INVALID_LEGACY_PBKDF2_ITERATIONS'
          );
        }
      });

      it('should reject zero legacyPbkdf2Iterations', () => {
        expect(
          () => new CryptoManager({ legacyPbkdf2Iterations: 0 })
        ).toThrow(CryptoError);
      });

      it('should reject non-integer legacyPbkdf2Iterations', () => {
        expect(
          () => new CryptoManager({ legacyPbkdf2Iterations: 1.5 })
        ).toThrow(CryptoError);
      });
    });

    describe('v1 ciphertext header', () => {
      it('should embed 600000 in v1 sync text header by default', () => {
        const cm = new CryptoManager();
        const encrypted = cm.encryptTextSync(testText, testPassword);
        const parsed = cm.inspectHeader(encrypted);
        expect(parsed).not.toBeNull();
        expect(parsed?.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
        if (parsed?.params.kind === 'pbkdf2-sha256') {
          expect(parsed.params.iterations).toBe(600000);
        }
      });

      it('should embed 600000 in v1 sync file header by default', () => {
        const cm = new CryptoManager();
        const inputPath = path.join(tempDir, 'pbkdf2-iter-input.txt');
        const encryptedPath = path.join(
          tempDir,
          'pbkdf2-iter-encrypted.bin'
        );
        try {
          writeFileSync(inputPath, testText);
          cm.encryptFileSync(inputPath, encryptedPath, testPassword);
          const fileBuf = readFileSync(encryptedPath);
          const parsed = cm.inspectHeader(fileBuf);
          expect(parsed?.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
          if (parsed?.params.kind === 'pbkdf2-sha256') {
            expect(parsed.params.iterations).toBe(600000);
          }
        } finally {
          for (const f of [inputPath, encryptedPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });

      it('should embed custom iterations in v1 sync text header', () => {
        const cm = new CryptoManager({ pbkdf2Iterations: 250000 });
        const encrypted = cm.encryptTextSync(testText, testPassword);
        const parsed = cm.inspectHeader(encrypted);
        if (parsed?.params.kind === 'pbkdf2-sha256') {
          expect(parsed.params.iterations).toBe(250000);
        }
      });

      it('should round-trip v1 sync text with custom iterations', () => {
        const cm = new CryptoManager({ pbkdf2Iterations: 50000 });
        const encrypted = cm.encryptTextSync(testText, testPassword);
        const decrypted = cm.decryptTextSync(encrypted, testPassword);
        expect(decrypted).toBe(testText);
      });

      it('should round-trip v1 sync file with custom iterations', () => {
        const cm = new CryptoManager({ pbkdf2Iterations: 50000 });
        const inputPath = path.join(tempDir, 'pbkdf2-rt-input.txt');
        const encryptedPath = path.join(tempDir, 'pbkdf2-rt-encrypted.bin');
        const decryptedPath = path.join(tempDir, 'pbkdf2-rt-decrypted.txt');
        try {
          writeFileSync(inputPath, testText);
          cm.encryptFileSync(inputPath, encryptedPath, testPassword);
          cm.decryptFileSync(encryptedPath, decryptedPath, testPassword);
          expect(readFileSync(decryptedPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [inputPath, encryptedPath, decryptedPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });
    });

    describe('Cross-instance interop via embedded iterations', () => {
      it('should decrypt v1 sync text encrypted with different iterations', () => {
        const enc = new CryptoManager({ pbkdf2Iterations: 30000 });
        const dec = new CryptoManager({ pbkdf2Iterations: 1000000 });
        const ciphertext = enc.encryptTextSync(testText, testPassword);
        const result = dec.decryptTextSync(ciphertext, testPassword);
        expect(result).toBe(testText);
      });

      it('should decrypt v1 sync file encrypted with different iterations', () => {
        const enc = new CryptoManager({ pbkdf2Iterations: 30000 });
        const dec = new CryptoManager({ pbkdf2Iterations: 1000000 });
        const inputPath = path.join(tempDir, 'pbkdf2-cross-input.txt');
        const encryptedPath = path.join(tempDir, 'pbkdf2-cross-encrypted.bin');
        const decryptedPath = path.join(
          tempDir,
          'pbkdf2-cross-decrypted.txt'
        );
        try {
          writeFileSync(inputPath, testText);
          enc.encryptFileSync(inputPath, encryptedPath, testPassword);
          dec.decryptFileSync(encryptedPath, decryptedPath, testPassword);
          expect(readFileSync(decryptedPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [inputPath, encryptedPath, decryptedPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });
    });

    describe('Legacy v0 backward compatibility', () => {
      // Build a v0 ciphertext using a specific iteration count (the v0
      // format had no embedded iteration count, so the encoder and decoder
      // must agree out-of-band).
      function buildV0SyncText(
        cm: CryptoManager,
        text: string,
        password: string,
        iterations: number
      ): string {
        const salt = cm.generateSecureRandom(32);
        const iv = cm.generateSecureRandom(12);
        const key = cm.deriveKeySync(password, salt, iterations);
        const { encrypted, tag } = cm.encryptData(
          Buffer.from(text, 'utf8'),
          key,
          iv
        );
        return Buffer.concat([salt, iv, tag, encrypted]).toString(
          'base64url'
        );
      }

      function buildV0SyncFile(
        cm: CryptoManager,
        content: Buffer,
        password: string,
        iterations: number,
        outputPath: string
      ): void {
        const salt = cm.generateSecureRandom(32);
        const iv = cm.generateSecureRandom(12);
        const key = cm.deriveKeySync(password, salt, iterations);
        const { encrypted, tag } = cm.encryptData(content, key, iv);
        writeFileSync(outputPath, Buffer.concat([salt, iv, encrypted, tag]));
      }

      it('should decrypt a v0 sync text built with 100000 iterations (default legacy)', () => {
        const cm = new CryptoManager();
        const v0 = buildV0SyncText(cm, testText, testPassword, 100000);
        expect(hasMagic(Buffer.from(v0, 'base64url'))).toBe(false);
        const result = cm.decryptTextSync(v0, testPassword);
        expect(result).toBe(testText);
      });

      it('should decrypt a v0 sync file built with 100000 iterations (default legacy)', () => {
        const cm = new CryptoManager();
        const filePath = path.join(tempDir, 'pbkdf2-v0-default.bin');
        const outPath = path.join(tempDir, 'pbkdf2-v0-default-out.txt');
        try {
          buildV0SyncFile(
            cm,
            Buffer.from(testText, 'utf8'),
            testPassword,
            100000,
            filePath
          );
          cm.decryptFileSync(filePath, outPath, testPassword);
          expect(readFileSync(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });

      it('should fail to decrypt v0 sync text built with non-default iterations under default legacyPbkdf2Iterations', () => {
        const builder = new CryptoManager();
        // v0 was built with 250000 — but default legacyPbkdf2Iterations is 100000
        const v0 = buildV0SyncText(builder, testText, testPassword, 250000);
        const decoder = new CryptoManager(); // uses default legacyPbkdf2Iterations = 100000
        expect(() => decoder.decryptTextSync(v0, testPassword)).toThrow(
          CryptoError
        );
      });

      it('should decrypt v0 sync text with non-default iterations when legacyPbkdf2Iterations is overridden', () => {
        const builder = new CryptoManager();
        const v0 = buildV0SyncText(builder, testText, testPassword, 250000);
        const decoder = new CryptoManager({
          legacyPbkdf2Iterations: 250000,
        });
        const result = decoder.decryptTextSync(v0, testPassword);
        expect(result).toBe(testText);
      });

      it('should decrypt v0 sync file with non-default iterations when legacyPbkdf2Iterations is overridden', () => {
        const builder = new CryptoManager();
        const filePath = path.join(tempDir, 'pbkdf2-v0-custom.bin');
        const outPath = path.join(tempDir, 'pbkdf2-v0-custom-out.txt');
        try {
          buildV0SyncFile(
            builder,
            Buffer.from(testText, 'utf8'),
            testPassword,
            250000,
            filePath
          );
          const decoder = new CryptoManager({
            legacyPbkdf2Iterations: 250000,
          });
          decoder.decryptFileSync(filePath, outPath, testPassword);
          expect(readFileSync(outPath, 'utf8')).toBe(testText);
        } finally {
          for (const f of [filePath, outPath]) {
            if (existsSync(f)) unlinkSync(f);
          }
        }
      });

      it('legacyPbkdf2Iterations should NOT affect v1 ciphertexts (header-embedded value wins)', () => {
        // Encrypt with default (600000) and inspect: header should reflect 600000.
        const enc = new CryptoManager();
        const ciphertext = enc.encryptTextSync(testText, testPassword);
        // Decoder has legacyPbkdf2Iterations = 12345 — irrelevant for v1.
        const dec = new CryptoManager({ legacyPbkdf2Iterations: 12345 });
        const result = dec.decryptTextSync(ciphertext, testPassword);
        expect(result).toBe(testText);
      });

      it('should reject v0 ciphertext in strict mode regardless of iteration count', () => {
        const builder = new CryptoManager();
        const v0 = buildV0SyncText(builder, testText, testPassword, 100000);
        const strict = new CryptoManager({ legacyMode: 'strict' });
        try {
          strict.decryptTextSync(v0, testPassword);
          throw new Error('Expected throw');
        } catch (error) {
          expect(error).toBeInstanceOf(CryptoError);
          expect((error as CryptoError).code).toBe('LEGACY_FORMAT_REJECTED');
        }
      });
    });

    describe('deriveKeySync default behaviour', () => {
      it('should use configured pbkdf2Iterations when called with no iterations argument', () => {
        const cm = new CryptoManager({ pbkdf2Iterations: 50000 });
        const salt = cm.generateSecureRandom(32);
        // Same password+salt+iterations should produce the same key.
        const keyA = cm.deriveKeySync(testPassword, salt);
        const keyB = cm.deriveKeySync(testPassword, salt, 50000);
        expect(keyA.equals(keyB)).toBe(true);
      });

      it('should accept explicit iterations override regardless of constructor default', () => {
        const cm = new CryptoManager({ pbkdf2Iterations: 50000 });
        const salt = cm.generateSecureRandom(32);
        const keyDefault = cm.deriveKeySync(testPassword, salt);
        const keyOverride = cm.deriveKeySync(testPassword, salt, 100000);
        expect(keyDefault.equals(keyOverride)).toBe(false);
      });
    });
  });

  // ==========================================================================
  // secureClear semantics (Task 5)
  // ==========================================================================

  describe('secureClear - decrypt path hygiene', () => {
    it('should zero the combined buffer after decryptTextSync round-trip', () => {
      // Spy on secureClear to verify it is called for `combined`.
      const cm = new CryptoManager();
      const encrypted = cm.encryptTextSync(testText, testPassword);
      const spy = jest.spyOn(cm, 'secureClear');
      const result = cm.decryptTextSync(encrypted, testPassword);
      expect(result).toBe(testText);
      // At minimum we expect 3 secureClear calls: key, decrypted, combined.
      expect(spy.mock.calls.length).toBeGreaterThanOrEqual(3);
      // One of the calls must be a Buffer of length >= the input ciphertext
      // length (i.e. the combined buffer itself).
      const expectedCombinedLen = Buffer.from(encrypted, 'base64url').length;
      const sawCombined = spy.mock.calls.some(([buf]) => {
        return Buffer.isBuffer(buf) && buf.length === expectedCombinedLen;
      });
      expect(sawCombined).toBe(true);
      spy.mockRestore();
    });

    it('should zero the combined buffer after decryptText round-trip (async)', async () => {
      const cm = new CryptoManager();
      const encrypted = await cm.encryptText(testText, testPassword);
      const spy = jest.spyOn(cm, 'secureClear');
      const result = await cm.decryptText(encrypted, testPassword);
      expect(result).toBe(testText);
      expect(spy.mock.calls.length).toBeGreaterThanOrEqual(3);
      const expectedCombinedLen = Buffer.from(encrypted, 'base64url').length;
      const sawCombined = spy.mock.calls.some(([buf]) => {
        return Buffer.isBuffer(buf) && buf.length === expectedCombinedLen;
      });
      expect(sawCombined).toBe(true);
      spy.mockRestore();
    });

    it('should zero key/salt/iv/tag after decryptFileSync round-trip', () => {
      // After Task 3 streaming, decryptFileSync no longer loads the whole
      // file into memory; instead it scrubs the smaller key/salt/iv/tag
      // buffers individually plus a fixed-size chunk reuse buffer. Verify
      // each of those buffers is cleared at least once.
      const cm = new CryptoManager();
      const inputPath = path.join(tempDir, 'sc-input.txt');
      const encryptedPath = path.join(tempDir, 'sc-encrypted.bin');
      const decryptedPath = path.join(tempDir, 'sc-decrypted.txt');
      try {
        writeFileSync(inputPath, testText);
        cm.encryptFileSync(inputPath, encryptedPath, testPassword);
        const spy = jest.spyOn(cm, 'secureClear');
        cm.decryptFileSync(encryptedPath, decryptedPath, testPassword);
        // Inspect call lengths (only Buffer args are interesting).
        const lens = spy.mock.calls
          .map(([buf]) => (Buffer.isBuffer(buf) ? buf.length : -1))
          .filter((l) => l >= 0);
        // We expect at minimum: key (32), salt (32), iv (12), tag (16).
        // The salt and key are both 32 bytes; require at least one of each
        // length to appear among the cleared buffers.
        const has = (n: number): boolean => lens.includes(n);
        expect(has(32)).toBe(true); // key or salt
        expect(has(12)).toBe(true); // iv
        expect(has(16)).toBe(true); // tag
        // Total clear calls should be >= 4 (key + salt + iv + tag).
        expect(spy.mock.calls.length).toBeGreaterThanOrEqual(4);
        spy.mockRestore();
      } finally {
        for (const f of [inputPath, encryptedPath, decryptedPath]) {
          if (existsSync(f)) unlinkSync(f);
        }
      }
    });

    it('should zero key/salt/iv/tag after decryptFile round-trip (async)', async () => {
      const cm = new CryptoManager();
      const inputPath = path.join(tempDir, 'sc-async-input.txt');
      const encryptedPath = path.join(tempDir, 'sc-async-encrypted.bin');
      const decryptedPath = path.join(tempDir, 'sc-async-decrypted.txt');
      try {
        await writeFile(inputPath, testText);
        await cm.encryptFile(inputPath, encryptedPath, testPassword);
        const spy = jest.spyOn(cm, 'secureClear');
        await cm.decryptFile(encryptedPath, decryptedPath, testPassword);
        const lens = spy.mock.calls
          .map(([buf]) => (Buffer.isBuffer(buf) ? buf.length : -1))
          .filter((l) => l >= 0);
        const has = (n: number): boolean => lens.includes(n);
        expect(has(32)).toBe(true); // key or salt
        expect(has(12)).toBe(true); // iv
        expect(has(16)).toBe(true); // tag
        expect(spy.mock.calls.length).toBeGreaterThanOrEqual(4);
        spy.mockRestore();
      } finally {
        for (const f of [inputPath, encryptedPath, decryptedPath]) {
          if (existsSync(f)) await unlink(f);
        }
      }
    });

    it('should produce correct plaintext even though combined is zeroed', () => {
      // The combined buffer is cleared AFTER decryption, so the plaintext
      // (which is a separate string copy) must remain valid.
      const cm = new CryptoManager();
      const longText = 'A'.repeat(1024) + 'B'.repeat(1024) + 'C'.repeat(1024);
      const encrypted = cm.encryptTextSync(longText, testPassword);
      const result = cm.decryptTextSync(encrypted, testPassword);
      expect(result).toBe(longText);
    });
  });

  // ==========================================================================
  // Streaming decryption (Task 3) — large file round-trips for v0 and v1.
  // The body of these tests is gated by SKIP_LARGE_TESTS=1 because they
  // generate multi-MiB files. Default size is 10 MiB; set
  // LARGE_FILE_TEST_MB=50 to bump it. Jest timeout is bumped to 120000.
  // ==========================================================================

  describe('large-file streaming round-trip (Task 3)', () => {
    const skipLarge = process.env['SKIP_LARGE_TESTS'] === '1';
    const sizeMb = Math.max(
      1,
      parseInt(process.env['LARGE_FILE_TEST_MB'] ?? '10', 10) || 10
    );
    const sizeBytes = sizeMb * 1024 * 1024;
    const describeOrSkip = skipLarge ? describe.skip : describe;

    /**
     * Generate a deterministic-but-non-uniform test file by writing
     * 64 KiB chunks of pseudo-random bytes seeded from a counter, so we
     * exercise multiple chunk reads in the streaming decryptor without
     * holding the whole payload in memory at once during generation.
     */
    function generateLargeFileSync(filePath: string, total: number): void {
      const chunkSize = 64 * 1024;
      const fd = openSync(filePath, 'w');
      try {
        const chunk = Buffer.alloc(chunkSize);
        let written = 0;
        let counter = 0;
        while (written < total) {
          // Fill with cheap deterministic bytes — enough variability to
          // catch an off-by-one in the streaming logic but not so random
          // we burn CPU on the seeding.
          for (let i = 0; i < chunkSize; i++) {
            chunk[i] = (counter + i * 31) & 0xff;
          }
          const remaining = total - written;
          const toWrite = Math.min(chunkSize, remaining);
          writeSync(fd, chunk, 0, toWrite);
          written += toWrite;
          counter++;
        }
      } finally {
        closeSync(fd);
      }
    }

    /**
     * Compare two files chunk-by-chunk so we don't load multi-MiB blobs
     * into a JS Buffer when asserting equality.
     */
    function filesEqualSync(a: string, b: string): boolean {
      const sizeA = statSync(a).size;
      const sizeB = statSync(b).size;
      if (sizeA !== sizeB) return false;
      const fdA = openSync(a, 'r');
      const fdB = openSync(b, 'r');
      try {
        const chunkSize = 64 * 1024;
        const bufA = Buffer.alloc(chunkSize);
        const bufB = Buffer.alloc(chunkSize);
        let offset = 0;
        while (offset < sizeA) {
          const wantBytes = Math.min(chunkSize, sizeA - offset);
          const readA = readSync(fdA, bufA, 0, wantBytes, offset);
          const readB = readSync(fdB, bufB, 0, wantBytes, offset);
          if (readA !== readB) return false;
          if (
            !bufA.subarray(0, readA).equals(bufB.subarray(0, readB))
          ) {
            return false;
          }
          offset += readA;
        }
        return true;
      } finally {
        closeSync(fdA);
        closeSync(fdB);
      }
    }

    /**
     * Build a v0 (legacy, no header) async file ciphertext directly via
     * Argon2id-derived key + a single AES-GCM encryption pass. Used to
     * verify the streaming decrypt path handles v0 files just as it
     * handles v1 files.
     */
    async function buildLegacyV0FileLarge(
      cm: CryptoManager,
      sourcePath: string,
      outputPath: string,
      password: string
    ): Promise<void> {
      const salt = cm.generateSecureRandom(32);
      const iv = cm.generateSecureRandom(12);
      const key = await cm.deriveKey(password, salt);
      const data = await readFile(sourcePath);
      const { encrypted, tag } = cm.encryptData(data, key, iv);
      await writeFile(outputPath, Buffer.concat([salt, iv, encrypted, tag]));
    }

    function buildLegacyV0FileSyncLarge(
      cm: CryptoManager,
      sourcePath: string,
      outputPath: string,
      password: string
    ): void {
      const salt = cm.generateSecureRandom(32);
      const iv = cm.generateSecureRandom(12);
      // Note: 100000 to match the historical v0 sync iteration count.
      const key = cm.deriveKeySync(password, salt, 100000);
      const data = readFileSync(sourcePath);
      const { encrypted, tag } = cm.encryptData(data, key, iv);
      writeFileSync(
        outputPath,
        Buffer.concat([salt, iv, encrypted, tag])
      );
    }

    describeOrSkip(`${sizeMb} MiB`, () => {
      const inputPath = path.join(tempDir, 'large-input.bin');
      const encryptedPath = path.join(tempDir, 'large-encrypted.bin');
      const decryptedPath = path.join(tempDir, 'large-decrypted.bin');

      beforeAll(() => {
        // Generate the source file once for all tests in this block.
        generateLargeFileSync(inputPath, sizeBytes);
      }, 120000);

      afterAll(() => {
        for (const f of [inputPath, encryptedPath, decryptedPath]) {
          if (existsSync(f)) {
            try {
              unlinkSync(f);
            } catch {
              /* ignore */
            }
          }
        }
      });

      afterEach(() => {
        for (const f of [encryptedPath, decryptedPath]) {
          if (existsSync(f)) {
            try {
              unlinkSync(f);
            } catch {
              /* ignore */
            }
          }
        }
      });

      it(
        'should round-trip v1 async (encryptFile + streaming decryptFile)',
        async () => {
          await crypto.encryptFile(inputPath, encryptedPath, testPassword);
          // Sanity: encrypted file should have the v1 header magic.
          const buf = readFileSync(encryptedPath, { flag: 'r' }).subarray(
            0,
            HEADER_LENGTH
          );
          expect(hasMagic(buf)).toBe(true);

          await crypto.decryptFile(
            encryptedPath,
            decryptedPath,
            testPassword
          );
          expect(filesEqualSync(inputPath, decryptedPath)).toBe(true);
        },
        120000
      );

      it(
        'should round-trip v1 sync (encryptFileSync + streaming decryptFileSync)',
        () => {
          crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
          const buf = readFileSync(encryptedPath, { flag: 'r' }).subarray(
            0,
            HEADER_LENGTH
          );
          expect(hasMagic(buf)).toBe(true);

          crypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
          expect(filesEqualSync(inputPath, decryptedPath)).toBe(true);
        },
        120000
      );

      it(
        'should round-trip v0 async (legacy file + streaming decryptFile)',
        async () => {
          await buildLegacyV0FileLarge(
            crypto,
            inputPath,
            encryptedPath,
            testPassword
          );
          const front = readFileSync(encryptedPath).subarray(0, 4);
          expect(hasMagic(front)).toBe(false);

          await crypto.decryptFile(
            encryptedPath,
            decryptedPath,
            testPassword
          );
          expect(filesEqualSync(inputPath, decryptedPath)).toBe(true);
        },
        120000
      );

      it(
        'should round-trip v0 sync (legacy file + streaming decryptFileSync)',
        () => {
          buildLegacyV0FileSyncLarge(
            crypto,
            inputPath,
            encryptedPath,
            testPassword
          );
          const front = readFileSync(encryptedPath).subarray(0, 4);
          expect(hasMagic(front)).toBe(false);

          crypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
          expect(filesEqualSync(inputPath, decryptedPath)).toBe(true);
        },
        120000
      );
    });
  });

  // ==========================================================================
  // Large file streaming (Task 20).
  //
  // This block complements the Task 3 round-trip block above with an
  // additional set of tests that exercise the streaming path through a
  // hash-based round-trip integrity check. Differences from the Task 3
  // block:
  //
  //   - File generation uses `fs.createWriteStream` + chunked async writes
  //     (rather than `openSync`/`writeSync` loops). This matches the
  //     Task 20 spec and exercises the read side of the encryption
  //     pipeline against a stream that was itself produced by the
  //     standard async stream API.
  //   - Round-trip integrity is verified via a `sha256` hash compare on
  //     the original and decrypted files (rather than the chunk-by-chunk
  //     byte comparison used in Task 3). The hash check is end-to-end and
  //     a more concise statement of "the bytes survived the round-trip
  //     intact".
  //   - The default file size is 10 MiB and is overridable via the
  //     `LARGE_FILE_TEST_MB` env var (matches Task 3).
  //   - The whole block is skipped (via `it.skip`) when
  //     `SKIP_LARGE_TESTS === '1'`. Setting the env var lets CI runners
  //     opt out of the disk + CPU cost without recompiling the test
  //     binary.
  //   - Per-test timeout is 120000 ms (2 min) to absorb worst-case I/O on
  //     slow CI runners.
  //
  // We deliberately do NOT duplicate the v0/v1 + sync/async matrix from
  // Task 3 — those four corners are already covered there. This block
  // adds two complementary tests (async + sync via the stream-generated
  // file + hash check) so that the cumulative test surface for large
  // files is meaningfully broader than the sum of either block alone.
  // ==========================================================================

  describe('large file streaming (Task 20)', () => {
    const skipLarge = process.env['SKIP_LARGE_TESTS'] === '1';
    const sizeMb = Math.max(
      1,
      parseInt(process.env['LARGE_FILE_TEST_MB'] ?? '10', 10) || 10
    );
    const sizeBytes = sizeMb * 1024 * 1024;
    // Use `it.skip` when SKIP_LARGE_TESTS=1, so the spec rows still
    // appear in the runner output (with a "skipped" marker) rather than
    // vanishing entirely. This makes it obvious that the test was
    // intentionally elided rather than accidentally absent.
    const itOrSkip = skipLarge ? it.skip : it;

    const inputPath = path.join(tempDir, 'task20-stream-input.bin');
    const encryptedPath = path.join(tempDir, 'task20-stream-enc.bin');
    const decryptedPath = path.join(tempDir, 'task20-stream-dec.bin');

    /**
     * Generate a large test file via `fs.createWriteStream` with chunked
     * async writes. We honour the stream's backpressure by `await`-ing
     * the `drain` event whenever `write()` returns false; this mimics
     * the textbook recipe for filling a stream from a producer that has
     * a fixed total budget rather than a piped source.
     *
     * The chunk pattern is deterministic (counter-seeded) but
     * non-uniform — the encryption stream sees varying bytes, so a
     * future bug that, say, only triggers on long runs of identical
     * bytes would still be caught here.
     */
    async function generateLargeFileStream(
      filePath: string,
      total: number
    ): Promise<void> {
      const { createWriteStream } = await import('node:fs');
      const chunkSize = 64 * 1024;
      return new Promise<void>((resolve, reject) => {
        const stream = createWriteStream(filePath);
        stream.on('error', reject);
        stream.on('finish', resolve);

        let written = 0;
        let counter = 0;

        const writeNext = (): void => {
          while (written < total) {
            const remaining = total - written;
            const toWrite = Math.min(chunkSize, remaining);
            const chunk = Buffer.alloc(toWrite);
            // Cheap deterministic pattern — see Task 3 generator.
            for (let i = 0; i < toWrite; i++) {
              chunk[i] = (counter + i * 31) & 0xff;
            }
            counter++;
            written += toWrite;

            const ok = stream.write(chunk);
            if (!ok) {
              // Backpressure — wait for drain before continuing.
              stream.once('drain', writeNext);
              return;
            }
          }
          stream.end();
        };

        writeNext();
      });
    }

    /**
     * Streaming sha256 hash of a file via `fs.createReadStream`. We
     * deliberately use streams here too so that the hash computation
     * for a large test file does not itself blow up RAM — the test
     * would fail to *measure* a true streaming round-trip if the test
     * harness loaded the whole file into memory to compute its hash.
     */
    async function hashFileStream(filePath: string): Promise<string> {
      const { createReadStream } = await import('node:fs');
      return new Promise<string>((resolve, reject) => {
        const hasher = nodeCrypto.createHash('sha256');
        const stream = createReadStream(filePath);
        stream.on('data', chunk => hasher.update(chunk));
        stream.on('end', () => resolve(hasher.digest('hex')));
        stream.on('error', reject);
      });
    }

    afterEach(async () => {
      for (const f of [inputPath, encryptedPath, decryptedPath]) {
        if (existsSync(f)) {
          try {
            await unlink(f);
          } catch {
            /* ignore */
          }
        }
      }
    });

    itOrSkip(
      `should round-trip a ${sizeMb} MiB file via async streaming with sha256 integrity check`,
      async () => {
        await generateLargeFileStream(inputPath, sizeBytes);
        // Sanity: the input file should be exactly the configured size
        // — catches bugs in the stream generator that would otherwise
        // make the round-trip pass for the wrong reasons.
        expect(statSync(inputPath).size).toBe(sizeBytes);

        const inputHash = await hashFileStream(inputPath);

        await crypto.encryptFile(inputPath, encryptedPath, testPassword);
        // The encrypted file should be roughly the input size plus
        // header (6 bytes) + KDF-params (16) + salt (32) + IV (12) +
        // tag (16) ~= 82 bytes of overhead. We just assert "at least
        // as big as the input + header constants".
        expect(statSync(encryptedPath).size).toBeGreaterThan(sizeBytes);

        await crypto.decryptFile(
          encryptedPath,
          decryptedPath,
          testPassword
        );
        expect(statSync(decryptedPath).size).toBe(sizeBytes);

        const decryptedHash = await hashFileStream(decryptedPath);
        // The crucial integrity check: the decrypted file must match
        // the original byte-for-byte. A hash collision is
        // astronomically unlikely (sha256 collision resistance is
        // ~2^128), so this is a tight check.
        expect(decryptedHash).toBe(inputHash);
      },
      120000
    );

    itOrSkip(
      `should round-trip a ${sizeMb} MiB file via sync streaming with sha256 integrity check`,
      async () => {
        await generateLargeFileStream(inputPath, sizeBytes);
        expect(statSync(inputPath).size).toBe(sizeBytes);

        const inputHash = await hashFileStream(inputPath);

        crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
        expect(statSync(encryptedPath).size).toBeGreaterThan(sizeBytes);

        crypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
        expect(statSync(decryptedPath).size).toBe(sizeBytes);

        const decryptedHash = await hashFileStream(decryptedPath);
        expect(decryptedHash).toBe(inputHash);
      },
      120000
    );
  });

  // ==========================================================================
  // Streaming decryption — small / boundary cases that exercise the chunk
  // boundaries in the sync streaming path. These run unconditionally.
  // ==========================================================================

  describe('streaming decrypt boundary cases', () => {
    const inputPath = path.join(tempDir, 'sb-input.bin');
    const encryptedPath = path.join(tempDir, 'sb-encrypted.bin');
    const decryptedPath = path.join(tempDir, 'sb-decrypted.bin');

    afterEach(async () => {
      for (const f of [inputPath, encryptedPath, decryptedPath]) {
        if (existsSync(f)) {
          try {
            await unlink(f);
          } catch {
            /* ignore */
          }
        }
      }
    });

    // The sync streaming chunk size is 64 KiB. We verify exactly-on-boundary
    // and just-over-boundary inputs to catch off-by-one issues.
    const SYNC_CHUNK = 64 * 1024;

    it('should decrypt sync file just above sync chunk size', () => {
      const data = Buffer.alloc(SYNC_CHUNK + 1, 0xa5);
      writeFileSync(inputPath, data);
      crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      crypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
      expect(readFileSync(decryptedPath)).toEqual(data);
    });

    it('should decrypt sync file at exactly 2x sync chunk size', () => {
      const data = Buffer.alloc(SYNC_CHUNK * 2, 0x5a);
      writeFileSync(inputPath, data);
      crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      crypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
      expect(readFileSync(decryptedPath)).toEqual(data);
    });

    it('should decrypt async file at exactly 2x sync chunk size', async () => {
      const data = Buffer.alloc(SYNC_CHUNK * 2, 0x77);
      writeFileSync(inputPath, data);
      await crypto.encryptFile(inputPath, encryptedPath, testPassword);
      await crypto.decryptFile(encryptedPath, decryptedPath, testPassword);
      expect(readFileSync(decryptedPath)).toEqual(data);
    });

    it('should fail on a truncated v1 file (one byte short of full body)', async () => {
      const data = Buffer.alloc(4096, 0x42);
      writeFileSync(inputPath, data);
      await crypto.encryptFile(inputPath, encryptedPath, testPassword);
      // Truncate the file by 1 byte (corrupting auth tag bookkeeping).
      const buf = readFileSync(encryptedPath);
      writeFileSync(
        encryptedPath,
        buf.subarray(0, buf.length - 1)
      );
      await expect(
        crypto.decryptFile(encryptedPath, decryptedPath, testPassword)
      ).rejects.toThrow(CryptoError);
      // Output must not be created on auth failure.
      expect(existsSync(decryptedPath)).toBe(false);
    });

    it('should fail synchronously on a truncated v1 file', () => {
      const data = Buffer.alloc(4096, 0x42);
      writeFileSync(inputPath, data);
      crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      const buf = readFileSync(encryptedPath);
      writeFileSync(
        encryptedPath,
        buf.subarray(0, buf.length - 1)
      );
      expect(() =>
        crypto.decryptFileSync(encryptedPath, decryptedPath, testPassword)
      ).toThrow(CryptoError);
      expect(existsSync(decryptedPath)).toBe(false);
    });
  });

  // ==========================================================================
  // Task 12 — NFC password normalisation
  //
  // `'café'` typed as a precomposed `é` (U+00E9) — the NFC form most input
  // methods produce — and the same character typed as `e + U+0301` (NFD) are
  // visually identical but encode to different UTF-8 byte sequences. Without
  // NFC normalisation in `deriveKey`/`deriveKeySync` they would derive
  // different keys and the user would silently fail to decrypt their own
  // ciphertexts.
  // ==========================================================================

  describe('NFC password normalisation (Task 12)', () => {
    // Precomposed (NFC): "café" using U+00E9 directly.
    const passwordNFC = 'café';
    // Decomposed (NFD): "cafe" + U+0301 (combining acute accent).
    const passwordNFD = 'café';

    it('should produce same Argon2id key for NFC and NFD forms', async () => {
      const cm = new CryptoManager();
      const salt = cm.generateSecureRandom(32);

      // Sanity check: the two strings are byte-different but visually equal.
      expect(passwordNFC).not.toBe(passwordNFD);
      expect(Buffer.byteLength(passwordNFC, 'utf8')).not.toBe(
        Buffer.byteLength(passwordNFD, 'utf8')
      );
      expect(passwordNFC.normalize('NFC')).toBe(passwordNFD.normalize('NFC'));

      const keyNFC = await cm.deriveKey(passwordNFC, salt);
      const keyNFD = await cm.deriveKey(passwordNFD, salt);

      expect(keyNFC.equals(keyNFD)).toBe(true);
    });

    it('should produce same PBKDF2 key for NFC and NFD forms', () => {
      const cm = new CryptoManager();
      const salt = cm.generateSecureRandom(32);

      const keyNFC = cm.deriveKeySync(passwordNFC, salt);
      const keyNFD = cm.deriveKeySync(passwordNFD, salt);

      expect(keyNFC.equals(keyNFD)).toBe(true);
    });

    it('should round-trip async text encrypted with NFC and decrypted with NFD', async () => {
      // Use a strong NFC password so encryption-side validation passes.
      const strongNFC = 'StrongP@ss1éaaaaa';
      const strongNFD = 'StrongP@ss1caféaaaaa'.replace(
        'café',
        'éaaaaa'
      );
      // Construct strongNFD as the NFD equivalent of strongNFC by re-using
      // the canonical decomposition rather than hand-rolling.
      const decomposed = strongNFC.normalize('NFD');
      const cm = new CryptoManager();
      const ciphertext = await cm.encryptText(testText, strongNFC);
      const recovered = await cm.decryptText(ciphertext, decomposed);
      expect(recovered).toBe(testText);
      // Sanity-suppress unused-var lint on the manual NFD spelling: it's
      // here only to document the decomposition for future readers.
      void strongNFD;
    });

    it('should round-trip sync text encrypted with NFD and decrypted with NFC', () => {
      const strongNFC = 'StrongP@ss1éaaaaa';
      const strongNFD = strongNFC.normalize('NFD');
      const cm = new CryptoManager();
      const ciphertext = cm.encryptTextSync(testText, strongNFD);
      const recovered = cm.decryptTextSync(ciphertext, strongNFC);
      expect(recovered).toBe(testText);
    });

    it('should still differentiate genuinely different passwords', async () => {
      // Sanity: NFC normalisation must not collapse different passwords.
      const cm = new CryptoManager();
      const salt = cm.generateSecureRandom(32);
      const keyA = await cm.deriveKey('cafépassword1!', salt);
      const keyB = await cm.deriveKey('cafèpassword1!', salt);
      expect(keyA.equals(keyB)).toBe(false);
    });
  });

  // ==========================================================================
  // Task 14 — defaultPassphrase strength validation in the constructor
  // ==========================================================================

  describe('constructor defaultPassphrase validation (Task 14)', () => {
    it('should accept a strong defaultPassphrase', () => {
      expect(
        () => new CryptoManager({ defaultPassphrase: 'StrongP@ss1' })
      ).not.toThrow();
    });

    it('should accept a long passphrase as defaultPassphrase', () => {
      expect(
        () =>
          new CryptoManager({
            defaultPassphrase: 'correct horse battery staple longer',
          })
      ).not.toThrow();
    });

    it('should throw WEAK_PASSWORD for a weak defaultPassphrase', () => {
      try {
        // 'abc' is too short and lacks all categories.
        new CryptoManager({ defaultPassphrase: 'abc' });
        throw new Error('expected constructor to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('WEAK_PASSWORD');
        expect((err as CryptoError).type).toBe(
          CryptoErrorType.INVALID_PASSWORD
        );
      }
    });

    it('should throw WEAK_PASSWORD for an 8-char passphrase missing a category', () => {
      try {
        // 8 chars with all letters/digits but no non-alphanumeric.
        new CryptoManager({ defaultPassphrase: 'Abcdef12' });
        throw new Error('expected constructor to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('WEAK_PASSWORD');
      }
    });

    it('should bypass validation when skipPasswordValidation is true', () => {
      expect(
        () =>
          new CryptoManager({
            defaultPassphrase: 'abc',
            skipPasswordValidation: true,
          })
      ).not.toThrow();
    });

    it('should still NOT bypass NFC normalisation when skipPasswordValidation is true', async () => {
      // skipPasswordValidation only relaxes the strength check — it must
      // not affect Unicode normalisation in deriveKey/deriveKeySync.
      const weak = 'abc';
      const cm = new CryptoManager({
        defaultPassphrase: weak,
        skipPasswordValidation: true,
      });
      const salt = cm.generateSecureRandom(32);
      const keyNFC = await cm.deriveKey(weak.normalize('NFC'), salt);
      const keyNFD = await cm.deriveKey(weak.normalize('NFD'), salt);
      expect(keyNFC.equals(keyNFD)).toBe(true);
    });

    it('should preserve the empty-string skip behaviour', () => {
      // Empty string is not stored as a default passphrase and should
      // still skip validation (no passphrase to validate).
      const cm = new CryptoManager({ defaultPassphrase: '' });
      expect(cm.hasDefaultPassphrase()).toBe(false);
    });

    it('should preserve undefined defaultPassphrase behaviour', () => {
      const cm = new CryptoManager({});
      expect(cm.hasDefaultPassphrase()).toBe(false);
    });

    it('should leave hasDefaultPassphrase true after passing validation', () => {
      const cm = new CryptoManager({
        defaultPassphrase: 'StrongP@ss1',
      });
      expect(cm.hasDefaultPassphrase()).toBe(true);
    });

    it('should not throw when skipPasswordValidation is true and passphrase is strong', () => {
      // skipPasswordValidation: true on a strong password should be a no-op.
      const cm = new CryptoManager({
        defaultPassphrase: 'StrongP@ss1',
        skipPasswordValidation: true,
      });
      expect(cm.hasDefaultPassphrase()).toBe(true);
    });
  });

  describe('file progress callbacks (Task 10)', () => {
    // We use a 256 KiB input so the async streams emit at least 4 chunks
    // (Node default highWaterMark is 64 KiB) and the sync decrypt loop
    // iterates 4 times — both giving us multiple monotonic increments to
    // assert against, while still keeping the test fast (each round-trip
    // takes ~2-5 seconds end-to-end at the post-Task-18 default Argon2id
    // memory cost).
    const PAYLOAD_SIZE = 256 * 1024;
    const inputPath = path.join(tempDir, 'progress-input.bin');
    const encryptedPath = path.join(tempDir, 'progress-encrypted.bin');
    const decryptedPath = path.join(tempDir, 'progress-decrypted.bin');

    beforeEach(async () => {
      const payload = nodeCrypto.randomBytes(PAYLOAD_SIZE);
      await writeFile(inputPath, payload);
    });

    afterEach(async () => {
      for (const file of [inputPath, encryptedPath, decryptedPath]) {
        if (existsSync(file)) {
          await unlink(file);
        }
      }
    });

    /**
     * Validate the universal invariants every progress run must satisfy:
     *   - at least one event was emitted
     *   - every event's `total` matches the expected total
     *   - `processed` values are monotonically non-decreasing
     *   - `0 <= processed <= total` for every event
     *   - the FINAL event has `processed === total` (the spec's "100% on
     *     success" guarantee)
     */
    function assertProgressInvariants(
      events: ReadonlyArray<readonly [number, number]>,
      expectedTotal: number
    ): void {
      expect(events.length).toBeGreaterThan(0);
      let prevProcessed = -1;
      for (const [processed, total] of events) {
        expect(total).toBe(expectedTotal);
        expect(processed).toBeGreaterThanOrEqual(0);
        expect(processed).toBeLessThanOrEqual(total);
        expect(processed).toBeGreaterThanOrEqual(prevProcessed);
        prevProcessed = processed;
      }
      // We just asserted events.length > 0, so events[events.length - 1]
      // is guaranteed to be defined; cast through `unknown` to satisfy
      // `noUncheckedIndexedAccess` without using a non-null assertion (which
      // the project lint config flags as `forbidden`).
      const last = events[events.length - 1] as unknown as readonly [
        number,
        number,
      ];
      expect(last[0]).toBe(expectedTotal);
      expect(last[1]).toBe(expectedTotal);
    }

    describe('encryptFile (async)', () => {
      it('invokes progress at least once with monotonic processed and a final 100% event', async () => {
        const events: Array<[number, number]> = [];
        await crypto.encryptFile(
          inputPath,
          encryptedPath,
          testPassword,
          (processed, total) => {
            events.push([processed, total]);
          }
        );
        assertProgressInvariants(events, PAYLOAD_SIZE);
        // Sanity check: the file did successfully encrypt.
        expect(existsSync(encryptedPath)).toBe(true);
      });

      it('emits a 0/total bracket event before any chunk is processed', async () => {
        const events: Array<[number, number]> = [];
        await crypto.encryptFile(
          inputPath,
          encryptedPath,
          testPassword,
          (processed, total) => {
            events.push([processed, total]);
          }
        );
        // The first event should be (0, PAYLOAD_SIZE).
        expect(events[0]).toEqual([0, PAYLOAD_SIZE]);
      });

      it('reports total === input file size in bytes', async () => {
        let observedTotal = -1;
        await crypto.encryptFile(
          inputPath,
          encryptedPath,
          testPassword,
          (_processed, total) => {
            observedTotal = total;
          }
        );
        expect(observedTotal).toBe(PAYLOAD_SIZE);
      });

      it('aborts the operation when the callback throws (Option A — honest abort)', async () => {
        // The throw should propagate (NOT be swallowed) and the temp file
        // should NOT linger at outputPath. Because the throw originates in
        // the user-supplied callback we preserve the caller's identity
        // rather than wrapping in CryptoError(FILE_ENCRYPTION_FAILED).
        class ProgressBoom extends Error {
          public override readonly name = 'ProgressBoom';
        }
        let calls = 0;
        let caught: unknown;
        try {
          await crypto.encryptFile(
            inputPath,
            encryptedPath,
            testPassword,
            () => {
              calls += 1;
              if (calls === 1) {
                throw new ProgressBoom('nope');
              }
            }
          );
          throw new Error('expected encryptFile to reject');
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(ProgressBoom);
        expect(existsSync(encryptedPath)).toBe(false);
      });

      it('does not leave an orphan .tmp file when the initial 0/total callback throws', async () => {
        // Regression guard: an earlier version of encryptFile invoked the
        // initial `(0, totalBytes)` event AFTER opening the temp-file
        // write stream. A throw at that moment left the underlying file
        // descriptor open, which on Windows blocks fs.unlink and leaves
        // an orphan `${outputPath}.<rand>.tmp` behind. Lock the
        // ordering in place by asserting the directory contains no
        // sibling .tmp files after the abort.
        class ProgressBoom extends Error {
          public override readonly name = 'ProgressBoom';
        }
        let caught: unknown;
        try {
          await crypto.encryptFile(
            inputPath,
            encryptedPath,
            testPassword,
            () => {
              // Throw on the very first invocation, which is the bracket
              // (0, totalBytes) event.
              throw new ProgressBoom('throw on initial event');
            }
          );
          throw new Error('expected encryptFile to reject');
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(ProgressBoom);
        expect(existsSync(encryptedPath)).toBe(false);

        // Scan the output directory for any sibling `.tmp` files left
        // behind. The temp-file naming pattern is
        // `${outputPath}.<random-hex>.tmp`, so we look for entries that
        // share the canonical base name as a prefix.
        const outputDir = path.dirname(encryptedPath);
        const baseName = path.basename(encryptedPath);
        const lingerers = readdirSync(outputDir).filter(
          (entry) => entry.startsWith(`${baseName}.`) && entry.endsWith('.tmp')
        );
        expect(lingerers).toEqual([]);
      });
    });

    describe('decryptFile (async)', () => {
      beforeEach(async () => {
        await crypto.encryptFile(inputPath, encryptedPath, testPassword);
      });

      it('invokes progress at least once with monotonic processed and a final 100% event', async () => {
        const events: Array<[number, number]> = [];
        const totalBytes = statSync(encryptedPath).size;
        await crypto.decryptFile(
          encryptedPath,
          decryptedPath,
          testPassword,
          (processed, total) => {
            events.push([processed, total]);
          }
        );
        assertProgressInvariants(events, totalBytes);
      });

      it('reports total === ciphertext file size in bytes', async () => {
        const expectedTotal = statSync(encryptedPath).size;
        let observedTotal = -1;
        await crypto.decryptFile(
          encryptedPath,
          decryptedPath,
          testPassword,
          (_processed, total) => {
            observedTotal = total;
          }
        );
        expect(observedTotal).toBe(expectedTotal);
      });

      it('aborts the operation when the callback throws', async () => {
        class ProgressBoom extends Error {
          public override readonly name = 'ProgressBoom';
        }
        let calls = 0;
        let caught: unknown;
        try {
          await crypto.decryptFile(
            encryptedPath,
            decryptedPath,
            testPassword,
            () => {
              calls += 1;
              if (calls >= 2) {
                throw new ProgressBoom('nope');
              }
            }
          );
          throw new Error('expected decryptFile to reject');
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(ProgressBoom);
        expect(existsSync(decryptedPath)).toBe(false);
      });
    });

    describe('encryptFileSync', () => {
      it('invokes progress at least once with monotonic processed and a final 100% event', () => {
        const events: Array<[number, number]> = [];
        crypto.encryptFileSync(
          inputPath,
          encryptedPath,
          testPassword,
          (processed, total) => {
            events.push([processed, total]);
          }
        );
        assertProgressInvariants(events, PAYLOAD_SIZE);
        expect(existsSync(encryptedPath)).toBe(true);
      });

      it('emits exactly two bracket events (0/total and total/total)', () => {
        // The sync encrypt path reads input fully into memory — the spec
        // describes this as the "two-bracket events" flavour rather than
        // chunked progress. Lock the contract in.
        const events: Array<[number, number]> = [];
        crypto.encryptFileSync(
          inputPath,
          encryptedPath,
          testPassword,
          (processed, total) => {
            events.push([processed, total]);
          }
        );
        expect(events).toEqual([
          [0, PAYLOAD_SIZE],
          [PAYLOAD_SIZE, PAYLOAD_SIZE],
        ]);
      });

      it('aborts the operation when the callback throws', () => {
        class ProgressBoom extends Error {
          public override readonly name = 'ProgressBoom';
        }
        let caught: unknown;
        try {
          crypto.encryptFileSync(inputPath, encryptedPath, testPassword, () => {
            throw new ProgressBoom('nope');
          });
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(ProgressBoom);
        expect(existsSync(encryptedPath)).toBe(false);
      });
    });

    describe('decryptFileSync', () => {
      beforeEach(() => {
        crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      });

      it('invokes progress at least once with monotonic processed and a final 100% event', () => {
        const events: Array<[number, number]> = [];
        const totalBytes = statSync(encryptedPath).size;
        crypto.decryptFileSync(
          encryptedPath,
          decryptedPath,
          testPassword,
          (processed, total) => {
            events.push([processed, total]);
          }
        );
        assertProgressInvariants(events, totalBytes);
      });

      it('emits per-chunk events in addition to the bracket events', () => {
        // The sync decrypt path streams in 64 KiB chunks (Task 3), so a
        // 256 KiB body should produce roughly 4 per-chunk events plus the
        // two bracket events. We don't pin the exact number (it can vary
        // by ±1 depending on body alignment after the front matter / tag
        // are excluded) but we DO assert it's strictly more than the sync
        // encrypt path's 2 events.
        const events: Array<[number, number]> = [];
        crypto.decryptFileSync(
          encryptedPath,
          decryptedPath,
          testPassword,
          (processed, total) => {
            events.push([processed, total]);
          }
        );
        expect(events.length).toBeGreaterThan(2);
      });

      it('aborts the operation when the callback throws', () => {
        class ProgressBoom extends Error {
          public override readonly name = 'ProgressBoom';
        }
        let calls = 0;
        let caught: unknown;
        try {
          crypto.decryptFileSync(
            encryptedPath,
            decryptedPath,
            testPassword,
            () => {
              calls += 1;
              if (calls >= 2) {
                throw new ProgressBoom('nope');
              }
            }
          );
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(ProgressBoom);
        expect(existsSync(decryptedPath)).toBe(false);
      });
    });

    describe('round-trip with progress on both sides', () => {
      it('reaches 100% on both encrypt and decrypt for a real round-trip', async () => {
        const encEvents: Array<[number, number]> = [];
        const decEvents: Array<[number, number]> = [];

        await crypto.encryptFile(
          inputPath,
          encryptedPath,
          testPassword,
          (p, t) => encEvents.push([p, t])
        );
        await crypto.decryptFile(
          encryptedPath,
          decryptedPath,
          testPassword,
          (p, t) => decEvents.push([p, t])
        );

        // Encrypt total = input file size (plaintext).
        assertProgressInvariants(encEvents, PAYLOAD_SIZE);
        // Decrypt total = ciphertext file size (which is larger by the v1
        // header + salt + iv + auth tag overhead).
        const ciphertextSize = statSync(encryptedPath).size;
        assertProgressInvariants(decEvents, ciphertextSize);

        // Sanity: the round-tripped plaintext matches the original input.
        const originalBuf = await readFile(inputPath);
        const decryptedBuf = await readFile(decryptedPath);
        expect(decryptedBuf.equals(originalBuf)).toBe(true);
      });
    });

    describe('omitting the progress argument is backward compatible', () => {
      // The whole point of making `progress` optional is that every call
      // shape that worked before Task 10 must continue to work. We
      // exercise each method with the legacy 3-arg shape and a brand-new
      // CryptoManager so a regression that accidentally requires
      // `progress` would fail loudly.
      it('encryptFile works with no progress arg', async () => {
        await crypto.encryptFile(inputPath, encryptedPath, testPassword);
        expect(existsSync(encryptedPath)).toBe(true);
      });

      it('decryptFile works with no progress arg', async () => {
        await crypto.encryptFile(inputPath, encryptedPath, testPassword);
        await crypto.decryptFile(encryptedPath, decryptedPath, testPassword);
        expect(existsSync(decryptedPath)).toBe(true);
      });

      it('encryptFileSync works with no progress arg', () => {
        crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
        expect(existsSync(encryptedPath)).toBe(true);
      });

      it('decryptFileSync works with no progress arg', () => {
        crypto.encryptFileSync(inputPath, encryptedPath, testPassword);
        crypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
        expect(existsSync(decryptedPath)).toBe(true);
      });
    });
  });

  /**
   * Iteration 2 Task 1 — verify that v1 header bytes are bound to the
   * AES-GCM auth tag. Pre-fix, an attacker could flip bits in the
   * reserved-byte regions (offsets 16-21 for Argon2id, offsets 10-21
   * for PBKDF2) without invalidating the auth tag, contradicting the
   * documented integrity contract. Post-fix, ANY tampering with the
   * 22-byte header surfaces as a CryptoError on decrypt.
   *
   * These tests also exercise the v0 backward-compat path explicitly
   * (the v0 AAD must remain `this.aad` only — old ciphertexts must
   * keep decrypting after the fix).
   */
  describe('v1 header AAD binding (Task 1)', () => {
    // Use a low-cost Argon2id configuration for the per-byte loop tests
    // so the test suite doesn't burn minutes running the default 128 MiB
    // memoryCost on every byte. The AAD binding logic is independent of
    // the KDF cost — it just changes the AAD payload — so a low-cost
    // configuration exercises the same code path.
    const fastCrypto = new CryptoManager({
      memoryCost: 2 ** 12, // 4 MiB
      timeCost: 1,
      parallelism: 1,
      pbkdf2Iterations: 1000, // Fast PBKDF2 for sync loop tests.
    });

    /**
     * Encrypt text via the public API, decode the base64url, flip the
     * given byte to `value`, re-encode, and assert that decryption now
     * throws a CryptoError. The exact error code may be `DECRYPTION_FAILED`
     * (most common — the GCM tag mismatches because the AAD differs from
     * what was bound at encrypt time) or any other CryptoError code (e.g.
     * `UNSUPPORTED_VERSION` if we tampered with the version byte). The
     * invariant is "tamper -> CryptoError"; the specific code is incidental.
     */
    async function expectAsyncTamperFails(
      cm: CryptoManager,
      offset: number,
      value: number
    ): Promise<void> {
      const enc = await cm.encryptText(testText, testPassword);
      const buf = Buffer.from(enc, 'base64url');
      buf[offset] = value;
      const tampered = buf.toString('base64url');
      await expect(cm.decryptText(tampered, testPassword)).rejects.toThrow(
        CryptoError
      );
    }

    function expectSyncTamperFails(
      cm: CryptoManager,
      offset: number,
      value: number
    ): void {
      const enc = cm.encryptTextSync(testText, testPassword);
      const buf = Buffer.from(enc, 'base64url');
      buf[offset] = value;
      const tampered = buf.toString('base64url');
      expect(() => cm.decryptTextSync(tampered, testPassword)).toThrow(
        CryptoError
      );
    }

    describe('async (Argon2id) path', () => {
      it(
        'rejects tampering with reserved bytes 16..21 (the previously-mutable region)',
        async () => {
          // Argon2id reserved bytes live at offsets 16-21 inside the 22-byte
          // header. Pre-fix this region was silently mutable. Post-fix any
          // bit-flip here flips the GCM tag because the on-disk header
          // bytes are bound into AAD verbatim.
          for (let offset = 16; offset <= 21; offset++) {
            await expectAsyncTamperFails(fastCrypto, offset, 0xff);
          }
        },
        60_000
      );

      it('rejects tampering with magic / version / kdfId bytes', async () => {
        // These were already detected pre-fix (the parser bounds-checks
        // them), but verify they STILL fail post-fix so we don't
        // regress while wiring the AAD binding.
        await expectAsyncTamperFails(fastCrypto, 0, 0x00); // magic byte 0
        await expectAsyncTamperFails(fastCrypto, 4, 0xff); // version
        await expectAsyncTamperFails(fastCrypto, 5, 0x42); // kdfId
      }, 30_000);

      it(
        'rejects tampering with KDF param bytes 6..15',
        async () => {
          // These were already detected via "wrong key derived" pre-fix.
          // Verify they STILL fail post-fix.
          for (let offset = 6; offset <= 15; offset++) {
            await expectAsyncTamperFails(fastCrypto, offset, 0xff);
          }
        },
        90_000
      );

      it('still round-trips a clean ciphertext (no tampering)', async () => {
        const enc = await fastCrypto.encryptText(testText, testPassword);
        const result = await fastCrypto.decryptText(enc, testPassword);
        expect(result).toBe(testText);
      });
    });

    describe('sync (PBKDF2) path', () => {
      it('rejects tampering with reserved bytes 10..21 (the previously-mutable region)', () => {
        // PBKDF2 reserved bytes live at offsets 10-21 inside the 22-byte
        // header (the params block is just a 4-byte iteration count
        // followed by 12 reserved bytes).
        for (let offset = 10; offset <= 21; offset++) {
          expectSyncTamperFails(fastCrypto, offset, 0xff);
        }
      });

      it('still round-trips a clean ciphertext (no tampering)', () => {
        const enc = fastCrypto.encryptTextSync(testText, testPassword);
        const result = fastCrypto.decryptTextSync(enc, testPassword);
        expect(result).toBe(testText);
      });
    });

    describe('file paths', () => {
      const inputPath = path.join(tempDir, 'aad-bind-input.txt');
      const encryptedPath = path.join(tempDir, 'aad-bind-encrypted.bin');
      const decryptedPath = path.join(tempDir, 'aad-bind-decrypted.txt');

      beforeEach(() => {
        writeFileSync(inputPath, 'AAD-binding regression test payload.');
      });

      afterEach(() => {
        for (const p of [inputPath, encryptedPath, decryptedPath]) {
          if (existsSync(p)) unlinkSync(p);
        }
      });

      it('async file: rejects reserved-byte tampering at offset 16', async () => {
        await fastCrypto.encryptFile(inputPath, encryptedPath, testPassword);
        const buf = readFileSync(encryptedPath);
        buf[16] = 0xff;
        writeFileSync(encryptedPath, buf);
        await expect(
          fastCrypto.decryptFile(encryptedPath, decryptedPath, testPassword)
        ).rejects.toThrow(CryptoError);
      });

      it('sync file: rejects reserved-byte tampering at offset 10 (PBKDF2 reserved region)', () => {
        fastCrypto.encryptFileSync(inputPath, encryptedPath, testPassword);
        const buf = readFileSync(encryptedPath);
        buf[10] = 0xff;
        writeFileSync(encryptedPath, buf);
        expect(() =>
          fastCrypto.decryptFileSync(encryptedPath, decryptedPath, testPassword)
        ).toThrow(CryptoError);
      });

      it('async file: still round-trips a clean ciphertext', async () => {
        await fastCrypto.encryptFile(inputPath, encryptedPath, testPassword);
        await fastCrypto.decryptFile(
          encryptedPath,
          decryptedPath,
          testPassword
        );
        expect(readFileSync(decryptedPath, 'utf8')).toBe(
          'AAD-binding regression test payload.'
        );
      });
    });

    describe('v0 backward compatibility (must keep working)', () => {
      // v0 has no header, so AAD remains `this.aad` only. The legacy
      // helpers below call encryptData WITHOUT an aadOverride, so they
      // produce v0 ciphertexts under the default AAD. Decrypt must
      // succeed under the default decrypt path that uses `this.aad`
      // for v0 ciphertexts.
      async function buildLegacyV0Text(
        cm: CryptoManager,
        text: string,
        password: string
      ): Promise<string> {
        const salt = cm.generateSecureRandom(32);
        const iv = cm.generateSecureRandom(12);
        const key = await cm.deriveKey(password, salt);
        const { encrypted, tag } = cm.encryptData(
          Buffer.from(text, 'utf8'),
          key,
          iv
        );
        return Buffer.concat([salt, iv, tag, encrypted]).toString('base64url');
      }

      it('still decrypts a v0 ciphertext (AAD change must not affect v0 paths)', async () => {
        const v0 = await buildLegacyV0Text(fastCrypto, testText, testPassword);
        expect(hasMagic(Buffer.from(v0, 'base64url'))).toBe(false);
        const result = await fastCrypto.decryptText(v0, testPassword);
        expect(result).toBe(testText);
      });
    });

    describe('legacyHeaderAad option', () => {
      it('lets a 1.0.0-format v1 ciphertext (header NOT bound) decrypt under legacyHeaderAad: true', async () => {
        // Manually construct a v1 ciphertext using the pre-fix AAD
        // (just `this.aad`, NOT the header). Decrypt with the legacy
        // option set to true should succeed; without it, the AAD
        // mismatch causes DECRYPTION_FAILED.
        const cmBound = new CryptoManager({
          memoryCost: 2 ** 12,
          timeCost: 1,
          parallelism: 1,
        });
        const cmLegacy = new CryptoManager({
          memoryCost: 2 ** 12,
          timeCost: 1,
          parallelism: 1,
          legacyHeaderAad: true,
        });

        // Build a "1.0.0-style" ciphertext by hand. The unbound AAD path
        // is exactly what cmLegacy.encryptText produces, so use it as
        // the source of truth.
        const v100 = await cmLegacy.encryptText(testText, testPassword);

        // Sanity: it parses as v1 (has magic).
        expect(hasMagic(Buffer.from(v100, 'base64url'))).toBe(true);

        // legacyHeaderAad=true decrypts.
        expect(await cmLegacy.decryptText(v100, testPassword)).toBe(testText);

        // Default (legacyHeaderAad=false) FAILS because the AAD differs.
        await expect(cmBound.decryptText(v100, testPassword)).rejects.toThrow(
          CryptoError
        );
      });

      it('reserved-byte tampering still SUCCEEDS under legacyHeaderAad: true (the v1.0.0 bug is intentionally preserved for legacy decrypt)', async () => {
        // Note: this is a deliberate documentation point — under
        // legacyHeaderAad: true the library reverts to the v1.0.0
        // behaviour, and the v1.0.0 bug (silent reserved-byte tamper)
        // is intentionally preserved to allow legacy decryption.
        // Current ciphertexts SHOULD use the default (false).
        const cmLegacy = new CryptoManager({
          memoryCost: 2 ** 12,
          timeCost: 1,
          parallelism: 1,
          legacyHeaderAad: true,
        });
        const enc = await cmLegacy.encryptText(testText, testPassword);
        const buf = Buffer.from(enc, 'base64url');
        buf[16] = 0xff; // Argon2id reserved byte
        const tampered = buf.toString('base64url');
        // Under legacyHeaderAad: true, this SUCCEEDS (matches v1.0.0
        // behaviour). This test pins down the contract so that flipping
        // the option's default (or removing it) is loud.
        const result = await cmLegacy.decryptText(tampered, testPassword);
        expect(result).toBe(testText);
      });
    });
  });

  /**
   * Iteration 2 Task 2 + 16 — verify that maliciously-large KDF
   * parameters parsed from a ciphertext header are rejected fast,
   * BEFORE the KDF (`argon2.hash` / `crypto.pbkdf2Sync`) is invoked.
   * Pre-fix, a 100-byte ciphertext with memoryCost=2^22 or
   * iterations=100M would block for seconds-to-minutes; post-fix it
   * throws KDF_PARAMS_OUT_OF_BOUNDS in <100ms.
   */
  describe('KDF parameter bounds (Task 2 + 16)', () => {
    /**
     * Build a v1 Argon2id ciphertext by hand using packHeader (which
     * does NOT cap parameters — the cap is only applied at parse time)
     * so we can produce a ciphertext that requests pathologically large
     * parameters. The body bytes are random — we expect the bounds
     * check to fire BEFORE any KDF work, so the body never matters.
     */
    function craftMaliciousArgon2idText(params: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
    }): string {
      const header = packHeader(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        memoryCost: params.memoryCost,
        timeCost: params.timeCost,
        parallelism: params.parallelism,
      });
      // Random salt + IV + tag + 1 byte ciphertext (size doesn't matter
      // — bounds check fires first).
      const salt = nodeCrypto.randomBytes(32);
      const iv = nodeCrypto.randomBytes(12);
      const tag = nodeCrypto.randomBytes(16);
      const body = nodeCrypto.randomBytes(1);
      return Buffer.concat([header, salt, iv, tag, body]).toString(
        'base64url'
      );
    }

    function craftMaliciousPbkdf2Text(iterations: number): string {
      const header = packHeader(KDF_ID_PBKDF2_SHA256, {
        kind: 'pbkdf2-sha256',
        iterations,
      });
      const salt = nodeCrypto.randomBytes(32);
      const iv = nodeCrypto.randomBytes(12);
      const tag = nodeCrypto.randomBytes(16);
      const body = nodeCrypto.randomBytes(1);
      return Buffer.concat([header, salt, iv, tag, body]).toString(
        'base64url'
      );
    }

    describe('Argon2id', () => {
      it('rejects memoryCost > 2^22 with KDF_PARAMS_OUT_OF_BOUNDS', async () => {
        const malicious = craftMaliciousArgon2idText({
          memoryCost: 2 ** 22 + 1,
          timeCost: 3,
          parallelism: 1,
        });
        const start = Date.now();
        try {
          await crypto.decryptText(malicious, testPassword);
          throw new Error('Expected throw');
        } catch (err) {
          expect(err).toBeInstanceOf(CryptoError);
          expect((err as CryptoError).code).toBe('KDF_PARAMS_OUT_OF_BOUNDS');
          // Must fire BEFORE Argon2 is invoked (would otherwise allocate
          // gigabytes and block the test).
          expect(Date.now() - start).toBeLessThan(2000);
        }
      });

      it('rejects timeCost > 100 with KDF_PARAMS_OUT_OF_BOUNDS', async () => {
        const malicious = craftMaliciousArgon2idText({
          memoryCost: 65536,
          timeCost: 101,
          parallelism: 1,
        });
        await expect(
          crypto.decryptText(malicious, testPassword)
        ).rejects.toMatchObject({
          code: 'KDF_PARAMS_OUT_OF_BOUNDS',
        });
      });

      it('rejects parallelism > 64 with KDF_PARAMS_OUT_OF_BOUNDS', async () => {
        const malicious = craftMaliciousArgon2idText({
          memoryCost: 65536,
          timeCost: 3,
          parallelism: 65,
        });
        await expect(
          crypto.decryptText(malicious, testPassword)
        ).rejects.toMatchObject({
          code: 'KDF_PARAMS_OUT_OF_BOUNDS',
        });
      });

      it('rejects the validator-reproducer-equivalent (memoryCost above the 4 GiB cap, timeCost=100) fast', async () => {
        // The validator's reproducer used 1 GiB; our cap is 4 GiB. Use
        // the same shape (a value just above the cap so this test is
        // tight against the intended behaviour) and assert it fires
        // fast — pre-fix this would hang trying to allocate 4+ GiB.
        const malicious = craftMaliciousArgon2idText({
          memoryCost: 2 ** 22 + 1,
          timeCost: 100,
          parallelism: 1,
        });
        const start = Date.now();
        await expect(
          crypto.decryptText(malicious, testPassword)
        ).rejects.toMatchObject({
          code: 'KDF_PARAMS_OUT_OF_BOUNDS',
        });
        // Must fire fast — pre-fix this hung for 5+ seconds.
        expect(Date.now() - start).toBeLessThan(2000);
      });

      it('accepts memoryCost = 2^22 (the cap value) when ciphertext otherwise valid', () => {
        // We can't actually decrypt without the key, but parseHeader
        // should at least PARSE successfully at the boundary.
        const header = packHeader(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 2 ** 22,
          timeCost: 100,
          parallelism: 64,
        });
        const parsed = parseHeader(header);
        expect(parsed.params.kind).toBe('argon2id');
        if (parsed.params.kind === 'argon2id') {
          expect(parsed.params.memoryCost).toBe(2 ** 22);
          expect(parsed.params.timeCost).toBe(100);
          expect(parsed.params.parallelism).toBe(64);
        }
      });
    });

    describe('PBKDF2', () => {
      it('rejects iterations > 10M with KDF_PARAMS_OUT_OF_BOUNDS', () => {
        const malicious = craftMaliciousPbkdf2Text(10_000_001);
        const start = Date.now();
        try {
          crypto.decryptTextSync(malicious, testPassword);
          throw new Error('Expected throw');
        } catch (err) {
          expect(err).toBeInstanceOf(CryptoError);
          expect((err as CryptoError).code).toBe('KDF_PARAMS_OUT_OF_BOUNDS');
          expect(Date.now() - start).toBeLessThan(1000);
        }
      });

      it('rejects the full validator-reproducer (iterations=100M) fast (pre-fix this blocked indefinitely)', () => {
        const malicious = craftMaliciousPbkdf2Text(100_000_000);
        const start = Date.now();
        expect(() =>
          crypto.decryptTextSync(malicious, testPassword)
        ).toThrow(CryptoError);
        // Pre-fix this blocked for >12 seconds in the validator's repro;
        // post-fix it fires in <1s.
        expect(Date.now() - start).toBeLessThan(1000);
      });

      it('accepts iterations = 10M (the cap value)', () => {
        const header = packHeader(KDF_ID_PBKDF2_SHA256, {
          kind: 'pbkdf2-sha256',
          iterations: 10_000_000,
        });
        const parsed = parseHeader(header);
        expect(parsed.params.kind).toBe('pbkdf2-sha256');
        if (parsed.params.kind === 'pbkdf2-sha256') {
          expect(parsed.params.iterations).toBe(10_000_000);
        }
      });
    });

    describe('inspectHeader (Task 16) — caps applied at parse time', () => {
      it('inspectHeader on a malicious Argon2id header throws KDF_PARAMS_OUT_OF_BOUNDS', () => {
        const malicious = craftMaliciousArgon2idText({
          memoryCost: 2 ** 22 + 1,
          timeCost: 3,
          parallelism: 1,
        });
        expect(() => crypto.inspectHeader(malicious)).toThrow(CryptoError);
        try {
          crypto.inspectHeader(malicious);
        } catch (err) {
          expect((err as CryptoError).code).toBe('KDF_PARAMS_OUT_OF_BOUNDS');
        }
      });

      it('inspectHeader on a malicious PBKDF2 header throws KDF_PARAMS_OUT_OF_BOUNDS', () => {
        const malicious = craftMaliciousPbkdf2Text(20_000_000);
        expect(() => crypto.inspectHeader(malicious)).toThrow(CryptoError);
        try {
          crypto.inspectHeader(malicious);
        } catch (err) {
          expect((err as CryptoError).code).toBe('KDF_PARAMS_OUT_OF_BOUNDS');
        }
      });

      it('inspectHeader returns bounded values for legitimate ciphertexts (sanity)', async () => {
        const fast = new CryptoManager({
          memoryCost: 2 ** 12,
          timeCost: 1,
          parallelism: 1,
        });
        const legit = await fast.encryptText(testText, testPassword);
        const inspected = fast.inspectHeader(legit);
        expect(inspected).not.toBeNull();
        if (inspected !== null && inspected.params.kind === 'argon2id') {
          expect(inspected.params.memoryCost).toBeLessThanOrEqual(2 ** 22);
          expect(inspected.params.timeCost).toBeLessThanOrEqual(100);
          expect(inspected.params.parallelism).toBeLessThanOrEqual(64);
        }
      });
    });

    // ── Argon2id memoryCost >= 8 * parallelism floor (Phase 3) ───────────────
    // parseHeader now rejects headers where memoryCost < 8*parallelism before
    // returning. Without this check a crafted ciphertext reaches argon2.hash()
    // which throws — and the deriveKey catch wraps it as ENCRYPTION_FAILED /
    // KEY_DERIVATION_FAILED, an encryption-typed error on a decrypt operation.
    describe('Argon2id memoryCost >= 8 * parallelism floor (Phase 3)', () => {
      it('parseHeader rejects memoryCost < 8 * parallelism with DECRYPTION_FAILED / INVALID_HEADER_PARAM', () => {
        // Classic sub-floor case: memoryCost=8, parallelism=64 → 8 < 8×64=512
        const hdr = packHeader(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 8,
          timeCost: 3,
          parallelism: 64,
        });
        expect(() => parseHeader(hdr)).toThrow(CryptoError);
        try {
          parseHeader(hdr);
        } catch (err) {
          expect((err as CryptoError).type).toBe(CryptoErrorType.DECRYPTION_FAILED);
          expect((err as CryptoError).code).toBe('INVALID_HEADER_PARAM');
          expect((err as CryptoError).message).toContain('memoryCost (8)');
          expect((err as CryptoError).message).toContain('8 × 64');
        }
      });

      it('parseHeader rejects minimum sub-floor case: memoryCost=1, parallelism=1 (1 < 8×1=8)', () => {
        const hdr = packHeader(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 1,
          timeCost: 1,
          parallelism: 1,
        });
        expect(() => parseHeader(hdr)).toThrow(CryptoError);
        try {
          parseHeader(hdr);
        } catch (err) {
          expect((err as CryptoError).type).toBe(CryptoErrorType.DECRYPTION_FAILED);
          expect((err as CryptoError).code).toBe('INVALID_HEADER_PARAM');
        }
      });

      it('parseHeader accepts memoryCost exactly at the floor (8 * parallelism)', () => {
        // memoryCost = 8, parallelism = 1 → floor = 8*1 = 8 → exactly at floor
        const hdr = packHeader(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 8,
          timeCost: 1,
          parallelism: 1,
        });
        const parsed = parseHeader(hdr);
        expect(parsed.params.kind).toBe('argon2id');
        if (parsed.params.kind === 'argon2id') {
          expect(parsed.params.memoryCost).toBe(8);
          expect(parsed.params.parallelism).toBe(1);
        }
      });

      it('decryptText of crafted sub-floor ciphertext throws DECRYPTION_FAILED (not ENCRYPTION_FAILED) in auto mode', async () => {
        // Craft a v1 Argon2id ciphertext header with memoryCost=8, parallelism=64
        // (violates floor: 8 < 512). The decrypt should reject with DECRYPTION_FAILED,
        // NOT ENCRYPTION_FAILED / KEY_DERIVATION_FAILED.
        const subFloor = craftMaliciousArgon2idText({
          memoryCost: 8,
          timeCost: 3,
          parallelism: 64,
        });
        const cm = new CryptoManager(); // legacyMode: 'auto' (default)
        await expect(cm.decryptText(subFloor, testPassword)).rejects.toMatchObject({
          type: CryptoErrorType.DECRYPTION_FAILED,
        });
        // Explicitly confirm the wrong error type is gone
        await expect(cm.decryptText(subFloor, testPassword)).rejects.not.toMatchObject({
          type: CryptoErrorType.ENCRYPTION_FAILED,
        });
      });

      it('decryptText of crafted sub-floor ciphertext throws DECRYPTION_FAILED in strict mode', async () => {
        const subFloor = craftMaliciousArgon2idText({
          memoryCost: 8,
          timeCost: 3,
          parallelism: 64,
        });
        const cm = new CryptoManager({ legacyMode: 'strict' });
        await expect(cm.decryptText(subFloor, testPassword)).rejects.toMatchObject({
          type: CryptoErrorType.DECRYPTION_FAILED,
          code: 'INVALID_HEADER_PARAM',
        });
      });

      it('decryptText of crafted sub-floor ciphertext throws DECRYPTION_FAILED in reject mode', async () => {
        const subFloor = craftMaliciousArgon2idText({
          memoryCost: 8,
          timeCost: 3,
          parallelism: 64,
        });
        const cm = new CryptoManager({ legacyMode: 'reject' });
        await expect(cm.decryptText(subFloor, testPassword)).rejects.toMatchObject({
          type: CryptoErrorType.DECRYPTION_FAILED,
          code: 'INVALID_HEADER_PARAM',
        });
      });

      it('decryptTextSync with strict mode: sub-floor Argon2id header throws DECRYPTION_FAILED / INVALID_HEADER_PARAM immediately', () => {
        // In strict mode the parseHeader floor violation is re-thrown immediately
        // (no v0 PBKDF2 fallback) — a clean, fast, explicit rejection.
        const subFloor = craftMaliciousArgon2idText({
          memoryCost: 8,
          timeCost: 3,
          parallelism: 64,
        });
        const cm = new CryptoManager({ legacyMode: 'strict' });
        expect(() => cm.decryptTextSync(subFloor, testPassword)).toThrow(CryptoError);
        try {
          cm.decryptTextSync(subFloor, testPassword);
        } catch (err) {
          expect((err as CryptoError).type).toBe(CryptoErrorType.DECRYPTION_FAILED);
          expect((err as CryptoError).code).toBe('INVALID_HEADER_PARAM');
        }
      });

      it('inspectHeader on sub-floor Argon2id header throws DECRYPTION_FAILED / INVALID_HEADER_PARAM', () => {
        const subFloor = craftMaliciousArgon2idText({
          memoryCost: 8,
          timeCost: 3,
          parallelism: 64,
        });
        expect(() => crypto.inspectHeader(subFloor)).toThrow(CryptoError);
        try {
          crypto.inspectHeader(subFloor);
        } catch (err) {
          expect((err as CryptoError).type).toBe(CryptoErrorType.DECRYPTION_FAILED);
          expect((err as CryptoError).code).toBe('INVALID_HEADER_PARAM');
        }
      });
    });
  });

  // ── Phase 3: key scrub on error paths ─────────────────────────────────────
  // Verifies that secureClear is called on the 32-byte derived key even when
  // an error is thrown AFTER key derivation but BEFORE the success-path scrub.
  // For each of the 8 high-level methods: encryptText, decryptText,
  // encryptTextSync, decryptTextSync, encryptFile, decryptFile,
  // encryptFileSync, decryptFileSync.
  describe('key scrub on error paths (Phase 3 — Tasks 3.1/3.2)', () => {
    // Fast KDF params so tests run quickly.
    const validPwd = testPassword;
    const wrongPwd = 'WrongP@ssw0rd123!';

    afterEach(() => {
      jest.restoreAllMocks();
    });

    // Assert secureClear was called with a 32-byte Buffer (the AES-256 key).
    function assertKeyScrubbed(spy: ReturnType<typeof jest.spyOn>): void {
      const keyCallFound = spy.mock.calls.some(
        ([buf]) => Buffer.isBuffer(buf) && buf.length === 32
      );
      expect(keyCallFound).toBe(true);
    }

    it('encryptText: scrubs key when encryptData throws post-derivation', async () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        parallelism: 1,
      });
      const clearSpy = jest.spyOn(cm, 'secureClear');
      jest.spyOn(cm, 'encryptData').mockImplementationOnce(() => {
        throw new Error('forced post-derivation failure');
      });
      await expect(cm.encryptText(testText, validPwd)).rejects.toThrow();
      assertKeyScrubbed(clearSpy);
    });

    it('decryptText: scrubs key on wrong-password failure (GCM tag mismatch)', async () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        parallelism: 1,
      });
      const ciphertext = await cm.encryptText(testText, validPwd);
      const clearSpy = jest.spyOn(cm, 'secureClear');
      await expect(cm.decryptText(ciphertext, wrongPwd)).rejects.toThrow(
        CryptoError
      );
      assertKeyScrubbed(clearSpy);
    });

    it('encryptTextSync: scrubs key when encryptData throws post-derivation', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        pbkdf2Iterations: 1000,
        parallelism: 1,
      });
      const clearSpy = jest.spyOn(cm, 'secureClear');
      jest.spyOn(cm, 'encryptData').mockImplementationOnce(() => {
        throw new Error('forced post-derivation failure');
      });
      expect(() => cm.encryptTextSync(testText, validPwd)).toThrow();
      assertKeyScrubbed(clearSpy);
    });

    it('decryptTextSync: scrubs key on wrong-password failure (GCM tag mismatch)', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        pbkdf2Iterations: 1000,
        parallelism: 1,
      });
      const ciphertext = cm.encryptTextSync(testText, validPwd);
      const clearSpy = jest.spyOn(cm, 'secureClear');
      expect(() => cm.decryptTextSync(ciphertext, wrongPwd)).toThrow(
        CryptoError
      );
      assertKeyScrubbed(clearSpy);
    });

    it('encryptFile: scrubs key when progress callback throws post-derivation', async () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        parallelism: 1,
      });
      const inPath = path.join(tempDir, 'ks-ef-in.txt');
      const outPath = path.join(tempDir, 'ks-ef-out.enc');
      try {
        writeFileSync(inPath, testText);
        const clearSpy = jest.spyOn(cm, 'secureClear');
        // In encryptFile the first progress call (0, totalBytes) fires AFTER
        // key derivation. Throwing on any invocation therefore tests the
        // catch-path key scrub.
        await expect(
          cm.encryptFile(inPath, outPath, validPwd, () => {
            throw new Error('progress abort');
          })
        ).rejects.toThrow();
        assertKeyScrubbed(clearSpy);
      } finally {
        for (const f of [inPath, outPath]) {
          if (existsSync(f)) unlinkSync(f);
        }
      }
    });

    it('decryptFile: scrubs key on wrong-password failure (GCM tag mismatch)', async () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        parallelism: 1,
      });
      const inPath = path.join(tempDir, 'ks-df-in.txt');
      const encPath = path.join(tempDir, 'ks-df-enc.bin');
      const outPath = path.join(tempDir, 'ks-df-out.txt');
      try {
        writeFileSync(inPath, testText);
        await cm.encryptFile(inPath, encPath, validPwd);
        const clearSpy = jest.spyOn(cm, 'secureClear');
        await expect(
          cm.decryptFile(encPath, outPath, wrongPwd)
        ).rejects.toThrow(CryptoError);
        assertKeyScrubbed(clearSpy);
      } finally {
        for (const f of [inPath, encPath, outPath]) {
          if (existsSync(f)) unlinkSync(f);
        }
      }
    });

    it('encryptFileSync: scrubs key when progress callback throws after key derivation', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        pbkdf2Iterations: 1000,
        parallelism: 1,
      });
      const inPath = path.join(tempDir, 'ks-efs-in.txt');
      const outPath = path.join(tempDir, 'ks-efs-out.enc');
      try {
        writeFileSync(inPath, testText);
        const clearSpy = jest.spyOn(cm, 'secureClear');
        // In encryptFileSync the first progress call (0, totalBytes) fires
        // BEFORE key derivation; the second (totalBytes, totalBytes) fires
        // AFTER encryption and rename. Throw on the 2nd call to exercise
        // the catch-path key scrub.
        let callCount = 0;
        expect(() =>
          cm.encryptFileSync(inPath, outPath, validPwd, () => {
            callCount++;
            if (callCount >= 2) {
              throw new Error('progress abort on final event');
            }
          })
        ).toThrow();
        assertKeyScrubbed(clearSpy);
      } finally {
        for (const f of [inPath, outPath]) {
          if (existsSync(f)) unlinkSync(f);
        }
      }
    });

    it('decryptFileSync: scrubs key on wrong-password failure (GCM tag mismatch)', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 12,
        timeCost: 1,
        pbkdf2Iterations: 1000,
        parallelism: 1,
      });
      const inPath = path.join(tempDir, 'ks-dfs-in.txt');
      const encPath = path.join(tempDir, 'ks-dfs-enc.bin');
      const outPath = path.join(tempDir, 'ks-dfs-out.txt');
      try {
        writeFileSync(inPath, testText);
        cm.encryptFileSync(inPath, encPath, validPwd);
        const clearSpy = jest.spyOn(cm, 'secureClear');
        expect(() =>
          cm.decryptFileSync(encPath, outPath, wrongPwd)
        ).toThrow(CryptoError);
        assertKeyScrubbed(clearSpy);
      } finally {
        for (const f of [inPath, encPath, outPath]) {
          if (existsSync(f)) unlinkSync(f);
        }
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Phase 6 — encryptFileSync streaming round-trip tests (Task 6.2).
  //
  // Verifies that the chunked readSync→cipher.update→writeFileSync(fd,...)
  // loop produces byte-identical output to the previous single-read
  // implementation, and that cross-path round-trips (encryptFileSync →
  // decryptFile and vice versa) work correctly. Edge cases: empty file and
  // a file smaller than one 64 KiB chunk.
  // ---------------------------------------------------------------------------
  describe('encryptFileSync - chunked streaming round-trips (Phase 6)', () => {
    // Low-cost config keeps the suite fast without sacrificing correctness.
    // pbkdf2Iterations: 10_000 is emphatically NOT for production use.
    let fastCrypto: CryptoManager;

    const CHUNK = 64 * 1024; // 64 KiB — must match SYNC_ENCRYPT_CHUNK_SIZE

    const inputPath = path.join(tempDir, 'phase6-enc-input.bin');
    const encryptedPath = path.join(tempDir, 'phase6-enc-output.bin');
    const decryptedPath = path.join(tempDir, 'phase6-enc-decrypted.bin');

    beforeAll(() => {
      fastCrypto = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 1,
        parallelism: 1,
        pbkdf2Iterations: 10_000,
      });
    });

    afterEach(async () => {
      for (const f of [inputPath, encryptedPath, decryptedPath]) {
        if (existsSync(f)) await unlink(f);
      }
    });

    it('round-trips a multi-chunk input (> 2 × 64 KiB) via encryptFileSync → decryptFileSync', () => {
      // 3 × 64 KiB + 1 KiB = 197 632 bytes → loop runs 4 iterations.
      const plaintext = Buffer.alloc(3 * CHUNK + 1024, 0x5a);
      writeFileSync(inputPath, plaintext);
      fastCrypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      fastCrypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
      const result = readFileSync(decryptedPath);
      expect(result.equals(plaintext)).toBe(true);
    });

    it('cross-KDF: decryptFile (async/Argon2id) correctly rejects encryptFileSync (PBKDF2) ciphertext', async () => {
      // encryptFileSync produces v1 PBKDF2 (KDF id 1); decryptFile expects
      // v1 Argon2id (KDF id 0). Verifies the v1 header produced by the new
      // chunked implementation is well-formed enough to trigger the KDF
      // mismatch guard (not just a generic parse error).
      const plaintext = Buffer.alloc(2 * CHUNK + 512, 0x7f);
      writeFileSync(inputPath, plaintext);
      fastCrypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      // auto mode: KDF_MISMATCH is caught → v0 fallback → wrong key → DECRYPTION_FAILED
      await expect(
        fastCrypto.decryptFile(encryptedPath, decryptedPath, testPassword)
      ).rejects.toBeInstanceOf(CryptoError);
      // strict mode: re-throws KDF_MISMATCH directly — pins the assertKdfMatches
      // call site in decryptFile (src/crypto-manager.ts). A generic parse or size
      // error would also satisfy rejects.toThrow(CryptoError); asserting the
      // specific code confirms the v1 header was structurally valid and the KDF
      // id mismatch guard fired, not an earlier sanity check (audit #10).
      const strictCrypto = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 1,
        parallelism: 1,
        pbkdf2Iterations: 10_000,
        legacyMode: 'strict',
      });
      let caught: CryptoError | undefined;
      try {
        await strictCrypto.decryptFile(
          encryptedPath,
          decryptedPath,
          testPassword
        );
      } catch (e) {
        caught = e as CryptoError;
      }
      expect(caught).toBeInstanceOf(CryptoError);
      expect(caught?.code).toBe('KDF_MISMATCH');
    });

    it('cross-KDF: decryptFileSync (sync/PBKDF2) correctly rejects encryptFile (async/Argon2id) ciphertext', async () => {
      // Mirror of the test above. encryptFile produces v1 Argon2id (KDF id 0);
      // decryptFileSync expects v1 PBKDF2 (KDF id 1). Pins the assertKdfMatches
      // call site in decryptFileSync (src/crypto-manager.ts) — both call sites
      // are now independently covered (audit #10).
      const plaintext = Buffer.alloc(CHUNK + 512, 0x3c);
      writeFileSync(inputPath, plaintext);
      await fastCrypto.encryptFile(inputPath, encryptedPath, testPassword);
      // auto mode: KDF_MISMATCH is caught → v0 fallback → wrong key → DECRYPTION_FAILED
      expect(() =>
        fastCrypto.decryptFileSync(encryptedPath, decryptedPath, testPassword)
      ).toThrow(CryptoError);
      // strict mode: re-throws KDF_MISMATCH directly, pinning the assertKdfMatches
      // call site in decryptFileSync.
      const strictCrypto = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 1,
        parallelism: 1,
        pbkdf2Iterations: 10_000,
        legacyMode: 'strict',
      });
      let caughtSync: CryptoError | undefined;
      try {
        strictCrypto.decryptFileSync(
          encryptedPath,
          decryptedPath,
          testPassword
        );
      } catch (e) {
        caughtSync = e as CryptoError;
      }
      expect(caughtSync).toBeInstanceOf(CryptoError);
      expect(caughtSync?.code).toBe('KDF_MISMATCH');
    });

    it('encrypts and decrypts an empty file (zero plaintext bytes)', () => {
      writeFileSync(inputPath, Buffer.alloc(0));
      fastCrypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      fastCrypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
      const result = readFileSync(decryptedPath);
      expect(result.length).toBe(0);
    });

    it('encrypts and decrypts a file smaller than one chunk (sub-chunk size)', () => {
      // 100 bytes — well under the 64 KiB chunk boundary.
      const plaintext = Buffer.alloc(100, 0x42);
      writeFileSync(inputPath, plaintext);
      fastCrypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      fastCrypto.decryptFileSync(encryptedPath, decryptedPath, testPassword);
      const result = readFileSync(decryptedPath);
      expect(result.equals(plaintext)).toBe(true);
    });

    it('ciphertext byte layout: encryptFileSync still produces v1 PBKDF2 format with correct field sizes', () => {
      // Verify the on-disk layout is unchanged: [header(22)][salt(32)][iv(12)][ciphertext][tag(16)]
      const plaintext = Buffer.alloc(100, 0x01);
      writeFileSync(inputPath, plaintext);
      fastCrypto.encryptFileSync(inputPath, encryptedPath, testPassword);
      const ciphertext = readFileSync(encryptedPath);

      // v1 magic + format version
      expect(ciphertext.subarray(0, 4).equals(MAGIC_BYTES)).toBe(true);
      expect(ciphertext.readUInt8(4)).toBe(FORMAT_VERSION); // 0x01
      expect(ciphertext.readUInt8(5)).toBe(KDF_ID_PBKDF2_SHA256); // 0x01

      // Total size: header(22) + salt(32) + iv(12) + ciphertext(100) + tag(16) = 182
      expect(ciphertext.length).toBe(HEADER_LENGTH + 32 + 12 + plaintext.length + 16);
    });
  });

  // ---------------------------------------------------------------------------
  // Phase 2 — memory-hygiene: text-method plaintext/decrypted buffer scrub
  // ---------------------------------------------------------------------------
  //
  // The four text methods hoist their plaintext/decrypted buffer to the
  // method's outer scope (`let ... = null`) so the catch block can zero-fill
  // it if a failure occurs after allocation. This mirrors the fix already in
  // place for encryptFileSync's plaintext chunk (v1.4.1).
  //
  // For the encrypt paths: a failure inside `encryptData` is the realistic
  // scenario — the plaintext buffer is fully allocated before the call. We
  // spy on `encryptData` to inject that failure and verify `secureClear` was
  // invoked with the plaintext buffer in the catch.
  //
  // For the decrypt paths: the post-`decryptData` throw window is narrow
  // (Buffer.toString cannot throw for a valid Buffer), so we cover symmetry
  // only — asserting the round-trip and wrong-password paths are unaffected
  // by the hoist.

  describe('Phase 2 — text-method plaintext-buffer scrub on error path', () => {
    // Use a text whose UTF-8 byte length (17) is distinct from the fixed
    // crypto field sizes (key=32, salt=32, iv=12, tag=16) so we can
    // unambiguously locate it in the secureClear call list.
    const SCRUB_TEXT = 'phase2-scrub-test';

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('encryptText: secureClear is called with the plaintext textBuffer when encryptData throws', async () => {
      const cm = new CryptoManager({ memoryCost: 2 ** 12, timeCost: 1, parallelism: 1 });
      const clearSpy = jest.spyOn(cm, 'secureClear');

      // Inject a failure AFTER textBuffer is allocated but inside encryptData.
      jest.spyOn(cm, 'encryptData').mockImplementation(() => {
        throw new Error('injected encryptData failure after textBuffer allocation');
      });

      await expect(cm.encryptText(SCRUB_TEXT, testPassword)).rejects.toThrow();

      // Without the fix, textBuffer was const inside the try and invisible
      // to the catch — secureClear was never called with it on error.
      // With the fix, the catch block calls secureClear(textBuffer).
      const expectedLen = Buffer.from(SCRUB_TEXT, 'utf8').length;
      const scrubCall = clearSpy.mock.calls.find(
        ([buf]) => buf instanceof Buffer && buf.length === expectedLen
      );
      expect(scrubCall).toBeDefined();
    });

    it('encryptTextSync: secureClear is called with the plaintext textBuffer when encryptData throws', () => {
      const cm = new CryptoManager({ pbkdf2Iterations: 1000 });
      const clearSpy = jest.spyOn(cm, 'secureClear');

      jest.spyOn(cm, 'encryptData').mockImplementation(() => {
        throw new Error('injected encryptData failure after textBuffer allocation');
      });

      expect(() => cm.encryptTextSync(SCRUB_TEXT, testPassword)).toThrow();

      const expectedLen = Buffer.from(SCRUB_TEXT, 'utf8').length;
      const scrubCall = clearSpy.mock.calls.find(
        ([buf]) => buf instanceof Buffer && buf.length === expectedLen
      );
      expect(scrubCall).toBeDefined();
    });

    it('decryptText: hoist does not regress round-trip or wrong-password behavior', async () => {
      const cm = new CryptoManager({ memoryCost: 2 ** 12, timeCost: 1, parallelism: 1 });
      const enc = await cm.encryptText(SCRUB_TEXT, testPassword);

      // Normal round-trip must still work.
      await expect(cm.decryptText(enc, testPassword)).resolves.toBe(SCRUB_TEXT);

      // Wrong password re-throws decryptData's CryptoError as-is (code: DECRYPTION_FAILED),
      // not the method-level wrapper — only truly unexpected non-CryptoErrors become
      // TEXT_DECRYPTION_FAILED.
      await expect(
        cm.decryptText(enc, 'WrongPass!1234567890Abc')
      ).rejects.toMatchObject({ code: 'DECRYPTION_FAILED' });
    });

    it('decryptTextSync: hoist does not regress round-trip or wrong-password behavior', () => {
      const cm = new CryptoManager({ pbkdf2Iterations: 1000 });
      const enc = cm.encryptTextSync(SCRUB_TEXT, testPassword);

      // Normal round-trip must still work.
      expect(cm.decryptTextSync(enc, testPassword)).toBe(SCRUB_TEXT);

      // Wrong password re-throws decryptData's CryptoError as-is (code: DECRYPTION_FAILED).
      expect(() =>
        cm.decryptTextSync(enc, 'WrongPass!1234567890Abc')
      ).toThrow(
        expect.objectContaining({ code: 'DECRYPTION_FAILED' })
      );
    });
  });
});
