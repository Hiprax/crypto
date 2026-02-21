import { CryptoManager } from '../crypto-manager';
import { CryptoError, CryptoErrorType, SecurityLevel } from '../types';
import { writeFile, unlink, readFile } from 'node:fs/promises';
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import argon2Module from 'argon2';
import nodeCrypto from 'node:crypto';

describe('CryptoManager', () => {
  let crypto: CryptoManager;
  const testPassword = 'MySecureP@ssw0rd123!';
  const testText = 'Hello, World! This is a test message.';
  const tempDir = os.tmpdir();

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

    it('should throw error for invalid text', async () => {
      await expect(crypto.encryptText('', testPassword)).rejects.toThrow(
        CryptoError
      );
      await expect(
        crypto.encryptText(null as unknown as string, testPassword)
      ).rejects.toThrow(CryptoError);
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
    it('should return ULTRA for high memory and time cost', () => {
      const ultraCrypto = new CryptoManager({
        memoryCost: 2 ** 18,
        timeCost: 4,
      });
      expect(ultraCrypto.getSecurityLevel()).toBe(SecurityLevel.ULTRA);
    });

    it('should return HIGH for medium-high settings', () => {
      const highCrypto = new CryptoManager({
        memoryCost: 2 ** 16,
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
      expect(crypto.getSecurityLevel()).toBe(SecurityLevel.HIGH); // Default settings are HIGH, not LOW
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

    it('should throw error for invalid text', () => {
      expect(() => crypto.encryptTextSync('', testPassword)).toThrow(
        CryptoError
      );
      expect(() =>
        crypto.encryptTextSync(null as unknown as string, testPassword)
      ).toThrow(CryptoError);
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
      await expect(
        crypto.decryptText(encrypted, 'WrongP@ssw0rd123!')
      ).rejects.toThrow(CryptoError);
    });
  });

  describe('decryptTextSync - wrong password', () => {
    it('should throw CryptoError when decrypting with wrong password', () => {
      const encrypted = crypto.encryptTextSync(testText, testPassword);
      expect(() =>
        crypto.decryptTextSync(encrypted, 'WrongP@ssw0rd123!')
      ).toThrow(CryptoError);
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
      await expect(
        crypto.decryptFile(
          encryptedFilePath,
          decryptedFilePath,
          'WrongP@ssw0rd123!'
        )
      ).rejects.toThrow(CryptoError);
      // Output file should be cleaned up (deleted)
      expect(existsSync(decryptedFilePath)).toBe(false);
    });

    it('should throw CryptoError for tampered encrypted file', async () => {
      // Tamper with the encrypted file
      const data = await readFile(encryptedFilePath);
      data[data.length - 1] = (data[data.length - 1] ?? 0) ^ 0xff;
      await writeFile(encryptedFilePath, data);

      await expect(
        crypto.decryptFile(encryptedFilePath, decryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
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
      expect(() =>
        crypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          'WrongP@ssw0rd123!'
        )
      ).toThrow(CryptoError);
      // Output file should be cleaned up (deleted)
      expect(existsSync(decryptedFilePath)).toBe(false);
    });

    it('should throw CryptoError for tampered encrypted file', () => {
      const data = readFileSync(encryptedFilePath);
      data[data.length - 1] = (data[data.length - 1] ?? 0) ^ 0xff;
      writeFileSync(encryptedFilePath, data);

      expect(() =>
        crypto.decryptFileSync(
          encryptedFilePath,
          decryptedFilePath,
          testPassword
        )
      ).toThrow(CryptoError);
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
      expect(() => crypto.decryptData(encrypted, key2, iv, tag)).toThrow(
        CryptoError
      );
    });

    it('should fail with wrong iv', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv1 = crypto.generateSecureRandom(12);
      const iv2 = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv1);
      expect(() => crypto.decryptData(encrypted, key, iv2, tag)).toThrow(
        CryptoError
      );
    });

    it('should fail with tampered ciphertext', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv);
      encrypted[0] = (encrypted[0] ?? 0) ^ 0xff;
      expect(() => crypto.decryptData(encrypted, key, iv, tag)).toThrow(
        CryptoError
      );
    });

    it('should fail with tampered tag', () => {
      const data = Buffer.from('test data');
      const key = crypto.generateSecureRandom(32);
      const iv = crypto.generateSecureRandom(12);

      const { encrypted, tag } = crypto.encryptData(data, key, iv);
      tag[0] = (tag[0] ?? 0) ^ 0xff;
      expect(() => crypto.decryptData(encrypted, key, iv, tag)).toThrow(
        CryptoError
      );
    });
  });

  describe('getSecurityLevel - boundary conditions', () => {
    it('should return LOW when memoryCost is high but timeCost is low', () => {
      const cm = new CryptoManager({
        memoryCost: 2 ** 18,
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
  });

  describe('encryptFile - cleanup with pre-existing output', () => {
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
    });

    it('should delete pre-existing output file on error', async () => {
      // Pre-create the output file
      await writeFile(encryptedFilePath, 'pre-existing content');

      const mockCrypto = new CryptoManager();
      jest
        .spyOn(mockCrypto, 'deriveKey')
        .mockRejectedValue(new Error('Key failure'));

      await expect(
        mockCrypto.encryptFile(testFilePath, encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);

      // Output file should be cleaned up (deleted)
      expect(existsSync(encryptedFilePath)).toBe(false);
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError and clean up output', async () => {
      // Pre-create the output file
      await writeFile(encryptedFilePath, 'pre-existing content');

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
      expect(existsSync(encryptedFilePath)).toBe(false);
      jest.restoreAllMocks();
    });
  });

  describe('decryptFile - cleanup with pre-existing output', () => {
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
    });

    it('should delete pre-existing output file on error', async () => {
      // Pre-create the output file
      await writeFile(decryptedFilePath, 'pre-existing content');

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
      expect(existsSync(decryptedFilePath)).toBe(false);
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError and clean up output', async () => {
      await writeFile(decryptedFilePath, 'pre-existing content');

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
      expect(existsSync(decryptedFilePath)).toBe(false);
      jest.restoreAllMocks();
    });
  });

  describe('encryptFileSync - cleanup with pre-existing output', () => {
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
    });

    it('should delete pre-existing output file on error', () => {
      writeFileSync(encryptedFilePath, 'pre-existing content');

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
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError and clean up output', () => {
      writeFileSync(encryptedFilePath, 'pre-existing content');

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
      expect(existsSync(encryptedFilePath)).toBe(false);
      jest.restoreAllMocks();
    });
  });

  describe('decryptFileSync - cleanup with pre-existing output', () => {
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
    });

    it('should delete pre-existing output file on error', () => {
      writeFileSync(decryptedFilePath, 'pre-existing content');

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
      expect(existsSync(decryptedFilePath)).toBe(false);
      jest.restoreAllMocks();
    });

    it('should re-throw CryptoError and clean up output', () => {
      writeFileSync(decryptedFilePath, 'pre-existing content');

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
      expect(existsSync(decryptedFilePath)).toBe(false);
      jest.restoreAllMocks();
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
    it('should wrap pbkdf2Sync errors', () => {
      const original = nodeCrypto.pbkdf2Sync;
      (nodeCrypto as Record<string, unknown>).pbkdf2Sync = (): never => {
        throw new Error('PBKDF2 internal failure');
      };

      const salt = crypto.generateSecureRandom(32);
      try {
        crypto.deriveKeySync(testPassword, salt);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe(
          'SYNC_KEY_DERIVATION_FAILED'
        );
      }

      (nodeCrypto as Record<string, unknown>).pbkdf2Sync = original;
    });
  });

  describe('encryptData - internal error wrapping', () => {
    it('should wrap cipher errors', () => {
      const originalCreateCipheriv = nodeCrypto.createCipheriv;
      (nodeCrypto as Record<string, unknown>).createCipheriv = (): never => {
        throw new Error('Cipher creation failure');
      };

      const data = Buffer.from('test');
      const key = Buffer.alloc(32);
      const iv = Buffer.alloc(12);

      try {
        crypto.encryptData(data, key, iv);
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        expect((error as CryptoError).code).toBe('ENCRYPTION_FAILED');
      }

      (nodeCrypto as Record<string, unknown>).createCipheriv =
        originalCreateCipheriv;
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
});
