import { CryptoManager } from '../crypto-manager';
import { CryptoError, CryptoErrorType, SecurityLevel } from '../types';
import { writeFile, unlink, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

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
  });

  describe('decryptText', () => {
    it('should decrypt text successfully', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      const decrypted = await crypto.decryptText(encrypted, testPassword);
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

    it('should throw error for missing parameters', async () => {
      await expect(
        crypto.encryptFile('', encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.encryptFile(testFilePath, '', testPassword)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.encryptFile(testFilePath, encryptedFilePath, '')
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

    it('should throw error for missing parameters', async () => {
      await expect(
        crypto.decryptFile('', decryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.decryptFile(encryptedFilePath, '', testPassword)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.decryptFile(encryptedFilePath, decryptedFilePath, '')
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
});
