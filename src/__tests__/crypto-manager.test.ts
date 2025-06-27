import { CryptoManager } from '../crypto-manager';
import { CryptoError, CryptoErrorType } from '../types';
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
  });

  describe('validatePassword', () => {
    it('should validate strong passwords', () => {
      expect(crypto.validatePassword('MySecureP@ssw0rd123!')).toBe(true);
      expect(crypto.validatePassword('Weak123')).toBe(false);
      expect(crypto.validatePassword('')).toBe(false);
      expect(crypto.validatePassword('12345678')).toBe(false);
    });

    it('should handle invalid input types', () => {
      expect(crypto.validatePassword(null as unknown as string)).toBe(false);
      expect(crypto.validatePassword(undefined as unknown as string)).toBe(
        false
      );
      expect(crypto.validatePassword(123 as unknown as string)).toBe(false);
    });
  });

  describe('Text Encryption/Decryption', () => {
    it('should encrypt and decrypt text successfully', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      expect(typeof encrypted).toBe('string');
      expect(encrypted).not.toBe(testText);

      const decrypted = await crypto.decryptText(encrypted, testPassword);
      expect(decrypted).toBe(testText);
    });

    it('should throw error for weak password', async () => {
      await expect(crypto.encryptText(testText, 'weak')).rejects.toThrow(
        CryptoError
      );
    });

    it('should throw error for invalid encrypted text', async () => {
      await expect(
        crypto.decryptText('invalid-base64', testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for wrong password', async () => {
      const encrypted = await crypto.encryptText(testText, testPassword);
      await expect(
        crypto.decryptText(encrypted, 'WrongP@ssw0rd123!')
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for empty text', async () => {
      await expect(crypto.encryptText('', testPassword)).rejects.toThrow(
        CryptoError
      );
      await expect(crypto.decryptText('', testPassword)).rejects.toThrow(
        CryptoError
      );
    });

    it('should throw error for invalid text input', async () => {
      await expect(
        crypto.encryptText(null as unknown as string, testPassword)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.decryptText(null as unknown as string, testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for invalid password input', async () => {
      await expect(
        crypto.encryptText(testText, null as unknown as string)
      ).rejects.toThrow(CryptoError);
      await expect(
        crypto.decryptText('encrypted', null as unknown as string)
      ).rejects.toThrow(CryptoError);
    });

    it('should handle encrypted data too small', async () => {
      await expect(
        crypto.decryptText('SGVsbG8=', testPassword) // Too small base64
      ).rejects.toThrow(CryptoError);
    });

    it('should handle non-CryptoError exceptions', async () => {
      // Mock deriveKey to throw a regular Error
      const originalDeriveKey = crypto.deriveKey.bind(crypto);
      crypto.deriveKey = jest.fn().mockRejectedValue(new Error('Mock error'));

      await expect(crypto.encryptText(testText, testPassword)).rejects.toThrow(
        CryptoError
      );

      // Restore original method
      crypto.deriveKey = originalDeriveKey;
    });
  });

  describe('File Encryption/Decryption', () => {
    const testFilePath = path.join(tempDir, 'test-file.txt');
    const encryptedFilePath = path.join(tempDir, 'test-file.enc');
    const decryptedFilePath = path.join(tempDir, 'test-file-decrypted.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, testText);
    });

    afterEach(async () => {
      // Clean up test files
      const files = [testFilePath, encryptedFilePath, decryptedFilePath];
      for (const file of files) {
        if (existsSync(file)) {
          try {
            await unlink(file);
          } catch {
            // Ignore cleanup errors
          }
        }
      }
    });

    it('should encrypt and decrypt file successfully', async () => {
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
      expect(existsSync(encryptedFilePath)).toBe(true);

      await crypto.decryptFile(
        encryptedFilePath,
        decryptedFilePath,
        testPassword
      );
      expect(existsSync(decryptedFilePath)).toBe(true);

      const decryptedContent = await readFile(decryptedFilePath, 'utf8');
      expect(decryptedContent).toBe(testText);
    });

    it('should throw error for non-existent input file', async () => {
      await expect(
        crypto.encryptFile('non-existent.txt', encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for weak password', async () => {
      await expect(
        crypto.encryptFile(testFilePath, encryptedFilePath, 'weak')
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for wrong password during decryption', async () => {
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);
      await expect(
        crypto.decryptFile(
          encryptedFilePath,
          decryptedFilePath,
          'WrongP@ssw0rd123!'
        )
      ).rejects.toThrow(CryptoError);
    });

    it('should throw error for missing required parameters', async () => {
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

    it('should handle file too small for decryption', async () => {
      // Create a file that's too small to be a valid encrypted file
      const smallFile = path.join(tempDir, 'small-file.enc');
      await writeFile(smallFile, 'small');

      await expect(
        crypto.decryptFile(smallFile, decryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);
    });

    it('should handle non-CryptoError exceptions during encryption', async () => {
      // Mock deriveKey to throw a regular Error
      const originalDeriveKey = crypto.deriveKey.bind(crypto);
      crypto.deriveKey = jest.fn().mockRejectedValue(new Error('Mock error'));

      await expect(
        crypto.encryptFile(testFilePath, encryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);

      // Restore original method
      crypto.deriveKey = originalDeriveKey;
    });

    it('should handle non-CryptoError exceptions during decryption', async () => {
      await crypto.encryptFile(testFilePath, encryptedFilePath, testPassword);

      // Mock deriveKey to throw a regular Error
      const originalDeriveKey = crypto.deriveKey.bind(crypto);
      crypto.deriveKey = jest.fn().mockRejectedValue(new Error('Mock error'));

      await expect(
        crypto.decryptFile(encryptedFilePath, decryptedFilePath, testPassword)
      ).rejects.toThrow(CryptoError);

      // Restore original method
      crypto.deriveKey = originalDeriveKey;
    });
  });

  describe('secureClear', () => {
    it('should clear buffer successfully', () => {
      const buffer = Buffer.from('sensitive data');
      crypto.secureClear(buffer);
      expect(buffer.every(byte => byte === 0)).toBe(true);
    });

    it('should handle null/undefined buffer', () => {
      expect(() => crypto.secureClear(null as unknown as Buffer)).not.toThrow();
      expect(() =>
        crypto.secureClear(undefined as unknown as Buffer)
      ).not.toThrow();
    });

    it('should handle non-buffer input', () => {
      expect(() =>
        crypto.secureClear('string' as unknown as Buffer)
      ).not.toThrow();
      expect(() => crypto.secureClear(123 as unknown as Buffer)).not.toThrow();
    });
  });

  describe('Security Level', () => {
    it('should return correct security level', () => {
      const lowCrypto = new CryptoManager({ memoryCost: 2 ** 12, timeCost: 1 });
      expect(lowCrypto.getSecurityLevel()).toBe('low');

      const mediumCrypto = new CryptoManager({
        memoryCost: 2 ** 14,
        timeCost: 2,
      });
      expect(mediumCrypto.getSecurityLevel()).toBe('medium');

      const highCrypto = new CryptoManager({
        memoryCost: 2 ** 16,
        timeCost: 3,
      });
      expect(highCrypto.getSecurityLevel()).toBe('high');

      const ultraCrypto = new CryptoManager({
        memoryCost: 2 ** 18,
        timeCost: 4,
      });
      expect(ultraCrypto.getSecurityLevel()).toBe('ultra');
    });
  });

  describe('Error Handling', () => {
    it('should throw CryptoError with correct type and code', async () => {
      try {
        await crypto.encryptText('', '');
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoError);
        if (error instanceof CryptoError) {
          expect(error.type).toBe(CryptoErrorType.INVALID_INPUT);
          expect(error.code).toBe('INVALID_TEXT');
        }
      }
    });
  });
});
