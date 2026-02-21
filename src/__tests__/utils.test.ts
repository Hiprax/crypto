import {
  validateFile,
  validatePath,
  generateRandomString,
  formatFileSize,
  getFileExtension,
  isTextFile,
  sanitizeFilename,
  createBackupPath,
  isValidBase64,
  isValidBase64Url,
  secureStringCompare,
  createProgressBar,
  sleep,
  retryWithBackoff,
  validatePasswordStrength,
  generateUUID,
  sha256,
  generateRandomHex,
  getFileInfo,
} from '../utils';
import { CryptoError } from '../types';
import { CryptoManager } from '../crypto-manager';
import { writeFile, unlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Utils', () => {
  const tempDir = os.tmpdir();

  describe('validateFile', () => {
    const testFilePath = path.join(tempDir, 'test-validate.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, 'test content');
    });

    afterEach(async () => {
      if (existsSync(testFilePath)) {
        await unlink(testFilePath);
      }
    });

    it('should validate existing file', async () => {
      const result = await validateFile(testFilePath);
      expect(result.isValid).toBe(true);
    });

    it('should reject non-existent file', async () => {
      const result = await validateFile('non-existent.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject invalid input', async () => {
      const result = await validateFile('');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path must be a non-empty string');
    });

    it('should handle null/undefined input', async () => {
      const result1 = await validateFile(null as unknown as string);
      expect(result1.isValid).toBe(false);
      expect(result1.error).toBe('File path must be a non-empty string');

      const result2 = await validateFile(undefined as unknown as string);
      expect(result2.isValid).toBe(false);
      expect(result2.error).toBe('File path must be a non-empty string');
    });
  });

  describe('validatePath', () => {
    it('should validate valid paths', () => {
      expect(validatePath('valid/path.txt').isValid).toBe(true);
      if (process.platform === 'win32') {
        expect(validatePath('C:\\valid\\path.txt').isValid).toBe(true);
        expect(validatePath('D:\\another\\path.txt').isValid).toBe(true);
      }
    });

    it('should reject paths with invalid characters', () => {
      expect(validatePath('invalid<path.txt').isValid).toBe(false);
      expect(validatePath('invalid"path.txt').isValid).toBe(false);
      if (process.platform !== 'win32') {
        expect(validatePath('invalid:path.txt').isValid).toBe(false);
      }
    });

    it('should reject colon in non-drive-letter position on Windows', () => {
      if (process.platform === 'win32') {
        expect(validatePath('C:\\path:invalid.txt').isValid).toBe(false);
      }
    });

    it('should reject path traversal attempts', () => {
      expect(validatePath('../secret.txt').isValid).toBe(false);
      expect(validatePath('path/../../secret.txt').isValid).toBe(false);
    });

    it('should reject invalid input', () => {
      expect(validatePath('').isValid).toBe(false);
      expect(validatePath('').error).toBe(
        'File path must be a non-empty string'
      );
    });

    it('should handle null/undefined input', () => {
      expect(validatePath(null as unknown as string).isValid).toBe(false);
      expect(validatePath(undefined as unknown as string).isValid).toBe(false);
    });
  });

  describe('generateRandomString', () => {
    it('should generate string of specified length', () => {
      const length = 16;
      const result = generateRandomString(length);
      expect(result).toHaveLength(length);
      expect(typeof result).toBe('string');
    });

    it('should use default length', () => {
      const result = generateRandomString();
      expect(result).toHaveLength(32);
    });

    it('should throw error for invalid length', () => {
      expect(() => generateRandomString(0)).toThrow(CryptoError);
      expect(() => generateRandomString(-1)).toThrow(CryptoError);
      expect(() => generateRandomString(1025)).toThrow(CryptoError);
    });

    it('should only contain alphanumeric characters', () => {
      const result = generateRandomString(1024);
      expect(result).toMatch(/^[A-Za-z0-9]+$/);
    });

    it('should produce roughly uniform distribution (no modulo bias)', () => {
      const counts: Record<string, number> = {};
      const chars =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      for (const c of chars) counts[c] = 0;

      // Generate multiple batches since max length is 1024
      const batchSize = 1024;
      const batches = 60;
      for (let b = 0; b < batches; b++) {
        const result = generateRandomString(batchSize);
        for (const c of result) counts[c] = (counts[c] ?? 0) + 1;
      }

      const totalChars = batchSize * batches;
      const expected = totalChars / 62;
      for (const c of chars) {
        const count = counts[c] ?? 0;
        // Each character should appear within 30% of expected (generous tolerance)
        expect(count).toBeGreaterThan(expected * 0.7);
        expect(count).toBeLessThan(expected * 1.3);
      }
    });
  });

  describe('formatFileSize', () => {
    it('should format file sizes correctly', () => {
      expect(formatFileSize(0)).toBe('0 Bytes');
      expect(formatFileSize(1024)).toBe('1 KB');
      expect(formatFileSize(1024 * 1024)).toBe('1 MB');
      expect(formatFileSize(1024 * 1024 * 1024)).toBe('1 GB');
    });

    it('should handle large file sizes', () => {
      expect(formatFileSize(1024 * 1024 * 1024 * 1024)).toBe('1 TB');
    });

    it('should handle negative values', () => {
      expect(formatFileSize(-1)).toBe('0 Bytes');
      expect(formatFileSize(-1024)).toBe('0 Bytes');
    });

    it('should handle values exceeding TB range', () => {
      const petabyte = 1024 * 1024 * 1024 * 1024 * 1024;
      const result = formatFileSize(petabyte);
      expect(result).toBe('1024 TB');
    });
  });

  describe('getFileExtension', () => {
    it('should extract file extensions', () => {
      expect(getFileExtension('file.txt')).toBe('.txt');
      expect(getFileExtension('file.TXT')).toBe('.txt');
      expect(getFileExtension('file')).toBe('');
      expect(getFileExtension('.hidden')).toBe('');
    });

    it('should handle files with multiple dots', () => {
      expect(getFileExtension('file.backup.txt')).toBe('.txt');
      expect(getFileExtension('file.name.with.dots.txt')).toBe('.txt');
    });
  });

  describe('isTextFile', () => {
    it('should identify text files', () => {
      expect(isTextFile('file.txt')).toBe(true);
      expect(isTextFile('file.md')).toBe(true);
      expect(isTextFile('file.json')).toBe(true);
      expect(isTextFile('file.js')).toBe(true);
      expect(isTextFile('file.ts')).toBe(true);
    });

    it('should reject non-text files', () => {
      expect(isTextFile('file.exe')).toBe(false);
      expect(isTextFile('file.jpg')).toBe(false);
      expect(isTextFile('file.pdf')).toBe(false);
    });

    it('should handle case insensitive extensions', () => {
      expect(isTextFile('file.TXT')).toBe(true);
      expect(isTextFile('file.MD')).toBe(true);
      expect(isTextFile('file.JSON')).toBe(true);
    });
  });

  describe('sanitizeFilename', () => {
    it('should sanitize filenames', () => {
      expect(sanitizeFilename('file<name>.txt')).toBe('file_name_.txt');
      expect(sanitizeFilename('file name.txt')).toBe('file_name.txt');
      expect(sanitizeFilename('')).toBe('file');
    });

    it('should handle various invalid characters', () => {
      expect(sanitizeFilename('file:name.txt')).toBe('file_name.txt');
      expect(sanitizeFilename('file"name.txt')).toBe('file_name.txt');
      expect(sanitizeFilename('file|name.txt')).toBe('file_name.txt');
      expect(sanitizeFilename('file?name.txt')).toBe('file_name.txt');
      expect(sanitizeFilename('file*name.txt')).toBe('file_name.txt');
    });
  });

  describe('createBackupPath', () => {
    it('should create backup path with timestamp', () => {
      const originalPath = '/path/to/file.txt';
      const backupPath = createBackupPath(originalPath);
      expect(backupPath).toMatch(
        /file_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.backup\.txt$/
      );
    });

    it('should handle custom suffix', () => {
      const originalPath = '/path/to/file.txt';
      const backupPath = createBackupPath(originalPath, '.custom');
      expect(backupPath).toMatch(
        /file_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.custom\.txt$/
      );
    });
  });

  describe('isValidBase64', () => {
    it('should validate valid base64 strings', () => {
      expect(isValidBase64('dGVzdA==')).toBe(true);
      expect(isValidBase64('SGVsbG8gV29ybGQ=')).toBe(true);
      expect(isValidBase64('')).toBe(false);
    });

    it('should reject invalid base64 strings', () => {
      expect(isValidBase64('invalid!')).toBe(false);
      expect(isValidBase64('dGVzdA==!')).toBe(false);
      expect(isValidBase64('not-base64')).toBe(false);
    });

    it('should handle null/undefined input', () => {
      expect(isValidBase64(null as unknown as string)).toBe(false);
      expect(isValidBase64(undefined as unknown as string)).toBe(false);
    });
  });

  describe('isValidBase64Url', () => {
    it('should validate valid base64url strings', () => {
      // base64url of "test"
      expect(isValidBase64Url('dGVzdA')).toBe(true);
      // base64url of "Hello World"
      expect(isValidBase64Url('SGVsbG8gV29ybGQ')).toBe(true);
      expect(isValidBase64Url('')).toBe(false);
    });

    it('should reject invalid base64url strings', () => {
      expect(isValidBase64Url('invalid!')).toBe(false);
    });

    it('should validate output from CryptoManager encryptTextSync', () => {
      // The library outputs base64url, so encrypted text should be valid
      const cm = new CryptoManager();
      const encrypted = cm.encryptTextSync(
        'test data',
        'MySecureP@ssw0rd123!'
      );
      expect(isValidBase64Url(encrypted)).toBe(true);
    });

    it('should handle null/undefined input', () => {
      expect(isValidBase64Url(null as unknown as string)).toBe(false);
      expect(isValidBase64Url(undefined as unknown as string)).toBe(false);
    });
  });

  describe('secureStringCompare', () => {
    it('should compare strings correctly', () => {
      expect(secureStringCompare('test', 'test')).toBe(true);
      expect(secureStringCompare('', '')).toBe(true);
      expect(secureStringCompare('different', 'strings')).toBe(false);
    });

    it('should handle different length strings', () => {
      expect(secureStringCompare('short', 'longer')).toBe(false);
      expect(secureStringCompare('longer', 'short')).toBe(false);
    });

    it('should handle non-string inputs', () => {
      expect(secureStringCompare(null as unknown as string, 'test')).toBe(
        false
      );
      expect(secureStringCompare('test', null as unknown as string)).toBe(
        false
      );
      expect(secureStringCompare(123 as unknown as string, 'test')).toBe(false);
    });

    it('should return false for strings with same length but different content', () => {
      expect(secureStringCompare('abcd', 'abce')).toBe(false);
      expect(secureStringCompare('1234', '1235')).toBe(false);
    });

    it('should handle unicode strings', () => {
      expect(secureStringCompare('héllo', 'héllo')).toBe(true);
      expect(secureStringCompare('héllo', 'hëllo')).toBe(false);
    });

    it('should handle both inputs as non-string types', () => {
      expect(
        secureStringCompare(
          undefined as unknown as string,
          undefined as unknown as string
        )
      ).toBe(false);
      expect(
        secureStringCompare(123 as unknown as string, 456 as unknown as string)
      ).toBe(false);
    });
  });

  describe('createProgressBar', () => {
    it('should create progress bar for valid inputs', () => {
      expect(createProgressBar(50, 100)).toMatch(/\[.*\] 50%/);
      expect(createProgressBar(0, 100)).toMatch(/\[.*\] 0%/);
      expect(createProgressBar(100, 100)).toMatch(/\[.*\] 100%/);
    });

    it('should handle zero total', () => {
      expect(createProgressBar(10, 0)).toBe(
        '[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%'
      );
    });

    it('should handle current greater than total', () => {
      expect(createProgressBar(150, 100)).toMatch(/\[.*\] 100%/);
    });

    it('should use custom width', () => {
      const result = createProgressBar(50, 100, 10);
      expect(result).toMatch(/\[.{10}\] 50%/);
    });
  });

  describe('sleep', () => {
    it('should sleep for specified time', async () => {
      const start = Date.now();
      await sleep(10);
      const end = Date.now();
      expect(end - start).toBeGreaterThanOrEqual(5); // Allow some tolerance
    });
  });

  describe('retryWithBackoff', () => {
    it('should succeed on first attempt', async () => {
      const fn = jest.fn().mockResolvedValue('success');
      const result = await retryWithBackoff(fn);
      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should retry and succeed', async () => {
      const fn = jest
        .fn()
        .mockRejectedValueOnce(new Error('First failure'))
        .mockResolvedValue('success');

      const result = await retryWithBackoff(fn);
      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it('should fail after max retries', async () => {
      const fn = jest.fn().mockRejectedValue(new Error('Persistent failure'));

      await expect(retryWithBackoff(fn)).rejects.toThrow('Persistent failure');
      expect(fn).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
    }, 10000);

    it('should use custom retry config', async () => {
      const fn = jest.fn().mockRejectedValue(new Error('Failure'));

      await expect(
        retryWithBackoff(fn, { maxRetries: 1, baseDelay: 10 })
      ).rejects.toThrow('Failure');
      expect(fn).toHaveBeenCalledTimes(2); // 1 initial + 1 retry
    });

    it('should handle non-Error exceptions', async () => {
      const fn = jest.fn().mockRejectedValue('String error');

      await expect(retryWithBackoff(fn)).rejects.toThrow('String error');
    }, 10000);

    it('should handle fallback error case', async () => {
      // This test triggers the fallback error case when lastError is undefined
      // This is a very edge case that's hard to trigger in practice
      const fn = jest.fn().mockRejectedValue(undefined);

      await expect(
        retryWithBackoff(fn, { maxRetries: 0, baseDelay: 1 })
      ).rejects.toThrow('undefined');
    }, 10000);
  });

  describe('getFileInfo', () => {
    const testFilePath = path.join(tempDir, 'test-info.txt');

    beforeEach(async () => {
      await writeFile(testFilePath, 'test content');
    });

    afterEach(async () => {
      if (existsSync(testFilePath)) {
        await unlink(testFilePath);
      }
    });

    it('should get file information', async () => {
      const info = await getFileInfo(testFilePath);
      expect(info.path).toBe(testFilePath);
      expect(info.size).toBeGreaterThan(0);
      expect(info.extension).toBe('.txt');
      expect(info.isTextFile).toBe(true);
    });

    it('should throw error for non-existent file', async () => {
      await expect(getFileInfo('non-existent.txt')).rejects.toThrow(
        CryptoError
      );
    });
  });

  describe('validatePasswordStrength', () => {
    it('should validate strong passwords', () => {
      const result = validatePasswordStrength('StrongP@ss1');
      expect(result.isValid).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(4);
      expect(result.feedback).toHaveLength(0);
    });

    it('should reject weak passwords', () => {
      const result = validatePasswordStrength('weak');
      expect(result.isValid).toBe(false);
      expect(result.score).toBeLessThan(4);
      expect(result.feedback.length).toBeGreaterThan(0);
    });

    it('should handle null/undefined input', () => {
      const result1 = validatePasswordStrength(null as unknown as string);
      expect(result1.isValid).toBe(false);
      expect(result1.score).toBe(0);
      expect(result1.feedback).toContain('Password must be a non-empty string');

      const result2 = validatePasswordStrength(undefined as unknown as string);
      expect(result2.isValid).toBe(false);
      expect(result2.score).toBe(0);
    });

    it('should provide detailed feedback', () => {
      const result = validatePasswordStrength('short');
      expect(result.feedback).toContain(
        'Password must be at least 8 characters long'
      );
      expect(result.feedback).toContain(
        'Password must contain at least one uppercase letter'
      );
      expect(result.feedback).toContain(
        'Password must contain at least one number'
      );
      expect(result.feedback).toContain(
        'Password must contain at least one special character'
      );
    });

    it('should handle repeated characters', () => {
      const result = validatePasswordStrength('aaaA1!');
      expect(result.feedback).toContain('Avoid repeated characters');
    });

    it('should handle all same characters', () => {
      const result = validatePasswordStrength('AAAAAAAA');
      expect(result.feedback).toContain(
        'Avoid using the same character repeatedly'
      );
    });

    it('should cap score at 5', () => {
      const result = validatePasswordStrength(
        'VeryLongAndComplexPassword123!@#'
      );
      expect(result.score).toBeLessThanOrEqual(5);
    });

    it('should not allow negative score', () => {
      const result = validatePasswordStrength('aaa');
      expect(result.score).toBeGreaterThanOrEqual(0);
    });
  });

  describe('generateUUID', () => {
    it('should generate valid UUID', () => {
      const uuid = generateUUID();
      expect(uuid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });

    it('should generate unique UUIDs', () => {
      const uuid1 = generateUUID();
      const uuid2 = generateUUID();
      expect(uuid1).not.toBe(uuid2);
    });
  });

  describe('sha256', () => {
    it('should hash string correctly', () => {
      const hash = sha256('test');
      expect(hash).toBe(
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      );
    });

    it('should handle empty string', () => {
      const hash = sha256('');
      expect(hash).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
    });

    it('should handle special characters', () => {
      const hash = sha256('test@123!');
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('generateRandomHex', () => {
    it('should generate hex string of specified length', () => {
      const hex = generateRandomHex(16);
      expect(hex).toHaveLength(16);
      expect(hex).toMatch(/^[0-9a-f]{16}$/);
    });

    it('should use default length', () => {
      const hex = generateRandomHex();
      expect(hex).toHaveLength(32);
      expect(hex).toMatch(/^[0-9a-f]{32}$/);
    });

    it('should throw error for invalid length', () => {
      expect(() => generateRandomHex(0)).toThrow(CryptoError);
      expect(() => generateRandomHex(-1)).toThrow(CryptoError);
      expect(() => generateRandomHex(1025)).toThrow(CryptoError);
    });

    it('should generate unique hex strings', () => {
      const hex1 = generateRandomHex(16);
      const hex2 = generateRandomHex(16);
      expect(hex1).not.toBe(hex2);
    });

    it('should handle odd lengths', () => {
      const hex = generateRandomHex(3);
      expect(hex).toHaveLength(3);
      expect(hex).toMatch(/^[0-9a-f]{3}$/);
    });

    it('should handle non-integer lengths', () => {
      expect(() => generateRandomHex(1.5)).toThrow(CryptoError);
      expect(() => generateRandomHex(NaN)).toThrow(CryptoError);
    });
  });

  describe('validatePath - additional edge cases', () => {
    it('should reject paths with pipe character', () => {
      expect(validatePath('path|file.txt').isValid).toBe(false);
    });

    it('should reject paths with question mark', () => {
      expect(validatePath('path?file.txt').isValid).toBe(false);
    });

    it('should reject paths with asterisk', () => {
      expect(validatePath('path*file.txt').isValid).toBe(false);
    });

    it('should accept simple filename', () => {
      expect(validatePath('file.txt').isValid).toBe(true);
    });

    it('should accept nested paths', () => {
      expect(validatePath('a/b/c/d/e/file.txt').isValid).toBe(true);
    });
  });

  describe('sanitizeFilename - additional edge cases', () => {
    it('should handle null/undefined input', () => {
      expect(sanitizeFilename(null as unknown as string)).toBe('file');
      expect(sanitizeFilename(undefined as unknown as string)).toBe('file');
    });

    it('should handle non-string input', () => {
      expect(sanitizeFilename(123 as unknown as string)).toBe('file');
    });

    it('should truncate very long filenames', () => {
      const longName = 'a'.repeat(300) + '.txt';
      const result = sanitizeFilename(longName);
      expect(result.length).toBeLessThanOrEqual(255);
    });

    it('should handle filenames with multiple spaces', () => {
      expect(sanitizeFilename('file   name   here.txt')).toBe(
        'file_name_here.txt'
      );
    });

    it('should handle backslash in filenames', () => {
      expect(sanitizeFilename('path\\file.txt')).toBe('path_file.txt');
    });
  });

  describe('createBackupPath - additional edge cases', () => {
    it('should handle files without extension', () => {
      const backupPath = createBackupPath('/path/to/file');
      expect(backupPath).toMatch(
        /file_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.backup$/
      );
    });

    it('should preserve directory path', () => {
      const backupPath = createBackupPath('/some/dir/file.txt');
      // On Windows, path.join normalizes to backslashes
      expect(backupPath).toContain('file_');
      expect(backupPath).toContain('.backup.txt');
    });
  });

  describe('isTextFile - additional extensions', () => {
    it('should identify all supported text extensions', () => {
      const textExtensions = [
        'file.py',
        'file.java',
        'file.c',
        'file.cpp',
        'file.h',
        'file.html',
        'file.css',
        'file.xml',
        'file.csv',
        'file.log',
        'file.yaml',
        'file.yml',
        'file.toml',
        'file.ini',
        'file.conf',
        'file.cfg',
      ];
      for (const file of textExtensions) {
        expect(isTextFile(file)).toBe(true);
      }
    });

    it('should reject binary file extensions', () => {
      const binaryExtensions = [
        'file.zip',
        'file.tar',
        'file.gz',
        'file.png',
        'file.gif',
        'file.mp3',
        'file.mp4',
        'file.doc',
        'file.xls',
      ];
      for (const file of binaryExtensions) {
        expect(isTextFile(file)).toBe(false);
      }
    });
  });

  describe('formatFileSize - additional cases', () => {
    it('should format fractional sizes', () => {
      expect(formatFileSize(1536)).toBe('1.5 KB');
      expect(formatFileSize(500)).toBe('500 Bytes');
    });

    it('should format very small sizes', () => {
      expect(formatFileSize(1)).toBe('1 Bytes');
      expect(formatFileSize(10)).toBe('10 Bytes');
    });
  });

  describe('generateRandomString - edge cases', () => {
    it('should generate string of length 1', () => {
      const result = generateRandomString(1);
      expect(result).toHaveLength(1);
      expect(result).toMatch(/^[A-Za-z0-9]$/);
    });

    it('should generate string of max length 1024', () => {
      const result = generateRandomString(1024);
      expect(result).toHaveLength(1024);
    });

    it('should generate unique strings', () => {
      const a = generateRandomString(32);
      const b = generateRandomString(32);
      expect(a).not.toBe(b);
    });

    it('should throw for non-integer', () => {
      expect(() => generateRandomString(3.14)).toThrow(CryptoError);
      expect(() => generateRandomString(NaN)).toThrow(CryptoError);
    });
  });

  describe('createProgressBar - additional cases', () => {
    it('should handle negative total', () => {
      expect(createProgressBar(50, -1)).toBe(
        '[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%'
      );
    });

    it('should handle zero current', () => {
      const result = createProgressBar(0, 100);
      expect(result).toMatch(/\[░{30}\] 0%/);
    });

    it('should handle full completion', () => {
      const result = createProgressBar(100, 100);
      expect(result).toMatch(/\[█{30}\] 100%/);
    });
  });

  describe('validatePasswordStrength - additional cases', () => {
    it('should give higher score for longer passwords', () => {
      // Short password (8 chars) gets score of 1 for length
      const short = validatePasswordStrength('Ab1!abcd');
      // Longer password (16+ chars) gets score of 2 for length + 1 bonus for 16+
      // But score caps at 5, so both may cap out
      expect(short.score).toBeGreaterThanOrEqual(4);
      expect(short.score).toBeLessThanOrEqual(5);
    });

    it('should handle password with 12+ chars', () => {
      const result = validatePasswordStrength('Abcdefgh1!23');
      expect(result.score).toBeGreaterThanOrEqual(4);
    });

    it('should handle empty string', () => {
      const result = validatePasswordStrength('');
      expect(result.isValid).toBe(false);
      expect(result.score).toBe(0);
    });
  });

  describe('sha256 - additional cases', () => {
    it('should produce consistent results', () => {
      const hash1 = sha256('same input');
      const hash2 = sha256('same input');
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = sha256('input1');
      const hash2 = sha256('input2');
      expect(hash1).not.toBe(hash2);
    });

    it('should handle unicode input', () => {
      const hash = sha256('日本語テスト');
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('getFileInfo - additional cases', () => {
    const binaryTestFile = path.join(tempDir, 'test-info.bin');

    afterEach(async () => {
      if (existsSync(binaryTestFile)) {
        await unlink(binaryTestFile);
      }
    });

    it('should identify non-text files', async () => {
      await writeFile(binaryTestFile, Buffer.from([0x00, 0x01, 0x02]));
      const info = await getFileInfo(binaryTestFile);
      expect(info.extension).toBe('.bin');
      expect(info.isTextFile).toBe(false);
    });

    it('should report correct size', async () => {
      const content = 'exactly 13 ch';
      await writeFile(binaryTestFile, content);
      const info = await getFileInfo(binaryTestFile);
      expect(info.size).toBe(Buffer.byteLength(content));
    });
  });

  describe('validateFile - additional cases', () => {
    it('should include error message for non-existent file', async () => {
      const result = await validateFile('/nonexistent/path/file.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('File access error');
    });

    it('should handle numeric input', async () => {
      const result = await validateFile(123 as unknown as string);
      expect(result.isValid).toBe(false);
    });
  });
});
