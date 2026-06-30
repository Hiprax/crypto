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
import { CryptoError, CryptoErrorType } from '../types';
import { CryptoManager, isValidPassword } from '../crypto-manager';
import { writeFile, unlink } from 'node:fs/promises';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Unique per-suite scratch directory. mkdtempSync creates the directory
// atomically with a random suffix — the CodeQL-approved secure pattern
// for temp-directory creation.
const TEST_DIR = mkdtempSync(path.join(os.tmpdir(), 'hiprax-crypto-utils-'));

describe('Utils', () => {
  const tempDir = TEST_DIR;

  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

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

    it('should reject Windows drive-relative path traversal (C:.. bypass)', () => {
      // These inputs are Windows-specific: 'C:..\\Windows\\foo', 'C:foo\\..\\..\\bar',
      // and 'C:..' are drive-relative paths where path.normalize keeps '..' glued
      // to the drive specifier ('C:..') instead of producing a standalone '..'
      // segment. Previously the strict /^[a-zA-Z]:$/ drive-strip missed 'C:..'
      // and the exact includes('..') check failed, so all three wrongly returned
      // isValid:true. The fix strips the 'C:' prefix before the '..' scan.
      if (process.platform !== 'win32') return;
      const bs = String.fromCharCode(92); // backslash (avoids shell-escaping ambiguity)
      const r1 = validatePath('C:..' + bs + 'Windows' + bs + 'foo');
      expect(r1.isValid).toBe(false);
      expect(r1.error).toBe('Path traversal is not allowed');

      const r2 = validatePath('C:foo' + bs + '..' + bs + '..' + bs + 'bar');
      expect(r2.isValid).toBe(false);
      expect(r2.error).toBe('Path traversal is not allowed');

      const r3 = validatePath('C:..');
      expect(r3.isValid).toBe(false);
      expect(r3.error).toBe('Path traversal is not allowed');
    });

    it('should still accept a legitimate absolute Windows path after the drive-strip fix', () => {
      if (process.platform !== 'win32') return;
      const bs = String.fromCharCode(92);
      const r = validatePath('C:' + bs + 'Users' + bs + 'foo');
      expect(r.isValid).toBe(true);
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

    // Task 24: negative values are now a programming error and must
    // throw rather than silently returning '0 Bytes'.
    it('should throw CryptoError on negative values', () => {
      expect(() => formatFileSize(-1)).toThrow(CryptoError);
      expect(() => formatFileSize(-1024)).toThrow(CryptoError);
    });

    it('should throw with NEGATIVE_FILE_SIZE code on negative input', () => {
      try {
        formatFileSize(-1);
        // Unreachable — the call above must throw.
        throw new Error('Expected formatFileSize(-1) to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('NEGATIVE_FILE_SIZE');
      }
    });

    it('should throw with INVALID_FILE_SIZE code on NaN / Infinity / non-number input', () => {
      for (const bad of [
        Number.NaN,
        Number.POSITIVE_INFINITY,
        Number.NEGATIVE_INFINITY,
      ]) {
        try {
          formatFileSize(bad);
          throw new Error('Expected formatFileSize to throw');
        } catch (err) {
          expect(err).toBeInstanceOf(CryptoError);
          expect((err as CryptoError).code).toBe('INVALID_FILE_SIZE');
        }
      }
      // Non-number inputs (e.g. string) also trip INVALID_FILE_SIZE.
      try {
        formatFileSize('1024' as unknown as number);
        throw new Error('Expected formatFileSize to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_FILE_SIZE');
      }
    });

    it('should handle values exceeding TB range', () => {
      const petabyte = 1024 * 1024 * 1024 * 1024 * 1024;
      const result = formatFileSize(petabyte);
      expect(result).toBe('1024 TB');
    });

    // Task 10 — upper-bound check. Without this guard, a caller
    // passing Number.MAX_VALUE (1.79e+308) would get a mathematical
    // artefact like "1.7976931348623157e+308 TB" because the unit
    // ladder caps at TB but the coefficient grows unbounded.
    it('should throw FILE_SIZE_TOO_LARGE for values above Number.MAX_SAFE_INTEGER', () => {
      // Number.MAX_SAFE_INTEGER + 1 is the smallest unsafe positive
      // integer. JS rounds it to MAX_SAFE_INTEGER + 2 since +1 is
      // unrepresentable, but a value strictly greater is
      // representable (e.g. MAX_SAFE_INTEGER * 2).
      const tooLarge = Number.MAX_SAFE_INTEGER * 2;
      expect(() => formatFileSize(tooLarge)).toThrow(CryptoError);
      try {
        formatFileSize(tooLarge);
        throw new Error('Expected formatFileSize to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('FILE_SIZE_TOO_LARGE');
        expect((err as CryptoError).type).toBe(CryptoErrorType.INVALID_INPUT);
      }
    });

    it('should throw FILE_SIZE_TOO_LARGE for Number.MAX_VALUE', () => {
      // Number.MAX_VALUE is a finite number (~1.79e308) but vastly
      // exceeds Number.MAX_SAFE_INTEGER. Pre-fix, this was silently
      // formatted as a ridiculous coefficient stuck at TB.
      expect(() => formatFileSize(Number.MAX_VALUE)).toThrow(CryptoError);
      try {
        formatFileSize(Number.MAX_VALUE);
        throw new Error('Expected formatFileSize to throw');
      } catch (err) {
        expect((err as CryptoError).code).toBe('FILE_SIZE_TOO_LARGE');
      }
    });

    it('should accept exactly Number.MAX_SAFE_INTEGER (the boundary)', () => {
      // The threshold is `> MAX_SAFE_INTEGER` (strict), so the
      // boundary value itself is accepted.
      const result = formatFileSize(Number.MAX_SAFE_INTEGER);
      // ~8 PB → reported in TB at the cap. The regex below has two
      // `\d+` quantifiers separated by an optional `(\.\d+)?` group,
      // which `safe-regex` (the conservative scanner used by
      // `security/detect-unsafe-regex`) flags as potentially
      // exponential. It isn't — the `\s+TB$` anchor on the right
      // forces the engine to commit, and the input under test
      // (formatFileSize output) is bounded to a few characters, so
      // catastrophic backtracking cannot occur.
      // eslint-disable-next-line security/detect-unsafe-regex
      expect(result).toMatch(/\d+(\.\d+)?\s+TB$/);
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

    it('should throw CryptoError for non-string input (Phase 1 guard)', () => {
      // Non-string input previously threw a raw Node TypeError; now throws
      // a typed CryptoError consistent with the rest of the utils contract.
      const nonStrings: unknown[] = [123, null, undefined, {}, []];
      for (const val of nonStrings) {
        let err: unknown;
        try {
          getFileExtension(val as string);
        } catch (e) {
          err = e;
        }
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_INPUT');
        expect((err as CryptoError).type).toBe(CryptoErrorType.INVALID_INPUT);
      }
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

    it('should throw CryptoError for non-string input (Phase 1 guard)', () => {
      const nonStrings: unknown[] = [123, null, undefined, {}];
      for (const val of nonStrings) {
        let err: unknown;
        try {
          isTextFile(val as string);
        } catch (e) {
          err = e;
        }
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_INPUT');
        expect((err as CryptoError).type).toBe(CryptoErrorType.INVALID_INPUT);
      }
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
    // Task 24: backup filenames now include a 6-character random hex
    // discriminator before the suffix, e.g.
    // `file_2026-05-04T12-00-00_a3f9b2.backup.txt`. The discriminator
    // prevents intra-second collisions when two backups are taken
    // within the same second.
    it('should create backup path with timestamp and 6-char random hex', () => {
      const originalPath = '/path/to/file.txt';
      const backupPath = createBackupPath(originalPath);
      expect(backupPath).toMatch(
        /file_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}_[0-9a-f]{6}\.backup\.txt$/
      );
    });

    it('should handle custom suffix', () => {
      const originalPath = '/path/to/file.txt';
      const backupPath = createBackupPath(originalPath, '.custom');
      expect(backupPath).toMatch(
        /file_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}_[0-9a-f]{6}\.custom\.txt$/
      );
    });

    it('should produce different paths on repeated calls in the same second', () => {
      // 16 calls in tight succession — they will overwhelmingly land
      // in the same second on any modern machine, so collision
      // resistance must come from the random suffix, not the
      // timestamp. With 6 hex chars (24 bits, ~16.7M values) the
      // birthday-bound collision probability for 16 samples is well
      // below 1e-12, so this test is effectively deterministic.
      const originalPath = '/path/to/file.txt';
      const seen = new Set<string>();
      for (let i = 0; i < 16; i++) {
        seen.add(createBackupPath(originalPath));
      }
      expect(seen.size).toBe(16);
    });

    it('should have lowercase hex in the random discriminator', () => {
      const originalPath = '/path/to/file.txt';
      const backupPath = createBackupPath(originalPath);
      const match = backupPath.match(
        /_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})_([0-9a-f]{6})\.backup\.txt$/
      );
      expect(match).not.toBeNull();
      expect(match?.[2]).toMatch(/^[0-9a-f]{6}$/);
    });

    // Task 22: createBackupPath now passes its constructed basename
    // through sanitizeFilename so very long input names cannot produce
    // a basename that exceeds the 255-char filesystem maximum.
    it('should cap the result basename at 255 chars for very long input names', () => {
      const longName = 'a'.repeat(300);
      const originalPath = `/path/to/${longName}.txt`;
      const backupPath = createBackupPath(originalPath);
      const basename = path.basename(backupPath);
      expect(basename.length).toBeLessThanOrEqual(255);
      // Extension must be preserved by the sanitizer's extension-aware
      // truncation.
      expect(basename.endsWith('.txt')).toBe(true);
    });

    it('should preserve extension when truncating very long input names', () => {
      const longName = 'b'.repeat(500);
      const originalPath = `/path/to/${longName}.json`;
      const backupPath = createBackupPath(originalPath);
      const basename = path.basename(backupPath);
      expect(basename.length).toBeLessThanOrEqual(255);
      expect(path.extname(basename)).toBe('.json');
      // Random discriminator and timestamp must still be present —
      // truncation removes characters from the very long `name`
      // portion at the front of the basename, not from the
      // timestamp/random/suffix tail.
      expect(basename).toMatch(
        /_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}_[0-9a-f]{6}\.backup\.json$/
      );
    });

    it('should still produce unique results when input is over the cap', () => {
      // Even after sanitization truncates the front of the basename,
      // the random discriminator at the tail must keep results unique
      // across rapid successive calls.
      const longName = 'c'.repeat(400);
      const originalPath = `/path/to/${longName}.log`;
      const seen = new Set<string>();
      for (let i = 0; i < 8; i++) {
        seen.add(createBackupPath(originalPath));
      }
      expect(seen.size).toBe(8);
    });

    it('should preserve directory portion when basename is truncated', () => {
      const longName = 'd'.repeat(300);
      const originalPath = path.join('/some/nested/dir', `${longName}.txt`);
      const backupPath = createBackupPath(originalPath);
      // Directory must NOT be affected by sanitisation (sanitizeFilename
      // would replace `/` with `_`, but createBackupPath only sanitises
      // the basename).
      expect(path.dirname(backupPath)).toBe(path.dirname(originalPath));
      expect(path.basename(backupPath).length).toBeLessThanOrEqual(255);
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
      const encrypted = cm.encryptTextSync('test data', 'MySecureP@ssw0rd123!');
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

    // -----------------------------------------------------------------
    // Task 25: shouldRetry predicate
    // -----------------------------------------------------------------

    it('should stop retrying when custom shouldRetry returns false', async () => {
      // The function rejects every call, but shouldRetry returns
      // false on the first failure, so the loop must abort
      // immediately after the initial attempt rather than continuing
      // through `maxRetries` extra calls.
      const fn = jest.fn().mockRejectedValue(new Error('Stop me'));
      const shouldRetry = jest.fn().mockReturnValue(false);

      await expect(
        retryWithBackoff(fn, {
          maxRetries: 5,
          baseDelay: 1,
          shouldRetry,
        })
      ).rejects.toThrow('Stop me');
      expect(fn).toHaveBeenCalledTimes(1);
      // shouldRetry is consulted exactly once — after the first
      // (and only) failed attempt.
      expect(shouldRetry).toHaveBeenCalledTimes(1);
      const firstCall = shouldRetry.mock.calls[0];
      expect(firstCall).toBeDefined();
      const [firstErr, firstAttempt] = firstCall as [Error, number];
      expect(firstErr.message).toBe('Stop me');
      expect(firstAttempt).toBe(0);
    });

    it('should keep retrying when custom shouldRetry returns true', async () => {
      // shouldRetry always returns true, so the function should be
      // retried up to maxRetries+1 total calls before failing.
      const fn = jest.fn().mockRejectedValue(new Error('Try again'));
      const shouldRetry = jest.fn().mockReturnValue(true);

      await expect(
        retryWithBackoff(fn, {
          maxRetries: 2,
          baseDelay: 1,
          shouldRetry,
        })
      ).rejects.toThrow('Try again');
      expect(fn).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
      // shouldRetry is consulted after every failure EXCEPT the
      // final one (where the loop bails out via the maxRetries
      // guard before consulting the predicate).
      expect(shouldRetry).toHaveBeenCalledTimes(2);
    });

    it('should call shouldRetry with the error and zero-indexed attempt', async () => {
      const fn = jest
        .fn()
        .mockRejectedValueOnce(new Error('one'))
        .mockRejectedValueOnce(new Error('two'))
        .mockResolvedValue('ok');
      const shouldRetry = jest.fn().mockReturnValue(true);

      const result = await retryWithBackoff(fn, {
        maxRetries: 5,
        baseDelay: 1,
        shouldRetry,
      });
      expect(result).toBe('ok');
      expect(shouldRetry).toHaveBeenCalledTimes(2);
      const callOne = shouldRetry.mock.calls[0];
      const callTwo = shouldRetry.mock.calls[1];
      expect(callOne).toBeDefined();
      expect(callTwo).toBeDefined();
      const [errOne, attemptOne] = callOne as [Error, number];
      const [errTwo, attemptTwo] = callTwo as [Error, number];
      expect(errOne.message).toBe('one');
      expect(attemptOne).toBe(0);
      expect(errTwo.message).toBe('two');
      expect(attemptTwo).toBe(1);
    });

    it('should NOT retry WEAK_PASSWORD CryptoError under default policy', async () => {
      const weakPasswordError = new CryptoError(
        'Password is too weak',
        CryptoErrorType.INVALID_PASSWORD,
        'WEAK_PASSWORD'
      );
      const fn = jest.fn().mockRejectedValue(weakPasswordError);

      await expect(
        retryWithBackoff(fn, { maxRetries: 5, baseDelay: 1 })
      ).rejects.toBe(weakPasswordError);
      // No retries performed: only the initial attempt ran.
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should NOT retry INVALID_PASSWORD CryptoError under default policy', async () => {
      const invalidPasswordError = new CryptoError(
        'Password is invalid',
        CryptoErrorType.INVALID_PASSWORD,
        'INVALID_PASSWORD'
      );
      const fn = jest.fn().mockRejectedValue(invalidPasswordError);

      await expect(
        retryWithBackoff(fn, { maxRetries: 5, baseDelay: 1 })
      ).rejects.toBe(invalidPasswordError);
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should NOT retry any CryptoError of type INVALID_PASSWORD even with a non-password code', async () => {
      // Defence-in-depth: the type check should also apply, not just
      // the code allow-list. A CryptoError of type INVALID_PASSWORD
      // with an arbitrary code is still a deterministic-failure
      // surface and must not be retried.
      const err = new CryptoError(
        'Password problem',
        CryptoErrorType.INVALID_PASSWORD,
        'SOME_OTHER_PASSWORD_CODE'
      );
      const fn = jest.fn().mockRejectedValue(err);

      await expect(
        retryWithBackoff(fn, { maxRetries: 5, baseDelay: 1 })
      ).rejects.toBe(err);
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should retry generic errors (e.g. network timeout) under default policy', async () => {
      // Generic, non-CryptoError errors continue to be retried — the
      // new default policy only excludes password-class CryptoErrors.
      const fn = jest
        .fn()
        .mockRejectedValueOnce(new Error('ETIMEDOUT'))
        .mockRejectedValueOnce(new Error('ETIMEDOUT'))
        .mockResolvedValue('ok');

      const result = await retryWithBackoff(fn, {
        maxRetries: 3,
        baseDelay: 1,
      });
      expect(result).toBe('ok');
      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should retry non-password CryptoError types under default policy', async () => {
      // CryptoErrors that are NOT password-related (e.g. file errors,
      // encryption failures) should still be retried by default.
      const fn = jest
        .fn()
        .mockRejectedValueOnce(
          new CryptoError('Disk full', CryptoErrorType.FILE_ERROR, 'DISK_FULL')
        )
        .mockResolvedValue('recovered');

      const result = await retryWithBackoff(fn, {
        maxRetries: 2,
        baseDelay: 1,
      });
      expect(result).toBe('recovered');
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it('should let an explicit shouldRetry override the default password exclusion', async () => {
      // Pre-v0.19.0 callers that relied on retrying everything can
      // opt back in by passing `shouldRetry: () => true` even for
      // password-class CryptoErrors.
      const err = new CryptoError(
        'Weak password',
        CryptoErrorType.INVALID_PASSWORD,
        'WEAK_PASSWORD'
      );
      const fn = jest.fn().mockRejectedValue(err);
      const shouldRetry = jest.fn().mockReturnValue(true);

      await expect(
        retryWithBackoff(fn, {
          maxRetries: 2,
          baseDelay: 1,
          shouldRetry,
        })
      ).rejects.toBe(err);
      expect(fn).toHaveBeenCalledTimes(3);
      expect(shouldRetry).toHaveBeenCalledTimes(2);
    });
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
        /file_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}_[0-9a-f]{6}\.backup$/
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

  describe('createProgressBar - robustness (Phase 1 hardening)', () => {
    // All edge cases must return a well-formed "[...] N%" string and never throw.
    const wellFormed = /^\[.*\] \d+%$/;

    it('should clamp negative current to 0% without throwing', () => {
      const result = createProgressBar(-5, 10);
      expect(result).toMatch(wellFormed);
      expect(result).toBe('[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%');
    });

    it('should fall back to default width (30) for negative width without throwing', () => {
      // -3 is not a positive integer → width falls back to 30
      const result = createProgressBar(5, 10, -3);
      expect(result).toMatch(wellFormed);
      expect(result).toMatch(/\[.{30}\] 50%/);
    });

    it('should treat NaN current as 0 progress without throwing or emitting NaN', () => {
      const result = createProgressBar(NaN, 10);
      expect(result).toMatch(wellFormed);
      expect(result).not.toContain('NaN');
      expect(result).toBe('[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%');
    });

    it('should treat Infinity current as 0 progress without throwing', () => {
      const result = createProgressBar(Infinity, 10);
      expect(result).toMatch(wellFormed);
      expect(result).toBe('[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%');
    });

    it('should fall back to default width for non-integer width without throwing', () => {
      // 15.5 is not an integer → falls back to 30
      const result = createProgressBar(5, 10, 15.5);
      expect(result).toMatch(wellFormed);
      expect(result).toMatch(/\[.{30}\] 50%/);
    });

    it('should fall back to default width for zero width without throwing', () => {
      // 0 is not positive → falls back to 30
      const result = createProgressBar(5, 10, 0);
      expect(result).toMatch(wellFormed);
      expect(result).toMatch(/\[.{30}\] 50%/);
    });

    // Regression: existing happy-path behaviors must be unchanged
    it('should preserve happy-path output exactly', () => {
      expect(createProgressBar(50, 100)).toMatch(/\[.*\] 50%/);
      expect(createProgressBar(0, 100)).toMatch(/\[░{30}\] 0%/);
      expect(createProgressBar(100, 100)).toMatch(/\[█{30}\] 100%/);
      expect(createProgressBar(150, 100)).toMatch(/\[.*\] 100%/);
      expect(createProgressBar(10, 0)).toBe(
        '[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%'
      );
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

    // ---------------------------------------------------------------------
    // Task 13: extended acceptance rules
    // ---------------------------------------------------------------------

    it('should accept long passphrases (>= 20 chars) regardless of categories', () => {
      const result = validatePasswordStrength(
        'correct horse battery staple longer'
      );
      expect(result.isValid).toBe(true);
      expect(result.score).toBe(5);
      expect(result.feedback).toHaveLength(0);
    });

    it('should still emit feedback for short passwords missing categories', () => {
      // 19 chars (just under the passphrase shortcut), all lowercase: must
      // still emit category-feedback errors.
      const result = validatePasswordStrength('aaaaaaaaaaaaaaaaaaa');
      expect(result.isValid).toBe(false);
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

    it('should accept broadened specials like underscore as special char', () => {
      // `_` was previously not counted; with the broadened
      // `[^A-Za-z0-9]` rule it now satisfies the special-char check.
      const result = validatePasswordStrength('Aa1_aaaa');
      expect(result.feedback).not.toContain(
        'Password must contain at least one special character'
      );
    });
  });

  // -----------------------------------------------------------------
  // Phase 4 (pw-parity): validatePasswordStrength.isValid must agree
  // exactly with isValidPassword across all inputs. Repeat-character
  // penalties (score/feedback) must NOT affect isValid.
  // -----------------------------------------------------------------
  describe('validatePasswordStrength ⟷ isValidPassword parity', () => {
    it('isValid must equal isValidPassword for every input in the battery', () => {
      // Battery covers the two regression cases plus representative
      // accept/reject inputs for both acceptance rules.
      const battery: Array<string | null> = [
        // Regression: repeat-char penalties previously flipped isValid vs isValidPassword
        'Aaaa1234_', // repeat 'aaa' — isValidPassword=true, old isValid was false
        'Passw0rd!!!', // repeat '!!!' — isValidPassword=true, old isValid was false
        // 8+ chars, all 4 categories, has repeats — still valid
        'Ab1!aaaa',
        // Cases isValidPassword rejects
        'aaaaaaaa', // 8 lower-only, no upper/digit/special
        'short1!', // 7 chars — too short
        '', // empty string
        // Passphrase rule: 20 lowercase 'a's
        'aaaaaaaaaaaaaaaaaaaa',
        // 8 chars, all 4 categories, no repeats
        'Ab1!dcef',
      ];
      expect.assertions(battery.length + 1); // +1 for the null case below
      for (const pw of battery) {
        expect(validatePasswordStrength(pw as string).isValid).toBe(
          isValidPassword(pw as string)
        );
      }
      // Non-string: both functions must return false
      expect(validatePasswordStrength(null as unknown as string).isValid).toBe(
        isValidPassword(null as unknown as string)
      );
    });

    it('regression: Aaaa1234_ is valid under both validators', () => {
      expect(validatePasswordStrength('Aaaa1234_').isValid).toBe(true);
      expect(isValidPassword('Aaaa1234_')).toBe(true);
    });

    it('regression: Passw0rd!!! is valid under both validators', () => {
      expect(validatePasswordStrength('Passw0rd!!!').isValid).toBe(true);
      expect(isValidPassword('Passw0rd!!!')).toBe(true);
    });

    it('repeat-char feedback does not affect isValid when acceptance rules are met', () => {
      const result = validatePasswordStrength('Aaaa1234_');
      expect(result.isValid).toBe(true);
      expect(result.feedback).toContain('Avoid repeated characters');
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

    it('should throw CryptoError for non-string input (Phase 1 guard)', () => {
      // Previously threw a raw Node TypeError; now throws a typed CryptoError
      // matching the library's "all errors are CryptoError" contract.
      const nonStrings: unknown[] = [123, null, undefined, {}, []];
      for (const val of nonStrings) {
        let err: unknown;
        try {
          sha256(val as string);
        } catch (e) {
          err = e;
        }
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_INPUT');
        expect((err as CryptoError).type).toBe(CryptoErrorType.INVALID_INPUT);
      }
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

  // ---------------------------------------------------------------
  // Task 11: null-byte / control-char rejection in validatePath, and
  // ..-aware sanitizeFilename with extension-preserving truncation.
  // Task 32: optional `allowedRoot` containment check on validatePath.
  // ---------------------------------------------------------------

  describe('validatePath - null bytes and control chars (Task 11/32)', () => {
    it('should reject path containing a literal null byte', () => {
      const result = validatePath('foo bar.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains a null byte');
    });

    it('should reject path with null byte at the end', () => {
      const result = validatePath('file.txt ');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains a null byte');
    });

    it('should reject path with null byte at the start', () => {
      const result = validatePath(' file.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains a null byte');
    });

    it('should reject path with ASCII control character (tab, codepoint 0x09)', () => {
      const result = validatePath('foo\tbar.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains control characters');
    });

    it('should reject path with newline (codepoint 0x0a)', () => {
      const result = validatePath('foo\nbar.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains control characters');
    });

    it('should reject path with carriage return (codepoint 0x0d)', () => {
      const result = validatePath('foo\rbar.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains control characters');
    });

    it('should reject path with bell character (codepoint 0x07)', () => {
      const result = validatePath('foo\x07bar.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains control characters');
    });

    it('should reject path containing DEL (codepoint 0x7f)', () => {
      const result = validatePath('foobar.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File path contains control characters');
    });

    it('should reject every codepoint in the [0x01, 0x1F] range', () => {
      // Spot-check a few common control characters across the range.
      // Codepoint 0x00 is tested separately as the null-byte case.
      for (const code of [0x01, 0x05, 0x0b, 0x0f, 0x10, 0x1a, 0x1f]) {
        const ch = String.fromCharCode(code);
        const result = validatePath(`pre${ch}post.txt`);
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('File path contains control characters');
      }
    });

    it('should accept printable ASCII path with no control chars', () => {
      // Sanity check that the new control-char rejection does not
      // overreach onto valid printable content.
      expect(validatePath('plain/path/file.txt').isValid).toBe(true);
      expect(validatePath('file with spaces.txt').isValid).toBe(true);
      expect(
        validatePath('file_with_underscores-and-hyphens.txt').isValid
      ).toBe(true);
    });

    it('should accept path containing high-codepoint Unicode (>= 0x80)', () => {
      // Non-ASCII characters are permitted by the validator (filesystems
      // generally handle them via UTF-8). Only ASCII control codepoints
      // are rejected.
      expect(validatePath('café/résumé.txt').isValid).toBe(true);
      expect(validatePath('日本語/ファイル.txt').isValid).toBe(true);
    });
  });

  describe('validatePath - allowedRoot containment (Task 32)', () => {
    it('should accept input equal to the allowed root', () => {
      const root = path.resolve(tempDir, 'project');
      const result = validatePath(root, { allowedRoot: root });
      expect(result.isValid).toBe(true);
    });

    it('should accept input that is a direct child of the allowed root', () => {
      const root = path.resolve(tempDir, 'project');
      const child = path.join(root, 'file.txt');
      const result = validatePath(child, { allowedRoot: root });
      expect(result.isValid).toBe(true);
    });

    it('should accept input nested several levels under the allowed root', () => {
      const root = path.resolve(tempDir, 'project');
      const nested = path.join(root, 'a', 'b', 'c', 'file.txt');
      const result = validatePath(nested, { allowedRoot: root });
      expect(result.isValid).toBe(true);
    });

    it('should reject input that escapes the allowed root via ..', () => {
      // The literal `..` would be caught by the existing traversal check
      // first; here we use a relative path resolved against cwd that is
      // outside any plausible `allowedRoot` we choose.
      const root = path.resolve(tempDir, 'restricted-root');
      const escape = path.resolve(tempDir, 'sibling/file.txt');
      const result = validatePath(escape, { allowedRoot: root });
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('Path is outside the allowed root');
    });

    it('should reject within-drive cross-traversal (C:\\Users\\..\\Windows escapes C:\\Users)', () => {
      // This is the canonical example from FIX.md C8: the literal-`..`
      // check passes because `path.normalize` collapses the cancel-out
      // to a clean path, but the resolved path escapes the configured
      // allowed root.
      if (process.platform === 'win32') {
        const result = validatePath('C:\\Users\\..\\Windows', {
          allowedRoot: 'C:\\Users',
        });
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Path is outside the allowed root');
      } else {
        const result = validatePath('/home/user/../etc', {
          allowedRoot: '/home/user',
        });
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Path is outside the allowed root');
      }
    });

    it('should NOT match when the input string-prefixes the root without a path separator (no /etc/sec ↔ /etc/secret)', () => {
      // The trailing-separator edge case: a naive `startsWith` would
      // accept `/etc/secret` for an `allowedRoot` of `/etc/sec`. The
      // segment-aware prefix match rejects this.
      if (process.platform === 'win32') {
        const result = validatePath('C:\\etc\\secret\\file.txt', {
          allowedRoot: 'C:\\etc\\sec',
        });
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Path is outside the allowed root');
      } else {
        const result = validatePath('/etc/secret/file.txt', {
          allowedRoot: '/etc/sec',
        });
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Path is outside the allowed root');
      }
    });

    it('should accept the allowed root with a trailing path separator', () => {
      // Robustness: callers should not have to strip trailing separators
      // off `allowedRoot` themselves.
      const root = path.resolve(tempDir, 'project');
      const rootWithSep = root + path.sep;
      const child = path.join(root, 'file.txt');
      const result = validatePath(child, { allowedRoot: rootWithSep });
      expect(result.isValid).toBe(true);
    });

    it('should accept Windows path with forward slashes when allowedRoot uses backslashes', () => {
      // Node.js normalizes `C:/Users/foo` and `C:\\Users\\foo` to the
      // same path on Windows; the validator should agree.
      if (process.platform === 'win32') {
        const result = validatePath('C:/Users/project/file.txt', {
          allowedRoot: 'C:\\Users\\project',
        });
        expect(result.isValid).toBe(true);
      }
    });

    it('should accept Windows path with backslashes when allowedRoot uses forward slashes', () => {
      if (process.platform === 'win32') {
        const result = validatePath('C:\\Users\\project\\file.txt', {
          allowedRoot: 'C:/Users/project',
        });
        expect(result.isValid).toBe(true);
      }
    });

    it('should perform case-insensitive comparison on Windows', () => {
      if (process.platform === 'win32') {
        const result = validatePath('c:\\users\\PROJECT\\file.txt', {
          allowedRoot: 'C:\\Users\\project',
        });
        expect(result.isValid).toBe(true);
      }
    });

    it('should perform case-sensitive comparison on POSIX', () => {
      if (process.platform !== 'win32') {
        const result = validatePath('/Home/User/file.txt', {
          allowedRoot: '/home/user',
        });
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Path is outside the allowed root');
      }
    });

    it('should reject when allowedRoot is an empty string', () => {
      const result = validatePath('file.txt', { allowedRoot: '' });
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('allowedRoot must be a non-empty string');
    });

    it('should reject when allowedRoot is a non-string value', () => {
      const result = validatePath('file.txt', {
        allowedRoot: 123 as unknown as string,
      });
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('allowedRoot must be a non-empty string');
    });

    it('should reject when allowedRoot itself contains a null byte', () => {
      const result = validatePath('file.txt', {
        allowedRoot: 'good root',
      });
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('allowedRoot contains invalid characters');
    });

    it('should reject when allowedRoot itself contains control characters', () => {
      const result = validatePath('file.txt', {
        allowedRoot: 'good\troot',
      });
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('allowedRoot contains invalid characters');
    });

    it('should leave the legacy single-argument call shape backward-compatible', () => {
      // No `options` argument: function should behave exactly as before.
      expect(validatePath('valid/path.txt').isValid).toBe(true);
      expect(validatePath('../escape.txt').isValid).toBe(false);
    });

    it('should accept calls with an empty options object', () => {
      // Calling with `{}` should also be a no-op compared to omitting.
      expect(validatePath('valid/path.txt', {}).isValid).toBe(true);
      expect(validatePath('../escape.txt', {}).isValid).toBe(false);
    });

    it('should still apply the literal-.. check when allowedRoot is set', () => {
      const root = path.resolve(tempDir, 'project');
      // A literal `..` segment in the input should be rejected by the
      // pre-existing traversal check, BEFORE the `allowedRoot` check
      // gets a chance.
      const result = validatePath('../escape.txt', { allowedRoot: root });
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('Path traversal is not allowed');
    });

    it('should reject control-character paths even when allowedRoot is provided', () => {
      const root = path.resolve(tempDir, 'project');
      const result = validatePath('foo bar.txt', { allowedRoot: root });
      expect(result.isValid).toBe(false);
      // The null-byte / control-char check fires before allowedRoot.
      expect(result.error).toBe('File path contains a null byte');
    });
  });

  describe('sanitizeFilename - traversal hardening + extension preservation (Task 11)', () => {
    it('should replace literal .. sequences with __', () => {
      // Two consecutive dots become two consecutive underscores after
      // the post-replacement scrub.
      expect(sanitizeFilename('..')).toBe('__');
    });

    it('should neutralize ../ traversal even after invalid-char replacement', () => {
      // `../etc/passwd` → first replacement turns `/` into `_` so we
      // get `.._etc_passwd`, then the `..`-scrub turns that into
      // `___etc_passwd`. The important property is that no `..`
      // survives anywhere in the result.
      const result = sanitizeFilename('../etc/passwd');
      expect(result).not.toContain('..');
    });

    it('should fully scrub overlapping .... sequences', () => {
      // Four dots: regex /\.\./g is non-overlapping so a single pass
      // turns `....` into `____`.
      expect(sanitizeFilename('....')).toBe('____');
    });

    it('should leave a single dot intact', () => {
      // A lone `.` is not a traversal pattern and should survive.
      expect(sanitizeFilename('.txt')).toBe('.txt');
    });

    it('should replace a triple-dot sequence safely (no .. survives)', () => {
      // `...` after one regex pass becomes `__.`. No `..` remains.
      const result = sanitizeFilename('...');
      expect(result).not.toContain('..');
    });

    it('should preserve the file extension when truncating long names', () => {
      const longName = 'a'.repeat(300) + '.txt';
      const result = sanitizeFilename(longName);
      expect(result.length).toBeLessThanOrEqual(255);
      expect(result.endsWith('.txt')).toBe(true);
      // Base name should be truncated to 255 - len('.txt') = 251.
      expect(result.length).toBe(255);
    });

    it('should preserve a multi-character extension when truncating', () => {
      const longName = 'b'.repeat(300) + '.tar.gz';
      const result = sanitizeFilename(longName);
      expect(result.length).toBeLessThanOrEqual(255);
      // path.extname returns only the LAST extension piece (.gz).
      expect(result.endsWith('.gz')).toBe(true);
    });

    it('should still truncate when there is no extension', () => {
      const longName = 'c'.repeat(300);
      const result = sanitizeFilename(longName);
      expect(result.length).toBeLessThanOrEqual(255);
      expect(result.length).toBe(255);
    });

    it('should not lose the extension on names just over 255 chars', () => {
      const longName = 'd'.repeat(252) + '.txt';
      // Original length is 256; after truncation it must be 255 with
      // the extension intact.
      const result = sanitizeFilename(longName);
      expect(result.length).toBe(255);
      expect(result.endsWith('.txt')).toBe(true);
    });

    it('should preserve names that fit exactly in 255 chars', () => {
      const exact = 'e'.repeat(251) + '.txt';
      expect(exact.length).toBe(255);
      const result = sanitizeFilename(exact);
      expect(result).toBe(exact);
    });

    it('should preserve names well under 255 chars unchanged', () => {
      expect(sanitizeFilename('normal.txt')).toBe('normal.txt');
    });

    it('should still return "file" when sanitization produces empty output', () => {
      // The empty-string short-circuit covers this, but verify the
      // post-sanitization fallback path as well by passing characters
      // that all map to underscore.
      expect(sanitizeFilename('   ')).toBe('_');
    });
  });
});
