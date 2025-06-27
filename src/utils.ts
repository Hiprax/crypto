import crypto from 'node:crypto';
import { access, constants, stat } from 'node:fs/promises';
import path from 'node:path';
import type { ValidationResult, FileInfo, RetryConfig } from './types.js';
import { CryptoError, CryptoErrorType } from './types.js';

/**
 * Validate if a file exists and is accessible
 * @param filePath - Path to the file
 * @returns Promise that resolves to validation result
 */
export async function validateFile(
  filePath: string
): Promise<ValidationResult> {
  if (!filePath || typeof filePath !== 'string') {
    return {
      isValid: false,
      error: 'File path must be a non-empty string',
    };
  }

  try {
    await access(filePath, constants.R_OK);
    return { isValid: true };
  } catch (error) {
    return {
      isValid: false,
      error: `File access error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Validate if a path is valid for writing
 * @param filePath - Path to validate
 * @returns Validation result
 */
export function validatePath(filePath: string): ValidationResult {
  if (!filePath || typeof filePath !== 'string') {
    return {
      isValid: false,
      error: 'File path must be a non-empty string',
    };
  }

  // Check for invalid characters (excluding backslashes for Windows compatibility)
  const invalidChars = /[<>:"|?*]/;
  if (invalidChars.test(filePath)) {
    return {
      isValid: false,
      error: 'File path contains invalid characters',
    };
  }

  // Check for path traversal attempts
  const segments = path.normalize(filePath).split(path.sep);
  // On Windows, ignore the first segment if it's a drive letter (e.g., 'C:')
  const firstSegment = segments[0] ?? '';
  const checkSegments =
    process.platform === 'win32' && /^[a-zA-Z]:$/.test(firstSegment)
      ? segments.slice(1)
      : segments;
  if (checkSegments.includes('..')) {
    return {
      isValid: false,
      error: 'Path traversal is not allowed',
    };
  }

  return { isValid: true };
}

/**
 * Generate a secure random string
 * @param length - Length of the string (default: 32)
 * @returns Random string
 * @throws CryptoError if length is invalid
 */
export function generateRandomString(length: number = 32): string {
  if (!Number.isInteger(length) || length <= 0 || length > 1024) {
    throw new CryptoError(
      'Invalid length for random string generation. Must be between 1 and 1024.',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_RANDOM_STRING_LENGTH'
    );
  }

  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomBytes = crypto.randomBytes(length);

  for (let i = 0; i < length; i++) {
    const randomByte = randomBytes[i];
    if (randomByte !== undefined) {
      result += chars.charAt(randomByte % chars.length);
    }
  }

  return result;
}

/**
 * Format file size in human readable format
 * @param bytes - Size in bytes
 * @returns Formatted size string
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Get file extension
 * @param filePath - File path
 * @returns File extension (lowercase)
 */
export function getFileExtension(filePath: string): string {
  return path.extname(filePath).toLowerCase();
}

/**
 * Check if file is a text file based on extension
 * @param filePath - File path
 * @returns True if text file
 */
export function isTextFile(filePath: string): boolean {
  const textExtensions = [
    '.txt',
    '.md',
    '.json',
    '.js',
    '.ts',
    '.py',
    '.java',
    '.c',
    '.cpp',
    '.h',
    '.html',
    '.css',
    '.xml',
    '.csv',
    '.log',
    '.yaml',
    '.yml',
    '.toml',
    '.ini',
    '.conf',
    '.cfg',
  ];
  return textExtensions.includes(getFileExtension(filePath));
}

/**
 * Sanitize filename for security
 * @param filename - Original filename
 * @returns Sanitized filename
 */
export function sanitizeFilename(filename: string): string {
  if (!filename || typeof filename !== 'string') {
    return 'file';
  }

  // Remove or replace dangerous characters
  return filename
    .replace(/[<>:"/\\|?*]/g, '_')
    .replace(/\s+/g, '_')
    .substring(0, 255); // Limit length
}

/**
 * Create a backup filename
 * @param originalPath - Original file path
 * @param suffix - Suffix to add (default: '.backup')
 * @returns Backup file path
 */
export function createBackupPath(
  originalPath: string,
  suffix: string = '.backup'
): string {
  const dir = path.dirname(originalPath);
  const ext = path.extname(originalPath);
  const name = path.basename(originalPath, ext);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);

  return path.join(dir, `${name}_${timestamp}${suffix}${ext}`);
}

/**
 * Validate base64 string
 * @param str - String to validate
 * @returns True if valid base64
 */
export function isValidBase64(str: string): boolean {
  if (!str || typeof str !== 'string') {
    return false;
  }

  try {
    // Check if it's valid base64
    const decoded = Buffer.from(str, 'base64');
    const reEncoded = decoded.toString('base64');
    return str === reEncoded;
  } catch {
    return false;
  }
}

/**
 * Secure string comparison (constant time)
 * @param a - First string
 * @param b - Second string
 * @returns True if strings are equal
 */
export function secureStringCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Generate a progress bar
 * @param current - Current value
 * @param total - Total value
 * @param width - Bar width (default: 30)
 * @returns Progress bar string
 */
export function createProgressBar(
  current: number,
  total: number,
  width: number = 30
): string {
  if (total <= 0) {
    return '[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%';
  }

  const percentage = Math.min(current / total, 1);
  const filled = Math.round(width * percentage);
  const empty = width - filled;

  const filledBar = '█'.repeat(filled);
  const emptyBar = '░'.repeat(empty);

  return `[${filledBar}${emptyBar}] ${Math.round(percentage * 100)}%`;
}

/**
 * Sleep for a specified number of milliseconds
 * @param ms - Milliseconds to sleep
 * @returns Promise that resolves after the specified time
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => globalThis.setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff
 * @param fn - Function to retry
 * @param config - Retry configuration
 * @returns Promise that resolves to function result
 * @throws Last error if all retries fail
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  config: RetryConfig = { maxRetries: 3, baseDelay: 1000 }
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt === config.maxRetries) {
        throw lastError;
      }

      const delay = config.baseDelay * Math.pow(2, attempt);
      await sleep(delay);
    }
  }

  throw lastError || new Error('Retry failed with unknown error');
}

/**
 * Get file information
 * @param filePath - Path to the file
 * @returns Promise that resolves to file information
 * @throws CryptoError if file access fails
 */
export async function getFileInfo(filePath: string): Promise<FileInfo> {
  try {
    const stats = await stat(filePath);
    const extension = getFileExtension(filePath);

    return {
      path: filePath,
      size: stats.size,
      extension,
      isTextFile: isTextFile(filePath),
    };
  } catch (error) {
    throw new CryptoError(
      `Failed to get file info: ${error instanceof Error ? error.message : 'Unknown error'}`,
      CryptoErrorType.FILE_ERROR,
      'FILE_INFO_FAILED'
    );
  }
}

/**
 * Validate password strength with detailed feedback
 * @param password - Password to validate
 * @returns Object with validation result and feedback
 */
export function validatePasswordStrength(password: string): {
  isValid: boolean;
  score: number;
  feedback: string[];
} {
  const feedback: string[] = [];
  let score = 0;

  if (!password || typeof password !== 'string') {
    return {
      isValid: false,
      score: 0,
      feedback: ['Password must be a non-empty string'],
    };
  }

  // Length check
  if (password.length < 8) {
    feedback.push('Password must be at least 8 characters long');
  } else if (password.length >= 12) {
    score += 2;
  } else {
    score += 1;
  }

  // Character variety checks
  if (/[A-Z]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one uppercase letter');
  }

  if (/[a-z]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one lowercase letter');
  }

  if (/\d/.test(password)) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one number');
  }

  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one special character');
  }

  // Additional strength checks
  if (password.length >= 16) {
    score += 1;
  }

  if (/(.)\1{2,}/.test(password)) {
    score -= 1;
    feedback.push('Avoid repeated characters');
  }

  if (/^(.)\1+$/.test(password)) {
    score -= 2;
    feedback.push('Avoid using the same character repeatedly');
  }

  const isValid = score >= 4 && feedback.length === 0;

  return {
    isValid,
    score: Math.max(0, Math.min(5, score)),
    feedback,
  };
}

/**
 * Generate a secure random UUID v4
 * @returns UUID string
 */
export function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Hash a string using SHA-256
 * @param input - String to hash
 * @returns SHA-256 hash as hex string
 */
export function sha256(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Generate a secure random hex string
 * @param length - Length of hex string (default: 32)
 * @returns Hex string
 * @throws CryptoError if length is invalid
 */
export function generateRandomHex(length: number = 32): string {
  if (!Number.isInteger(length) || length <= 0 || length > 1024) {
    throw new CryptoError(
      'Invalid length for random hex generation. Must be between 1 and 1024.',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_RANDOM_HEX_LENGTH'
    );
  }

  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}
