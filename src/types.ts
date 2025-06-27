/**
 * Configuration options for CryptoManager
 */
export interface CryptoManagerOptions {
  /** Argon2 memory cost (default: 65536) */
  memoryCost?: number;
  /** Argon2 time cost (default: 3) */
  timeCost?: number;
  /** Argon2 parallelism (default: 1) */
  parallelism?: number;
  /** Custom AAD (Additional Authenticated Data) */
  aad?: string;
}

/**
 * Argon2 configuration options
 */
export interface Argon2Options {
  type: number;
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  hashLength: number;
  saltLength: number;
}

/**
 * Encryption parameters for debugging/info
 */
export interface EncryptionParameters {
  algorithm: string;
  keyLength: number;
  ivLength: number;
  saltLength: number;
  tagLength: number;
  argon2Options: Argon2Options;
}

/**
 * Result of encryption operation
 */
export interface EncryptionResult {
  encrypted: Buffer;
  tag: Buffer;
}

/**
 * File encryption progress callback
 */
export interface ProgressCallback {
  (bytesProcessed: number, totalBytes: number): void;
}

/**
 * Retry configuration for operations
 */
export interface RetryConfig {
  maxRetries: number;
  baseDelay: number;
}

/**
 * Validation result for file operations
 */
export interface ValidationResult {
  isValid: boolean;
  error?: string;
}

/**
 * File information
 */
export interface FileInfo {
  path: string;
  size: number;
  extension: string;
  isTextFile: boolean;
}

/**
 * Security level enumeration
 */
export enum SecurityLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  ULTRA = 'ultra',
}

/**
 * Supported encryption algorithms
 */
export enum EncryptionAlgorithm {
  AES_256_GCM = 'aes-256-gcm',
  AES_256_CBC = 'aes-256-cbc',
}

/**
 * Error types for better error handling
 */
export enum CryptoErrorType {
  INVALID_PASSWORD = 'INVALID_PASSWORD',
  INVALID_INPUT = 'INVALID_INPUT',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  FILE_ERROR = 'FILE_ERROR',
  MEMORY_ERROR = 'MEMORY_ERROR',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
}

/**
 * Custom error class for crypto operations
 */
export class CryptoError extends Error {
  public readonly type: CryptoErrorType;
  public readonly code: string;

  constructor(
    message: string,
    type: CryptoErrorType = CryptoErrorType.VALIDATION_ERROR,
    code: string = 'CRYPTO_ERROR'
  ) {
    super(message);
    this.name = 'CryptoError';
    this.type = type;
    this.code = code;
  }
}
