import crypto from 'node:crypto';
import argon2 from 'argon2';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { dirname } from 'node:path';
import type {
  CryptoManagerOptions,
  Argon2Options,
  EncryptionParameters,
  EncryptionResult,
} from './types.js';
import {
  CryptoError,
  CryptoErrorType,
  SecurityLevel,
  EncryptionAlgorithm,
} from './types.js';

/**
 * High-security encryption manager using AES-256-GCM and Argon2id
 * Implements industry-standard cryptographic practices with improved security
 */
export class CryptoManager {
  private readonly algorithm: string;
  private readonly keyLength: number;
  private readonly ivLength: number;
  private readonly saltLength: number;
  private readonly tagLength: number;
  private readonly argon2Options: Argon2Options;
  private readonly aad: Buffer;
  private readonly defaultPassphrase?: string;

  constructor(options: CryptoManagerOptions = {}) {
    this.algorithm = EncryptionAlgorithm.AES_256_GCM;
    this.keyLength = 32; // 256 bits
    this.ivLength = 12; // 96 bits for GCM
    this.saltLength = 32; // 256 bits
    this.tagLength = 16; // 128 bits for GCM

    // Store default passphrase if provided and not empty
    if (
      options.defaultPassphrase !== undefined &&
      options.defaultPassphrase !== ''
    ) {
      this.defaultPassphrase = options.defaultPassphrase;
    }

    // Argon2id parameters (high security)
    this.argon2Options = {
      type: argon2.argon2id,
      memoryCost: options.memoryCost ?? 2 ** 16, // 64MB
      timeCost: options.timeCost ?? 3,
      parallelism: options.parallelism ?? 1,
      hashLength: this.keyLength,
      saltLength: this.saltLength,
    };

    // Use custom AAD or default
    const aadString = options.aad ?? 'secure-crypto-tool-v2';
    this.aad = Buffer.from(aadString, 'utf8');
  }

  /**
   * Generate cryptographically secure random bytes
   * @param length - Number of bytes to generate
   * @returns Random bytes
   * @throws CryptoError if length is invalid
   */
  public generateSecureRandom(length: number): Buffer {
    if (!Number.isInteger(length) || length <= 0 || length > 1024) {
      throw new CryptoError(
        'Invalid length for random generation. Must be between 1 and 1024 bytes.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_RANDOM_LENGTH'
      );
    }
    return crypto.randomBytes(length);
  }

  /**
   * Derive encryption key from password using Argon2id
   * @param password - User password
   * @param salt - Random salt
   * @returns Derived key
   * @throws CryptoError if derivation fails
   */
  public async deriveKey(password: string, salt: Buffer): Promise<Buffer> {
    if (!password || typeof password !== 'string') {
      throw new CryptoError(
        'Password must be a non-empty string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    if (!Buffer.isBuffer(salt) || salt.length !== this.saltLength) {
      throw new CryptoError(
        `Invalid salt provided. Expected ${this.saltLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_SALT'
      );
    }

    try {
      const key = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: this.argon2Options.memoryCost,
        timeCost: this.argon2Options.timeCost,
        parallelism: this.argon2Options.parallelism,
        hashLength: this.argon2Options.hashLength,
        salt,
        raw: true,
      });

      // Ensure we get exactly the key length we need
      return Buffer.from(key).subarray(0, this.keyLength);
    } catch (error) {
      throw new CryptoError(
        `Key derivation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'KEY_DERIVATION_FAILED'
      );
    }
  }

  /**
   * Derive encryption key from password using PBKDF2 (synchronous alternative to Argon2id)
   * @param password - User password
   * @param salt - Random salt
   * @returns Derived key
   * @throws CryptoError if derivation fails
   */
  public deriveKeySync(password: string, salt: Buffer): Buffer {
    if (!password || typeof password !== 'string') {
      throw new CryptoError(
        'Password must be a non-empty string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    if (!Buffer.isBuffer(salt) || salt.length !== this.saltLength) {
      throw new CryptoError(
        `Invalid salt provided. Expected ${this.saltLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_SALT'
      );
    }

    try {
      // Use PBKDF2 as a synchronous alternative to Argon2id
      // Note: PBKDF2 is less secure than Argon2id but provides synchronous operation
      const iterations = 100000; // High iteration count for security
      const key = crypto.pbkdf2Sync(
        password,
        salt,
        iterations,
        this.keyLength,
        'sha256'
      );

      return key;
    } catch (error) {
      throw new CryptoError(
        `Synchronous key derivation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'SYNC_KEY_DERIVATION_FAILED'
      );
    }
  }

  /**
   * Encrypt data using AES-256-GCM
   * @param data - Data to encrypt
   * @param key - Encryption key
   * @param iv - Initialization vector
   * @returns Encrypted data with auth tag
   * @throws CryptoError if encryption fails
   */
  public encryptData(data: Buffer, key: Buffer, iv: Buffer): EncryptionResult {
    if (!Buffer.isBuffer(data)) {
      throw new CryptoError(
        'Data must be a Buffer',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_DATA'
      );
    }

    if (!Buffer.isBuffer(key) || key.length !== this.keyLength) {
      throw new CryptoError(
        `Invalid key provided. Expected ${this.keyLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_KEY'
      );
    }

    if (!Buffer.isBuffer(iv) || iv.length !== this.ivLength) {
      throw new CryptoError(
        `Invalid IV provided. Expected ${this.ivLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_IV'
      );
    }

    try {
      const cipher = crypto.createCipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.CipherGCM;
      cipher.setAAD(this.aad);

      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      const tag = cipher.getAuthTag();

      return { encrypted, tag };
    } catch (error) {
      throw new CryptoError(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param encryptedData - Encrypted data
   * @param key - Decryption key
   * @param iv - Initialization vector
   * @param tag - Authentication tag
   * @returns Decrypted data
   * @throws CryptoError if decryption fails
   */
  public decryptData(
    encryptedData: Buffer,
    key: Buffer,
    iv: Buffer,
    tag: Buffer
  ): Buffer {
    if (!Buffer.isBuffer(encryptedData)) {
      throw new CryptoError(
        'Encrypted data must be a Buffer',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_ENCRYPTED_DATA'
      );
    }

    if (!Buffer.isBuffer(key) || key.length !== this.keyLength) {
      throw new CryptoError(
        `Invalid key provided. Expected ${this.keyLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_KEY'
      );
    }

    if (!Buffer.isBuffer(iv) || iv.length !== this.ivLength) {
      throw new CryptoError(
        `Invalid IV provided. Expected ${this.ivLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_IV'
      );
    }

    if (!Buffer.isBuffer(tag) || tag.length !== this.tagLength) {
      throw new CryptoError(
        `Invalid authentication tag provided. Expected ${this.tagLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_TAG'
      );
    }

    try {
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.DecipherGCM;
      decipher.setAAD(this.aad);
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encryptedData);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted;
    } catch (error) {
      throw new CryptoError(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.DECRYPTION_FAILED,
        'DECRYPTION_FAILED'
      );
    }
  }

  /**
   * Encrypt text with password
   * @param text - Text to encrypt
   * @param password - Encryption password (optional if default passphrase is set)
   * @returns Base64 encoded encrypted data
   * @throws CryptoError if encryption fails
   */
  public async encryptText(text: string, password?: string): Promise<string> {
    if (!text || typeof text !== 'string') {
      throw new CryptoError(
        'Text must be a non-empty string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_TEXT'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    // Validate password strength
    if (!this.validatePassword(finalPassword)) {
      throw new CryptoError(
        'Password does not meet security requirements',
        CryptoErrorType.INVALID_PASSWORD,
        'WEAK_PASSWORD'
      );
    }

    try {
      // Generate salt and IV
      const salt = this.generateSecureRandom(this.saltLength);
      const iv = this.generateSecureRandom(this.ivLength);

      // Derive key from password
      const key = await this.deriveKey(finalPassword, salt);

      // Encrypt the text
      const textBuffer = Buffer.from(text, 'utf8');
      const { encrypted, tag } = this.encryptData(textBuffer, key, iv);

      // Combine all components: salt + iv + tag + encrypted data
      const combined = Buffer.concat([salt, iv, tag, encrypted]);

      // Clear sensitive data from memory
      this.secureClear(key);
      this.secureClear(textBuffer);

      return combined.toString('base64');
    } catch (error) {
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Text encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'TEXT_ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Decrypt text with password
   * @param encryptedText - Base64 encoded encrypted text
   * @param password - Decryption password (optional if default passphrase is set)
   * @returns Decrypted text
   * @throws CryptoError if decryption fails
   */
  public async decryptText(
    encryptedText: string,
    password?: string
  ): Promise<string> {
    if (!encryptedText || typeof encryptedText !== 'string') {
      throw new CryptoError(
        'Encrypted text must be a non-empty string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_ENCRYPTED_TEXT'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    try {
      // Decode base64
      const combined = Buffer.from(encryptedText, 'base64');

      // Validate minimum size
      const minSize = this.saltLength + this.ivLength + this.tagLength;
      if (combined.length < minSize) {
        throw new CryptoError(
          'Encrypted data is too small to be valid',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_DATA_SIZE'
        );
      }

      // Extract components
      const salt = combined.subarray(0, this.saltLength);
      const iv = combined.subarray(
        this.saltLength,
        this.saltLength + this.ivLength
      );
      const tag = combined.subarray(
        this.saltLength + this.ivLength,
        this.saltLength + this.ivLength + this.tagLength
      );
      const encrypted = combined.subarray(
        this.saltLength + this.ivLength + this.tagLength
      );

      // Derive key from password
      const key = await this.deriveKey(finalPassword, salt);

      // Decrypt the data
      const decrypted = this.decryptData(encrypted, key, iv, tag);

      // Clear sensitive data from memory
      this.secureClear(key);

      return decrypted.toString('utf8');
    } catch (error) {
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Text decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.DECRYPTION_FAILED,
        'TEXT_DECRYPTION_FAILED'
      );
    }
  }

  /**
   * Encrypt text with password (synchronous version)
   * @param text - Text to encrypt
   * @param password - Encryption password (optional if default passphrase is set)
   * @returns Base64 encoded encrypted data
   * @throws CryptoError if encryption fails
   */
  public encryptTextSync(text: string, password?: string): string {
    if (!text || typeof text !== 'string') {
      throw new CryptoError(
        'Text must be a non-empty string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_TEXT'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    // Validate password strength
    if (!this.validatePassword(finalPassword)) {
      throw new CryptoError(
        'Password does not meet security requirements',
        CryptoErrorType.INVALID_PASSWORD,
        'WEAK_PASSWORD'
      );
    }

    try {
      // Generate salt and IV
      const salt = this.generateSecureRandom(this.saltLength);
      const iv = this.generateSecureRandom(this.ivLength);

      // Derive key from password (synchronous)
      const key = this.deriveKeySync(finalPassword, salt);

      // Encrypt the text
      const textBuffer = Buffer.from(text, 'utf8');
      const { encrypted, tag } = this.encryptData(textBuffer, key, iv);

      // Combine all components: salt + iv + tag + encrypted data
      const combined = Buffer.concat([salt, iv, tag, encrypted]);

      // Clear sensitive data from memory
      this.secureClear(key);
      this.secureClear(textBuffer);

      return combined.toString('base64');
    } catch (error) {
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Synchronous text encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'SYNC_TEXT_ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Decrypt text with password (synchronous version)
   * @param encryptedText - Base64 encoded encrypted text
   * @param password - Decryption password (optional if default passphrase is set)
   * @returns Decrypted text
   * @throws CryptoError if decryption fails
   */
  public decryptTextSync(
    encryptedText: string,
    password?: string
  ): string {
    if (!encryptedText || typeof encryptedText !== 'string') {
      throw new CryptoError(
        'Encrypted text must be a non-empty string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_ENCRYPTED_TEXT'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    try {
      // Decode base64
      const combined = Buffer.from(encryptedText, 'base64');

      // Validate minimum size
      const minSize = this.saltLength + this.ivLength + this.tagLength;
      if (combined.length < minSize) {
        throw new CryptoError(
          'Encrypted data is too small to be valid',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_DATA_SIZE'
        );
      }

      // Extract components
      const salt = combined.subarray(0, this.saltLength);
      const iv = combined.subarray(
        this.saltLength,
        this.saltLength + this.ivLength
      );
      const tag = combined.subarray(
        this.saltLength + this.ivLength,
        this.saltLength + this.ivLength + this.tagLength
      );
      const encrypted = combined.subarray(
        this.saltLength + this.ivLength + this.tagLength
      );

      // Derive key from password (synchronous)
      const key = this.deriveKeySync(finalPassword, salt);

      // Decrypt the data
      const decrypted = this.decryptData(encrypted, key, iv, tag);

      // Clear sensitive data from memory
      this.secureClear(key);

      return decrypted.toString('utf8');
    } catch (error) {
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Synchronous text decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.DECRYPTION_FAILED,
        'SYNC_TEXT_DECRYPTION_FAILED'
      );
    }
  }

  /**
   * Encrypt file with password (streaming for large files)
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Encryption password (optional if default passphrase is set)
   * @throws CryptoError if encryption fails
   */
  public async encryptFile(
    inputPath: string,
    outputPath: string,
    password?: string
  ): Promise<void> {
    if (!inputPath || !outputPath) {
      throw new CryptoError(
        'Input path and output path are required',
        CryptoErrorType.INVALID_INPUT,
        'MISSING_REQUIRED_PARAMS'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    // Validate password strength
    if (!this.validatePassword(finalPassword)) {
      throw new CryptoError(
        'Password does not meet security requirements',
        CryptoErrorType.INVALID_PASSWORD,
        'WEAK_PASSWORD'
      );
    }

    try {
      // Check if input file exists
      if (!existsSync(inputPath)) {
        throw new CryptoError(
          `Input file does not exist: ${inputPath}`,
          CryptoErrorType.FILE_ERROR,
          'INPUT_FILE_NOT_FOUND'
        );
      }

      // Ensure output directory exists
      const outputDir = dirname(outputPath);
      if (!existsSync(outputDir)) {
        try {
          await mkdir(outputDir, { recursive: true });
        } catch (dirError) {
          throw new CryptoError(
            `Cannot create output directory: ${dirError instanceof Error ? dirError.message : 'Unknown error'}`,
            CryptoErrorType.FILE_ERROR,
            'OUTPUT_DIR_CREATION_FAILED'
          );
        }
      }

      // Generate salt and IV
      const salt = this.generateSecureRandom(this.saltLength);
      const iv = this.generateSecureRandom(this.ivLength);

      // Derive key from password
      const key = await this.deriveKey(finalPassword, salt);

      // Write header: salt + iv
      const header = Buffer.concat([salt, iv]);
      await writeFile(outputPath, header);

      // Create encryption transform stream
      const cipher = crypto.createCipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.CipherGCM;
      cipher.setAAD(this.aad);

      // Create streams
      const inputStream = createReadStream(inputPath);
      const outputStream = createWriteStream(outputPath, { flags: 'a' });

      // Pipe through encryption
      await pipeline(inputStream, cipher, outputStream);

      // Write authentication tag
      const tag = cipher.getAuthTag();
      await writeFile(outputPath, tag, { flag: 'a' });

      // Clear sensitive data
      this.secureClear(key);
    } catch (error) {
      // Clean up partial output file if it exists
      try {
        if (existsSync(outputPath)) {
          await writeFile(outputPath, ''); // Clear the file
        }
      } catch {
        // Ignore cleanup errors
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `File encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'FILE_ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Decrypt file with password (streaming for large files)
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Decryption password (optional if default passphrase is set)
   * @throws CryptoError if decryption fails
   */
  public async decryptFile(
    inputPath: string,
    outputPath: string,
    password?: string
  ): Promise<void> {
    if (!inputPath || !outputPath) {
      throw new CryptoError(
        'Input path and output path are required',
        CryptoErrorType.INVALID_INPUT,
        'MISSING_REQUIRED_PARAMS'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    try {
      // Check if input file exists
      if (!existsSync(inputPath)) {
        throw new CryptoError(
          `Input file does not exist: ${inputPath}`,
          CryptoErrorType.FILE_ERROR,
          'INPUT_FILE_NOT_FOUND'
        );
      }

      // Ensure output directory exists
      const outputDir = dirname(outputPath);
      if (!existsSync(outputDir)) {
        try {
          await mkdir(outputDir, { recursive: true });
        } catch (dirError) {
          throw new CryptoError(
            `Cannot create output directory: ${dirError instanceof Error ? dirError.message : 'Unknown error'}`,
            CryptoErrorType.FILE_ERROR,
            'OUTPUT_DIR_CREATION_FAILED'
          );
        }
      }

      // Read the entire file to get its size
      const fileBuffer = await readFile(inputPath);

      // Calculate positions
      const headerSize = this.saltLength + this.ivLength;
      const tagStart = fileBuffer.length - this.tagLength;

      // Validate file size
      if (fileBuffer.length < headerSize + this.tagLength) {
        throw new CryptoError(
          'File is too small to be a valid encrypted file',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_FILE_SIZE'
        );
      }

      // Extract components
      const salt = fileBuffer.slice(0, this.saltLength);
      const iv = fileBuffer.slice(this.saltLength, headerSize);
      const tag = fileBuffer.slice(tagStart);
      const encryptedData = fileBuffer.slice(headerSize, tagStart);

      // Derive key from password
      const key = await this.deriveKey(finalPassword, salt);

      // Create decryption transform stream
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.DecipherGCM;
      decipher.setAAD(this.aad);
      decipher.setAuthTag(tag);

      // Decrypt the data
      let decrypted = decipher.update(encryptedData);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      // Write decrypted data
      await writeFile(outputPath, decrypted);

      // Clear sensitive data
      this.secureClear(key);
    } catch (error) {
      // Clean up partial output file if it exists
      try {
        if (existsSync(outputPath)) {
          await writeFile(outputPath, ''); // Clear the file
        }
      } catch {
        // Ignore cleanup errors
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `File decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.DECRYPTION_FAILED,
        'FILE_DECRYPTION_FAILED'
      );
    }
  }

  /**
   * Encrypt file with password (synchronous version)
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Encryption password (optional if default passphrase is set)
   * @throws CryptoError if encryption fails
   */
  public encryptFileSync(
    inputPath: string,
    outputPath: string,
    password?: string
  ): void {
    if (!inputPath || !outputPath) {
      throw new CryptoError(
        'Input path and output path are required',
        CryptoErrorType.INVALID_INPUT,
        'MISSING_REQUIRED_PARAMS'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    // Validate password strength
    if (!this.validatePassword(finalPassword)) {
      throw new CryptoError(
        'Password does not meet security requirements',
        CryptoErrorType.INVALID_PASSWORD,
        'WEAK_PASSWORD'
      );
    }

    try {
      // Check if input file exists
      if (!existsSync(inputPath)) {
        throw new CryptoError(
          `Input file does not exist: ${inputPath}`,
          CryptoErrorType.FILE_ERROR,
          'INPUT_FILE_NOT_FOUND'
        );
      }

      // Ensure output directory exists
      const outputDir = dirname(outputPath);
      if (!existsSync(outputDir)) {
        try {
          mkdirSync(outputDir, { recursive: true });
        } catch (dirError) {
          throw new CryptoError(
            `Cannot create output directory: ${dirError instanceof Error ? dirError.message : 'Unknown error'}`,
            CryptoErrorType.FILE_ERROR,
            'OUTPUT_DIR_CREATION_FAILED'
          );
        }
      }

      // Generate salt and IV
      const salt = this.generateSecureRandom(this.saltLength);
      const iv = this.generateSecureRandom(this.ivLength);

      // Derive key from password (synchronous)
      const key = this.deriveKeySync(finalPassword, salt);

      // Read input file
      const inputData = readFileSync(inputPath);

      // Create encryption transform
      const cipher = crypto.createCipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.CipherGCM;
      cipher.setAAD(this.aad);

      // Encrypt the data
      let encrypted = cipher.update(inputData);
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      // Get authentication tag
      const tag = cipher.getAuthTag();

      // Write header: salt + iv
      const header = Buffer.concat([salt, iv]);
      writeFileSync(outputPath, header);

      // Write encrypted data
      writeFileSync(outputPath, encrypted, { flag: 'a' });

      // Write authentication tag
      writeFileSync(outputPath, tag, { flag: 'a' });

      // Clear sensitive data
      this.secureClear(key);
    } catch (error) {
      // Clean up partial output file if it exists
      try {
        if (existsSync(outputPath)) {
          writeFileSync(outputPath, ''); // Clear the file
        }
      } catch {
        // Ignore cleanup errors
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Synchronous file encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'SYNC_FILE_ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Decrypt file with password (synchronous version)
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Decryption password (optional if default passphrase is set)
   * @throws CryptoError if decryption fails
   */
  public decryptFileSync(
    inputPath: string,
    outputPath: string,
    password?: string
  ): void {
    if (!inputPath || !outputPath) {
      throw new CryptoError(
        'Input path and output path are required',
        CryptoErrorType.INVALID_INPUT,
        'MISSING_REQUIRED_PARAMS'
      );
    }

    // Use provided password or default passphrase
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    try {
      // Check if input file exists
      if (!existsSync(inputPath)) {
        throw new CryptoError(
          `Input file does not exist: ${inputPath}`,
          CryptoErrorType.FILE_ERROR,
          'INPUT_FILE_NOT_FOUND'
        );
      }

      // Ensure output directory exists
      const outputDir = dirname(outputPath);
      if (!existsSync(outputDir)) {
        try {
          mkdirSync(outputDir, { recursive: true });
        } catch (dirError) {
          throw new CryptoError(
            `Cannot create output directory: ${dirError instanceof Error ? dirError.message : 'Unknown error'}`,
            CryptoErrorType.FILE_ERROR,
            'OUTPUT_DIR_CREATION_FAILED'
          );
        }
      }

      // Read the entire file
      const fileBuffer = readFileSync(inputPath);

      // Calculate positions
      const headerSize = this.saltLength + this.ivLength;
      const tagStart = fileBuffer.length - this.tagLength;

      // Validate file size
      if (fileBuffer.length < headerSize + this.tagLength) {
        throw new CryptoError(
          'File is too small to be a valid encrypted file',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_FILE_SIZE'
        );
      }

      // Extract components
      const salt = fileBuffer.slice(0, this.saltLength);
      const iv = fileBuffer.slice(this.saltLength, headerSize);
      const tag = fileBuffer.slice(tagStart);
      const encryptedData = fileBuffer.slice(headerSize, tagStart);

      // Derive key from password (synchronous)
      const key = this.deriveKeySync(finalPassword, salt);

      // Create decryption transform
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.DecipherGCM;
      decipher.setAAD(this.aad);
      decipher.setAuthTag(tag);

      // Decrypt the data
      let decrypted = decipher.update(encryptedData);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      // Write decrypted data
      writeFileSync(outputPath, decrypted);

      // Clear sensitive data
      this.secureClear(key);
    } catch (error) {
      // Clean up partial output file if it exists
      try {
        if (existsSync(outputPath)) {
          writeFileSync(outputPath, ''); // Clear the file
        }
      } catch {
        // Ignore cleanup errors
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Synchronous file decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.DECRYPTION_FAILED,
        'SYNC_FILE_DECRYPTION_FAILED'
      );
    }
  }

  /**
   * Securely clear sensitive data from memory
   * @param buffer - Buffer to clear
   */
  public secureClear(buffer: Buffer): void {
    if (buffer && Buffer.isBuffer(buffer)) {
      buffer.fill(0);
    }
  }

  /**
   * Validate password strength
   * @param password - Password to validate
   * @returns True if password meets requirements
   */
  public validatePassword(password: string): boolean {
    if (!password || typeof password !== 'string') {
      return false;
    }

    // Minimum 8 characters, at least one uppercase, one lowercase, one number, one special character
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return (
      password.length >= minLength &&
      hasUpperCase &&
      hasLowerCase &&
      hasNumbers &&
      hasSpecialChar
    );
  }

  /**
   * Get encryption parameters for debugging/info
   * @returns Current encryption parameters
   */
  public getParameters(): EncryptionParameters {
    return {
      algorithm: this.algorithm,
      keyLength: this.keyLength,
      ivLength: this.ivLength,
      saltLength: this.saltLength,
      tagLength: this.tagLength,
      argon2Options: { ...this.argon2Options },
    };
  }

  /**
   * Get security level based on current configuration
   * @returns Security level
   */
  public getSecurityLevel(): SecurityLevel {
    const { memoryCost, timeCost } = this.argon2Options;

    if (memoryCost >= 2 ** 18 && timeCost >= 4) {
      return SecurityLevel.ULTRA;
    } else if (memoryCost >= 2 ** 16 && timeCost >= 3) {
      return SecurityLevel.HIGH;
    } else if (memoryCost >= 2 ** 14 && timeCost >= 2) {
      return SecurityLevel.MEDIUM;
    } else {
      return SecurityLevel.LOW;
    }
  }

  /**
   * Check if a default passphrase is set
   * @returns True if default passphrase is configured
   */
  public hasDefaultPassphrase(): boolean {
    return (
      this.defaultPassphrase !== undefined && this.defaultPassphrase !== ''
    );
  }
}
