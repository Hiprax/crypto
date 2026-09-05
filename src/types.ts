/**
 * Behaviour when a ciphertext is missing the v1 magic header
 * (i.e. it is in the legacy v0 format produced by versions prior
 * to the introduction of the versioned ciphertext format).
 *
 * - `'auto'`   (default) — accept legacy v0 ciphertexts and decrypt them
 *                          using the parameters configured on this CryptoManager.
 * - `'strict'` — reject v0 ciphertexts (error code `LEGACY_FORMAT_REJECTED`).
 * - `'reject'` — reject v0 ciphertexts (error code `UNSUPPORTED_FORMAT`).
 *
 * Encryption always produces v1 output regardless of this option.
 */
export type LegacyMode = 'auto' | 'strict' | 'reject';

/**
 * Configuration options for CryptoManager
 */
export interface CryptoManagerOptions {
  /** Argon2 memory cost (default: 131072 — 2 ** 17, 128 MiB) */
  memoryCost?: number;
  /** Argon2 time cost (default: 3) */
  timeCost?: number;
  /** Argon2 parallelism (default: 1) */
  parallelism?: number;
  /** Custom AAD (Additional Authenticated Data) */
  aad?: string;
  /**
   * Default passphrase to use when no password is provided to
   * encryption/decryption methods.
   *
   * **Memory-retention caveat (defence-in-depth gap).** The library stores
   * this value on the instance as `this.defaultPassphrase: string`. V8
   * strings are immutable and GC-managed; the library cannot scrub them
   * with `secureClear` (which only zero-fills `Buffer`-backed allocations).
   * As a consequence, a `CryptoManager` instance constructed with a
   * `defaultPassphrase` keeps a copy of that passphrase resident in process
   * memory for the entire lifetime of the instance — and V8 may have
   * additional internal copies (string interning, compiler deopt paths)
   * that survive even instance disposal until the next major GC cycle.
   *
   * The threat-model implication is documented in the README "Threat Model"
   * section under "Memory hygiene for buffer-resident secrets" and in
   * SECURITY.md. For long-lived processes that handle sensitive data,
   * **prefer passing the password explicitly to each encrypt/decrypt call**
   * rather than configuring a `defaultPassphrase` — that keeps the
   * password's V8-string lifetime bounded by the call frame rather than
   * the manager instance.
   *
   * Setting `defaultPassphrase: ''` is treated as "not set" and is
   * NOT stored.
   */
  defaultPassphrase?: string;
  /**
   * Controls how legacy (pre-v1) ciphertexts are handled during decryption.
   * Defaults to `'auto'` (accept and decrypt). New ciphertexts are always
   * produced in v1 format regardless of this setting.
   */
  legacyMode?: LegacyMode;
  /**
   * PBKDF2 iteration count used by all sync encrypt/derive paths (default:
   * 600000 — matches the OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256).
   * The chosen value is embedded in every v1 ciphertext header produced by
   * the sync paths, so future decryption uses the embedded value rather than
   * the constructor default. Must be a positive integer.
   */
  pbkdf2Iterations?: number;
  /**
   * PBKDF2 iteration count used to decrypt **legacy v0** sync ciphertexts
   * (those produced before the versioned ciphertext format and which
   * therefore carry no embedded iteration count). Defaults to 100000 — the
   * value baked into every v0 sync ciphertext produced by versions of this
   * library prior to 0.11.0. Override this only if you have legacy data that
   * was produced with a non-default iteration count. Must be a positive
   * integer. Has no effect on v1 ciphertexts (which carry the iteration
   * count embedded in their header).
   */
  legacyPbkdf2Iterations?: number;
  /**
   * If `true`, the constructor will NOT validate `defaultPassphrase` against
   * the password-strength rules. Defaults to `false` (i.e. constructor
   * rejects a weak `defaultPassphrase` with `WEAK_PASSWORD`).
   *
   * Use this only when you need to decrypt legacy data that was encrypted
   * under a password that does not meet the current strength rules. It does
   * NOT relax password validation on encryption — calls to `encryptText` /
   * `encryptFile` (and their sync siblings) still enforce the strength rules
   * on whatever password they end up using. It also does NOT affect Unicode
   * normalisation: passwords are still NFC-normalised before key derivation
   * regardless of this flag.
   */
  skipPasswordValidation?: boolean;
  /**
   * **Backward-compat shim for v1 ciphertexts produced by @hiprax/crypto
   * v1.0.0.** Defaults to `false` (current and recommended behaviour).
   *
   * Background: v1.0.0 introduced the v1 ciphertext format but did NOT bind
   * the v1 header bytes to the AES-GCM Additional Authenticated Data
   * (AAD). v1.1.0 (this release) closes that gap by including the
   * on-disk header bytes verbatim in the AAD passed to
   * `cipher.setAAD` / `decipher.setAAD`. The fix changes the AAD value
   * used for v1 ciphertexts, so v1 ciphertexts produced by v1.0.0 will
   * NOT decrypt under the new default.
   *
   * Set this option to `true` to opt back in to the v1.0.0 AAD format
   * (just `aad`, no header bytes) so legacy ciphertexts continue to
   * decrypt. v0 (legacy unversioned) ciphertexts are unaffected by this
   * option — they always use `aad` only, since they have no header to
   * bind. This option only affects v1 ciphertexts.
   *
   * Recommendation: leave this `false` for any new code. Use it only as a
   * temporary migration aid — re-encrypt your data under v1.1.0+ to get
   * the integrity-bound headers, then turn the flag back off. Documented
   * regression-test name for callers wiring this in:
   * `legacyHeaderAad: backward-compat decrypt of v1.0.0 ciphertexts`.
   */
  legacyHeaderAad?: boolean;
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

// `EncryptionResult` (the `Buffer`-typed result of the low-level
// `CryptoManager.encryptData`) deliberately does NOT live here. This module is
// isomorphic: it is re-exported by `./index.browser.js` and therefore sits in
// the browser declaration graph, where the Node `Buffer` global does not exist.
// A browser-only consumer (`"types": []`, `"skipLibCheck": false`) got two hard
// `TS2591 Cannot find name 'Buffer'` errors from those two fields. The type now
// lives beside its only producer in `./crypto-manager.js` — the Node-only
// module — and is re-exported from `./index.js`, so both public Node import
// paths (`@hiprax/crypto` and `@hiprax/crypto/crypto-manager`) are unchanged.
// `npm run check:types:browser` is the gate that keeps this module Node-free.

/**
 * File encryption progress callback
 */
export interface ProgressCallback {
  (bytesProcessed: number, totalBytes: number): void;
}

/**
 * Retry configuration for operations.
 *
 * Used by {@link retryWithBackoff} (in `./utils.js`) to control how
 * many times a failing async function is retried, the base exponential
 * backoff delay between attempts, and (optionally) a custom predicate
 * controlling whether a particular error should be retried at all.
 */
export interface RetryConfig {
  /** Number of retries after the initial attempt (so total attempts = `maxRetries + 1`). */
  maxRetries: number;
  /**
   * Base delay in milliseconds for the exponential backoff schedule.
   * The actual delay before retry attempt `n` (zero-indexed) is
   * `baseDelay * 2 ** n`.
   */
  baseDelay: number;
  /**
   * Optional predicate that decides whether a particular error should
   * trigger another retry. Called with the captured error and the
   * zero-indexed attempt number that just failed (so the value passed
   * for the first failed attempt is `0`).
   *
   * Return `true` to allow the next retry, `false` to abort
   * immediately and re-throw the captured error to the caller. If the
   * predicate is omitted, `retryWithBackoff` falls back to a built-in
   * default policy that retries every error EXCEPT `CryptoError`s
   * with code `WEAK_PASSWORD` or `INVALID_PASSWORD` (these are
   * surfaced from password-strength / wrong-password failures and
   * retrying them only burns CPU on doomed work). Pass an explicit
   * predicate (`() => true`) to opt back in to the pre-v0.19.0
   * "retry everything" behaviour.
   */
  shouldRetry?: (error: Error, attempt: number) => boolean;
}

/**
 * Validation result for file operations.
 *
 * NOTE: When emitted by `validatePath`, the result reflects only a
 * **syntactic** check of the supplied path string (invalid characters,
 * null bytes, control characters, drive-letter handling, `..` traversal
 * segments, and — when `allowedRoot` is provided — a resolved-prefix
 * containment check). It does NOT touch the filesystem and therefore
 * does NOT detect or prevent traversal via filesystem **symlinks**:
 * a path like `/safe/dir/symlinkToEtc` with no `..` segments will pass
 * validation regardless of where the symlink resolves to. Callers that
 * need symlink-aware containment checks must additionally call
 * `fs.realpath`/`fs.realpathSync` on the resolved path and re-verify
 * the result against their allowed root.
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
 * Optional metadata a caller may attach to a v2 encryption container
 * (`encryptContainer`). Both fields are optional and, when present, are
 * encrypted alongside the payload — they never appear in cleartext anywhere
 * in the container bytes. `size` is NOT accepted here: it is derived from the
 * data length at encryption time and returned in {@link ContainerMetadata}.
 */
export interface ContainerMetadataInput {
  /** Original filename, if any (stored confidentially, UTF-8, ≤ 65535 bytes). */
  filename?: string;
  /** MIME type, if any (stored confidentially, UTF-8, ≤ 65535 bytes). */
  mime?: string;
}

/**
 * Metadata recovered from a v2 container by `decryptContainer`. Mirrors the
 * {@link ContainerMetadataInput} the producer supplied, plus the authenticated
 * `size` (the original plaintext byte length embedded in the container and
 * cross-checked against the decrypted payload during the integrity verify).
 */
export interface ContainerMetadata {
  /** Original filename, if the producer supplied one. */
  filename?: string;
  /** MIME type, if the producer supplied one. */
  mime?: string;
  /** Original plaintext length in bytes (authenticated; equals `data.length`). */
  size: number;
}

/**
 * Result of decrypting a v2 container (`decryptContainer`): the recovered
 * plaintext bytes plus the authenticated {@link ContainerMetadata}. The
 * embedded SHA-256 of the plaintext is verified before this is returned, so a
 * successful return guarantees the payload matches the producer's original
 * bytes (a mismatch throws `CryptoError` / `CONTAINER_INTEGRITY_FAILED`).
 */
export interface DecryptedContainer {
  /** The recovered plaintext bytes (caller owns the buffer). */
  data: Uint8Array;
  /** The authenticated metadata recovered from the container. */
  meta: ContainerMetadata;
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
 * Supported encryption algorithms.
 *
 * Currently only AES-256-GCM (authenticated encryption) is supported. The
 * previously-defined `AES_256_CBC` member was removed in v0.19.0 — it was
 * never instantiated anywhere in the library and CBC is generally
 * discouraged for new code (no built-in authentication, prone to padding
 * oracle attacks). If you need a non-GCM mode in the future, add it to
 * this enum together with a real implementation rather than reserving an
 * unused identifier here.
 */
export enum EncryptionAlgorithm {
  AES_256_GCM = 'aes-256-gcm',
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
