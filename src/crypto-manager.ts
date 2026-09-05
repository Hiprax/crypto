import crypto from 'node:crypto';
import {
  open as fsOpen,
  rename as fsRename,
  copyFile as fsCopyFile,
  mkdir,
  unlink,
} from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import {
  existsSync,
  writeFileSync,
  mkdirSync,
  unlinkSync,
  renameSync,
  openSync,
  closeSync,
  fstatSync,
  readSync,
  copyFileSync,
} from 'node:fs';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { dirname } from 'node:path';
import type { CryptoManagerOptions, ProgressCallback } from './types.js';
import { CryptoError, CryptoErrorType } from './types.js';
import {
  HEADER_LENGTH,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  hasMagic,
  parseHeader,
  assertGcmPlaintextLimit,
} from './format.js';
import { CryptoCore, SECURITY_THRESHOLDS, isValidPassword } from './core.js';
import { loadArgon2, nodeEngine } from './engine.node.js';
import type { Argon2Hasher, Argon2Provider } from './engine.node.js';

// The Argon2 lazy-load implementation (native `argon2` → pure-WASM `hash-wasm`
// fallback) lives in `engine.node.ts` as of the engine refactor. Re-export the
// internal test-only cache hooks and the provider/hasher types here so existing
// imports from `./crypto-manager` continue to resolve unchanged.
export {
  __resetArgon2ModuleCacheForTesting,
  __peekArgon2ProviderForTesting,
} from './engine.node.js';
export type { Argon2Hasher, Argon2Provider };

// `SECURITY_THRESHOLDS` and `isValidPassword` now live in the isomorphic core
// (`./core.js`) so the shared constructor validation and `getSecurityLevel`
// classification can use them without a runtime dependency. Re-export them here
// so existing imports from `./crypto-manager` (and `./index`) resolve unchanged.
export { SECURITY_THRESHOLDS, isValidPassword };

// The v2 container version byte, so a consumer can name the format this library
// produces instead of hard-coding `0x02`. `FORMAT_VERSION` (0x01) already
// reaches the entry points through `./format.js`; this is its v2 counterpart,
// and `./crypto-manager.browser.js` re-exports it identically so both entries
// expose the same name. A pure pass-through — nothing in this module's body
// uses it — hence a `export … from` statement rather than an import binding.
export { CONTAINER_VERSION } from './core.js';

/**
 * Symbol used to mark an error that was thrown by a user-supplied
 * {@link ProgressCallback}. The catch blocks in the file methods detect
 * this marker and re-throw the error as-is (preserving identity) instead of
 * wrapping it in `CryptoError(FILE_*_FAILED)` — the latter would obscure
 * the caller's own throw site, making the bug harder to diagnose.
 *
 * The marker is attached non-enumerably to avoid leaking it into JSON
 * serialisations and equality checks, and is local to this module so user
 * code cannot forge it.
 */
const PROGRESS_THROW: unique symbol = Symbol('PROGRESS_THROW');

/**
 * Tag a thrown value as originating from a user-supplied
 * {@link ProgressCallback}. The caller's identity is preserved when
 * possible (Error instances are mutated in place); non-Error throws are
 * wrapped into a fresh `Error` so we have a place to attach the marker.
 */
function tagProgressThrow(thrown: unknown): unknown {
  if (thrown !== null && typeof thrown === 'object') {
    try {
      Object.defineProperty(thrown, PROGRESS_THROW, {
        value: true,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      return thrown;
    } catch {
      // Some host objects refuse new properties (e.g. frozen Errors); fall
      // through to wrapping below.
    }
  }
  const wrapped = new Error(
    typeof thrown === 'string' ? thrown : 'Progress callback threw'
  );
  Object.defineProperty(wrapped, PROGRESS_THROW, {
    value: true,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  // Surface the original thrown value as `cause` for debuggability.
  Object.defineProperty(wrapped, 'cause', {
    value: thrown,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return wrapped;
}

/**
 * Test whether a thrown value carries the {@link PROGRESS_THROW} marker.
 */
function isProgressThrow(thrown: unknown): boolean {
  return (
    thrown !== null &&
    typeof thrown === 'object' &&
    (thrown as { [PROGRESS_THROW]?: true })[PROGRESS_THROW] === true
  );
}

/**
 * Result of encryption operation
 *
 * Declared here rather than in `./types.js` because it names the Node
 * `Buffer` global and `./types.js` is isomorphic — it is re-exported by
 * `./index.browser.js`, so a `Buffer` in it lands in the browser declaration
 * graph and breaks any browser-only consumer compiled without `@types/node`.
 * {@link CryptoManager.encryptData} is its only producer and lives in this
 * Node-only module, so this is where it belongs. It is re-exported from
 * `./index.js`, so `import type { EncryptionResult } from '@hiprax/crypto'` —
 * the path that carried it before — keeps working unchanged. Declaring it
 * here additionally exposes it on `@hiprax/crypto/crypto-manager`, which it
 * was NOT reachable from previously: that subpath's declarations only ever
 * type-IMPORTED the name from `./types.js` and never re-exported it. So the
 * Node surface strictly grows; only the browser entry loses the name, which
 * is the point (it names a global browsers do not have, and no browser API
 * produces one).
 */
export interface EncryptionResult {
  encrypted: Buffer;
  tag: Buffer;
}

/**
 * High-security encryption manager using AES-256-GCM and Argon2id
 * Implements industry-standard cryptographic practices with improved security
 */
export class CryptoManager extends CryptoCore {
  /**
   * Construct a Node `CryptoManager`. All option validation and the shared
   * isomorphic API live in {@link CryptoCore}; this constructor only injects
   * the Node {@link nodeEngine} and the Node default Argon2id profile (the
   * HIGH tier at `p=1` — 128 MiB / t=3 / p=1).
   *
   * @param options - see {@link CryptoManagerOptions}
   */
  constructor(options: CryptoManagerOptions = {}) {
    super(options, nodeEngine, {
      memoryCost: SECURITY_THRESHOLDS.HIGH.memoryCost, // 128 MiB
      timeCost: SECURITY_THRESHOLDS.HIGH.timeCost,
      parallelism: 1,
    });
  }

  /**
   * Node override of the {@link CryptoCore.encodeBase64url} seam: encode with
   * `Buffer.prototype.toString('base64url')` instead of the pure codec.
   *
   * This is an implementation swap behind an identical byte contract, not a
   * fork — `Buffer`'s base64url encoder emits the same canonical, unpadded,
   * URL-safe string the pure `bytesToBase64url` (`./codec.js`) does, for every input
   * (pinned byte-for-byte in `src/__tests__/codec-seam.test.ts`, and pinned
   * against `Buffer` as an oracle inside `src/__tests__/codec.test.ts`). It is
   * used because the native encoder is roughly two orders of magnitude faster
   * on large payloads, which is what `encryptText` spends most of its
   * non-KDF time on. The browser build deliberately does NOT override this
   * and keeps running the pure reference implementation.
   *
   * The non-`Buffer` branch wraps the input as a **view** — `Buffer.from(ab,
   * byteOffset, byteLength)` — rather than `Buffer.from(bytes)`, which would
   * copy. It is the hot branch: `encryptText` encodes the plain `Uint8Array`
   * that `CryptoCore.encryptBytes` assembles via `concatBytes`. The view is
   * read-only here and dies with the call, so the caller's buffer is neither
   * mutated nor retained (`encryptText` scrubs it immediately afterwards, and
   * `toString` has already materialised the string by then).
   *
   * @param bytes - bytes to encode (not mutated)
   * @returns the canonical unpadded base64url encoding of `bytes`
   */
  protected override encodeBase64url(bytes: Uint8Array): string {
    return Buffer.isBuffer(bytes)
      ? bytes.toString('base64url')
      : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString(
          'base64url'
        );
  }

  /**
   * Node override of the {@link CryptoCore.decodeBase64url} seam: decode with
   * `Buffer.from(s, 'base64url')` instead of the pure codec.
   *
   * `Buffer`'s base64 decoder is the exact oracle the pure
   * `base64urlToBytes` (`./codec.js`) was written against, leniency included (`=`
   * terminates, non-alphabet code units are skipped, `+`/`/` are accepted,
   * each UTF-16 code unit is truncated to its low 8 bits, an incomplete
   * trailing sextet is discarded), so swapping it in changes no accepted
   * input and no decoded byte.
   *
   * The returned `Buffer` is a **pooled** view — into a shared backing store,
   * at a possibly non-zero `byteOffset` — for any decode small enough that
   * Node serves it from its shared internal pool. Deliberately not stated as a
   * fixed byte count: the pool is sized by `Buffer.poolSize`, whose default
   * has differed across releases, and the decision is made on an ESTIMATE of
   * the decoded length rather than on the length itself, so the real crossover
   * does not sit on `Buffer.poolSize >>> 1`. The seam test discovers it at run
   * time instead of assuming it. That is safe for every
   * consumer: `format-core.ts`'s `viewOf` and `core.ts`'s `viewOf` bind
   * `byteOffset`/`byteLength` explicitly, `CryptoCore.decryptBytes` extracts
   * its components with `subarray`, and `secureClear`'s `fill(0)` zeroes only
   * this view's own range rather than the shared pool. `decryptTextSync` has
   * always fed the same pooled buffer to the same parsing code.
   *
   * @param s - the encoded string
   * @returns the decoded bytes (a pooled `Buffer` view for small results)
   */
  protected override decodeBase64url(s: string): Uint8Array {
    return Buffer.from(s, 'base64url');
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
   * @param overrides - Optional overrides for Argon2 parameters (used when
   *   decrypting v1 ciphertexts that embed parameters that differ from this
   *   CryptoManager's configured defaults).
   * @returns Derived key
   * @throws CryptoError if derivation fails
   */
  public async deriveKey(
    password: string,
    salt: Buffer,
    overrides?: { memoryCost: number; timeCost: number; parallelism: number }
  ): Promise<Buffer> {
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

    // Lazy-load an Argon2id hasher on first use. The loader tries the
    // native `argon2` module first and falls back to the pure-WASM
    // `hash-wasm` module if native is unavailable; both producers are
    // RFC 9106 Argon2id implementations and produce bit-identical raw
    // output for the same parameters, so the fallback never changes
    // ciphertext compatibility. If BOTH providers fail (no build tools
    // AND no hash-wasm installed), this throws CryptoError with code
    // `ARGON2_NOT_AVAILABLE` and an actionable message pointing at all
    // three fix paths (build tools / hash-wasm / *Sync PBKDF2 methods).
    // We do NOT wrap this in the try/catch below because we want the
    // load failure to bubble up with its own specific error code, not
    // get rewritten as `KEY_DERIVATION_FAILED`.
    const hasher: Argon2Hasher = await loadArgon2();

    try {
      const memoryCost = overrides?.memoryCost ?? this.argon2Options.memoryCost;
      const timeCost = overrides?.timeCost ?? this.argon2Options.timeCost;
      const parallelism =
        overrides?.parallelism ?? this.argon2Options.parallelism;

      // Apply Unicode NFC normalisation so visually-identical passwords
      // produce the same key regardless of how the input method composed
      // them. Without this, `'café'` typed via a precomposed `é`
      // (U+00E9, NFC) and the same character typed via `e` + combining
      // acute (U+0065 U+0301, NFD) would derive different keys despite
      // looking identical to the user. NFC is the form most input
      // methods produce and is the canonical W3C recommendation for
      // text-on-the-wire.
      const normalizedPassword = password.normalize('NFC');

      const key = await hasher.hash(normalizedPassword, {
        memoryCost,
        timeCost,
        parallelism,
        hashLength: this.argon2Options.hashLength,
        salt,
      });

      // Ensure we get exactly the key length we need
      return key.subarray(0, this.keyLength);
    } catch (error) {
      // Preserve `ARGON2_NOT_AVAILABLE` and any other CryptoError thrown
      // upstream — only wrap genuinely opaque errors from argon2.hash().
      if (error instanceof CryptoError) {
        throw error;
      }
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
   * @param iterations - Optional iteration count (used when decrypting v1
   *   ciphertexts that embed an iteration count that differs from the default).
   * @returns Derived key
   * @throws CryptoError if derivation fails
   */
  public deriveKeySync(
    password: string,
    salt: Buffer,
    iterations?: number
  ): Buffer {
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
      // Use PBKDF2 as a synchronous alternative to Argon2id.
      // Note: PBKDF2 is less secure than Argon2id but provides synchronous
      // operation. When called with no `iterations` argument we use the
      // instance-configured iteration count, which defaults to 600,000
      // (OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256).
      const effectiveIterations = iterations ?? this.pbkdf2Iterations;
      // Apply Unicode NFC normalisation so visually-identical passwords
      // produce the same key regardless of how the input method composed
      // them. See the matching note in `deriveKey` (async path) for the
      // detailed rationale; the same hazard applies to PBKDF2-HMAC-SHA256
      // because Node's `crypto.pbkdf2Sync` UTF-8-encodes the string and
      // hashes the resulting bytes verbatim.
      const normalizedPassword = password.normalize('NFC');
      const key = crypto.pbkdf2Sync(
        normalizedPassword,
        salt,
        effectiveIterations,
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
   * Encrypt data using AES-256-GCM.
   *
   * @security **(key, iv) reuse is catastrophic.** AES-GCM provides
   * confidentiality AND authenticity ONLY as long as no `(key, iv)` pair is
   * ever used to encrypt two different plaintexts. If a pair is reused:
   *
   *   1. An attacker who observes both ciphertexts can XOR them to recover
   *      the XOR of the plaintexts (the keystream cancels out — this is the
   *      classic "two-time pad" break and is sufficient to read the
   *      messages in many real-world settings).
   *   2. An attacker recovers the GCM authentication subkey (`H`) and can
   *      forge arbitrary authenticated ciphertexts under that key. This is
   *      *much worse* than a confidentiality break — the auth tag is no
   *      longer trustworthy on any subsequent message.
   *
   * Callers of this low-level API are therefore responsible for ensuring:
   *
   *   - **Each `(key, iv)` pair is used at most once.** The recommended
   *     pattern is a fresh random 12-byte IV per message via
   *     {@link generateSecureRandom} (96-bit random IVs collide after roughly
   *     `2 ** 32` invocations under the same key per NIST SP 800-38D).
   *   - **At most ~`2 ** 32` invocations per key.** Beyond this birthday
   *     bound the random-IV strategy becomes unsafe; rotate the key (e.g.
   *     re-derive with a fresh salt).
   *
   * The high-level methods {@link encryptText} / {@link encryptFile} (and
   * their Sync siblings) avoid this footgun by deriving a fresh key from a
   * fresh per-message salt AND generating a fresh random IV — collisions
   * across messages would require a salt collision, which is negligible.
   * If you call `encryptData` directly, you take on the IV-uniqueness
   * obligation yourself.
   *
   * Note: GCM with a fixed `(key, iv)` is **deterministic** — encrypting the
   * same plaintext twice produces an identical `(encrypted, tag)` pair. This
   * is *not* a feature; it is a symptom of the attack surface above. The
   * test `encryptData with reused key+iv (security boundary documentation)`
   * encodes this property as a regression guardrail and serves to motivate
   * why a fresh IV is required for every message.
   *
   * @param data - Data to encrypt
   * @param key - Encryption key (32 bytes)
   * @param iv - Initialization vector (12 bytes — caller-supplied, MUST be
   *   unique for every call under the same key)
   * @param aadOverride - Optional AAD to use instead of `this.aad`. Used
   *   internally by the high-level v1 paths to bind the on-disk header
   *   bytes to the auth tag (so any header tampering — including in
   *   reserved regions — flips the tag and decryption fails). External
   *   callers SHOULD NOT pass this argument unless they understand the
   *   wire-format implications: the same exact AAD must be supplied to
   *   {@link decryptData} or decryption will throw `DECRYPTION_FAILED`.
   * @returns Encrypted data with auth tag
   * @throws CryptoError if encryption fails
   * @throws CryptoError `INVALID_INPUT` / `DATA_TOO_LARGE_FOR_GCM` if the
   *   plaintext exceeds `MAX_GCM_PLAINTEXT_BYTES` (NIST SP 800-38D section
   *   5.2.1.1). There is no opt-out; past that bound AES-GCM's block counter
   *   wraps and the ciphertext has neither confidentiality nor authenticity.
   */
  public encryptData(
    data: Buffer,
    key: Buffer,
    iv: Buffer,
    aadOverride?: Buffer
  ): EncryptionResult {
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

    if (aadOverride !== undefined && !Buffer.isBuffer(aadOverride)) {
      throw new CryptoError(
        'aadOverride must be a Buffer when provided',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_AAD'
      );
    }

    // Outside the try below on purpose: that catch rewrites every exception
    // into the generic `ENCRYPTION_FAILED`, which would erase the typed
    // `DATA_TOO_LARGE_FOR_GCM` code callers need to distinguish "your input
    // is too big for GCM" from "the cipher blew up".
    assertGcmPlaintextLimit(data.length, 'DATA_TOO_LARGE_FOR_GCM');

    try {
      const cipher = crypto.createCipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.CipherGCM;
      cipher.setAAD(aadOverride ?? this.aad);

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
   * Decrypt data using AES-256-GCM.
   *
   * @security The `(key, iv)` reuse hazard described on {@link encryptData}
   * applies symmetrically to decryption: the caller MUST supply the exact
   * same `(key, iv, tag, aad)` quadruple that was used to encrypt. The auth
   * tag verifies integrity *and* the binding to the IV — a tag check
   * failure here either means the ciphertext was tampered with, the wrong
   * key/IV was supplied, or the ciphertext was originally produced under a
   * different `aad`. All such failures surface as `CryptoError(code:
   * 'DECRYPTION_FAILED')` with a deliberately generic message to avoid
   * leaking which of those conditions failed (an oracle would aid attackers
   * mounting a chosen-ciphertext attack).
   *
   * @param encryptedData - Encrypted data
   * @param key - Decryption key (32 bytes — must match the key used to
   *   encrypt)
   * @param iv - Initialization vector (12 bytes — must match the IV used
   *   to encrypt)
   * @param tag - Authentication tag (16 bytes — produced by encryption)
   * @param aadOverride - Optional AAD that must equal the AAD used at
   *   encrypt time. Used internally by the high-level v1 paths to bind
   *   the v1 header to the auth tag (any header tampering then flips the
   *   tag and decryption fails). External callers SHOULD NOT pass this
   *   argument unless they explicitly used a matching `aadOverride` at
   *   encrypt time. Mismatch surfaces as `DECRYPTION_FAILED`.
   * @returns Decrypted data
   * @throws CryptoError if decryption fails (wrong key/IV/AAD, tampered
   *   ciphertext, or tag mismatch — all surfaced as the same generic
   *   `DECRYPTION_FAILED` code).
   * @throws CryptoError `INVALID_INPUT` / `DATA_TOO_LARGE_FOR_GCM` if the
   *   ciphertext body exceeds `MAX_GCM_PLAINTEXT_BYTES` (NIST SP 800-38D
   *   section 5.2.1.1) — such a body could only come from a counter-wrapped,
   *   already-broken encryption.
   */
  public decryptData(
    encryptedData: Buffer,
    key: Buffer,
    iv: Buffer,
    tag: Buffer,
    aadOverride?: Buffer
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

    if (aadOverride !== undefined && !Buffer.isBuffer(aadOverride)) {
      throw new CryptoError(
        'aadOverride must be a Buffer when provided',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_AAD'
      );
    }

    // Outside the try below on purpose (see encryptData): that catch rewrites
    // every exception into the generic `DECRYPTION_FAILED`. A ciphertext this
    // large could only have come from a counter-wrapped encryption, so it is
    // refused rather than fed to the decipher.
    assertGcmPlaintextLimit(encryptedData.length, 'DATA_TOO_LARGE_FOR_GCM');

    try {
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.DecipherGCM;
      decipher.setAAD(aadOverride ?? this.aad);
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
   * Build a sibling temp-file path for atomic file output. Writers stream to
   * this path and rename to the final `outputPath` only on success; readers
   * therefore never observe a half-written file at the canonical path.
   *
   * Using `crypto.randomBytes(8).toString('hex')` yields 64 bits of entropy in
   * the suffix — large enough to make collisions effectively impossible when
   * many concurrent encryptors target the same directory. The `.tmp`
   * extension keeps it obvious to humans that the file is transient.
   */
  private buildTempOutputPath(outputPath: string): string {
    const suffix = crypto.randomBytes(8).toString('hex');
    return `${outputPath}.${suffix}.tmp`;
  }

  /**
   * Open `inputPath` for reading, mapping a missing file to the historical
   * `CryptoError(FILE_ERROR, 'INPUT_FILE_NOT_FOUND')` contract.
   *
   * This is the async counterpart of the open-first pattern `encryptFileSync`
   * and `decryptFileSync` already use, and it exists for two reasons:
   *
   * 1. **No TOCTOU window.** An `existsSync` pre-check followed by a later
   *    open answers a question about a *name* at time T and then acts on
   *    whatever that name resolves to at time T+1. Opening directly asks the
   *    kernel once and keeps the answer.
   * 2. **One descriptor for the whole operation.** The returned handle serves
   *    every subsequent read — the small positional front-matter/tag reads
   *    AND the body stream, via {@link FileHandle.createReadStream} — so an
   *    operation performs exactly one name lookup and pins exactly one inode.
   *    Previously the body was streamed by re-resolving `inputPath`, which
   *    could land on a different file than the one whose header was parsed.
   *
   * Any error other than `ENOENT` propagates unchanged (`EACCES`, `EISDIR`,
   * `ELOOP`, …) so the caller's outer catch wraps it as `FILE_*_FAILED`,
   * exactly as before.
   *
   * **Lifecycle contract for callers:** close the returned handle
   * unconditionally in a `finally`. `FileHandle.close()` is idempotent (a
   * second call resolves against the same settled close and issues no second
   * `close(2)`, so it can never close a recycled descriptor), and a stream
   * derived from the handle with the default `autoClose: true` only closes it
   * on `end`/`error` — neither of which fires for a stream that is
   * constructed but never consumed. An ownership flag that skips the close
   * when a stream was created therefore leaks the descriptor; an
   * unconditional close does not.
   *
   * Wrap that close best-effort (`try { await h.close(); } catch {}`), as the
   * sync paths do for `closeSync(inputFd)`: the handle is read-only, so a
   * close failure costs nothing, whereas letting it escape a `finally` would
   * discard already-completed output and mask the exception in flight.
   */
  private async openInputHandle(inputPath: string): Promise<FileHandle> {
    try {
      return await fsOpen(inputPath, 'r');
    } catch (openErr) {
      if ((openErr as Error & { code?: string }).code === 'ENOENT') {
        throw new CryptoError(
          `Input file does not exist: ${inputPath}`,
          CryptoErrorType.FILE_ERROR,
          'INPUT_FILE_NOT_FOUND'
        );
      }
      throw openErr;
    }
  }

  /**
   * Invoke a {@link ProgressCallback} for a single progress event.
   *
   * **Throw-propagation policy (Option A — "honest abort"):** if the supplied
   * callback throws, the error propagates out of the surrounding file
   * operation and aborts it. The temp file is then cleaned up in the calling
   * method's `catch` block, leaving `outputPath` untouched (per the atomic
   * rename contract). The error is wrapped in `CryptoError` only if it is not
   * already one — application errors thrown from a progress callback come
   * through unchanged so callers can identify their own throw site.
   *
   * Rationale: a throwing callback is a caller-side bug. Swallowing it would
   * mask the bug and hand back a "successful" encryption to a caller who
   * thought they had aborted it. Aborting the operation is the safer default;
   * callers who want best-effort progress reporting can wrap their own
   * callback in a try/catch and swallow internally.
   *
   * The wrapper deliberately performs no clamping or coercion: `processed`
   * and `total` are forwarded as-is so the callback sees the same values
   * any external observer would.
   */
  private invokeProgress(
    progress: ProgressCallback | undefined,
    processed: number,
    total: number
  ): void {
    if (progress === undefined) {
      return;
    }
    try {
      progress(processed, total);
    } catch (err) {
      throw tagProgressThrow(err);
    }
  }

  /**
   * Best-effort async unlink that swallows ENOENT and any other error. Used
   * exclusively for cleaning up temp files in error-handling paths so that a
   * cleanup failure never masks the real underlying error.
   */
  private async safeUnlink(filePath: string): Promise<void> {
    try {
      await unlink(filePath);
    } catch {
      // Ignore — the temp file may already have been renamed away or never
      // created in the first place.
    }
  }

  /**
   * Synchronous companion to `safeUnlink`.
   */
  private safeUnlinkSync(filePath: string): void {
    try {
      unlinkSync(filePath);
    } catch {
      // Ignore — see safeUnlink above.
    }
  }

  /**
   * Atomically replace `outputPath` with the contents of `tempPath`.
   *
   * `fs.rename` and `fs.renameSync` perform an atomic same-filesystem rename
   * on POSIX. On Windows, `rename`/`renameSync` (Node 18+) maps to the
   * `MoveFileExW` API with `MOVEFILE_REPLACE_EXISTING`, which atomically
   * replaces the destination file when one exists (subject to standard
   * Windows file-locking caveats — i.e. if another process holds the target
   * file open without `FILE_SHARE_DELETE`, the rename will fail). This is
   * the standard idiom used by atomic-write helpers (e.g. `write-file-atomic`
   * on npm) and is the right choice for our use case.
   *
   * If rename fails, we fall back to copy-then-delete to maximize the chance
   * the operation completes even in adversarial Windows scenarios. The
   * fallback is non-atomic but only kicks in when the atomic path fails.
   */
  private async atomicRename(
    tempPath: string,
    outputPath: string
  ): Promise<void> {
    try {
      await fsRename(tempPath, outputPath);
    } catch (error) {
      // Best-effort fallback for adversarial Windows cases (target locked
      // for renaming but not for opening). Copy + delete is non-atomic but
      // strictly better than leaving the temp file behind.
      try {
        await fsCopyFile(tempPath, outputPath);
        await this.safeUnlink(tempPath);
      } catch {
        // Surface the original rename error to the caller.
        throw error;
      }
    }
  }

  /**
   * Synchronous companion to `atomicRename`.
   */
  private atomicRenameSync(tempPath: string, outputPath: string): void {
    try {
      renameSync(tempPath, outputPath);
    } catch (error) {
      try {
        copyFileSync(tempPath, outputPath);
        this.safeUnlinkSync(tempPath);
      } catch {
        throw error;
      }
    }
  }

  /**
   * Encrypt text with password (synchronous version)
   * @param text - Text to encrypt (the empty string `''` is accepted and
   *   produces a valid authenticated ciphertext; only `null` and `undefined`
   *   are rejected)
   * @param password - Encryption password (optional if default passphrase is set)
   * @returns Base64url encoded encrypted data (v1 format)
   * @throws CryptoError if encryption fails
   */
  public encryptTextSync(text: string, password?: string): string {
    if (text === undefined || text === null || typeof text !== 'string') {
      throw new CryptoError(
        'Text must be a string',
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

    let key: Buffer | null = null;
    // Hoisted so the catch block can scrub the plaintext if the operation
    // fails after the buffer is allocated (e.g. encryptData throws).
    let textBuffer: Buffer | null = null;
    try {
      // Generate salt and IV
      const salt = this.generateSecureRandom(this.saltLength);
      const iv = this.generateSecureRandom(this.ivLength);

      // Derive key from password (synchronous)
      key = this.deriveKeySync(finalPassword, salt);

      // Build v1 header for sync (PBKDF2 KDF identifier). Built BEFORE
      // encryption so we can include its on-disk bytes in the AAD — see
      // encryptText for the full rationale on header-binding.
      const header = this.buildHeader(KDF_ID_PBKDF2_SHA256);

      // Encrypt the text with header-bound AAD.
      textBuffer = Buffer.from(text, 'utf8');
      const { encrypted, tag } = this.encryptData(
        textBuffer,
        key,
        iv,
        // `aadForV1` returns a `Uint8Array` (isomorphic core); `encryptData`
        // keeps its public `Buffer.isBuffer(aadOverride)` guard, so wrap it.
        Buffer.from(this.aadForV1(header))
      );

      // Combine: header + salt + iv + tag + encrypted data
      const combined = Buffer.concat([header, salt, iv, tag, encrypted]);

      // Encode to base64url FIRST so we still have the bytes available, then
      // scrub every Buffer-backed view onto sensitive material. See the
      // matching block in `encryptText` for full rationale (Task 14).
      const encoded = combined.toString('base64url');
      this.secureClear(key);
      this.secureClear(textBuffer);
      this.secureClear(encrypted);
      this.secureClear(tag);
      this.secureClear(combined);

      return encoded;
    } catch (error) {
      // Scrub the plaintext buffer if it was allocated before the failure.
      if (textBuffer !== null) {
        this.secureClear(textBuffer);
      }
      if (key !== null) {
        this.secureClear(key);
      }
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
   * @param encryptedText - Base64url encoded encrypted text (v0 or v1 format)
   * @param password - Decryption password (optional if default passphrase is set)
   * @returns Decrypted text
   * @throws CryptoError if decryption fails
   */
  public decryptTextSync(encryptedText: string, password?: string): string {
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

    let key: Buffer | null = null;
    // Hoisted so the catch block can scrub the decrypted buffer if the
    // operation fails in the narrow window after decryptData returns.
    let decrypted: Buffer | null = null;
    try {
      // Decode base64url
      const combined = Buffer.from(encryptedText, 'base64url');

      // Detect format version (v1 magic vs legacy v0).
      // For v1 ciphertexts, the iteration count is read from the header.
      // For v0 ciphertexts (no header), fall back to the configured legacy
      // value (defaults to 100000 — what every old sync ciphertext used).
      let bodyOffset: number;
      let pbkdf2Iterations: number = this.legacyPbkdf2Iterations;
      // For v1 ciphertexts, capture on-disk header bytes verbatim for AAD
      // binding (see decryptText for the deeper rationale on why
      // re-serialising would defeat the purpose).
      let headerForAad: Buffer | null = null;

      if (hasMagic(combined)) {
        // See decryptText for the full magic-collision recovery rationale.
        // For the sync path, pbkdf2Iterations is already initialised to
        // this.legacyPbkdf2Iterations (the v0 default), so no reset is
        // needed in the catch block.
        try {
          const parsed = parseHeader(combined);
          this.assertKdfMatches(parsed, KDF_ID_PBKDF2_SHA256);
          if (parsed.params.kind === 'pbkdf2-sha256') {
            pbkdf2Iterations = parsed.params.iterations;
          }
          bodyOffset = parsed.headerLen;
          headerForAad = combined.subarray(0, parsed.headerLen);
        } catch (headerParseErr) {
          if (this.legacyMode !== 'auto') {
            throw headerParseErr;
          }
          if (
            headerParseErr instanceof CryptoError &&
            headerParseErr.code === 'KDF_PARAMS_OUT_OF_BOUNDS'
          ) {
            throw headerParseErr;
          }
          // auto: v0 fallback — headerForAad stays null;
          // pbkdf2Iterations stays at this.legacyPbkdf2Iterations.
          bodyOffset = 0;
        }
      } else {
        this.enforceLegacyMode();
        bodyOffset = 0;
      }

      // Validate minimum size
      const minBodySize = this.saltLength + this.ivLength + this.tagLength;
      if (combined.length < bodyOffset + minBodySize) {
        throw new CryptoError(
          'Encrypted data is too small to be valid',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_DATA_SIZE'
        );
      }

      // Extract components. Each is a subarray view over `combined` — they
      // share the same underlying memory, so clearing `combined` later
      // zeroes salt/iv/tag/encrypted in one go.
      const saltStart = bodyOffset;
      const ivStart = saltStart + this.saltLength;
      const tagStart = ivStart + this.ivLength;
      const dataStart = tagStart + this.tagLength;

      const salt = combined.subarray(saltStart, ivStart);
      const iv = combined.subarray(ivStart, tagStart);
      const tag = combined.subarray(tagStart, dataStart);
      const encrypted = combined.subarray(dataStart);

      // Derive key from password (synchronous). Re-type any KDF failure to
      // DECRYPTION_FAILED — this is a decrypt op.
      try {
        key = this.deriveKeySync(finalPassword, salt, pbkdf2Iterations);
      } catch (err) {
        throw this.remapKdfErrorForDecryption(err);
      }

      // Decrypt the data with the matching AAD (header-bound for v1,
      // `this.aad`-only for v0).
      // `this.aad` / `aadForV1` return `Uint8Array` (isomorphic core);
      // `decryptData` keeps its public `Buffer.isBuffer(aadOverride)` guard,
      // so wrap the chosen AAD in a Buffer.
      const aad = Buffer.from(
        headerForAad === null ? this.aad : this.aadForV1(headerForAad)
      );
      decrypted = this.decryptData(encrypted, key, iv, tag, aad);
      const result = decrypted.toString('utf8');

      // Clear sensitive data from memory. `combined` is cleared *after*
      // decryption: the subarrays salt/iv/tag/encrypted are views over it,
      // so doing this earlier would corrupt the inputs to decryptData. The
      // V8 string `result` is GC-managed and cannot be scrubbed; see
      // secureClear's JSDoc for the limitations.
      this.secureClear(key);
      this.secureClear(decrypted);
      this.secureClear(combined);

      return result;
    } catch (error) {
      // Scrub the decrypted buffer if it was allocated before the failure.
      if (decrypted !== null) {
        this.secureClear(decrypted);
      }
      if (key !== null) {
        this.secureClear(key);
      }
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
   * Encrypt file with password (streaming for large files). Produces v1 format.
   *
   * Output is written to a sibling temp file (`${outputPath}.<random>.tmp`)
   * and atomically renamed to `outputPath` only on success. Readers of
   * `outputPath` therefore never observe a half-written ciphertext, and any
   * failure mid-stream leaves no file at the canonical destination.
   *
   * **Progress reporting:** if a `progress` callback is supplied, it is
   * invoked once with `(0, totalBytes)` before any plaintext is read, then
   * once per ciphertext stream chunk with `(bytesProcessed, totalBytes)`
   * (where `bytesProcessed` is the cumulative count of plaintext bytes
   * consumed from the input file), and finally once with
   * `(totalBytes, totalBytes)` after the body has been fully consumed.
   * `totalBytes` equals the input file size in bytes. If the callback
   * throws, the throw aborts the encryption — the temp file is cleaned up
   * and the error propagates to the caller. See {@link ProgressCallback}.
   *
   * @example
   * ```typescript
   * await crypto.encryptFile(
   *   'input.txt',
   *   'output.enc',
   *   'MySecureP@ssw0rd123!',
   *   (processed, total) => {
   *     const pct = total === 0 ? 100 : Math.round((processed / total) * 100);
   *     console.log(`encrypt ${pct}% (${processed}/${total} bytes)`);
   *   }
   * );
   * ```
   *
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Encryption password (optional if default passphrase is set)
   * @param progress - Optional progress callback. Throws propagate and abort.
   * @throws CryptoError if encryption fails
   * @throws CryptoError `INVALID_INPUT` / `DATA_TOO_LARGE_FOR_GCM` if the
   *   plaintext exceeds `MAX_GCM_PLAINTEXT_BYTES` (NIST SP 800-38D section
   *   5.2.1.1). There is no opt-out; past that bound AES-GCM's block counter
   *   wraps and the ciphertext has neither confidentiality nor authenticity.
   */
  public async encryptFile(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): Promise<void> {
    if (
      !inputPath ||
      typeof inputPath !== 'string' ||
      !outputPath ||
      typeof outputPath !== 'string'
    ) {
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

    let tempPath: string | null = null;
    let key: Buffer | null = null;

    // Assigned from the input handle's own `stat()` below; read again after
    // the handle has been closed for the final progress event.
    let totalBytes: number;

    try {
      // Open the input exactly once. ENOENT becomes the historical
      // INPUT_FILE_NOT_FOUND error; anything else falls through to the outer
      // catch. This replaces the old `existsSync` pre-check (a TOCTOU window)
      // and is the same descriptor the body stream reads from below.
      const fileHandle = await this.openInputHandle(inputPath);

      try {
        // Size comes from the OPEN handle, not a second name lookup: same
        // inode, no intervening rename/replace. The progress callback then
        // receives a stable `totalBytes` for every event.
        totalBytes = (await fileHandle.stat()).size;

        // Refuse an oversized input the moment its size is known — before the
        // output directory is created, before the temp path is built, before
        // the KDF runs and before any cipher exists. The whole file is one
        // AES-GCM invocation, so the NIST SP 800-38D bound applies to it as a
        // whole; past it the block counter wraps. No opt-out.
        assertGcmPlaintextLimit(totalBytes, 'DATA_TOO_LARGE_FOR_GCM');

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

        // Allocate a sibling temp path; we only rename to outputPath on success.
        tempPath = this.buildTempOutputPath(outputPath);

        // Generate salt and IV
        const salt = this.generateSecureRandom(this.saltLength);
        const iv = this.generateSecureRandom(this.ivLength);

        // Derive key from password
        key = await this.deriveKey(finalPassword, salt);

        // Build v1 header for the Argon2id KDF used by async file encryption.
        const versionHeader = this.buildHeader(KDF_ID_ARGON2ID);

        // Emit an initial 0/total event so callers can prime UI even on
        // empty files (where the data event never fires). We invoke this
        // BEFORE opening the temp output file: a throwing callback at this
        // point would otherwise leave the write-stream's underlying file
        // descriptor open, which on Windows blocks the subsequent
        // safeUnlink in the catch block and leaves an orphan tmp file
        // behind.
        this.invokeProgress(progress, 0, totalBytes);

        // Create encryption transform stream. AAD binds the on-disk v1
        // header bytes so any tampering with the header (including
        // reserved-byte regions) flips the GCM tag and decryption fails.
        const cipher = crypto.createCipheriv(
          this.algorithm,
          key,
          iv
        ) as crypto.CipherGCM;
        cipher.setAAD(this.aadForV1(versionHeader));

        // Open the temp output file once and stream everything through it.
        const outputStream = createWriteStream(tempPath, { flags: 'w' });

        // Persistent stream-error guard for the lifetime of this operation.
        // Records the first stream 'error' event so subsequent writeChunk
        // calls fail fast, and rejects any writeChunk that is currently
        // waiting for 'drain' (so the promise never hangs). Multiple 'error'
        // listeners on a stream are fine — pipeline() attaches its own and
        // they coexist independently.
        let streamError: Error | null = null;
        let pendingChunkReject: ((err: Error) => void) | null = null;
        const onStreamError = (err: Error): void => {
          streamError = err;
          if (pendingChunkReject !== null) {
            const rej = pendingChunkReject;
            pendingChunkReject = null;
            rej(err);
          }
        };
        outputStream.on('error', onStreamError);

        // Helper to await a single write that may apply backpressure. We need
        // this for the upfront [v1 header][salt][iv] prefix and for the
        // trailing auth tag — pipeline() handles the body for us but it
        // doesn't know about these out-of-band writes.
        //
        // Guarantees: the promise settles exactly once (idempotent
        // settleOnce guard); all transient 'drain' listeners are removed on
        // settle; a stream 'error' always rejects rather than crashing the
        // process (unhandled-error) or hanging (drain never fires after an
        // error). The ok===true path no longer resolves synchronously before
        // the write callback — that was the root cause of the silent-drop bug.
        const writeChunk = (chunk: Buffer): Promise<void> =>
          new Promise<void>((resolve, reject) => {
            // Fail fast if the stream already errored before this call.
            if (streamError !== null) {
              reject(streamError);
              return;
            }

            let settled = false;
            let drainListener: (() => void) | null = null;

            const settleOnce = (err?: Error | null): void => {
              if (settled) return;
              settled = true;
              // Deregister from the stream-level error handler.
              pendingChunkReject = null;
              // Remove any 'drain' listener (safe no-op if already fired
              // or never registered).
              if (drainListener !== null) {
                outputStream.removeListener('drain', drainListener);
                drainListener = null;
              }
              if (err) reject(err);
              else resolve();
            };

            // Register so onStreamError can settle us if the stream errors
            // while we are waiting for the write callback or for 'drain'.
            pendingChunkReject = (err): void => settleOnce(err);

            const ok = outputStream.write(chunk, err => {
              // Write callback fires when this chunk's data has been
              // processed. For ok===true: sole settlement path. For
              // ok===false: drain may have already settled us (idempotent).
              settleOnce(err ?? null);
            });

            if (!ok) {
              // Backpressured: resolve as soon as the buffer drains so the
              // producer can resume without waiting for the write callback
              // (which arrives after drain). The write callback's
              // settleOnce call is then a no-op.
              drainListener = (): void => settleOnce(null);
              outputStream.once('drain', drainListener);
            }
            // ok===true: the write callback (above) handles settlement.
            // We deliberately do NOT call resolve() here synchronously —
            // that was the bug: resolving before the callback meant a
            // subsequent write-callback error was silently dropped, and
            // the stream 'error' event went unhandled (process crash).
          });

        try {
          // Header: [v1 header][salt][iv]
          await writeChunk(Buffer.concat([versionHeader, salt, iv]));

          // Body: stream input -> cipher -> output. The cipher is a Transform,
          // so pipeline() handles backpressure and will reject if any stage
          // errors out, leaving the temp file truncated (we delete it below).
          //
          // The stream reads from the handle we already opened, so the bytes
          // encrypted are the bytes of the inode we stat'd — a second
          // `createReadStream(inputPath)` would re-resolve the name and could
          // land on a different file. `start: 0` is explicit and load-bearing:
          // a bare `createReadStream()` reads from the handle's CURRENT
          // position, so any non-positional read added above this line in
          // future would silently truncate the plaintext.
          const inputStream = fileHandle.createReadStream({ start: 0 });

          // Attach the progress listener BEFORE pipeline() so we never miss a
          // chunk. We accumulate `chunk.length` from the readable side
          // (plaintext bytes consumed); the cipher's output size differs from
          // the input due to GCM block padding, but reporting plaintext
          // progress is what callers expect ("how much of MY file have you
          // processed").
          let bytesProcessed = 0;
          let progressError: unknown = undefined;
          if (progress !== undefined) {
            inputStream.on('data', (chunk: Buffer | string) => {
              // If a previous chunk's callback already threw, skip further
              // invocations — the input stream is being torn down and we
              // do not want to dispatch a second event into a callback the
              // caller has already failed.
              if (progressError !== undefined) {
                return;
              }
              const len =
                typeof chunk === 'string'
                  ? Buffer.byteLength(chunk)
                  : chunk.length;
              bytesProcessed += len;
              // If the callback throws, capture the error and destroy the
              // input stream. pipeline() then rejects with the destroy
              // reason, the cipher and output stream are torn down, and the
              // outer catch handles temp-file cleanup. We tag the captured
              // error so the catch block can re-throw it (preserving the
              // caller's identity) instead of wrapping it as a generic
              // FILE_ENCRYPTION_FAILED.
              try {
                progress(bytesProcessed, totalBytes);
              } catch (err) {
                progressError = tagProgressThrow(err);
                inputStream.destroy(
                  err instanceof Error ? err : new Error(String(err))
                );
              }
            });
          }

          try {
            await pipeline(inputStream, cipher, outputStream, { end: false });
          } catch (pipelineError) {
            // If the pipeline rejection was triggered by our destroy() call
            // above, surface the original callback throw rather than the
            // (less informative) "stream destroyed" wrapper.
            if (progressError !== undefined) {
              throw progressError;
            }
            throw pipelineError;
          }

          // Trailing auth tag.
          await writeChunk(cipher.getAuthTag());
        } finally {
          // Close without rejecting — a close/flush error is captured by
          // onStreamError and re-thrown below. Rejecting here would mask an
          // in-flight error (a throw in `finally` replaces the current
          // exception). Skip end() on an already-destroyed stream to avoid
          // ERR_STREAM_DESTROYED; with the persistent 'error' listener
          // attached, end(cb) still fires its callback on a failed-open
          // stream, so this path neither hangs nor crashes the process.
          if (!outputStream.destroyed) {
            await new Promise<void>(resolve => {
              outputStream.end(() => resolve());
            });
          }
          // Remove the persistent error listener now that the stream is
          // closed — prevents a dangling reference on the (now-closed)
          // stream object.
          outputStream.removeListener('error', onStreamError);
        }

        // Surface any stream error captured by onStreamError that was not
        // already thrown by writeChunk or pipeline (belt-and-suspenders;
        // on the success path streamError is null — no-op).
        if (streamError !== null) {
          throw streamError;
        }
      } finally {
        // Unconditional, not conditional on whether a stream was created.
        // `FileHandle.close()` is idempotent — after the body stream ends
        // with the default `autoClose: true` the handle already reports
        // `fd === -1`, so this issues no second `close(2)` and cannot touch
        // a recycled descriptor. Skipping the close whenever a stream exists
        // would instead LEAK the descriptor in the case where a stream is
        // constructed but never consumed or destroyed: `autoClose` only fires
        // on `end`/`error`, and neither happens then. Every early throw above
        // — a failed `stat()`, OUTPUT_DIR_CREATION_FAILED, a KDF failure, a
        // throwing progress callback — lands here too.
        //
        // Best-effort, exactly like `closeSync(inputFd)` in `encryptFileSync`:
        // the input is read-only and, on the success path, every byte has
        // already been encrypted, authenticated and written, so a rare
        // EIO/EBADF here must not (a) skip the `atomicRename` below and send
        // the outer catch to `safeUnlink(tempPath)`, destroying a complete
        // ciphertext, or (b) replace an exception that is already in flight —
        // a throw in a `finally` supersedes the current one.
        try {
          await fileHandle.close();
        } catch {
          // ignore — benign close failure on a read-only input handle
        }
      }

      // Atomically promote the temp file to the final output path.
      await this.atomicRename(tempPath, outputPath);
      tempPath = null;

      // Final progress event: every byte of plaintext has now been encrypted,
      // authenticated, written, and fsync'd-via-rename to outputPath. We
      // emit this AFTER the rename so callers seeing 100% know the canonical
      // destination is fully populated.
      this.invokeProgress(progress, totalBytes, totalBytes);

      // Clear sensitive data
      this.secureClear(key);
    } catch (error) {
      if (key !== null) {
        this.secureClear(key);
      }
      // Clean up the temp file if we created one. Never touch the final
      // outputPath: it either already existed before this call (and is
      // therefore the caller's pre-existing data, which we must not delete)
      // or it was never created (because rename failed before completion).
      if (tempPath !== null) {
        await this.safeUnlink(tempPath);
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      // Preserve the identity of progress-callback throws so callers can
      // identify their own throw site (e.g. via `instanceof MyError`). Any
      // other non-CryptoError is an opaque internal failure and gets
      // wrapped in `FILE_ENCRYPTION_FAILED` (existing contract).
      if (isProgressThrow(error)) {
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
   * Decrypt file with password (streaming for large files). Accepts both
   * v1 (preferred) and legacy v0 (subject to `legacyMode`) ciphertext files.
   *
   * Reads only the small metadata regions (header, salt, IV, trailing tag)
   * eagerly via direct file-handle reads, then streams the body of the
   * ciphertext through a `Decipher` to a sibling temp file. On successful
   * `decipher.final()` (which authenticates the GCM tag), the temp file is
   * atomically renamed to `outputPath`. The full ciphertext is never held in
   * memory at once, so this works for arbitrarily large files.
   *
   * **Progress reporting:** if a `progress` callback is supplied, it is
   * invoked once with `(0, totalBytes)` before the body stream starts, then
   * once per body chunk with `(bytesProcessed, totalBytes)` (where
   * `bytesProcessed` is the cumulative count of CIPHERTEXT bytes consumed
   * from the input file — i.e. the front-matter offset plus the body bytes
   * fed through the decipher), and finally once with
   * `(totalBytes, totalBytes)` after authentication and rename succeed.
   * `totalBytes` equals the input ciphertext file size in bytes (including
   * the v1 header / salt / iv / auth tag overhead). If the callback throws,
   * the throw aborts decryption — the temp file is cleaned up and the
   * error propagates to the caller. See {@link ProgressCallback}.
   *
   * @example
   * ```typescript
   * await crypto.decryptFile(
   *   'output.enc',
   *   'decrypted.txt',
   *   'MySecureP@ssw0rd123!',
   *   (processed, total) => {
   *     console.log(`decrypt ${processed}/${total} bytes`);
   *   }
   * );
   * ```
   *
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Decryption password (optional if default passphrase is set)
   * @param progress - Optional progress callback. Throws propagate and abort.
   * @throws CryptoError if decryption fails
   * @throws CryptoError `INVALID_INPUT` / `DATA_TOO_LARGE_FOR_GCM` if the
   *   ciphertext body exceeds `MAX_GCM_PLAINTEXT_BYTES` (NIST SP 800-38D
   *   section 5.2.1.1) — such a body could only come from a counter-wrapped,
   *   already-broken encryption. Checked before any key derivation.
   */
  public async decryptFile(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): Promise<void> {
    if (
      !inputPath ||
      typeof inputPath !== 'string' ||
      !outputPath ||
      typeof outputPath !== 'string'
    ) {
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

    let tempPath: string | null = null;
    let key: Buffer | null = null;

    // All assigned inside the input-handle block below and read after it has
    // been closed (the final progress event and the key/salt/iv/tag scrub).
    let totalSize: number;
    let salt: Buffer;
    let iv: Buffer;
    let tag: Buffer;

    try {
      // Open the input exactly once, up front. ENOENT becomes the historical
      // INPUT_FILE_NOT_FOUND error; anything else falls through to the outer
      // catch. This replaces the old `existsSync` pre-check (a TOCTOU window)
      // AND the second `createReadStream(inputPath)` that used to re-resolve
      // the name for the body: every read below — the front matter, the
      // trailing tag, and the ciphertext body — is served from THIS handle,
      // so the bytes authenticated are the bytes of the inode whose header
      // was parsed.
      //
      // Opening before the output directory is created preserves the previous
      // failure ordering: a missing input still aborts without creating any
      // directory.
      const fileHandle = await this.openInputHandle(inputPath);

      let formatHeaderLen: number;
      let argonOverrides:
        | { memoryCost: number; timeCost: number; parallelism: number }
        | undefined;
      // For v1 ciphertexts, capture the on-disk header bytes verbatim so we
      // can include them in the AES-GCM AAD. Re-serialising via packHeader
      // would zero-fill reserved regions, hiding any tampering — see
      // decryptText for the full rationale.
      let headerForAad: Buffer | null = null;
      try {
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

        // Read just the metadata regions of the file (header + salt + iv at
        // the front, auth tag at the back) without loading the body.
        const stat = await fileHandle.stat();
        totalSize = stat.size;

        // Step 1: peek at the first MAGIC_LENGTH bytes to determine format.
        // We then read whatever else we need based on format version. To
        // reduce syscalls, just read the largest possible front-matter in
        // one shot (v1 header + salt + iv = HEADER_LENGTH + saltLength +
        // ivLength) when the file is large enough, otherwise read what's
        // available and detect short files.
        const maxFrontLen = HEADER_LENGTH + this.saltLength + this.ivLength;
        const frontReadLen = Math.min(maxFrontLen, totalSize);
        const front = Buffer.alloc(frontReadLen);
        if (frontReadLen > 0) {
          const { bytesRead: frontBytesRead } = await fileHandle.read(
            front,
            0,
            frontReadLen,
            0
          );
          if (frontBytesRead !== frontReadLen) {
            throw new CryptoError(
              'Failed to read full file header region',
              CryptoErrorType.INVALID_INPUT,
              'INVALID_ENCRYPTED_FILE_SIZE'
            );
          }
        }

        if (hasMagic(front)) {
          // See decryptText for the full magic-collision recovery rationale.
          try {
            if (front.length < HEADER_LENGTH) {
              throw new CryptoError(
                'File is too small to contain a valid v1 header',
                CryptoErrorType.INVALID_INPUT,
                'INVALID_ENCRYPTED_FILE_SIZE'
              );
            }
            const parsed = parseHeader(front);
            this.assertKdfMatches(parsed, KDF_ID_ARGON2ID);
            if (parsed.params.kind === 'argon2id') {
              argonOverrides = {
                memoryCost: parsed.params.memoryCost,
                timeCost: parsed.params.timeCost,
                parallelism: parsed.params.parallelism,
              };
            }
            formatHeaderLen = parsed.headerLen;
            // Copy the on-disk header bytes into a fresh Buffer (rather than
            // a subarray) so the AAD reference outlives any later
            // mutation/scrub of `front`.
            headerForAad = Buffer.from(front.subarray(0, formatHeaderLen));
          } catch (headerParseErr) {
            if (this.legacyMode !== 'auto') {
              throw headerParseErr;
            }
            if (
              headerParseErr instanceof CryptoError &&
              headerParseErr.code === 'KDF_PARAMS_OUT_OF_BOUNDS'
            ) {
              throw headerParseErr;
            }
            // auto: v0 fallback — headerForAad stays null;
            // argonOverrides stays undefined.
            formatHeaderLen = 0;
          }
        } else {
          this.enforceLegacyMode();
          formatHeaderLen = 0;
        }

        // Validate the file is at least large enough for the salt+iv+tag
        // metadata after the (possibly absent) format header.
        const minSize =
          formatHeaderLen + this.saltLength + this.ivLength + this.tagLength;
        if (totalSize < minSize) {
          throw new CryptoError(
            'File is too small to be a valid encrypted file',
            CryptoErrorType.INVALID_INPUT,
            'INVALID_ENCRYPTED_FILE_SIZE'
          );
        }

        // Slice salt and iv out of the front buffer (we always read enough
        // to cover both for a valid file). Copy into independent Buffers so
        // we own the memory and can scrub it later.
        salt = Buffer.from(
          front.subarray(formatHeaderLen, formatHeaderLen + this.saltLength)
        );
        iv = Buffer.from(
          front.subarray(
            formatHeaderLen + this.saltLength,
            formatHeaderLen + this.saltLength + this.ivLength
          )
        );

        // Step 2: read the trailing auth tag.
        tag = Buffer.alloc(this.tagLength);
        const tagOffset = totalSize - this.tagLength;
        const { bytesRead: tagBytesRead } = await fileHandle.read(
          tag,
          0,
          this.tagLength,
          tagOffset
        );
        if (tagBytesRead !== this.tagLength) {
          throw new CryptoError(
            'Failed to read full auth tag from file',
            CryptoErrorType.INVALID_INPUT,
            'INVALID_ENCRYPTED_FILE_SIZE'
          );
        }

        // Compute the byte range of the ciphertext body.
        const bodyStart = formatHeaderLen + this.saltLength + this.ivLength;
        const bodyEnd = totalSize - this.tagLength; // exclusive
        const bodyLen = bodyEnd - bodyStart;

        // Refuse an oversized ciphertext body. This sits ahead of `deriveKey`,
        // `buildTempOutputPath` and `createDecipheriv`, so nothing expensive or
        // observable has happened yet. A body this large could only have been
        // produced by a counter-wrapped (already broken) encryption.
        assertGcmPlaintextLimit(bodyLen, 'DATA_TOO_LARGE_FOR_GCM');

        // Derive key from password (use embedded params if v1). Re-type any
        // KDF failure to DECRYPTION_FAILED — this is a decrypt op.
        try {
          key = await this.deriveKey(finalPassword, salt, argonOverrides);
        } catch (err) {
          throw this.remapKdfErrorForDecryption(err);
        }

        // Allocate a sibling temp path; only rename on success.
        tempPath = this.buildTempOutputPath(outputPath);

        // Create the decipher and bind AAD and auth tag BEFORE writing any
        // ciphertext to it. The tag is read from the trailing bytes of the
        // input but must be set before decipher.update() so that a tampered
        // body fails authentication at decipher.final().
        //
        // For v1 ciphertexts, AAD includes the on-disk header bytes verbatim
        // (so any tampering with the header — including the reserved bytes
        // — flips the GCM tag and decryption fails). For v0 ciphertexts
        // (no header) the AAD is just `this.aad` to preserve backward
        // compatibility with pre-v1 ciphertexts.
        const decipher = crypto.createDecipheriv(
          this.algorithm,
          key,
          iv
        ) as crypto.DecipherGCM;
        const decipherAad =
          headerForAad === null ? this.aad : this.aadForV1(headerForAad);
        decipher.setAAD(decipherAad);
        decipher.setAuthTag(tag);

        // Initial progress event — a literal `(0, totalSize)` start sentinel,
        // matching the `decryptFileSync` contract. The metadata bytes
        // (header + salt + iv + tag) have already been read off disk by this
        // point, but we report `0` so callers can use the first event as a
        // deterministic start marker; per-chunk events (via the `data` event
        // on the body read stream) report `consumedFrontAndTag + bodyConsumed`
        // bytes, and the final event reports `(totalSize, totalSize)`.
        const consumedFrontAndTag =
          bodyStart + this.tagLength; /* bytes already read from input */
        this.invokeProgress(progress, 0, totalSize);

        // Stream the body bytes through the decipher into the temp file. We
        // bound the read to [bodyStart, bodyEnd) so the trailing tag is not
        // fed back into update(). For empty bodies (bodyLen === 0) we skip
        // the read stream and just call decipher.final() to authenticate.
        const outputStream = createWriteStream(tempPath, { flags: 'w' });

        // Persistent stream-error guard for the output stream's lifetime.
        // Without this, an 'error' event on outputStream with no listener
        // (e.g. a failed file-open when tempPath's parent is actually a
        // regular file → ENOTDIR) causes Node to raise ERR_UNHANDLED_ERROR
        // and crash the host process. With the listener, the error is
        // captured in streamError and re-thrown explicitly after the finally
        // so the outer catch can clean up the temp file and wrap it as
        // FILE_DECRYPTION_FAILED. This mirrors the onStreamError guard that
        // encryptFile has had since v1.4.0 (Phase 2 of the v1.4.0 plan).
        let streamError: Error | null = null;
        const onStreamError = (err: Error): void => {
          if (streamError === null) streamError = err;
        };
        outputStream.on('error', onStreamError);

        try {
          if (bodyLen > 0) {
            // Stream the body from the SAME handle the header and tag were
            // read from — no second name resolution, so the body cannot come
            // from a file that replaced `inputPath` mid-operation.
            const inputStream = fileHandle.createReadStream({
              start: bodyStart,
              end: bodyEnd - 1, // createReadStream end is INCLUSIVE
            });

            // Attach the progress listener BEFORE pipeline() so we never miss
            // a chunk. We accumulate ciphertext-body bytes consumed; the
            // reported `bytesProcessed` is `consumedFrontAndTag + bodyConsumed`
            // so the value monotonically grows from `consumedFrontAndTag` to
            // `totalSize` over the streaming portion.
            let bodyConsumed = 0;
            let progressError: unknown = undefined;
            if (progress !== undefined) {
              inputStream.on('data', (chunk: Buffer | string) => {
                if (progressError !== undefined) {
                  return;
                }
                const len =
                  typeof chunk === 'string'
                    ? Buffer.byteLength(chunk)
                    : chunk.length;
                bodyConsumed += len;
                try {
                  progress(consumedFrontAndTag + bodyConsumed, totalSize);
                } catch (err) {
                  progressError = tagProgressThrow(err);
                  inputStream.destroy(
                    err instanceof Error ? err : new Error(String(err))
                  );
                }
              });
            }

            try {
              await pipeline(inputStream, decipher, outputStream, {
                end: false,
              });
            } catch (pipelineError) {
              if (progressError !== undefined) {
                throw progressError;
              }
              throw pipelineError;
            }
          } else {
            // Empty plaintext: still need to drive update()/final() to
            // verify the tag. decipher.update with zero bytes is safe;
            // calling final() may throw if the tag is invalid.
            const finalBuf = decipher.final();
            if (finalBuf.length > 0) {
              await new Promise<void>((resolve, reject) => {
                outputStream.write(finalBuf, err => {
                  if (err) reject(err);
                  else resolve();
                });
              });
            }
          }
        } finally {
          // Close without rejecting — a close/flush error is captured by
          // onStreamError and re-thrown below. Rejecting here would mask an
          // in-flight error (a throw in `finally` replaces the current
          // exception). Skip end() on an already-destroyed stream to avoid
          // ERR_STREAM_DESTROYED; with the persistent 'error' listener
          // attached, end(cb) still fires its callback on a failed-open
          // stream, so this path neither hangs nor crashes the process.
          if (!outputStream.destroyed) {
            await new Promise<void>(resolve => {
              outputStream.end(() => resolve());
            });
          }
          outputStream.removeListener('error', onStreamError);
        }

        // Surface a stream error captured by onStreamError that was not
        // already thrown by the body pipeline (e.g. a failed temp-file open
        // on the empty-body path where pipeline() is never called).
        // On the success path streamError is null — this is a no-op.
        if (streamError !== null) {
          throw streamError;
        }
      } finally {
        // Unconditional, not conditional on whether the body stream was
        // created. `FileHandle.close()` is idempotent — once the stream has
        // ended with the default `autoClose: true` the handle already reports
        // `fd === -1`, so this issues no second `close(2)` and cannot touch a
        // recycled descriptor. Skipping the close whenever a stream exists
        // would instead LEAK the descriptor in the case where a stream is
        // constructed but never consumed or destroyed: `autoClose` only fires
        // on `end`/`error`, and neither happens then. It also covers the two
        // paths that create NO stream at all — the empty-body branch
        // (`bodyLen === 0`) and every early throw above (a short header read,
        // OUTPUT_DIR_CREATION_FAILED, a bad KDF parameter, a KDF failure).
        //
        // The close sits BEFORE the atomic rename below so the input
        // descriptor is released the moment the last byte is read, exactly as
        // it was when the body had its own stream.
        //
        // Best-effort, exactly like `closeSync(inputFd)` in `decryptFileSync`:
        // the input is read-only and, on the success path, authentication and
        // output writing have already succeeded, so a rare EIO/EBADF here must
        // not (a) skip the `atomicRename` below and send the outer catch to
        // `safeUnlink(tempPath)`, destroying the validated plaintext, or
        // (b) replace an exception that is already in flight — most
        // importantly a GCM authentication failure, which the caller must see
        // as such and not as an I/O error.
        try {
          await fileHandle.close();
        } catch {
          // ignore — benign close failure on a read-only input handle
        }
      }

      // Atomic rename and scrub key material.
      await this.atomicRename(tempPath, outputPath);
      tempPath = null;

      // Final progress event: every byte of input ciphertext has now been
      // consumed and the validated plaintext is at outputPath.
      this.invokeProgress(progress, totalSize, totalSize);

      this.secureClear(key);
      this.secureClear(salt);
      this.secureClear(iv);
      this.secureClear(tag);
    } catch (error) {
      if (key !== null) {
        this.secureClear(key);
      }
      // Clean up the temp file if any partial output exists. We never
      // touch outputPath itself: if rename succeeded, outputPath is the
      // valid plaintext; if rename failed, outputPath is whatever the
      // caller had there before (or doesn't exist).
      if (tempPath !== null) {
        await this.safeUnlink(tempPath);
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      // Preserve the identity of progress-callback throws (see encryptFile
      // for rationale).
      if (isProgressThrow(error)) {
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
   * Encrypt file with password (synchronous version). Produces v1 format.
   *
   * Output is written to a sibling temp file (`${outputPath}.<random>.tmp`)
   * and atomically renamed to `outputPath` only on success.
   *
   * Reads the input in fixed 64 KiB chunks via `fs.readSync`, feeds each
   * chunk through `cipher.update()`, and writes the resulting ciphertext
   * chunk via `fs.writeFileSync(fd, ...)`. This keeps peak memory
   * proportional to the chunk size regardless of input file size —
   * matching the bounded-memory model already used by `decryptFileSync`.
   * The on-disk layout `[v1 header][salt][iv][ciphertext body][auth tag]`
   * is byte-identical to the previous single-read implementation.
   *
   * **Progress reporting:** if a `progress` callback is supplied, it is
   * invoked once with `(0, totalBytes)` before encryption starts and once
   * with `(totalBytes, totalBytes)` after the temp file has been atomically
   * renamed to the canonical `outputPath`. No per-chunk events are emitted
   * — the two bracketing calls preserve the contract callers already depend
   * on. `totalBytes` equals the input file size in bytes. If the callback
   * throws, the throw aborts the operation. See {@link ProgressCallback}.
   *
   * @example
   * ```typescript
   * crypto.encryptFileSync(
   *   'input.txt',
   *   'output.enc',
   *   'MySecureP@ssw0rd123!',
   *   (processed, total) => console.log(`${processed}/${total} bytes`)
   * );
   * ```
   *
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Encryption password (optional if default passphrase is set)
   * @param progress - Optional progress callback. Throws propagate and abort.
   * @throws CryptoError if encryption fails
   * @throws CryptoError `INVALID_INPUT` / `DATA_TOO_LARGE_FOR_GCM` if the
   *   plaintext exceeds `MAX_GCM_PLAINTEXT_BYTES` (NIST SP 800-38D section
   *   5.2.1.1). There is no opt-out; past that bound AES-GCM's block counter
   *   wraps and the ciphertext has neither confidentiality nor authenticity.
   */
  public encryptFileSync(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): void {
    if (
      !inputPath ||
      typeof inputPath !== 'string' ||
      !outputPath ||
      typeof outputPath !== 'string'
    ) {
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

    let tempPath: string | null = null;
    let inputFd: number | null = null;
    let outputFd: number | null = null;
    let key: Buffer | null = null;
    // Hoisted so the catch block can scrub up to 64 KiB of plaintext if the
    // operation fails after the chunk buffer has been allocated. May be null
    // if the failure occurs before the allocation (early validation throws).
    let chunk: Buffer | null = null;

    try {
      // Open the input first to eliminate the TOCTOU race between an
      // existsSync check and the later openSync call. ENOENT is re-thrown
      // as INPUT_FILE_NOT_FOUND; other errors propagate to the outer catch.
      try {
        inputFd = openSync(inputPath, 'r');
      } catch (openErr) {
        if ((openErr as Error & { code?: string }).code === 'ENOENT') {
          throw new CryptoError(
            `Input file does not exist: ${inputPath}`,
            CryptoErrorType.FILE_ERROR,
            'INPUT_FILE_NOT_FOUND'
          );
        }
        throw openErr;
      }

      // Use the open fd for size — same inode, no intervening name lookup.
      const totalBytes = fstatSync(inputFd as number).size;

      // Refuse an oversized input the moment its size is known — before the
      // output directory is created, before the temp path is built, before the
      // PBKDF2 KDF runs and before any cipher exists. See
      // {@link assertGcmPlaintextLimit}. No opt-out.
      assertGcmPlaintextLimit(totalBytes, 'DATA_TOO_LARGE_FOR_GCM');

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

      // Initial progress event before the heavy work begins.
      this.invokeProgress(progress, 0, totalBytes);

      // Allocate temp path; only rename on success.
      tempPath = this.buildTempOutputPath(outputPath);

      // Generate salt and IV
      const salt = this.generateSecureRandom(this.saltLength);
      const iv = this.generateSecureRandom(this.ivLength);

      // Derive key from password (synchronous)
      key = this.deriveKeySync(finalPassword, salt);

      // Build v1 header for sync file (PBKDF2 KDF identifier). Built
      // BEFORE the cipher so we can include its on-disk bytes in the AAD
      // — see encryptText for the full rationale on header-binding.
      const versionHeader = this.buildHeader(KDF_ID_PBKDF2_SHA256);

      // Create encryption transform with header-bound AAD.
      const cipher = crypto.createCipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.CipherGCM;
      cipher.setAAD(this.aadForV1(versionHeader));

      // Open the temp file for writing. (Input fd was opened at the top of
      // this try block to eliminate TOCTOU — it is already assigned above.)
      outputFd = openSync(tempPath, 'w');

      // Write the prefix: [v1 header][salt][iv]. These three fields are
      // always written together up front; the ciphertext body follows
      // chunk by chunk, and the auth tag is appended last.
      writeFileSync(outputFd, Buffer.concat([versionHeader, salt, iv]));

      // Stream the plaintext in fixed-size chunks. The reuse buffer keeps
      // peak memory proportional to the chunk size regardless of input size.
      chunk = Buffer.alloc(this.SYNC_ENCRYPT_CHUNK_SIZE);
      let inputOffset = 0;

      while (inputOffset < totalBytes) {
        const bytesToRead = Math.min(
          this.SYNC_ENCRYPT_CHUNK_SIZE,
          totalBytes - inputOffset
        );
        const bytesRead = readSync(inputFd, chunk, 0, bytesToRead, inputOffset);
        if (bytesRead <= 0) {
          // Should never happen given the bounds checks above; treat as a
          // concurrently truncated or corrupted input file.
          throw new CryptoError(
            'Unexpected EOF while reading plaintext body',
            CryptoErrorType.FILE_ERROR,
            'INPUT_FILE_READ_FAILED'
          );
        }
        const inSlice =
          bytesRead === chunk.length ? chunk : chunk.subarray(0, bytesRead);
        const outSlice = cipher.update(inSlice);
        if (outSlice.length > 0) {
          writeFileSync(outputFd, outSlice);
        }
        inputOffset += bytesRead;
      }

      // Finalize the cipher — for AES-GCM this returns an empty Buffer
      // because CTR mode flushes on each update(), but we write it for
      // completeness in case mode changes.
      const finalBuf = cipher.final();
      if (finalBuf.length > 0) {
        writeFileSync(outputFd, finalBuf);
      }

      // Append the GCM auth tag. Must be called AFTER cipher.final().
      const tag = cipher.getAuthTag();
      writeFileSync(outputFd, tag);

      // Close the output file BEFORE the rename so Windows lets us replace
      // the destination.
      closeSync(outputFd);
      outputFd = null;

      // Close the input fd (holding it open through the rename is
      // unnecessary). A failure here is benign — the input is read-only
      // and all crypto + output writing has already succeeded; only an
      // outputFd close failure (above) can indicate unflushed or corrupt
      // output. Wrap best-effort so a rare EIO/EBADF cannot discard the
      // completed temp file.
      try {
        closeSync(inputFd);
      } catch {
        // ignore — benign close failure on read-only input fd
      }
      inputFd = null;

      // Atomic rename — final outputPath now reflects the full ciphertext.
      this.atomicRenameSync(tempPath, outputPath);
      tempPath = null;

      // Final progress event after the rename has succeeded.
      this.invokeProgress(progress, totalBytes, totalBytes);

      // Scrub the plaintext reuse buffer and the derived key.
      this.secureClear(chunk);
      this.secureClear(key);
    } catch (error) {
      // Scrub the plaintext reuse buffer if it was allocated before the
      // failure — it may hold up to 64 KiB of user plaintext in heap.
      if (chunk !== null) {
        this.secureClear(chunk);
      }
      if (key !== null) {
        this.secureClear(key);
      }
      // Make sure we drop any open file descriptors before unlinking.
      if (outputFd !== null) {
        try {
          closeSync(outputFd);
        } catch {
          // ignore
        }
      }
      if (inputFd !== null) {
        try {
          closeSync(inputFd);
        } catch {
          // ignore
        }
      }
      // Clean up the temp file. Never touch outputPath: it either was the
      // caller's pre-existing data (which we must not delete) or it never
      // got created.
      if (tempPath !== null) {
        this.safeUnlinkSync(tempPath);
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      // Preserve the identity of progress-callback throws (see encryptFile
      // for rationale).
      if (isProgressThrow(error)) {
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
   * Chunk size used by the synchronous streaming encryption path. Matches
   * `SYNC_DECRYPT_CHUNK_SIZE` and `fs.createReadStream`'s default
   * `highWaterMark` so the two sync I/O paths are symmetric.
   */
  private readonly SYNC_ENCRYPT_CHUNK_SIZE = 64 * 1024;

  /**
   * Chunk size used by the synchronous streaming decryption path. 64 KiB is
   * the same default that `fs.createReadStream` uses for highWaterMark, so
   * we get parity with the async path while keeping memory usage bounded.
   */
  private readonly SYNC_DECRYPT_CHUNK_SIZE = 64 * 1024;

  /**
   * Decrypt file with password (synchronous, streaming). Accepts both v1
   * (preferred) and legacy v0 (subject to `legacyMode`) ciphertext files.
   *
   * Reads the file in fixed 64 KiB chunks via `fs.readSync`, feeds each
   * chunk through `decipher.update()`, and writes the resulting plaintext
   * chunk to a sibling temp file via `fs.writeSync`. This keeps peak memory
   * proportional to the chunk size, regardless of input file size. The
   * temp file is renamed atomically to `outputPath` only after
   * `decipher.final()` validates the GCM auth tag.
   *
   * **Progress reporting:** if a `progress` callback is supplied, it is
   * invoked once with `(0, totalBytes)` before the body stream starts (a
   * "starting" sentinel — the metadata bytes have already been read off
   * disk by this point, but the callback gets a literal `0` so callers can
   * use it as a deterministic start marker), once per 64 KiB body chunk
   * during streaming with `(bytesProcessed, totalBytes)` where
   * `bytesProcessed` is the cumulative count of input ciphertext bytes
   * consumed so far (front matter + trailing tag + body bytes through this
   * chunk), and finally once with `(totalBytes, totalBytes)` after
   * authentication and rename succeed. `bytesProcessed` and `totalBytes`
   * are denominated in input ciphertext bytes (so consumers can compute a
   * single `processed/total` fraction without worrying about overhead). If
   * the callback throws, the throw aborts the operation. See
   * {@link ProgressCallback}.
   *
   * @example
   * ```typescript
   * crypto.decryptFileSync(
   *   'output.enc',
   *   'decrypted.txt',
   *   'MySecureP@ssw0rd123!',
   *   (processed, total) => console.log(`${processed}/${total} bytes`)
   * );
   * ```
   *
   * @param inputPath - Input file path
   * @param outputPath - Output file path
   * @param password - Decryption password (optional if default passphrase is set)
   * @param progress - Optional progress callback. Throws propagate and abort.
   * @throws CryptoError if decryption fails
   * @throws CryptoError `INVALID_INPUT` / `DATA_TOO_LARGE_FOR_GCM` if the
   *   ciphertext body exceeds `MAX_GCM_PLAINTEXT_BYTES` (NIST SP 800-38D
   *   section 5.2.1.1) — such a body could only come from a counter-wrapped,
   *   already-broken encryption. Checked before any key derivation.
   */
  public decryptFileSync(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): void {
    if (
      !inputPath ||
      typeof inputPath !== 'string' ||
      !outputPath ||
      typeof outputPath !== 'string'
    ) {
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

    let tempPath: string | null = null;
    let inputFd: number | null = null;
    let outputFd: number | null = null;
    let key: Buffer | null = null;

    try {
      // Open the input first to eliminate the TOCTOU race between an
      // existsSync check and the later openSync call. ENOENT is re-thrown
      // as INPUT_FILE_NOT_FOUND; other errors propagate to the outer catch.
      try {
        inputFd = openSync(inputPath, 'r');
      } catch (openErr) {
        if ((openErr as Error & { code?: string }).code === 'ENOENT') {
          throw new CryptoError(
            `Input file does not exist: ${inputPath}`,
            CryptoErrorType.FILE_ERROR,
            'INPUT_FILE_NOT_FOUND'
          );
        }
        throw openErr;
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

      // Stat the already-open fd to get the total size (no second name lookup).
      const stat = fstatSync(inputFd as number);
      const totalSize = stat.size;

      // Read the front of the file (up to v1 header + salt + iv) so we can
      // determine the format version and extract crypto metadata. Reading
      // more than the file contains is a no-op (readSync returns 0 for
      // out-of-range bytes) so we cap to totalSize.
      const maxFrontLen = HEADER_LENGTH + this.saltLength + this.ivLength;
      const frontReadLen = Math.min(maxFrontLen, totalSize);
      const front = Buffer.alloc(frontReadLen);
      if (frontReadLen > 0) {
        const bytesReadFront = readSync(inputFd, front, 0, frontReadLen, 0);
        if (bytesReadFront !== frontReadLen) {
          throw new CryptoError(
            'Failed to read full file header region',
            CryptoErrorType.INVALID_INPUT,
            'INVALID_ENCRYPTED_FILE_SIZE'
          );
        }
      }

      // Detect format version.
      let formatHeaderLen: number;
      let pbkdf2Iterations: number = this.legacyPbkdf2Iterations;
      // For v1 ciphertexts, capture on-disk header bytes verbatim for AAD
      // binding (see decryptText for the deeper rationale on why
      // re-serialising would defeat the purpose).
      let headerForAad: Buffer | null = null;

      if (hasMagic(front)) {
        // See decryptText for the full magic-collision recovery rationale.
        try {
          if (front.length < HEADER_LENGTH) {
            throw new CryptoError(
              'File is too small to contain a valid v1 header',
              CryptoErrorType.INVALID_INPUT,
              'INVALID_ENCRYPTED_FILE_SIZE'
            );
          }
          const parsed = parseHeader(front);
          this.assertKdfMatches(parsed, KDF_ID_PBKDF2_SHA256);
          if (parsed.params.kind === 'pbkdf2-sha256') {
            pbkdf2Iterations = parsed.params.iterations;
          }
          formatHeaderLen = parsed.headerLen;
          headerForAad = Buffer.from(front.subarray(0, formatHeaderLen));
        } catch (headerParseErr) {
          if (this.legacyMode !== 'auto') {
            throw headerParseErr;
          }
          if (
            headerParseErr instanceof CryptoError &&
            headerParseErr.code === 'KDF_PARAMS_OUT_OF_BOUNDS'
          ) {
            throw headerParseErr;
          }
          // auto: v0 fallback — headerForAad stays null;
          // pbkdf2Iterations stays at this.legacyPbkdf2Iterations.
          formatHeaderLen = 0;
        }
      } else {
        this.enforceLegacyMode();
        formatHeaderLen = 0;
      }

      // Validate file size.
      const minSize =
        formatHeaderLen + this.saltLength + this.ivLength + this.tagLength;
      if (totalSize < minSize) {
        throw new CryptoError(
          'File is too small to be a valid encrypted file',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_FILE_SIZE'
        );
      }

      // Byte range of the ciphertext body. Computed HERE — the earliest point
      // at which both `totalSize` and `formatHeaderLen` are known — rather
      // than next to the read loop below, so the AES-GCM bound can be enforced
      // before `deriveKeySync` burns hundreds of thousands of PBKDF2
      // iterations and before `openSync(tempPath, 'w')` puts a `.tmp` file on
      // disk. Refusing after either of those would still be correct, but it
      // would do irreversible work on input we are about to reject.
      const bodyStart = formatHeaderLen + this.saltLength + this.ivLength;
      const bodyEnd = totalSize - this.tagLength; // exclusive
      const bodyLen = bodyEnd - bodyStart;
      assertGcmPlaintextLimit(bodyLen, 'DATA_TOO_LARGE_FOR_GCM');

      // Slice salt/iv from the front buffer. Copy into independent Buffers
      // so we own the memory and can scrub it later.
      const salt = Buffer.from(
        front.subarray(formatHeaderLen, formatHeaderLen + this.saltLength)
      );
      const iv = Buffer.from(
        front.subarray(
          formatHeaderLen + this.saltLength,
          formatHeaderLen + this.saltLength + this.ivLength
        )
      );

      // Read the trailing auth tag from the end of the file.
      const tag = Buffer.alloc(this.tagLength);
      const tagOffset = totalSize - this.tagLength;
      const tagBytesRead = readSync(inputFd, tag, 0, this.tagLength, tagOffset);
      if (tagBytesRead !== this.tagLength) {
        throw new CryptoError(
          'Failed to read full auth tag from file',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_FILE_SIZE'
        );
      }

      // Derive key (synchronous, PBKDF2). Re-type any KDF failure to
      // DECRYPTION_FAILED — this is a decrypt op.
      try {
        key = this.deriveKeySync(finalPassword, salt, pbkdf2Iterations);
      } catch (err) {
        throw this.remapKdfErrorForDecryption(err);
      }

      // Allocate temp path and open it for writing.
      tempPath = this.buildTempOutputPath(outputPath);
      outputFd = openSync(tempPath, 'w');

      // Create the decipher and bind AAD + auth tag BEFORE feeding any
      // ciphertext bytes in. setAuthTag() must be called before final().
      //
      // For v1 ciphertexts, AAD includes the on-disk header bytes verbatim
      // (so any tampering — including reserved bytes — flips the GCM tag
      // and decryption fails). For v0 ciphertexts (no header) AAD is just
      // `this.aad` to preserve backward compatibility.
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        key,
        iv
      ) as crypto.DecipherGCM;
      const decipherAad =
        headerForAad === null ? this.aad : this.aadForV1(headerForAad);
      decipher.setAAD(decipherAad);
      decipher.setAuthTag(tag);

      // Stream the body in fixed-size chunks. We read [bodyStart, bodyEnd)
      // and stop once we hit the tag region. The chunk buffer is reused
      // across iterations to keep allocations bounded. (`bodyStart` /
      // `bodyEnd` / `bodyLen` were computed earlier, right after the
      // minimum-size check, so the AES-GCM bound could be enforced before the
      // KDF and the temp file — see the comment there.)
      let bodyConsumed = 0;
      const chunk = Buffer.alloc(this.SYNC_DECRYPT_CHUNK_SIZE);

      // Initial progress event — a literal `(0, totalSize)` start sentinel,
      // matching the async `decryptFile` contract. The metadata bytes
      // (header + salt + iv + tag) have already been read off disk by this
      // point, but we report `0` so callers can use the first event as a
      // deterministic start marker; per-chunk events below report
      // cumulative input-byte progress, and the final event reports
      // `(totalSize, totalSize)`. We invoke it AFTER setting up the temp
      // file but BEFORE the body loop.
      const consumedFrontAndTag = bodyStart + this.tagLength;
      this.invokeProgress(progress, 0, totalSize);

      while (bodyConsumed < bodyLen) {
        const bytesToRead = Math.min(
          this.SYNC_DECRYPT_CHUNK_SIZE,
          bodyLen - bodyConsumed
        );
        const offset = bodyStart + bodyConsumed;
        const bytesRead = readSync(inputFd, chunk, 0, bytesToRead, offset);
        if (bytesRead <= 0) {
          // Should never happen given the bounds checks above; treat as
          // a corrupted file.
          throw new CryptoError(
            'Unexpected EOF while reading ciphertext body',
            CryptoErrorType.INVALID_INPUT,
            'INVALID_ENCRYPTED_FILE_SIZE'
          );
        }
        const inSlice =
          bytesRead === chunk.length ? chunk : chunk.subarray(0, bytesRead);
        const outSlice = decipher.update(inSlice);
        if (outSlice.length > 0) {
          writeFileSync(outputFd, outSlice);
        }
        bodyConsumed += bytesRead;

        // Per-chunk progress: report cumulative ciphertext-byte position
        // in the input. `consumedFrontAndTag + bodyConsumed` grows
        // monotonically from `consumedFrontAndTag` (after first chunk) up
        // to `totalSize` (after last chunk). A throwing callback aborts
        // the loop via `invokeProgress` (which tags + re-throws), and the
        // outer catch handles fd close + temp-file cleanup.
        this.invokeProgress(
          progress,
          consumedFrontAndTag + bodyConsumed,
          totalSize
        );
      }

      // Final block — also authenticates the tag. If authentication fails
      // (wrong password, tampered ciphertext, mismatched AAD, ...) this
      // throws and the catch block below cleans up the temp file.
      const finalBuf = decipher.final();
      if (finalBuf.length > 0) {
        writeFileSync(outputFd, finalBuf);
      }

      // Close the output file BEFORE the rename so Windows lets us replace
      // the destination.
      closeSync(outputFd);
      outputFd = null;

      // Close the input handle (keeping it open through the rename below
      // is unnecessary). A failure here is benign — the input is
      // read-only and authentication + output writing have already
      // succeeded; only an outputFd close failure (above) can indicate
      // data loss. Wrap best-effort so a rare EIO/EBADF cannot discard
      // the validated plaintext temp file.
      try {
        closeSync(inputFd);
      } catch {
        // ignore — benign close failure on read-only input fd
      }
      inputFd = null;

      // Atomic rename — promotes the validated plaintext to the canonical
      // destination.
      this.atomicRenameSync(tempPath, outputPath);
      tempPath = null;

      // Final progress event after authentication + rename succeed. For
      // empty-body inputs (where the loop fired zero times) this is also
      // the only post-init progress event the caller will see, ensuring
      // the spec's "final invocation has processed === total" invariant
      // holds for all inputs.
      this.invokeProgress(progress, totalSize, totalSize);

      // Scrub the chunk reuse buffer plus key/salt/iv/tag.
      this.secureClear(chunk);
      this.secureClear(key);
      this.secureClear(salt);
      this.secureClear(iv);
      this.secureClear(tag);
    } catch (error) {
      if (key !== null) {
        this.secureClear(key);
      }
      // Make sure we drop any open file descriptors before unlinking.
      if (outputFd !== null) {
        try {
          closeSync(outputFd);
        } catch {
          // ignore
        }
      }
      if (inputFd !== null) {
        try {
          closeSync(inputFd);
        } catch {
          // ignore
        }
      }
      // Clean up the temp file (if any). Never touch the canonical
      // outputPath here.
      if (tempPath !== null) {
        this.safeUnlinkSync(tempPath);
      }

      if (error instanceof CryptoError) {
        throw error;
      }
      // Preserve the identity of progress-callback throws (see encryptFile
      // for rationale).
      if (isProgressThrow(error)) {
        throw error;
      }
      throw new CryptoError(
        `Synchronous file decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.DECRYPTION_FAILED,
        'SYNC_FILE_DECRYPTION_FAILED'
      );
    }
  }

  // Isomorphic surface — `inspectHeader`, `secureClear`, `validatePassword`,
  // `getParameters`, `getSecurityLevel`, `hasDefaultPassphrase`,
  // `getLegacyMode`, plus the in-memory `encryptBytes`/`decryptBytes` API —
  // is inherited unchanged from `CryptoCore`.
}

// Re-export the format-related constants for downstream consumers/tests.
export { HEADER_LENGTH };
