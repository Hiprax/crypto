/**
 * Isomorphic (runtime-agnostic) cryptographic core for @hiprax/crypto.
 *
 * `CryptoCore` holds everything that is identical in Node and the browser:
 * constructor option-validation, the in-memory async `encryptBytes` /
 * `decryptBytes` API, header/AAD assembly, security-level classification, and
 * the tooling helpers (`inspectHeader`, `getParameters`, `validatePassword`,
 * …). It depends only on the pure modules `./types.js`, `./format-core.js`,
 * `./codec.js`, and the `./engine.js` interface — it references NO Node global
 * (`Buffer`, `process`) and imports NO Node builtin, so the exact same class
 * runs unchanged in both runtimes. The runtime-specific primitives (CSPRNG,
 * Argon2id, AES-256-GCM, SHA-256) are injected through the {@link CryptoEngine}
 * the constructor receives.
 *
 * The Node `CryptoManager` (in `./crypto-manager.js`) and the browser
 * `CryptoManager` (added later) both `extends CryptoCore`, inject their engine
 * plus a default Argon2id profile, and add the runtime-only surface (Node:
 * `Buffer`-typed low-level, sync, and file/streaming methods; browser: throwing
 * stubs for those). Because the shared logic lives here exactly once, the
 * wire format is guaranteed byte-identical across runtimes.
 *
 * **Isomorphic-file rule (enforced by ESLint `no-restricted-globals` /
 * `no-restricted-imports`):** this file must never touch `Buffer`/`process` or
 * import any `node:*` builtin. All byte work uses `Uint8Array` and the pure
 * `./codec.js` helpers (`utf8Encode`, `concatBytes`, `base64urlToBytes`, …).
 */

import type {
  CryptoManagerOptions,
  Argon2Options,
  EncryptionParameters,
  LegacyMode,
} from './types.js';
import {
  CryptoError,
  CryptoErrorType,
  SecurityLevel,
  EncryptionAlgorithm,
} from './types.js';
import type { KdfHeaderParams, KdfId, ParsedHeader } from './format-core.js';
import {
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  hasMagic,
  packHeader,
  parseHeader,
  MAX_ARGON2_MEMORY_COST,
  MAX_ARGON2_TIME_COST,
  MAX_ARGON2_PARALLELISM,
  MAX_PBKDF2_ITERATIONS,
} from './format-core.js';
import {
  utf8Encode,
  concatBytes,
  base64urlToBytes,
  isValidBase64url,
} from './codec.js';
import type { CryptoEngine } from './engine.js';

/**
 * Argon2id parameter thresholds that classify a {@link CryptoCore} into
 * {@link SecurityLevel} buckets. Each tier is the **minimum** parameter set
 * for that label — see {@link CryptoCore.getSecurityLevel} for the exact
 * classification logic.
 *
 * Marked `as const` so consumers receive a deeply-readonly TYPE (so attempts
 * to mutate are caught by TypeScript), and additionally `Object.freeze`d at
 * runtime (recursively, on the outer object and each tier sub-object) so
 * even untyped consumers (or third-party code reaching in through
 * `(SECURITY_THRESHOLDS as any).HIGH.memoryCost = 1`) cannot weaken the
 * thresholds and trick the classifier into reporting a higher tier than
 * the configuration deserves.
 *
 * Tier rationale (OWASP 2026 guidance for Argon2id):
 *
 *  - **HIGH**   `memoryCost = 2 ** 17` (128 MiB), `timeCost = 3` — the
 *    "first choice" tier for high-security applications. This is the
 *    Node library default.
 *  - **ULTRA**  `memoryCost = 2 ** 19` (512 MiB), `timeCost = 4` — the
 *    "paranoid" tier; meaningful for offline/asymmetric workloads where the
 *    extra latency and memory pressure are tolerable.
 *  - **MEDIUM** `memoryCost = 2 ** 14` (16 MiB), `timeCost = 2` — minimum
 *    acceptable threshold; suitable only for resource-constrained devices.
 *
 * Anything below `MEDIUM` is reported as `LOW` with no fixed threshold of
 * its own.
 *
 * Re-exported from `crypto-manager.ts` and `index.ts` so downstream tooling
 * can introspect the thresholds (e.g. to assert at startup that a configured
 * policy is at least `HIGH`).
 */
export const SECURITY_THRESHOLDS = Object.freeze({
  ULTRA: Object.freeze({ memoryCost: 2 ** 19, timeCost: 4 }),
  HIGH: Object.freeze({ memoryCost: 2 ** 17, timeCost: 3 }),
  MEDIUM: Object.freeze({ memoryCost: 2 ** 14, timeCost: 2 }),
} as const);

/**
 * Default PBKDF2 iteration count for sync key derivation when producing new
 * v1 ciphertexts. Matches the OWASP 2023+ recommendation for
 * PBKDF2-HMAC-SHA256 (still current in 2026). Consumed only by the
 * constructor when defaulting `pbkdf2Iterations`; the Node sync paths read
 * the resolved instance field.
 */
const PBKDF2_DEFAULT_ITERATIONS = 600000;

/**
 * Iteration count assumed for legacy v0 sync ciphertexts (those produced by
 * versions of this library prior to 0.11.0, which used 100k iterations and
 * did not embed the iteration count in the ciphertext). v1 ciphertexts
 * carry the iteration count in their header and ignore this constant.
 */
const PBKDF2_LEGACY_ITERATIONS = 100000;

/**
 * Minimum length that allows a password to bypass character-category
 * requirements. Passwords meeting this length are accepted regardless of
 * character composition, which aligns with NIST SP 800-63B (which deprecates
 * composition rules in favour of length) and lets users rely on
 * XKCD-style passphrases (e.g. "correct horse battery staple longer") that
 * have very high entropy from word choice alone.
 */
const PASSPHRASE_MIN_LENGTH = 20;

/**
 * Minimum length when relying on the legacy character-category rule.
 */
const PASSWORD_MIN_LENGTH = 8;

/**
 * Numeric identifier for the Argon2id variant. Matches the value the native
 * `argon2` module uses (`argon2id === 2`) and is surfaced verbatim in
 * {@link CryptoCore.getParameters}'s `argon2Options.type`. Hardcoded here (a
 * plain number, no import) so the isomorphic core never has to reach into a
 * runtime-specific engine module just to stamp this metadata; `engine.node.ts`
 * keeps its own copy for the native `argon2` call.
 */
const ARGON2_ID = 2;

/**
 * Pure (static) password-strength validator. Does NOT depend on any
 * `CryptoCore` instance state — it is a deterministic function of the
 * password string alone. Extracted to module scope so that the
 * `CryptoCore` constructor can validate `defaultPassphrase` BEFORE
 * `this` is fully initialised (the public `validatePassword` instance
 * method delegates here).
 *
 * Acceptance rules (a password is valid if EITHER condition holds):
 *
 *  1. **Passphrase rule (NIST SP 800-63B style):** at least
 *     {@link PASSPHRASE_MIN_LENGTH} (20) characters, regardless of
 *     character composition. This accepts XKCD-style multi-word
 *     passphrases that are well-known to have high entropy from word
 *     choice alone but lack uppercase / digit / special-char categories.
 *
 *  2. **Composition rule (legacy):** at least
 *     {@link PASSWORD_MIN_LENGTH} (8) characters, AND contains at least one
 *     uppercase letter, one lowercase letter, one digit, and one
 *     non-alphanumeric character (matched by `/[^A-Za-z0-9]/`, which is
 *     intentionally broader than the previous narrow allow-list of
 *     `[!@#$%^&*(),.?":{}|<>]`).
 *
 * Non-string input or `null`/`undefined` returns `false`.
 *
 * @param password - The password to validate.
 * @returns `true` iff the password meets either acceptance rule.
 */
export function isValidPassword(password: string): boolean {
  if (!password || typeof password !== 'string') {
    return false;
  }

  // NIST passphrase style: long enough to skip character-category checks.
  if (password.length >= PASSPHRASE_MIN_LENGTH) {
    return true;
  }

  // Legacy composition rule: 8+ chars with all four categories. We
  // deliberately use `[^A-Za-z0-9]` (any non-alphanumeric character)
  // rather than the previous narrow allow-list `[!@#$%^&*(),.?":{}|<>]`
  // so that common but previously-rejected specials like `_` `-` `+` `[` `]`
  // and non-ASCII punctuation now count as "special".
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[^A-Za-z0-9]/.test(password);

  return (
    password.length >= PASSWORD_MIN_LENGTH &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumbers &&
    hasSpecialChar
  );
}

/**
 * Abstract, runtime-agnostic base class for the high-security encryption
 * manager. Holds the shared option validation, the isomorphic in-memory
 * `encryptBytes`/`decryptBytes` API, and the classification/tooling helpers.
 * Concrete subclasses inject a {@link CryptoEngine} and the default Argon2id
 * profile for their runtime and add any runtime-only methods.
 */
export abstract class CryptoCore {
  protected readonly algorithm: string;
  protected readonly keyLength: number;
  protected readonly ivLength: number;
  protected readonly saltLength: number;
  protected readonly tagLength: number;
  protected readonly argon2Options: Argon2Options;
  /**
   * Additional Authenticated Data context bytes, UTF-8-encoded from the
   * configured `aad` string. Stored as a `Uint8Array` (not a Node `Buffer`)
   * so the core stays runtime-agnostic; Node subclass call sites that pass
   * this to the `Buffer`-guarded low-level API wrap it in `Buffer.from(...)`.
   */
  protected readonly aad: Uint8Array;
  /**
   * Password retained by the manager when `defaultPassphrase` is set in
   * the constructor. Stored as a plain V8 string — V8 strings are
   * immutable and GC-managed, so the library cannot scrub this value with
   * `secureClear` (which only zero-fills byte-array allocations).
   *
   * **Lifetime:** the passphrase stays resident in process memory for the
   * full lifetime of this instance, plus an unbounded GC tail for any
   * internal V8 string copies created along the way. Long-lived managers
   * therefore keep the passphrase resident for the whole process lifetime.
   *
   * **Recommendation:** for sensitive workloads, prefer passing the
   * password explicitly to each encrypt/decrypt call rather than relying
   * on `defaultPassphrase`.
   */
  protected readonly defaultPassphrase?: string;
  protected readonly legacyMode: LegacyMode;
  protected readonly pbkdf2Iterations: number;
  protected readonly legacyPbkdf2Iterations: number;
  /**
   * When true, AES-GCM AAD for v1 ciphertexts uses just `this.aad` (the
   * v1.0.0 behaviour). Default false — the AAD includes the on-disk v1
   * header bytes, so any tampering with the header (including the
   * reserved-byte regions) flips the GCM tag and decryption fails.
   */
  protected readonly legacyHeaderAad: boolean;
  /**
   * The runtime-specific cryptographic engine (Node `node:crypto` or the
   * browser SubtleCrypto + hash-wasm). Injected by the concrete subclass so
   * the shared core can perform its crypto without importing any runtime
   * builtin.
   */
  protected readonly engine: CryptoEngine;

  /**
   * @param options - user-supplied manager options (validated here).
   * @param engine - the runtime cryptographic engine.
   * @param defaultProfile - the runtime's default Argon2id cost profile,
   *   used when the corresponding `options` field is omitted (Node injects
   *   the HIGH tier at `p=1`; the browser injects a lighter 32 MiB profile).
   */
  constructor(
    options: CryptoManagerOptions,
    engine: CryptoEngine,
    defaultProfile: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
    }
  ) {
    this.engine = engine;
    this.algorithm = EncryptionAlgorithm.AES_256_GCM;
    this.keyLength = 32; // 256 bits
    this.ivLength = 12; // 96 bits for GCM
    this.saltLength = 32; // 256 bits
    this.tagLength = 16; // 128 bits for GCM

    // Validate numeric options
    if (
      options.memoryCost !== undefined &&
      (!Number.isInteger(options.memoryCost) || options.memoryCost <= 0)
    ) {
      throw new CryptoError(
        'memoryCost must be a positive integer',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_MEMORY_COST'
      );
    }
    if (
      options.memoryCost !== undefined &&
      options.memoryCost > MAX_ARGON2_MEMORY_COST
    ) {
      throw new CryptoError(
        `memoryCost (${options.memoryCost}) exceeds the wire-format cap of ` +
          `${MAX_ARGON2_MEMORY_COST} (2^22 KiB = 4 GiB). Values above this cap ` +
          `produce ciphertext that cannot be decrypted (KDF_PARAMS_OUT_OF_BOUNDS). ` +
          `Use a value between 1 and ${MAX_ARGON2_MEMORY_COST}.`,
        CryptoErrorType.INVALID_INPUT,
        'MEMORY_COST_TOO_LARGE'
      );
    }
    if (
      options.timeCost !== undefined &&
      (!Number.isInteger(options.timeCost) || options.timeCost <= 0)
    ) {
      throw new CryptoError(
        'timeCost must be a positive integer',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_TIME_COST'
      );
    }
    if (
      options.timeCost !== undefined &&
      options.timeCost > MAX_ARGON2_TIME_COST
    ) {
      throw new CryptoError(
        `timeCost (${options.timeCost}) exceeds the wire-format cap of ` +
          `${MAX_ARGON2_TIME_COST}. Values above this cap produce ciphertext that ` +
          `cannot be decrypted (KDF_PARAMS_OUT_OF_BOUNDS). ` +
          `Use a value between 1 and ${MAX_ARGON2_TIME_COST}.`,
        CryptoErrorType.INVALID_INPUT,
        'TIME_COST_TOO_LARGE'
      );
    }
    if (
      options.parallelism !== undefined &&
      (!Number.isInteger(options.parallelism) || options.parallelism <= 0)
    ) {
      throw new CryptoError(
        'parallelism must be a positive integer',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PARALLELISM'
      );
    }
    if (
      options.parallelism !== undefined &&
      options.parallelism > MAX_ARGON2_PARALLELISM
    ) {
      throw new CryptoError(
        `parallelism (${options.parallelism}) exceeds the wire-format cap of ` +
          `${MAX_ARGON2_PARALLELISM}. Values above this cap produce ciphertext that ` +
          `cannot be decrypted (KDF_PARAMS_OUT_OF_BOUNDS). ` +
          `Use a value between 1 and ${MAX_ARGON2_PARALLELISM}.`,
        CryptoErrorType.INVALID_INPUT,
        'PARALLELISM_TOO_LARGE'
      );
    }
    if (
      options.pbkdf2Iterations !== undefined &&
      (!Number.isInteger(options.pbkdf2Iterations) ||
        options.pbkdf2Iterations <= 0)
    ) {
      throw new CryptoError(
        'pbkdf2Iterations must be a positive integer',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PBKDF2_ITERATIONS'
      );
    }
    if (
      options.pbkdf2Iterations !== undefined &&
      options.pbkdf2Iterations > MAX_PBKDF2_ITERATIONS
    ) {
      throw new CryptoError(
        `pbkdf2Iterations (${options.pbkdf2Iterations}) exceeds the wire-format cap of ` +
          `${MAX_PBKDF2_ITERATIONS}. Values above this cap produce ciphertext that ` +
          `cannot be decrypted (KDF_PARAMS_OUT_OF_BOUNDS). ` +
          `Use a value between 1 and ${MAX_PBKDF2_ITERATIONS}.`,
        CryptoErrorType.INVALID_INPUT,
        'PBKDF2_ITERATIONS_TOO_LARGE'
      );
    }
    if (
      options.legacyPbkdf2Iterations !== undefined &&
      (!Number.isInteger(options.legacyPbkdf2Iterations) ||
        options.legacyPbkdf2Iterations <= 0)
    ) {
      throw new CryptoError(
        'legacyPbkdf2Iterations must be a positive integer',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_LEGACY_PBKDF2_ITERATIONS'
      );
    }
    if (
      options.legacyPbkdf2Iterations !== undefined &&
      options.legacyPbkdf2Iterations > MAX_PBKDF2_ITERATIONS
    ) {
      throw new CryptoError(
        `legacyPbkdf2Iterations (${options.legacyPbkdf2Iterations}) exceeds the cap of ` +
          `${MAX_PBKDF2_ITERATIONS}. This value is fed directly to pbkdf2Sync; ` +
          `values above this cap risk blocking the event loop indefinitely. ` +
          `Use a value between 1 and ${MAX_PBKDF2_ITERATIONS}.`,
        CryptoErrorType.INVALID_INPUT,
        'LEGACY_PBKDF2_ITERATIONS_TOO_LARGE'
      );
    }

    this.pbkdf2Iterations =
      options.pbkdf2Iterations ?? PBKDF2_DEFAULT_ITERATIONS;
    this.legacyPbkdf2Iterations =
      options.legacyPbkdf2Iterations ?? PBKDF2_LEGACY_ITERATIONS;

    // Validate legacyMode option
    if (options.legacyMode !== undefined) {
      if (
        options.legacyMode !== 'auto' &&
        options.legacyMode !== 'strict' &&
        options.legacyMode !== 'reject'
      ) {
        throw new CryptoError(
          "legacyMode must be one of: 'auto', 'strict', 'reject'",
          CryptoErrorType.INVALID_INPUT,
          'INVALID_LEGACY_MODE'
        );
      }
    }
    this.legacyMode = options.legacyMode ?? 'auto';

    // Store default passphrase if provided and not empty.
    //
    // We validate `defaultPassphrase` strength **at construction time** so
    // that misconfigured weak passphrases fail fast rather than at first
    // encrypt/decrypt call. The validation is delegated to the module-level
    // `isValidPassword` helper so it does NOT depend on `this` being fully
    // initialised.
    //
    // Callers who need to decrypt legacy data encrypted under a weak
    // password can opt out via `skipPasswordValidation: true`. This flag
    // does NOT bypass NFC normalisation in the KDF paths.
    if (
      options.defaultPassphrase !== undefined &&
      options.defaultPassphrase !== ''
    ) {
      if (
        options.skipPasswordValidation !== true &&
        !isValidPassword(options.defaultPassphrase)
      ) {
        throw new CryptoError(
          'defaultPassphrase does not meet security requirements. ' +
            'Use a passphrase of at least 20 characters, OR a password of ' +
            '8+ characters containing uppercase, lowercase, digit, and ' +
            'non-alphanumeric. To bypass this check (e.g. for legacy ' +
            'data decryption), set `skipPasswordValidation: true`.',
          CryptoErrorType.INVALID_PASSWORD,
          'WEAK_PASSWORD'
        );
      }
      this.defaultPassphrase = options.defaultPassphrase;
    }

    // Argon2id parameters. `type` is hardcoded to the numeric Argon2id
    // identifier (`2`) rather than read from a runtime engine module so that
    // constructing a manager does NOT trigger loading the native module —
    // consumers who only use the *Sync methods (PBKDF2) can run with argon2
    // absent.
    //
    // The default `memoryCost`/`timeCost`/`parallelism` come from the
    // runtime's `defaultProfile` (Node: the HIGH tier at 128 MiB / t=3 / p=1;
    // browser: a lighter 32 MiB profile). Existing v1 ciphertexts produced
    // with a different profile continue to decrypt because each ciphertext
    // header embeds the exact memoryCost / timeCost / parallelism that were
    // used to derive its key, so the decoder applies the embedded values
    // rather than this constructor default.
    this.argon2Options = {
      type: ARGON2_ID,
      memoryCost: options.memoryCost ?? defaultProfile.memoryCost,
      timeCost: options.timeCost ?? defaultProfile.timeCost,
      parallelism: options.parallelism ?? defaultProfile.parallelism,
      hashLength: this.keyLength,
      saltLength: this.saltLength,
    };

    // Argon2id mandates memoryCost >= 8 * parallelism. Enforcing this on the
    // resolved (post-defaulting) values at construction time means the first
    // async encrypt call fails fast with a clear error rather than an opaque
    // KEY_DERIVATION_FAILED from deep inside the KDF. The defaults trivially
    // pass, as do all documented opt-down profiles. The sync PBKDF2 path
    // ignores memoryCost entirely, so this check is scoped strictly to the
    // Argon2 options that drive async paths.
    const argon2MemFloor = 8 * this.argon2Options.parallelism;
    if (this.argon2Options.memoryCost < argon2MemFloor) {
      throw new CryptoError(
        `memoryCost (${this.argon2Options.memoryCost}) must be at least ` +
          `8 * parallelism (${argon2MemFloor} = 8 × ${this.argon2Options.parallelism}) ` +
          `for Argon2id. Use a memoryCost of at least ${argon2MemFloor} or reduce parallelism.`,
        CryptoErrorType.INVALID_INPUT,
        'MEMORY_COST_TOO_SMALL'
      );
    }

    // Validate aad type before encoding it. A non-string `aad` would produce
    // surprising bytes (arrays coerce, numbers/objects throw a raw
    // TypeError), neither of which is a CryptoError — so we reject it here
    // with the same typed CryptoError shape as every other option.
    if (options.aad !== undefined && typeof options.aad !== 'string') {
      throw new CryptoError(
        'aad must be a string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_AAD'
      );
    }

    // Use custom AAD or default. UTF-8-encode to a Uint8Array (isomorphic
    // replacement for `Buffer.from(aadString, 'utf8')`; byte-identical).
    const aadString = options.aad ?? 'secure-crypto-tool-v2';
    this.aad = utf8Encode(aadString);

    // Default to the integrity-binding AAD format introduced in v1.1.0.
    // Callers needing to decrypt legacy v1.0.0 ciphertexts can opt back in
    // to the bound-aad-only format via `legacyHeaderAad: true`. Note this
    // affects v1 ciphertexts only — v0 ciphertexts always use `this.aad`
    // alone (they have no header to bind).
    this.legacyHeaderAad = options.legacyHeaderAad === true;
  }

  /**
   * Compute the AAD that AES-GCM should bind to a v1 ciphertext.
   *
   * Includes the on-disk v1 header bytes verbatim after `this.aad`. Both
   * encrypt and decrypt paths call this with the **exact same bytes** they
   * have on the wire (the encrypt path uses the buffer it just packed; the
   * decrypt path uses the bytes it read out of the input, NOT a re-serialised
   * copy — so reserved-byte tampering remains visible).
   *
   * @param headerBytes - the 22-byte v1 header (including any reserved
   *   bytes, exactly as it will be / was written on the wire)
   * @returns the AAD value to pass to the engine's AEAD calls
   */
  protected aadForV1(headerBytes: Uint8Array): Uint8Array {
    if (this.legacyHeaderAad) {
      // Backward-compat shim for v1.0.0 ciphertexts: AAD is just the
      // configured context string, header bytes are NOT bound.
      return this.aad;
    }
    return concatBytes(this.aad, headerBytes);
  }

  /**
   * Build the v1 header that should be prepended to every newly produced
   * ciphertext, parameterised for the given KDF. Shared by the isomorphic
   * byte path and every Node subclass construction site so all paths emit
   * byte-identical headers.
   */
  protected buildHeader(kdfId: KdfId): Uint8Array {
    if (kdfId === KDF_ID_ARGON2ID) {
      const params: KdfHeaderParams = {
        kind: 'argon2id',
        memoryCost: this.argon2Options.memoryCost,
        timeCost: this.argon2Options.timeCost,
        parallelism: this.argon2Options.parallelism,
      };
      return packHeader(KDF_ID_ARGON2ID, params);
    }
    const params: KdfHeaderParams = {
      kind: 'pbkdf2-sha256',
      iterations: this.pbkdf2Iterations,
    };
    return packHeader(KDF_ID_PBKDF2_SHA256, params);
  }

  /**
   * Apply the configured legacy-mode policy to a v0 ciphertext (one that does
   * not start with the "HPCR" magic). Returns nothing on success and throws
   * with the appropriate error code when v0 is not allowed.
   */
  protected enforceLegacyMode(): void {
    if (this.legacyMode === 'auto') {
      return;
    }
    if (this.legacyMode === 'strict') {
      throw new CryptoError(
        'Legacy v0 ciphertext format is not accepted in strict legacy mode',
        CryptoErrorType.DECRYPTION_FAILED,
        'LEGACY_FORMAT_REJECTED'
      );
    }
    // 'reject'
    throw new CryptoError(
      'Unsupported (legacy v0) ciphertext format',
      CryptoErrorType.DECRYPTION_FAILED,
      'UNSUPPORTED_FORMAT'
    );
  }

  /**
   * Validate that a parsed v1 header matches the KDF expected by the calling
   * decryption path (async expects Argon2id, sync expects PBKDF2-SHA256).
   */
  protected assertKdfMatches(parsed: ParsedHeader, expected: KdfId): void {
    if (parsed.kdfId !== expected) {
      throw new CryptoError(
        `Ciphertext was produced with KDF id ${parsed.kdfId} but this decryption path expects ${expected}. ` +
          'Use the matching encrypt/decrypt pair (async with async, sync with sync).',
        CryptoErrorType.DECRYPTION_FAILED,
        'KDF_MISMATCH'
      );
    }
  }

  /**
   * Re-type a key-derivation failure that surfaced during a DECRYPT
   * operation so it carries `DECRYPTION_FAILED` instead of the
   * direction-neutral `ENCRYPTION_FAILED` produced by the KDF helpers.
   *
   * The KDF helpers are direction-agnostic: a direct derivation call is
   * neither an encrypt nor a decrypt, so they keep their historical
   * `ENCRYPTION_FAILED` typing. Only decrypt call sites re-map, at the call
   * site, because that is where we actually know the operation is a
   * decryption.
   *
   * Only the two derivation-failure shapes are re-typed:
   * `ENCRYPTION_FAILED` + (`KEY_DERIVATION_FAILED` | `SYNC_KEY_DERIVATION_FAILED`).
   * The `.code` is preserved so callers keying on `.code` are unaffected;
   * only the `.type` category is corrected. Everything else passes through
   * untouched — in particular `ARGON2_NOT_AVAILABLE` (type `MEMORY_ERROR`)
   * and `INVALID_SALT` / `INVALID_PASSWORD` (type `INVALID_INPUT`), which are
   * already correctly typed.
   *
   * @param error - The value thrown by a decrypt-path key derivation call.
   * @returns The original error, or a re-typed `CryptoError` when it is a
   *   derivation failure.
   */
  protected remapKdfErrorForDecryption(error: unknown): unknown {
    if (
      error instanceof CryptoError &&
      error.type === CryptoErrorType.ENCRYPTION_FAILED &&
      (error.code === 'KEY_DERIVATION_FAILED' ||
        error.code === 'SYNC_KEY_DERIVATION_FAILED')
    ) {
      return new CryptoError(
        error.message,
        CryptoErrorType.DECRYPTION_FAILED,
        error.code
      );
    }
    return error;
  }

  /**
   * Derive a raw AES key from a password using Argon2id via the injected
   * engine. Isomorphic counterpart of the Node subclass's `deriveKey`:
   * validates inputs, NFC-normalises the password, and applies embedded
   * parameter overrides when decrypting v1 ciphertexts.
   *
   * @param password - user password (non-empty string)
   * @param salt - random salt (`saltLength` bytes)
   * @param overrides - optional Argon2 parameters embedded in a v1 header,
   *   used so a ciphertext produced by an instance with different defaults
   *   still decrypts.
   * @returns the derived key bytes (`keyLength` bytes)
   * @throws CryptoError if derivation fails (`INVALID_PASSWORD`,
   *   `INVALID_SALT`, `ARGON2_NOT_AVAILABLE`, or `KEY_DERIVATION_FAILED`)
   */
  private async deriveKeyBytes(
    password: string,
    salt: Uint8Array,
    overrides?: { memoryCost: number; timeCost: number; parallelism: number }
  ): Promise<Uint8Array> {
    if (!password || typeof password !== 'string') {
      throw new CryptoError(
        'Password must be a non-empty string',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    if (!(salt instanceof Uint8Array) || salt.length !== this.saltLength) {
      throw new CryptoError(
        `Invalid salt provided. Expected ${this.saltLength} bytes.`,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_SALT'
      );
    }

    try {
      const memoryCost = overrides?.memoryCost ?? this.argon2Options.memoryCost;
      const timeCost = overrides?.timeCost ?? this.argon2Options.timeCost;
      const parallelism =
        overrides?.parallelism ?? this.argon2Options.parallelism;

      // Apply Unicode NFC normalisation so visually-identical passwords
      // produce the same key regardless of how the input method composed
      // them (e.g. precomposed `é` U+00E9 vs `e` + combining acute). NFC is
      // the canonical W3C recommendation for text-on-the-wire and matches
      // the Node subclass's `deriveKey`/`deriveKeySync` behaviour. The
      // engine hashes the exact string it is handed (engine contract).
      const normalizedPassword = password.normalize('NFC');

      const key = await this.engine.deriveArgon2id(normalizedPassword, salt, {
        memoryCost,
        timeCost,
        parallelism,
        hashLength: this.argon2Options.hashLength,
      });

      // Ensure we get exactly the key length we need.
      return key.subarray(0, this.keyLength);
    } catch (error) {
      // Preserve `ARGON2_NOT_AVAILABLE` and any other CryptoError thrown
      // upstream — only wrap genuinely opaque errors from the engine.
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
   * Encrypt raw bytes with a password, producing a v1 Argon2id ciphertext in
   * the TEXT byte layout `[header:22][salt:32][iv:12][tag:16][ciphertext]`.
   *
   * This is the isomorphic in-memory API: the exact same code (and the exact
   * same output bytes) runs in Node and the browser. The Node `encryptText`
   * and the browser build are both re-expressed on top of this method, so
   * there is one wire format and one code path.
   *
   * @param data - plaintext bytes (the empty `Uint8Array` is accepted and
   *   produces a valid authenticated ciphertext; only non-`Uint8Array`
   *   inputs are rejected). The caller's buffer is NOT mutated or scrubbed.
   * @param password - encryption password (optional if a default passphrase
   *   is configured)
   * @returns the v1 ciphertext bytes
   * @throws CryptoError on invalid input, weak password, or an engine failure
   */
  public async encryptBytes(
    data: Uint8Array,
    password?: string
  ): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array)) {
      throw new CryptoError(
        'Data must be a Uint8Array',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_DATA'
      );
    }

    // Use provided password or default passphrase.
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    // Validate password strength.
    if (!this.validatePassword(finalPassword)) {
      throw new CryptoError(
        'Password does not meet security requirements',
        CryptoErrorType.INVALID_PASSWORD,
        'WEAK_PASSWORD'
      );
    }

    let key: Uint8Array | null = null;
    try {
      // Generate salt and IV.
      const salt = this.engine.randomBytes(this.saltLength);
      const iv = this.engine.randomBytes(this.ivLength);

      // Derive key from password (Argon2id, instance params).
      key = await this.deriveKeyBytes(finalPassword, salt);

      // Build v1 header (Argon2id parameters that were used). We build it
      // BEFORE encrypting so we can include the on-disk header bytes in the
      // AES-GCM AAD — this binds the header to the auth tag, so any tampering
      // with the header (including reserved bytes) flips the tag and
      // decryption fails.
      const header = this.buildHeader(KDF_ID_ARGON2ID);

      // Encrypt with header-bound AAD; the engine returns the tag separately.
      const { ciphertext, tag } = await this.engine.aeadEncrypt(
        key,
        iv,
        data,
        this.aadForV1(header)
      );

      // Combine: header + salt + iv + tag + ciphertext (TEXT layout).
      const combined = concatBytes(header, salt, iv, tag, ciphertext);

      // Scrub the derived key now that the ciphertext is assembled. `data`
      // (the caller's plaintext) is deliberately NOT scrubbed — the caller
      // owns that buffer.
      this.secureClear(key);

      return combined;
    } catch (error) {
      if (key !== null) {
        this.secureClear(key);
      }
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.ENCRYPTION_FAILED,
        'ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Decrypt v1 (Argon2id) or legacy v0 ciphertext bytes with a password.
   *
   * Mirrors the Node `decryptText` byte path exactly: v1 magic detection,
   * header parse + `assertKdfMatches(Argon2id)`, embedded-parameter override,
   * header-bound AAD, and the `legacyMode` v0 fallback (with the
   * magic-collision recovery and the `KDF_PARAMS_OUT_OF_BOUNDS` re-throw).
   *
   * @param data - the ciphertext bytes. NOT mutated or scrubbed.
   * @param password - decryption password (optional if a default passphrase
   *   is configured)
   * @returns the recovered plaintext bytes (caller owns the buffer)
   * @throws CryptoError on invalid input, wrong password, tampering, or an
   *   unsupported/mismatched format (all confidentiality-relevant failures
   *   surface as the generic `DECRYPTION_FAILED`).
   */
  public async decryptBytes(
    data: Uint8Array,
    password?: string
  ): Promise<Uint8Array> {
    if (!(data instanceof Uint8Array)) {
      throw new CryptoError(
        'Encrypted data must be a Uint8Array',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_ENCRYPTED_DATA'
      );
    }

    // Use provided password or default passphrase.
    const finalPassword = password || this.defaultPassphrase;
    if (!finalPassword || typeof finalPassword !== 'string') {
      throw new CryptoError(
        'Password is required. Either provide a password parameter or set a default passphrase in the constructor.',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_PASSWORD'
      );
    }

    let key: Uint8Array | null = null;
    try {
      const combined = data;

      // Detect format version. v1 starts with HPCR magic; otherwise we fall
      // back to v0 if legacyMode allows it.
      let bodyOffset: number;
      let argonOverrides:
        | { memoryCost: number; timeCost: number; parallelism: number }
        | undefined;
      // For v1 ciphertexts, capture the on-disk header bytes VERBATIM so we
      // can include them in the AES-GCM AAD. Re-serialising via packHeader
      // would zero-fill reserved regions, hiding any tampering with those
      // bytes — the goal of this binding is precisely to detect such
      // tampering, so we must AAD the bytes that were actually on the wire.
      let headerForAad: Uint8Array | null = null;

      if (hasMagic(combined)) {
        // Attempt to parse as v1. parseHeader + assertKdfMatches are wrapped
        // so that a rare magic-collision on a v0 random salt (~2^-32 per
        // ciphertext) triggers the auto-mode recovery path rather than
        // becoming permanent data loss. A genuine v1 ciphertext always has
        // a valid parseable header, so this catch is unreachable for
        // well-formed v1 data — only colliding v0 blobs land here. We never
        // catch AEAD tag failures (those happen later and indicate wrong
        // password or tampering, not misclassification).
        try {
          const parsed = parseHeader(combined);
          this.assertKdfMatches(parsed, KDF_ID_ARGON2ID);
          if (parsed.params.kind === 'argon2id') {
            argonOverrides = {
              memoryCost: parsed.params.memoryCost,
              timeCost: parsed.params.timeCost,
              parallelism: parsed.params.parallelism,
            };
          }
          bodyOffset = parsed.headerLen;
          // Slice on-disk header bytes (a view over `combined`, which is the
          // caller's buffer — read-only here).
          headerForAad = combined.subarray(0, parsed.headerLen);
        } catch (headerParseErr) {
          // Header parse failed. In non-auto modes, re-throw so that
          // UNSUPPORTED_VERSION / UNSUPPORTED_KDF / KDF_MISMATCH remain
          // observable to callers and future-versioned ciphertexts are not
          // mis-reported as legacy. In auto mode we fall back to v0, with
          // one exception: KDF_PARAMS_OUT_OF_BOUNDS is always re-thrown so
          // that DoS-prevention (fast rejection before any KDF work) is
          // preserved regardless of magic-collision possibility.
          if (this.legacyMode !== 'auto') {
            throw headerParseErr;
          }
          if (
            headerParseErr instanceof CryptoError &&
            headerParseErr.code === 'KDF_PARAMS_OUT_OF_BOUNDS'
          ) {
            throw headerParseErr;
          }
          // auto: treat the full buffer as v0 [salt][iv][tag][body].
          // headerForAad stays null; argonOverrides stays undefined.
          bodyOffset = 0;
        }
      } else {
        this.enforceLegacyMode();
        bodyOffset = 0;
      }

      // Validate minimum size (after the header, the body is salt + iv + tag).
      const minBodySize = this.saltLength + this.ivLength + this.tagLength;
      if (combined.length < bodyOffset + minBodySize) {
        throw new CryptoError(
          'Encrypted data is too small to be valid',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_ENCRYPTED_DATA_SIZE'
        );
      }

      // Extract components. Each is a subarray view over `combined`.
      const saltStart = bodyOffset;
      const ivStart = saltStart + this.saltLength;
      const tagStart = ivStart + this.ivLength;
      const dataStart = tagStart + this.tagLength;

      const salt = combined.subarray(saltStart, ivStart);
      const iv = combined.subarray(ivStart, tagStart);
      const tag = combined.subarray(tagStart, dataStart);
      const encrypted = combined.subarray(dataStart);

      // Derive key from password (use embedded params if present so we can
      // decrypt ciphertext produced by an instance with different defaults).
      // Re-type any KDF failure to DECRYPTION_FAILED — this is a decrypt op.
      try {
        key = await this.deriveKeyBytes(finalPassword, salt, argonOverrides);
      } catch (err) {
        throw this.remapKdfErrorForDecryption(err);
      }

      // Decrypt with the matching AAD (header-bound for v1, `this.aad`-only
      // for v0). The engine throws generic DECRYPTION_FAILED on auth failure.
      const aad =
        headerForAad === null ? this.aad : this.aadForV1(headerForAad);
      const decrypted = await this.engine.aeadDecrypt(
        key,
        iv,
        encrypted,
        tag,
        aad
      );

      // Scrub the derived key. The plaintext is the return value (caller
      // owns it); the caller's ciphertext buffer is left untouched.
      this.secureClear(key);

      return decrypted;
    } catch (error) {
      if (key !== null) {
        this.secureClear(key);
      }
      if (error instanceof CryptoError) {
        throw error;
      }
      throw new CryptoError(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        CryptoErrorType.DECRYPTION_FAILED,
        'DECRYPTION_FAILED'
      );
    }
  }

  /**
   * Inspect the format header on a v1 ciphertext (text or file) without
   * decrypting. Returns `null` for legacy v0 ciphertexts that do not carry a
   * header. Useful for tooling and tests.
   *
   * String inputs are validated as well-formed base64url BEFORE decoding —
   * a base64url decode silently coerces invalid characters, which would make
   * a malformed input look like a v0 ciphertext (returning `null`) rather
   * than surfacing the encoding error. Failing fast matches the documented
   * contract. `Uint8Array` inputs (including Node `Buffer`s) are read as-is.
   *
   * @param input - either a base64url string (text format) or byte array
   *   (file contents). Strings are validated as base64url and decoded; byte
   *   arrays are read as-is.
   * @returns the parsed header, or `null` when the input lacks the v1 magic
   * @throws CryptoError (`INVALID_INPUT` / `INVALID_BASE64URL`) if the input
   *   string is not well-formed base64url, or if the input begins with the
   *   v1 magic but is otherwise malformed.
   */
  public inspectHeader(input: string | Uint8Array): ParsedHeader | null {
    let buf: Uint8Array;
    if (typeof input === 'string') {
      if (input.length === 0) {
        throw new CryptoError(
          'inspectHeader: input string must be non-empty',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_INPUT'
        );
      }
      // Validate the encoding BEFORE decoding, which silently drops invalid
      // characters (e.g. '!!!!' decodes to an empty buffer rather than
      // throwing). Without this check a caller that passed a malformed
      // string would get `null` back (looks like a v0 ciphertext) instead of
      // an explicit "this isn't base64url" error.
      if (!isValidBase64url(input)) {
        throw new CryptoError(
          'inspectHeader: input string is not valid base64url',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_BASE64URL'
        );
      }
      buf = base64urlToBytes(input);
    } else if (input instanceof Uint8Array) {
      buf = input;
    } else {
      throw new CryptoError(
        'inspectHeader: input must be a base64url string or Uint8Array',
        CryptoErrorType.INVALID_INPUT,
        'INVALID_INPUT'
      );
    }
    if (!hasMagic(buf)) {
      return null;
    }
    return parseHeader(buf);
  }

  /**
   * Best-effort buffer clearing.
   *
   * **NOT guaranteed against V8 string copies, GC-managed allocations, or
   * compiler reordering.** Useful only for explicit byte-array instances;
   * will not scrub the original input string or any V8-internal copies of
   * derived material.
   *
   * Specifically:
   * - `Uint8Array.fill(0)` zeroes the underlying ArrayBuffer slab — this is
   *   sufficient hygiene for raw key/IV/tag/salt material allocated as a
   *   byte array.
   * - Plaintext strings (the password parameter, the decoded plaintext) live
   *   on the GC-managed heap. They cannot be scrubbed from JavaScript; this
   *   method does not attempt to.
   * - The runtime may copy buffers during garbage collection or across the
   *   JS/native boundary; those copies are not reachable to clear.
   * - Compiler optimizations may eliminate "dead" stores.
   *
   * Use this method as defence in depth, not as a guarantee that secret
   * material has been forensically scrubbed from the process.
   *
   * The parameter is widened from `Buffer` to `Uint8Array` (backward
   * compatible — every `Buffer` IS a `Uint8Array`) and the guard is
   * `instanceof Uint8Array` (NOT `Buffer.isBuffer`) so a plain `Uint8Array`
   * — e.g. browser key material — is actually scrubbed rather than silently
   * skipped.
   *
   * @param buffer - byte array to clear
   */
  public secureClear(buffer: Uint8Array): void {
    if (buffer && buffer instanceof Uint8Array) {
      buffer.fill(0);
    }
  }

  /**
   * Validate password strength.
   *
   * A password is accepted if EITHER:
   *
   *  - it is at least 20 characters long (NIST SP 800-63B passphrase
   *    style — length alone provides sufficient entropy), OR
   *  - it is at least 8 characters long AND contains at least one
   *    uppercase letter, one lowercase letter, one digit, and one
   *    non-alphanumeric character (any character outside `[A-Za-z0-9]`).
   *
   * Implementation delegates to the module-level {@link isValidPassword}
   * helper so the constructor can validate `defaultPassphrase` before
   * `this` is fully initialised.
   *
   * @param password - Password to validate
   * @returns True if password meets either acceptance rule
   */
  public validatePassword(password: string): boolean {
    return isValidPassword(password);
  }

  /**
   * Get encryption parameters for debugging/info. Returns a shallow copy of
   * `argon2Options` so a caller mutating the result cannot alter the
   * manager's configuration.
   *
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
   * Get security level based on current configuration. Each tier is decided
   * by both `memoryCost` AND `timeCost` clearing the matching minimum
   * threshold in {@link SECURITY_THRESHOLDS}; if either parameter is below
   * its threshold, classification falls through to the next-lower tier.
   *
   * @returns Security level (`LOW` / `MEDIUM` / `HIGH` / `ULTRA`).
   */
  public getSecurityLevel(): SecurityLevel {
    const { memoryCost, timeCost } = this.argon2Options;

    if (
      memoryCost >= SECURITY_THRESHOLDS.ULTRA.memoryCost &&
      timeCost >= SECURITY_THRESHOLDS.ULTRA.timeCost
    ) {
      return SecurityLevel.ULTRA;
    } else if (
      memoryCost >= SECURITY_THRESHOLDS.HIGH.memoryCost &&
      timeCost >= SECURITY_THRESHOLDS.HIGH.timeCost
    ) {
      return SecurityLevel.HIGH;
    } else if (
      memoryCost >= SECURITY_THRESHOLDS.MEDIUM.memoryCost &&
      timeCost >= SECURITY_THRESHOLDS.MEDIUM.timeCost
    ) {
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

  /**
   * Get the configured legacy-format handling mode.
   * @returns one of `'auto'`, `'strict'`, or `'reject'`
   */
  public getLegacyMode(): LegacyMode {
    return this.legacyMode;
  }
}
