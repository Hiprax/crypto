import crypto from 'node:crypto';
import {
  open as fsOpen,
  rename as fsRename,
  copyFile as fsCopyFile,
  mkdir,
  unlink,
} from 'node:fs/promises';
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
  statSync,
} from 'node:fs';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { dirname } from 'node:path';
import type {
  CryptoManagerOptions,
  Argon2Options,
  EncryptionParameters,
  EncryptionResult,
  LegacyMode,
  ProgressCallback,
} from './types.js';
import {
  CryptoError,
  CryptoErrorType,
  SecurityLevel,
  EncryptionAlgorithm,
} from './types.js';
import type {
  KdfHeaderParams,
  KdfId,
  ParsedHeader,
} from './format.js';
import {
  HEADER_LENGTH,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  hasMagic,
  packHeader,
  parseHeader,
  MAX_ARGON2_MEMORY_COST,
  MAX_ARGON2_TIME_COST,
  MAX_ARGON2_PARALLELISM,
  MAX_PBKDF2_ITERATIONS,
} from './format.js';
import { isValidBase64Url } from './utils.js';

/**
 * Argon2id parameter thresholds that classify a {@link CryptoManager} into
 * {@link SecurityLevel} buckets. Each tier is the **minimum** parameter set
 * for that label — see {@link CryptoManager.getSecurityLevel} for the exact
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
 *    library default.
 *  - **ULTRA**  `memoryCost = 2 ** 19` (512 MiB), `timeCost = 4` — the
 *    "paranoid" tier; meaningful for offline/asymmetric workloads where the
 *    extra latency and memory pressure are tolerable.
 *  - **MEDIUM** `memoryCost = 2 ** 14` (16 MiB), `timeCost = 2` — minimum
 *    acceptable threshold; suitable only for resource-constrained devices.
 *
 * Anything below `MEDIUM` is reported as `LOW` with no fixed threshold of
 * its own.
 *
 * Re-exported from `index.ts` so downstream tooling can introspect the
 * thresholds (e.g. to assert at startup that a configured policy is at
 * least `HIGH`).
 */
export const SECURITY_THRESHOLDS = Object.freeze({
  ULTRA: Object.freeze({ memoryCost: 2 ** 19, timeCost: 4 }),
  HIGH: Object.freeze({ memoryCost: 2 ** 17, timeCost: 3 }),
  MEDIUM: Object.freeze({ memoryCost: 2 ** 14, timeCost: 2 }),
} as const);

/**
 * Default PBKDF2 iteration count for sync key derivation when producing new
 * v1 ciphertexts. Matches the OWASP 2023+ recommendation for
 * PBKDF2-HMAC-SHA256 (still current in 2026).
 */
const PBKDF2_DEFAULT_ITERATIONS = 600000;

/**
 * Iteration count assumed for legacy v0 sync ciphertexts (those produced by
 * versions of this library prior to 0.10.0, which used 100k iterations and
 * did not embed the iteration count in the ciphertext). v1 ciphertexts
 * carry the iteration count in their header and ignore this constant.
 */
const PBKDF2_LEGACY_ITERATIONS = 100000;

/**
 * Numeric identifier for the Argon2id variant in the `argon2` native module
 * (which exports `argon2id` as the literal number `2`). We hardcode the
 * value rather than importing it eagerly so that consumers who only use the
 * sync (PBKDF2) paths never trigger the native-module load and never hit a
 * `MODULE_NOT_FOUND` at import time when `argon2` is missing or fails to
 * build.
 */
const ARGON2_ID = 2;

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
 * Pure (static) password-strength validator. Does NOT depend on any
 * `CryptoManager` instance state — it is a deterministic function of the
 * password string alone. Extracted to module scope so that the
 * `CryptoManager` constructor can validate `defaultPassphrase` BEFORE
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
 * Minimal subset of the `argon2` module surface we actually use. Declared
 * locally so we never have to import the package's types eagerly — the
 * package ships its own `.d.cts` declarations but importing them at the top
 * level pulls the whole module in for type-resolution purposes.
 */
type Argon2Module = {
  hash: (
    password: string,
    options: {
      type: number;
      memoryCost: number;
      timeCost: number;
      parallelism: number;
      hashLength: number;
      salt: Buffer;
      raw: true;
    }
  ) => Promise<Buffer>;
};

/**
 * Minimal subset of the `hash-wasm` module surface we actually use. Declared
 * locally for the same reason as {@link Argon2Module} — type-resolution
 * isolation and to keep the import lazy.
 *
 * Parameter mapping (`argon2` ↔ `hash-wasm`):
 *
 *   - `memoryCost` (KiB)  ↔ `memorySize` (KiB)
 *   - `timeCost`          ↔ `iterations`
 *   - `parallelism`       ↔ `parallelism`
 *   - `hashLength`        ↔ `hashLength`
 *
 * Both libraries implement the RFC 9106 Argon2id reference, so the raw
 * 32-byte derived keys are bit-identical for the same `(password, salt,
 * memoryCost, timeCost, parallelism, hashLength)` tuple. This is verified
 * with a known-vector parity test in `argon2-lazy-load.test.ts` — drift
 * would mean a v1 ciphertext produced under one runtime cannot be decrypted
 * under the other, so the test pins the round-trip explicitly.
 */
type HashWasmModule = {
  argon2id: (options: {
    password: string;
    salt: Buffer;
    iterations: number;
    parallelism: number;
    memorySize: number;
    hashLength: number;
    outputType: 'binary';
  }) => Promise<Uint8Array>;
};

/**
 * Provider tag for the loaded Argon2 implementation. Used in the friendly
 * error message and exposed via the test-only inspection helper so tests can
 * assert which fallback path was hit. Internal — do NOT import from outside
 * the test suite.
 *
 * @internal
 */
export type Argon2Provider = 'native' | 'wasm';

/**
 * Unified hasher interface that both the native `argon2` module and the
 * `hash-wasm` fallback are normalised to. Encapsulating the differences
 * here keeps `deriveKey` provider-agnostic — it always sees the same
 * `(password, options) => Promise<Buffer>` shape regardless of which
 * provider produced the bytes.
 *
 * @internal
 */
export type Argon2Hasher = {
  /** Which underlying implementation produced this hasher. */
  provider: Argon2Provider;
  /**
   * Compute a raw `hashLength`-byte Argon2id key for the given password and
   * parameters. Both providers MUST produce bit-identical output for
   * identical inputs (verified by the parity test).
   */
  hash: (
    password: string,
    options: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
      hashLength: number;
      salt: Buffer;
    }
  ) => Promise<Buffer>;
};

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
 * Module-level cache for the loaded Argon2 hasher (native or WASM-backed).
 * Three observable states, with the in-flight loading state expressed as
 * the unsettled promise itself:
 *
 *   - `null`                       — load not yet attempted, OR the
 *                                    previous load attempt rejected (so
 *                                    the next caller will retry).
 *   - `Promise<Argon2Hasher>`      — either the in-flight load promise
 *                                    (concurrent callers await it) or, on
 *                                    success, a permanently-resolved
 *                                    promise that future callers `await`
 *                                    cheaply.
 *
 * Keeping this at module scope (not on the class instance) means multiple
 * `CryptoManager` instances share one load attempt, which is the right
 * behaviour: native modules are process-global anyway, and we don't want
 * to pay the import cost N times.
 *
 * **Why a promise rather than the resolved module?** Two requirements
 * pull in opposite directions:
 *
 *   1. Concurrent first-callers should share one `await import('argon2')`
 *      — without coalescing, N parallel `encryptText` calls would each
 *      fire their own dynamic import.
 *   2. Transient load failures (e.g. a temporary FS permission glitch on
 *      Windows during a build-tool install) should not permanently
 *      disable async crypto for the lifetime of the process.
 *
 * Storing the in-flight promise satisfies (1) — concurrent callers see
 * the same promise and await it. Clearing the slot on rejection (see
 * `loadArgon2` below) satisfies (2) — the next caller after a failure
 * starts a fresh load. On success the promise stays cached forever, so
 * subsequent callers pay only an `await` of an already-settled promise
 * (no re-import).
 */
let argon2ModuleCache: Promise<Argon2Hasher> | null = null;

/**
 * Internal hook used exclusively by tests to reset the lazy-load cache so
 * that simulated load failures are observable on subsequent calls. Not part
 * of the public API; do NOT call this from application code.
 *
 * @internal
 */
export function __resetArgon2ModuleCacheForTesting(): void {
  argon2ModuleCache = null;
}

/**
 * Internal hook used exclusively by tests to inspect which Argon2 provider
 * is currently cached. Returns `null` if no provider is cached yet, or the
 * provider tag of the resolved hasher. Not part of the public API.
 *
 * @internal
 */
export async function __peekArgon2ProviderForTesting(): Promise<Argon2Provider | null> {
  if (argon2ModuleCache === null) {
    return null;
  }
  try {
    const hasher = await argon2ModuleCache;
    return hasher.provider;
  } catch {
    return null;
  }
}

/**
 * Perform the actual dynamic import of the `argon2` native module and
 * normalise the CJS/ESM interop, then adapt the result to the unified
 * {@link Argon2Hasher} interface.
 *
 * Returns a hasher tagged `provider: 'native'` on success; rejects with a
 * raw `Error` on import failure (the caller composes the friendly error
 * after deciding whether the WASM fallback also fails).
 */
async function importNativeArgon2(): Promise<Argon2Hasher> {
  // Dynamic ESM import. argon2 ships as CJS, so the imported namespace's
  // `default` property is the actual module object (Node's CJS-ESM
  // interop). Fall back to the namespace itself in case a future argon2
  // release ships native ESM.
  const mod = (await import('argon2')) as
    | { default: Argon2Module }
    | Argon2Module;
  const resolved =
    'default' in mod && (mod as { default: Argon2Module }).default
      ? (mod as { default: Argon2Module }).default
      : (mod as Argon2Module);
  return {
    provider: 'native',
    hash: async (password, options): Promise<Buffer> => {
      const out = await resolved.hash(password, {
        type: ARGON2_ID,
        memoryCost: options.memoryCost,
        timeCost: options.timeCost,
        parallelism: options.parallelism,
        hashLength: options.hashLength,
        salt: options.salt,
        raw: true,
      });
      return Buffer.from(out);
    },
  };
}

/**
 * Perform the actual dynamic import of the `hash-wasm` module and adapt it
 * to the unified {@link Argon2Hasher} interface.
 *
 * Parameter mapping is the only twist: hash-wasm names `iterations` for
 * what the native argon2 package calls `timeCost`, and `memorySize` for
 * what native calls `memoryCost`. Output type `'binary'` returns a raw
 * `Uint8Array` of `hashLength` bytes (no encoded prefix), which we wrap in
 * a Buffer to match the native-provider return type.
 *
 * Returns a hasher tagged `provider: 'wasm'`; rejects with a raw `Error`
 * on import failure.
 */
async function importHashWasmArgon2(): Promise<Argon2Hasher> {
  const mod = (await import('hash-wasm')) as
    | { default: HashWasmModule }
    | HashWasmModule;
  // hash-wasm ships ESM with `argon2id` as a named export. Some bundlers
  // (and Jest's CJS-ESM interop) may surface it under `.default`; handle
  // both shapes the same way as we do for native argon2.
  const resolved =
    'default' in mod &&
    (mod as { default: HashWasmModule }).default &&
    typeof (mod as { default: HashWasmModule }).default.argon2id === 'function'
      ? (mod as { default: HashWasmModule }).default
      : (mod as HashWasmModule);
  return {
    provider: 'wasm',
    hash: async (password, options): Promise<Buffer> => {
      const out = await resolved.argon2id({
        password,
        salt: options.salt,
        iterations: options.timeCost,
        parallelism: options.parallelism,
        memorySize: options.memoryCost,
        hashLength: options.hashLength,
        outputType: 'binary',
      });
      return Buffer.from(out);
    },
  };
}

/**
 * Try the native `argon2` import first, then the `hash-wasm` import, and
 * if both fail throw a friendly {@link CryptoError} with a unified
 * `ARGON2_NOT_AVAILABLE` code.
 *
 * Both providers implement the RFC 9106 Argon2id reference and produce
 * bit-identical raw output for the same `(password, salt, memoryCost,
 * timeCost, parallelism, hashLength)` tuple. The fallback chain therefore
 * does NOT change ciphertext compatibility: a v1 ciphertext produced by a
 * native-backed manager round-trips through a WASM-backed manager and
 * vice versa.
 *
 * Extracted from {@link loadArgon2} so the in-flight promise stored in the
 * cache contains only the import + normalisation + fallback work (no extra
 * wrapping that would change the rejection shape callers see).
 */
async function importArgon2Hasher(): Promise<Argon2Hasher> {
  let nativeError: unknown;
  try {
    return await importNativeArgon2();
  } catch (err) {
    nativeError = err;
  }
  try {
    return await importHashWasmArgon2();
  } catch (wasmError) {
    // Both providers failed — surface a friendly error that points users at
    // both fix paths (install build tools for native, or install hash-wasm
    // for the pure-JS WASM fallback) plus the synchronous PBKDF2 escape
    // hatch that doesn't need either.
    const nativeMsg =
      nativeError instanceof Error ? nativeError.message : String(nativeError);
    const wasmMsg =
      wasmError instanceof Error ? wasmError.message : String(wasmError);
    throw new CryptoError(
      'argon2 native module unavailable. Install build tools (Python + node-gyp) ' +
        'or install the optional `hash-wasm` package for a pure-WASM Argon2id ' +
        'fallback (slower than native but works everywhere). Alternatively, use ' +
        '*Sync methods (PBKDF2). ' +
        `Native error: ${nativeMsg}. WASM error: ${wasmMsg}.`,
      CryptoErrorType.MEMORY_ERROR,
      'ARGON2_NOT_AVAILABLE'
    );
  }
}

/**
 * Lazily load an Argon2id hasher (native preferred, hash-wasm fallback)
 * using an in-flight-promise pattern that coalesces concurrent
 * first-callers and lets transient failures recover on the next call.
 *
 * Behaviour:
 *
 *   - First call (cache empty): assigns the in-flight import promise to
 *     the cache slot and awaits it. On success the resolved promise stays
 *     cached forever — subsequent callers `await` an already-settled
 *     promise (no re-import). On rejection the cache slot is cleared back
 *     to `null` so the NEXT caller starts a fresh load.
 *   - Concurrent first-callers: read the same in-flight promise from the
 *     cache, await it, and either all resolve to the same module or all
 *     reject with the same error. No duplicate `await import`.
 *   - Caller after a previous failure: cache is `null`, so this call
 *     behaves exactly like a first-time call. Transient failures (e.g.
 *     temporary FS permission errors during a parallel build-tool install)
 *     can recover on the next attempt rather than being stuck for the
 *     process lifetime.
 *
 * The cache-clear step uses a "compare-and-swap" pattern: only clear if
 * the slot still holds *our* failing promise. This guards against a race
 * where a concurrent caller resets the cache (via the test-only hook) or
 * a successful retry has already populated the slot.
 *
 * Why a function instead of inline in `deriveKey`: extracting it makes the
 * caching logic testable and keeps `deriveKey` readable.
 */
async function loadArgon2(): Promise<Argon2Hasher> {
  // Fast path: someone already started (or finished) the load. Reuse it.
  if (argon2ModuleCache !== null) {
    return argon2ModuleCache;
  }

  // Slow path: start a load. Assign the promise to the cache slot BEFORE
  // awaiting so concurrent callers landing here observe the in-flight
  // promise rather than starting their own. We capture the promise in a
  // local `inFlight` so the post-await CAS check is correct even if a
  // concurrent caller (or the test-only reset hook) replaces the cache
  // slot mid-flight.
  const inFlight = importArgon2Hasher();
  argon2ModuleCache = inFlight;

  try {
    return await inFlight;
  } catch (err) {
    // Clear the cache slot — but ONLY if it still holds OUR failing
    // promise. If a concurrent caller already started a fresh attempt
    // (which they couldn't have, given JS single-threaded semantics —
    // but a synchronous test-only reset between assignment and await is
    // possible) or the test reset hook emptied it, we don't overwrite.
    if (argon2ModuleCache === inFlight) {
      argon2ModuleCache = null;
    }
    throw err;
  }
}

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
  /**
   * Password retained by the manager when `defaultPassphrase` is set in
   * the constructor. Stored as a plain V8 string — V8 strings are
   * immutable and GC-managed, so the library cannot scrub this value with
   * `secureClear` (which only zero-fills `Buffer`-backed allocations).
   *
   * **Lifetime:** the passphrase stays resident in process memory for the
   * full lifetime of this `CryptoManager` instance, plus an unbounded GC
   * tail for any internal V8 string copies created along the way (e.g.
   * intern-table entries from comparisons). Long-lived managers therefore
   * keep the passphrase resident for the whole process lifetime.
   *
   * **Recommendation:** for sensitive workloads, prefer passing the
   * password explicitly to each encrypt/decrypt call rather than relying
   * on `defaultPassphrase`. See SECURITY.md and the README "Default
   * Passphrase" / "Threat Model" sections.
   */
  private readonly defaultPassphrase?: string;
  private readonly legacyMode: LegacyMode;
  private readonly pbkdf2Iterations: number;
  private readonly legacyPbkdf2Iterations: number;
  /**
   * When true, AES-GCM AAD for v1 ciphertexts uses just `this.aad` (the
   * v1.0.0 behaviour). Default false — the AAD includes the on-disk v1
   * header bytes, so any tampering with the header (including the
   * reserved-byte regions) flips the GCM tag and decryption fails.
   */
  private readonly legacyHeaderAad: boolean;

  constructor(options: CryptoManagerOptions = {}) {
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
    // encrypt/decrypt call (where the cause was previously much less
    // obvious). The validation is delegated to the module-level
    // `isValidPassword` helper so it does NOT depend on `this` being fully
    // initialised — at this point in the constructor `this.algorithm`
    // / `this.keyLength` etc. ARE set, but using a static helper keeps the
    // password rule centralised and avoids any future reordering hazard.
    //
    // Callers who need to decrypt legacy data encrypted under a weak
    // password can opt out via `skipPasswordValidation: true`. This flag
    // does NOT bypass NFC normalisation in `deriveKey`/`deriveKeySync`.
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

    // Argon2id parameters (high security). `type` is hardcoded to the
    // numeric Argon2id identifier (`2`) rather than read from the argon2
    // module so that constructing a CryptoManager does NOT trigger loading
    // the native module — consumers who only use the *Sync methods
    // (PBKDF2) can run with argon2 absent.
    //
    // The default `memoryCost` of `2 ** 17` (128 MiB) follows the OWASP
    // 2026 high-security recommendation for Argon2id (the previous default
    // of 64 MiB matched the OWASP "minimum" tier; 128 MiB is the "first
    // choice" tier for high-security applications). Resource-constrained
    // callers (mobile, embedded, low-memory containers) can opt back into
    // the lighter 64 MiB profile by passing `memoryCost: 2 ** 16` or any
    // smaller positive integer. Existing v1 ciphertexts produced with the
    // previous default continue to decrypt because each ciphertext header
    // embeds the exact memoryCost / timeCost / parallelism that were used
    // to derive its key, so the decoder applies the embedded values rather
    // than this constructor default.
    this.argon2Options = {
      type: ARGON2_ID,
      memoryCost: options.memoryCost ?? SECURITY_THRESHOLDS.HIGH.memoryCost, // 128 MiB
      timeCost: options.timeCost ?? SECURITY_THRESHOLDS.HIGH.timeCost,
      parallelism: options.parallelism ?? 1,
      hashLength: this.keyLength,
      saltLength: this.saltLength,
    };

    // Use custom AAD or default
    const aadString = options.aad ?? 'secure-crypto-tool-v2';
    this.aad = Buffer.from(aadString, 'utf8');

    // Default to the integrity-binding AAD format introduced in v1.1.0.
    // Callers needing to decrypt legacy v1.0.0 ciphertexts can opt back in
    // to the bound-aad-only format via `legacyHeaderAad: true`. Note this
    // affects v1 ciphertexts only — v0 ciphertexts always use `this.aad`
    // alone (they have no header to bind, and changing v0 AAD would break
    // every pre-existing v0 ciphertext in the wild).
    this.legacyHeaderAad = options.legacyHeaderAad === true;
  }

  /**
   * Compute the AAD that AES-GCM should bind to a v1 ciphertext.
   *
   * Includes the on-disk v1 header bytes verbatim after `this.aad`. Both
   * encrypt and decrypt paths call this with the **exact same bytes** they
   * have on disk (the encrypt path uses the buffer it just packed; the
   * decrypt path uses the bytes it read out of the input file/string,
   * NOT a re-serialised copy — so reserved-byte tampering remains visible).
   *
   * @param headerBytes - the 22-byte v1 header (including any reserved
   *   bytes, exactly as it will be / was written to disk)
   * @returns the AAD value to pass to `cipher.setAAD` / `decipher.setAAD`
   */
  private aadForV1(headerBytes: Buffer): Buffer {
    if (this.legacyHeaderAad) {
      // Backward-compat shim for v1.0.0 ciphertexts: AAD is just the
      // configured context string, header bytes are NOT bound.
      return this.aad;
    }
    return Buffer.concat([this.aad, headerBytes]);
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
    const hasher = await loadArgon2();

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
   * Build the v1 header that should be prepended to every newly produced
   * ciphertext, parameterised for the given KDF.
   */
  private buildHeader(kdfId: KdfId): Buffer {
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
  private enforceLegacyMode(): void {
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
  private assertKdfMatches(parsed: ParsedHeader, expected: KdfId): void {
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
   * Encrypt text with password
   * @param text - Text to encrypt
   * @param password - Encryption password (optional if default passphrase is set)
   * @returns Base64url encoded encrypted data (v1 format)
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

    let key: Buffer | null = null;
    try {
      // Generate salt and IV
      const salt = this.generateSecureRandom(this.saltLength);
      const iv = this.generateSecureRandom(this.ivLength);

      // Derive key from password
      key = await this.deriveKey(finalPassword, salt);

      // Build v1 header (Argon2id parameters that were used). We build it
      // BEFORE encrypting so we can include the on-disk header bytes in
      // the AES-GCM AAD — this binds the header to the auth tag, so any
      // tampering with the header (including reserved bytes) flips the
      // tag and decryption fails.
      const header = this.buildHeader(KDF_ID_ARGON2ID);

      // Encrypt the text with header-bound AAD.
      const textBuffer = Buffer.from(text, 'utf8');
      const { encrypted, tag } = this.encryptData(
        textBuffer,
        key,
        iv,
        this.aadForV1(header)
      );

      // Combine: header + salt + iv + tag + encrypted data
      const combined = Buffer.concat([header, salt, iv, tag, encrypted]);

      // Encode to base64url FIRST so we still have the bytes available, then
      // scrub every Buffer-backed view onto sensitive material. `encrypted`,
      // `tag`, and `combined` are not "secrets" per se — they are public
      // ciphertext components — but the cipher's internal state lingers in
      // those buffers until GC, and clearing them keeps the encrypt path
      // symmetric with the decrypt path (which already clears `combined`).
      // See Task 14 (FIX.md Iteration 2) for the rationale.
      const encoded = combined.toString('base64url');
      this.secureClear(key);
      this.secureClear(textBuffer);
      this.secureClear(encrypted);
      this.secureClear(tag);
      this.secureClear(combined);

      return encoded;
    } catch (error) {
      if (key !== null) {
        this.secureClear(key);
      }
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
   * @param encryptedText - Base64url encoded encrypted text (v0 or v1 format)
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

    let key: Buffer | null = null;
    try {
      // Decode base64url
      const combined = Buffer.from(encryptedText, 'base64url');

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
      // tampering, so we must AAD the bytes that were actually on disk.
      let headerForAad: Buffer | null = null;

      if (hasMagic(combined)) {
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
        // Slice on-disk header bytes (subarray shares memory with `combined`,
        // so it is automatically scrubbed when we call `secureClear(combined)`
        // at the end of the success path).
        headerForAad = combined.subarray(0, parsed.headerLen);
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

      // Derive key from password (use embedded params if present so we can
      // decrypt ciphertext produced by an instance with different defaults)
      key = await this.deriveKey(finalPassword, salt, argonOverrides);

      // Decrypt the data with the matching AAD (header-bound for v1,
      // `this.aad`-only for v0).
      const aad = headerForAad === null ? this.aad : this.aadForV1(headerForAad);
      const decrypted = this.decryptData(encrypted, key, iv, tag, aad);
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
      if (key !== null) {
        this.secureClear(key);
      }
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
   * @returns Base64url encoded encrypted data (v1 format)
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

    let key: Buffer | null = null;
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
      const textBuffer = Buffer.from(text, 'utf8');
      const { encrypted, tag } = this.encryptData(
        textBuffer,
        key,
        iv,
        this.aadForV1(header)
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
        const parsed = parseHeader(combined);
        this.assertKdfMatches(parsed, KDF_ID_PBKDF2_SHA256);
        if (parsed.params.kind === 'pbkdf2-sha256') {
          pbkdf2Iterations = parsed.params.iterations;
        }
        bodyOffset = parsed.headerLen;
        headerForAad = combined.subarray(0, parsed.headerLen);
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

      // Derive key from password (synchronous)
      key = this.deriveKeySync(finalPassword, salt, pbkdf2Iterations);

      // Decrypt the data with the matching AAD (header-bound for v1,
      // `this.aad`-only for v0).
      const aad = headerForAad === null ? this.aad : this.aadForV1(headerForAad);
      const decrypted = this.decryptData(encrypted, key, iv, tag, aad);
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
   */
  public async encryptFile(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): Promise<void> {
    if (!inputPath || typeof inputPath !== 'string' || !outputPath || typeof outputPath !== 'string') {
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

    try {
      // Check if input file exists
      if (!existsSync(inputPath)) {
        throw new CryptoError(
          `Input file does not exist: ${inputPath}`,
          CryptoErrorType.FILE_ERROR,
          'INPUT_FILE_NOT_FOUND'
        );
      }

      // Stat the input now so the progress callback receives a stable
      // `totalBytes` for every event (race-free against external writers
      // is impossible without exclusive open, but we at least lock in the
      // value we'll report).
      const totalBytes = statSync(inputPath).size;

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

          const ok = outputStream.write(chunk, (err) => {
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
        const inputStream = createReadStream(inputPath);

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
          await new Promise<void>((resolve) => {
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
   */
  public async decryptFile(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): Promise<void> {
    if (!inputPath || typeof inputPath !== 'string' || !outputPath || typeof outputPath !== 'string') {
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

      // Read just the metadata regions of the file (header + salt + iv at
      // the front, auth tag at the back) without loading the body. We open
      // the file once, do all small reads, then close the handle so the
      // subsequent createReadStream can take its own.
      const fileHandle = await fsOpen(inputPath, 'r');
      let totalSize: number;
      let formatHeaderLen: number;
      let argonOverrides:
        | { memoryCost: number; timeCost: number; parallelism: number }
        | undefined;
      let salt: Buffer;
      let iv: Buffer;
      let tag: Buffer;
      // For v1 ciphertexts, capture the on-disk header bytes verbatim so we
      // can include them in the AES-GCM AAD. Re-serialising via packHeader
      // would zero-fill reserved regions, hiding any tampering — see
      // decryptText for the full rationale.
      let headerForAad: Buffer | null = null;
      try {
        const stat = await fileHandle.stat();
        totalSize = stat.size;

        // Step 1: peek at the first MAGIC_LENGTH bytes to determine format.
        // We then read whatever else we need based on format version. To
        // reduce syscalls, just read the largest possible front-matter in
        // one shot (v1 header + salt + iv = HEADER_LENGTH + saltLength +
        // ivLength) when the file is large enough, otherwise read what's
        // available and detect short files.
        const maxFrontLen =
          HEADER_LENGTH + this.saltLength + this.ivLength;
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
        } else {
          this.enforceLegacyMode();
          formatHeaderLen = 0;
        }

        // Validate the file is at least large enough for the salt+iv+tag
        // metadata after the (possibly absent) format header.
        const minSize =
          formatHeaderLen +
          this.saltLength +
          this.ivLength +
          this.tagLength;
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
      } finally {
        await fileHandle.close();
      }

      // Compute the byte range of the ciphertext body.
      const bodyStart = formatHeaderLen + this.saltLength + this.ivLength;
      const bodyEnd = totalSize - this.tagLength; // exclusive
      const bodyLen = bodyEnd - bodyStart;

      // Derive key from password (use embedded params if v1).
      key = await this.deriveKey(finalPassword, salt, argonOverrides);

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

      // Emit an initial progress event reflecting the bytes already read out
      // of the file (header + salt + iv + tag). Reporting these as
      // "processed" matches the user's mental model that progress is "how
      // much of the input file have you consumed", not "how much body have
      // you decrypted".
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
          const inputStream = createReadStream(inputPath, {
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
              outputStream.write(finalBuf, (err) => {
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
          await new Promise<void>((resolve) => {
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
   */
  public encryptFileSync(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): void {
    if (!inputPath || typeof inputPath !== 'string' || !outputPath || typeof outputPath !== 'string') {
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

    try {
      // Check if input file exists
      if (!existsSync(inputPath)) {
        throw new CryptoError(
          `Input file does not exist: ${inputPath}`,
          CryptoErrorType.FILE_ERROR,
          'INPUT_FILE_NOT_FOUND'
        );
      }

      // Stat the input now so the progress callback receives a stable
      // `totalBytes` for both bracketing events.
      const totalBytes = statSync(inputPath).size;

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

      // Open the input for reading and the temp file for writing.
      inputFd = openSync(inputPath, 'r');
      outputFd = openSync(tempPath, 'w');

      // Write the prefix: [v1 header][salt][iv]. These three fields are
      // always written together up front; the ciphertext body follows
      // chunk by chunk, and the auth tag is appended last.
      writeFileSync(outputFd, Buffer.concat([versionHeader, salt, iv]));

      // Stream the plaintext in fixed-size chunks. The reuse buffer keeps
      // peak memory proportional to the chunk size regardless of input size.
      const chunk = Buffer.alloc(this.SYNC_ENCRYPT_CHUNK_SIZE);
      let inputOffset = 0;

      while (inputOffset < totalBytes) {
        const bytesToRead = Math.min(
          this.SYNC_ENCRYPT_CHUNK_SIZE,
          totalBytes - inputOffset
        );
        const bytesRead = readSync(
          inputFd,
          chunk,
          0,
          bytesToRead,
          inputOffset
        );
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
          bytesRead === chunk.length
            ? chunk
            : chunk.subarray(0, bytesRead);
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
      // unnecessary).
      closeSync(inputFd);
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
   */
  public decryptFileSync(
    inputPath: string,
    outputPath: string,
    password?: string,
    progress?: ProgressCallback
  ): void {
    if (!inputPath || typeof inputPath !== 'string' || !outputPath || typeof outputPath !== 'string') {
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

      // Open input read-only and stat it to get the total size.
      inputFd = openSync(inputPath, 'r');
      const stat = fstatSync(inputFd);
      const totalSize = stat.size;

      // Read the front of the file (up to v1 header + salt + iv) so we can
      // determine the format version and extract crypto metadata. Reading
      // more than the file contains is a no-op (readSync returns 0 for
      // out-of-range bytes) so we cap to totalSize.
      const maxFrontLen = HEADER_LENGTH + this.saltLength + this.ivLength;
      const frontReadLen = Math.min(maxFrontLen, totalSize);
      const front = Buffer.alloc(frontReadLen);
      if (frontReadLen > 0) {
        const bytesReadFront = readSync(
          inputFd,
          front,
          0,
          frontReadLen,
          0
        );
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
      const tagBytesRead = readSync(
        inputFd,
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

      // Derive key (synchronous, PBKDF2).
      key = this.deriveKeySync(finalPassword, salt, pbkdf2Iterations);

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
      // across iterations to keep allocations bounded.
      const bodyStart = formatHeaderLen + this.saltLength + this.ivLength;
      const bodyEnd = totalSize - this.tagLength; // exclusive
      const bodyLen = bodyEnd - bodyStart;
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

      // Close input handle (keeping it open through the rename below is
      // unnecessary).
      closeSync(inputFd);
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

  /**
   * Inspect the format header on a v1 ciphertext (text or file) without
   * decrypting. Returns `null` for legacy v0 ciphertexts that do not carry a
   * header. Useful for tooling and tests.
   *
   * String inputs are validated as well-formed base64url BEFORE decoding —
   * `Buffer.from(input, 'base64url')` silently coerces invalid characters to
   * an empty buffer, which would make a malformed input look like a v0
   * ciphertext (returning `null`) rather than surfacing the encoding error.
   * Failing fast on malformed input matches the documented contract of this
   * tooling-facing method.
   *
   * @param input - either a base64url string (text format) or a Buffer (file
   *   contents). Strings are validated as base64url and decoded; Buffers are
   *   read as-is.
   * @returns the parsed header, or `null` when the input lacks the v1 magic
   * @throws CryptoError (`INVALID_INPUT` / `INVALID_BASE64URL`) if the input
   *   string is not well-formed base64url.
   * @throws CryptoError if the input begins with the v1 magic but is otherwise
   *   malformed (truncated, unsupported version, unknown KDF, etc.)
   */
  public inspectHeader(input: string | Buffer): ParsedHeader | null {
    let buf: Buffer;
    if (typeof input === 'string') {
      if (input.length === 0) {
        throw new CryptoError(
          'inspectHeader: input string must be non-empty',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_INPUT'
        );
      }
      // Validate the encoding BEFORE Buffer.from, which silently drops
      // invalid characters (e.g. '!!!!' decodes to an empty buffer rather
      // than throwing). Without this check a caller that passed a
      // malformed string would get `null` back (looks like a v0
      // ciphertext) instead of an explicit "this isn't base64url" error.
      if (!isValidBase64Url(input)) {
        throw new CryptoError(
          'inspectHeader: input string is not valid base64url',
          CryptoErrorType.INVALID_INPUT,
          'INVALID_BASE64URL'
        );
      }
      buf = Buffer.from(input, 'base64url');
    } else if (Buffer.isBuffer(input)) {
      buf = input;
    } else {
      throw new CryptoError(
        'inspectHeader: input must be a base64url string or Buffer',
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
   * compiler reordering.** Useful only for explicit `Buffer` instances; will
   * not scrub the original input string or any V8-internal copies of derived
   * material.
   *
   * Specifically:
   * - `Buffer.fill(0)` zeroes the underlying ArrayBuffer slab that V8 uses
   *   to back the Buffer object — this is sufficient hygiene for raw
   *   key/IV/tag/salt material that was allocated as a Buffer.
   * - Plaintext strings (e.g. the password parameter passed in by the
   *   caller, or the UTF-8-decoded plaintext returned by `decryptText`)
   *   live on V8's GC-managed heap. They cannot be scrubbed from
   *   JavaScript code; this method does **not** attempt to do so.
   * - V8 may copy buffers during garbage collection or as a side effect of
   *   passing data across the JS/native boundary; those copies are not
   *   reachable to clear and will linger on the heap until GC compaction.
   * - Compiler optimizations may eliminate "dead" stores. Node.js does not
   *   currently apply such optimizations to `Buffer.fill`, but this is not
   *   guaranteed by the language semantics.
   *
   * Use this method as defense in depth, not as a guarantee that secret
   * material has been forensically scrubbed from the process. For
   * forensic-grade scrubbing, isolate sensitive operations in a short-lived
   * subprocess and let process termination reclaim the pages.
   *
   * @param buffer - Buffer to clear
   */
  public secureClear(buffer: Buffer): void {
    if (buffer && Buffer.isBuffer(buffer)) {
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
   *    non-alphanumeric character (any character outside `[A-Za-z0-9]`,
   *    so e.g. `_`, `-`, `+`, `[`, `]`, and non-ASCII punctuation all
   *    count as "special").
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

// Re-export the format-related constants for downstream consumers/tests.
export { HEADER_LENGTH };
