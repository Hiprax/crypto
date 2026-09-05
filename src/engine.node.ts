/**
 * Node (`node:crypto`) implementation of the {@link CryptoEngine} contract.
 *
 * This module hosts two things:
 *
 *  1. **The Argon2id lazy-load machinery** (native `argon2` preferred, pure-WASM
 *     `hash-wasm` fallback) — relocated here from `crypto-manager.ts` so the
 *     shared core can reach it through the engine abstraction. `crypto-manager.ts`
 *     still imports {@link loadArgon2} directly for its existing `deriveKey`
 *     method (kept byte-identical) and re-exports the two `__…ForTesting` hooks
 *     plus {@link Argon2Provider}/{@link Argon2Hasher} so existing test imports
 *     from `./crypto-manager` continue to resolve unchanged.
 *  2. **`nodeEngine`** — the concrete {@link CryptoEngine} backed by
 *     `node:crypto` (AES-256-GCM, SHA-256, CSPRNG) and the Argon2id loader.
 *
 * The `argon2`/`hash-wasm` imports stay lazy (dynamic `import()` inside the
 * loader functions) so constructing a manager or using only the sync PBKDF2
 * paths never triggers the native-module load.
 */

import crypto from 'node:crypto';
import { CryptoError, CryptoErrorType, EncryptionAlgorithm } from './types.js';
import type { CryptoEngine } from './engine.js';

/**
 * Numeric identifier for the Argon2id variant in the `argon2` native module
 * (which exports `argon2id` as the literal number `2`). We hardcode the
 * value rather than importing it eagerly so that consumers who only use the
 * sync (PBKDF2) paths never trigger the native-module load and never hit a
 * `MODULE_NOT_FOUND` at import time when `argon2` is missing or fails to
 * build.
 */
export const ARGON2_ID = 2;

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
 * raw `Error` on import failure OR on a module that loads but exposes no
 * callable `hash` (the caller composes the friendly error after deciding
 * whether the WASM fallback also fails).
 */
async function importNativeArgon2(): Promise<Argon2Hasher> {
  // Dynamic ESM import. argon2 ships as CJS, so the imported namespace's
  // `default` property is the actual module object (Node's CJS-ESM
  // interop). Fall back to the namespace itself in case a future argon2
  // release ships native ESM.
  const mod = (await import('argon2')) as {
    hash?: Argon2Module['hash'];
    default?: { hash?: Argon2Module['hash'] };
  };
  // `.default` FIRST — that is the shape the real, CJS-published package has,
  // so the happy path is byte-for-byte what it always was. But select it only
  // when its `hash` is genuinely CALLABLE: a truthiness test alone accepts a
  // `.default` that is a re-export shim or an empty object, and the resulting
  // hasher would resolve, be tagged `'native'`, and be CACHED FOREVER by
  // `loadArgon2` — after which every call fails with a misleading
  // `KEY_DERIVATION_FAILED` and `hash-wasm` is never tried, even when it is
  // installed and working. Throwing instead lets `importArgon2Hasher`'s
  // try/catch fall through to the WASM provider. This mirrors
  // `engine.web.ts`'s `loadArgon2id`, so the two engines report the same
  // condition the same way.
  const resolved =
    typeof mod.default?.hash === 'function'
      ? (mod.default as Argon2Module)
      : typeof mod.hash === 'function'
        ? (mod as Argon2Module)
        : null;
  if (resolved === null) {
    throw new Error('`argon2` loaded but exposes no `hash` function');
  }
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
 * on import failure OR on a module that loads but exposes no callable
 * `argon2id`.
 */
async function importHashWasmArgon2(): Promise<Argon2Hasher> {
  const mod = (await import('hash-wasm')) as {
    argon2id?: HashWasmModule['argon2id'];
    default?: { argon2id?: HashWasmModule['argon2id'] };
  };
  // hash-wasm ships ESM with `argon2id` as a named export. Some bundlers
  // (and Jest's CJS-ESM interop) may surface it under `.default`; handle
  // both shapes the same way as we do for native argon2. The candidate
  // selection is unchanged; what is new is the refusal below, which is the
  // symmetric half of `importNativeArgon2`'s: without it a module that loads
  // with no callable `argon2id` resolves an unusable hasher, which then fails
  // at CALL time as `KEY_DERIVATION_FAILED` instead of the actionable
  // `ARGON2_NOT_AVAILABLE` that `engine.web.ts` reports for the same shape.
  const resolved =
    typeof mod.default?.argon2id === 'function'
      ? (mod.default as HashWasmModule)
      : typeof mod.argon2id === 'function'
        ? (mod as HashWasmModule)
        : null;
  if (resolved === null) {
    // Same wording as `engine.web.ts`'s `loadArgon2id`, deliberately: one
    // condition, one message, whichever engine hits it.
    throw new Error('`hash-wasm` loaded but exposes no `argon2id` export');
  }
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
export async function loadArgon2(): Promise<Argon2Hasher> {
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
 * Argon2id derivation parameter shape, sourced from the {@link CryptoEngine}
 * contract so the Node engine and the interface cannot drift.
 */
type Argon2DeriveParams = Parameters<CryptoEngine['deriveArgon2id']>[2];

/**
 * {@link CryptoEngine.randomBytes} — Node CSPRNG. Synchronous.
 */
function nodeRandomBytes(length: number): Uint8Array {
  return crypto.randomBytes(length);
}

/**
 * {@link CryptoEngine.deriveArgon2id} — derive a raw Argon2id key via the
 * lazily-loaded native/WASM hasher. The caller has already NFC-normalised
 * `password` (engine contract), so this hashes the exact string it is given.
 * Both providers produce exactly `hashLength` bytes for these parameters.
 */
async function nodeDeriveArgon2id(
  password: string,
  salt: Uint8Array,
  params: Argon2DeriveParams
): Promise<Uint8Array> {
  const hasher = await loadArgon2();
  return hasher.hash(password, {
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
    salt: Buffer.from(salt),
  });
}

/**
 * {@link CryptoEngine.aeadEncrypt} — AES-256-GCM encrypt. The 16-byte auth
 * tag is returned SEPARATELY from the ciphertext (engine contract).
 */
async function nodeAeadEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  const cipher = crypto.createCipheriv(
    EncryptionAlgorithm.AES_256_GCM,
    key,
    iv
  ) as crypto.CipherGCM;
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag };
}

/**
 * {@link CryptoEngine.aeadDecrypt} — AES-256-GCM decrypt + tag verify. Any
 * authentication failure surfaces as a generic `DECRYPTION_FAILED`
 * CryptoError so the failure modes are indistinguishable (no oracle).
 */
async function nodeAeadDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  try {
    const decipher = crypto.createDecipheriv(
      EncryptionAlgorithm.AES_256_GCM,
      key,
      iv
    ) as crypto.DecipherGCM;
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (error) {
    throw new CryptoError(
      `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      CryptoErrorType.DECRYPTION_FAILED,
      'DECRYPTION_FAILED'
    );
  }
}

/**
 * {@link CryptoEngine.sha256} — SHA-256 digest. Async to match the interface
 * (the Web engine's `subtle.digest` is async); Node's hash is computed
 * synchronously and resolved.
 */
async function nodeSha256(data: Uint8Array): Promise<Uint8Array> {
  return crypto.createHash('sha256').update(data).digest();
}

/**
 * The Node {@link CryptoEngine}, backed by `node:crypto` for AES-256-GCM,
 * SHA-256, and the CSPRNG, and by the native→WASM Argon2id loader above.
 */
export const nodeEngine: CryptoEngine = {
  randomBytes: nodeRandomBytes,
  deriveArgon2id: nodeDeriveArgon2id,
  aeadEncrypt: nodeAeadEncrypt,
  aeadDecrypt: nodeAeadDecrypt,
  sha256: nodeSha256,
};
