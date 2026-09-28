/**
 * Node (`node:crypto`) implementation of the {@link CryptoEngine} contract.
 *
 * This module hosts two things:
 *
 *  1. **The Argon2id lazy-load machinery** — a three-provider chain, tried in
 *     the order native `argon2` → the runtime's built-in `crypto.argon2`
 *     (Node >= 24.7.0) → pure-WASM `hash-wasm`. Relocated here from
 *     `crypto-manager.ts` so the shared core can reach it through the engine
 *     abstraction. `crypto-manager.ts` still imports {@link loadArgon2}
 *     directly for its existing `deriveKey` method (kept byte-identical) and
 *     re-exports the two `__…ForTesting` hooks plus
 *     {@link Argon2Provider}/{@link Argon2Hasher} so existing test imports from
 *     `./crypto-manager` continue to resolve unchanged.
 *  2. **`nodeEngine`** — the concrete {@link CryptoEngine} backed by
 *     `node:crypto` (AES-256-GCM, SHA-256, CSPRNG) and the Argon2id loader.
 *
 * The `argon2`/`hash-wasm` imports stay lazy (dynamic `import()` inside the
 * loader functions) so constructing a manager or using only the sync PBKDF2
 * paths never triggers the native-module load. The built-in provider is probed
 * the same way, by reading `crypto.argon2` INSIDE its loader rather than at
 * module scope, so constructing a manager performs no capability check either.
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
 * Both libraries implement the RFC 9106 Argon2id reference, as does the third
 * provider in the chain, Node's built-in `crypto.argon2`, so the raw 32-byte
 * derived keys are bit-identical across ALL THREE for the same
 * `(password, salt, memoryCost, timeCost, parallelism, hashLength)` tuple.
 * This is verified with real, unmocked known-answer vectors in
 * `argon2-provider-parity.test.ts` (the adapter-wiring cases in
 * `argon2-lazy-load.test.ts` mock the two importable providers and are NOT
 * parity evidence) — drift would mean a v1 ciphertext produced under one
 * runtime cannot be decrypted under the other, so those tests pin the
 * round-trip explicitly.
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
 * Three members, in the order {@link importArgon2Hasher} tries them:
 *
 *   - `'native'` — the optional `argon2` npm package (a node-gyp addon).
 *   - `'node'`   — the runtime's own `crypto.argon2`, added in Node v24.7.0.
 *                  Needs no install at all, which is what makes
 *                  `npm i @hiprax/crypto --omit=optional` usable on a modern
 *                  Node.
 *   - `'wasm'`   — the optional `hash-wasm` package (pure WebAssembly).
 *
 * All three implement the RFC 9106 Argon2id reference and produce
 * bit-identical raw output for the same parameter tuple, so the tag is
 * diagnostic only: it never changes a derived key or a ciphertext byte.
 *
 * @internal
 */
export type Argon2Provider = 'native' | 'node' | 'wasm';

/**
 * Unified hasher interface that all three Argon2id providers — the native
 * `argon2` module, Node's built-in `crypto.argon2`, and the `hash-wasm`
 * fallback — are normalised to. Encapsulating the differences here keeps
 * `deriveKey` provider-agnostic: it always sees the same
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
   * parameters. All three providers MUST produce bit-identical output for
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
 * One Argon2id load attempt, as held in {@link argon2ModuleCache}: the promise
 * that every caller joining this attempt awaits.
 *
 * **Why the cache holds this record rather than the bare promise.** After a
 * rejection, {@link loadArgon2} clears the cache only if the cache still
 * belongs to ITS attempt. That is a question about identity (which attempt
 * owns the slot), so it compares these records and never compares promises.
 * Comparing two promises with `===` is valid JavaScript, but it reads exactly
 * like a forgotten `await`, and CodeQL's `js/missing-await` reported the old
 * form of this check as one, twice: first while the loader lived in
 * `crypto-manager.ts`, and again after it moved here. The repair that message
 * invites is the dangerous one. Awaiting the rejected promise inside that
 * `catch` re-throws before the cache is cleared, so a single transient load
 * failure would stay cached for the life of the process and every async
 * method would keep failing with it. Keeping the identity (the record) apart
 * from the value (its promise) removes the ambiguity instead of silencing it.
 */
type Argon2LoadAttempt = { readonly hasher: Promise<Argon2Hasher> };

/**
 * Module-level cache for the loaded Argon2 hasher (native, Node built-in,
 * or WASM-backed), holding at most one {@link Argon2LoadAttempt}.
 * Three observable states, with the in-flight loading state expressed as
 * an attempt whose promise has not settled yet:
 *
 *   - `null`                       — load not yet attempted, OR the
 *                                    previous load attempt rejected (so
 *                                    the next caller will retry).
 *   - `Argon2LoadAttempt`          — either the in-flight attempt
 *                                    (concurrent callers join it and await
 *                                    its promise) or, on success, a
 *                                    permanently-resolved attempt whose
 *                                    promise future callers `await`
 *                                    cheaply.
 *
 * Keeping this at module scope (not on the class instance) means multiple
 * `CryptoManager` instances share one load attempt, which is the right
 * behaviour: native modules are process-global anyway, and we don't want
 * to pay the import cost N times.
 *
 * **Why cache a pending attempt rather than the resolved module?** Two
 * requirements pull in opposite directions:
 *
 *   1. Concurrent first-callers should share one `await import('argon2')`
 *      — without coalescing, N parallel `encryptText` calls would each
 *      fire their own dynamic import.
 *   2. Transient load failures (e.g. a temporary FS permission glitch on
 *      Windows during a build-tool install) should not permanently
 *      disable async crypto for the lifetime of the process.
 *
 * Storing the in-flight attempt satisfies (1) — concurrent callers see
 * the same attempt and await its promise. Clearing the slot on rejection
 * (see `loadArgon2` below) satisfies (2) — the next caller after a failure
 * starts a fresh load. On success the attempt stays cached forever, so
 * subsequent callers pay only an `await` of an already-settled promise
 * (no re-import).
 */
let argon2ModuleCache: Argon2LoadAttempt | null = null;

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
  const attempt = argon2ModuleCache;
  if (attempt === null) {
    return null;
  }
  try {
    const hasher = await attempt.hasher;
    return hasher.provider;
  } catch {
    return null;
  }
}

/**
 * Report which Argon2id provider this process will actually use, resolving the
 * lazy-load chain if it has not run yet.
 *
 * **Why this is public, and why it matters for availability rather than
 * correctness.** All three providers implement RFC 9106 and derive
 * bit-identical keys, so the choice never affects whether a ciphertext
 * round-trips. It does affect one thing that is not a performance detail: the
 * native addon and the runtime's built-in `crypto.argon2` both derive OFF the
 * event loop, while `hash-wasm` computes synchronously on the calling thread
 * and **blocks it for the whole derivation**. Measured on Node v24.19.0 at the
 * 128 MiB default profile: 0 of ~138 expected timer ticks fired during a 694 ms
 * `hash-wasm` derivation, against 76 of ~78 for the native addon and 85 of ~86
 * for the built-in; at the Node decrypt budget's own ceiling a single
 * `hash-wasm` derivation blocked for 6 309 ms.
 *
 * Because `argon2` and `hash-wasm` are optional dependencies and a failed
 * native build does not fail an npm install, a deployment can land on the
 * blocking provider silently. A service that decrypts untrusted input can now
 * refuse to start on it:
 *
 * ```ts
 * import { getArgon2Provider } from '@hiprax/crypto/crypto-manager';
 *
 * if ((await getArgon2Provider()) === 'wasm') {
 *   throw new Error(
 *     'Argon2id resolved to the WASM provider, which blocks the event loop.'
 *   );
 * }
 * ```
 *
 * The three remedies, in the order they are worth trying: install a C++
 * toolchain so the native addon builds; run on Node >= 24.7.0, whose built-in
 * `crypto.argon2` needs no install at all; or move decryption into a
 * `worker_thread`, which keeps the main loop free whichever provider answers.
 *
 * Unlike the `@internal` `__peekArgon2ProviderForTesting`, this **forces**
 * resolution rather than reporting `null` for an untouched cache, which is what
 * makes it usable as a start-up assertion. It shares the module-level cache, so
 * calling it costs one lazy load for the process and nothing thereafter.
 *
 * @returns the resolved provider tag: `'native'` (the `argon2` addon),
 *   `'node'` (the runtime's built-in `crypto.argon2`), or `'wasm'`
 *   (`hash-wasm`)
 * @throws CryptoError `MEMORY_ERROR` / `'ARGON2_NOT_AVAILABLE'` when none of
 *   the three is usable — the same failure the async paths would report
 */
export async function getArgon2Provider(): Promise<Argon2Provider> {
  const hasher = await loadArgon2();
  return hasher.provider;
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
 * Adapt the runtime's OWN Argon2 implementation — `crypto.argon2`, added in
 * Node v24.7.0 — to the unified {@link Argon2Hasher} interface.
 *
 * Three things about this function are load-bearing.
 *
 * **1. The capability probe is lazy, read INSIDE the function.** There is no
 * module to import, so the obvious shortcut would be a module-scope
 * `const HAS_BUILTIN = typeof crypto.argon2 === 'function'`. That is wrong
 * twice over: it would run a capability check during `new CryptoManager()`
 * (the whole point of the lazy chain is that constructing a manager touches no
 * KDF), and it would freeze the answer at module-evaluation time, which is
 * before any test can make the property absent. The suite exercises the
 * "built-in missing" branch on a Node that HAS it by deleting the property and
 * restoring it in a `finally`; that only works because the read happens here.
 *
 * **2. It is synchronous on purpose.** Its two siblings are `async` because
 * they `await import(...)`; this one has nothing to await. `importArgon2Hasher`
 * is itself `async`, so returning a plain value from its `try` block behaves
 * identically to returning a promise, and a `throw` is caught the same way.
 *
 * **3. The parameter names differ from BOTH other providers**, and a silent
 * transposition would produce a different digest rather than an error, so the
 * mapping is spelled out once here and pinned by a known-answer test:
 *
 *   - `message`     ← `password`
 *   - `nonce`       ← `salt`         (min 8 bytes; 32 here)
 *   - `memory`      ← `memoryCost`   (**KiB blocks**, the same unit this
 *                                     library and the native addon use — NOT
 *                                     bytes)
 *   - `passes`      ← `timeCost`
 *   - `parallelism` ← `parallelism`
 *   - `tagLength`   ← `hashLength`
 *
 * `crypto.argon2` has no promise form and its callback is mandatory (passing
 * none throws `ERR_INVALID_ARG_TYPE`), so the callback is wrapped by hand
 * below. The derived key arrives as a `Buffer`; it is copied on return, the
 * same discipline the other two adapters follow.
 *
 * Returns a hasher tagged `provider: 'node'`; throws a raw `Error` when the
 * runtime is older than v24.7.0 and the function is simply not there (the
 * caller composes the friendly error after all three providers have failed).
 */
function importNodeBuiltinArgon2(): Argon2Hasher {
  // Lazy read — see note 1 above. Do NOT hoist this to module scope.
  const builtinArgon2 = crypto.argon2;
  if (typeof builtinArgon2 !== 'function') {
    throw new Error(
      '`node:crypto` exposes no `argon2` function ' +
        '(built-in Argon2id needs Node >= 24.7.0)'
    );
  }
  return {
    provider: 'node',
    hash: (password, options): Promise<Buffer> =>
      new Promise<Buffer>((resolve, reject) => {
        builtinArgon2(
          'argon2id',
          {
            message: password,
            nonce: options.salt,
            parallelism: options.parallelism,
            tagLength: options.hashLength,
            memory: options.memoryCost,
            passes: options.timeCost,
          },
          (err, derivedKey) => {
            if (err) {
              reject(err);
              return;
            }
            resolve(Buffer.from(derivedKey));
          }
        );
      }),
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
 * Try the native `argon2` import first, then Node's built-in `crypto.argon2`,
 * then the `hash-wasm` import, and if all three fail throw a friendly
 * {@link CryptoError} with a unified `ARGON2_NOT_AVAILABLE` code.
 *
 * All three providers implement the RFC 9106 Argon2id reference and produce
 * bit-identical raw output for the same `(password, salt, memoryCost,
 * timeCost, parallelism, hashLength)` tuple — verified across nine parameter
 * sets, including the `memoryCost === 8 * parallelism` floor and values that
 * are not multiples of `4 * parallelism` (all three apply the same rounding).
 * SIX `(memoryCost, timeCost, parallelism)` tuples are pinned as standing
 * regression tests in `argon2-provider-parity.test.ts`: the KAT `(4096, 2, 1)`,
 * plus `(8, 2, 1)`, `(9, 2, 1)`, `(100, 2, 7)`, `(8, 1, 1)` and `(4096, 1, 1)`.
 * A seventh case re-runs the KAT tuple with a multi-byte, non-ASCII password in
 * both NFC and NFD, which is what pins that the providers agree on how a
 * JavaScript string becomes bytes — an ASCII vector cannot, since ASCII is
 * byte-identical under every plausible encoding.
 *
 * **Each tuple is checked against every provider the HOST has**, which is all
 * three on a machine with the native addon and Node >= 24.7, and never fewer
 * than two: with one implementation there is nothing to compare, so the case
 * logs a skip rather than assert a parity claim it cannot make. That is why it
 * still says something on Node 22, where there is no built-in.
 *
 * **Be precise about the overlap with the nine: exactly TWO of the six, the
 * KAT and `(8, 1, 1)`, are literally among them.** The other four are
 * neighbours chosen to reach the same corners — the `8 * parallelism` floor,
 * the `4 * parallelism` rounding, and a `timeCost` of 1, which `@types/node`
 * declares out of range while this library, and `bench/codec.mjs`, both permit
 * it. (`parallelism` carries the identical "must be greater than 1" wording and
 * is the MORE consequential instance, since `p = 1` is this library's default
 * and therefore sits in essentially every ciphertext it has produced; the KAT
 * and four of the five tuples pin it.) So "six of the nine" would overstate it.
 * The remaining seven probes are recorded in no committed test; do not read
 * the test file as their full record.
 * The fallback chain therefore does NOT change ciphertext compatibility: a v1
 * ciphertext produced under any one provider round-trips under any other.
 *
 * **The order is fixed and must not be rearranged.** Two independent reasons:
 *
 *  1. *Measured cost.* At the production `HIGH` profile (m = 2^17 KiB, t = 3,
 *     p = 1) the three measured 343 ms (native), 403 ms (built-in) and 597 ms
 *     (`hash-wasm`). Native leads, and the built-in — which also runs off the
 *     event loop — turns the no-addon case from "slow WASM, or a hard failure
 *     when `hash-wasm` is absent too" into a fast, install-free success.
 *  2. *The snapshot suites depend on native being FIRST.*
 *     `format-snapshot.test.ts` and `container.test.ts` `unstable_mockModule`
 *     the `argon2` package with a hasher that SUCCEEDS and returns a fixed
 *     key, then assert checked-in byte layouts. Those mocks only bite because
 *     native is attempted first. Moving the built-in ahead of native would
 *     make both suites derive a real Argon2id key instead and every snapshot
 *     byte would change — a wire-format-looking failure with a tooling cause.
 *
 * Extracted from {@link loadArgon2} so the promise held by a cached load
 * attempt contains only the import + normalisation + fallback work (no extra
 * wrapping that would change the rejection shape callers see).
 */
async function importArgon2Hasher(): Promise<Argon2Hasher> {
  let nativeError: unknown;
  try {
    return await importNativeArgon2();
  } catch (err) {
    nativeError = err;
  }
  let builtinError: unknown;
  try {
    // Synchronous by design (no module to import) — see
    // `importNodeBuiltinArgon2`. Returning it from this `async` function
    // behaves identically to returning a promise.
    return importNodeBuiltinArgon2();
  } catch (err) {
    builtinError = err;
  }
  try {
    return await importHashWasmArgon2();
  } catch (wasmError) {
    // All three providers failed — surface a friendly error that points users
    // at every fix path (install build tools for native, upgrade the runtime
    // for the built-in, or install hash-wasm for the pure-WASM fallback) plus
    // the synchronous PBKDF2 escape hatch that needs none of them. Each
    // provider's own diagnosis is appended so the reader can tell "not
    // installed" from "installed but broken".
    //
    // The opening sentence is load-bearing text, not prose: `README.md` quotes
    // this message byte-for-byte and `argon2-lazy-load.test.ts` asserts the
    // fragment "argon2 native module unavailable. Install build tools".
    const nativeMsg =
      nativeError instanceof Error ? nativeError.message : String(nativeError);
    const builtinMsg =
      builtinError instanceof Error
        ? builtinError.message
        : String(builtinError);
    const wasmMsg =
      wasmError instanceof Error ? wasmError.message : String(wasmError);
    throw new CryptoError(
      'argon2 native module unavailable. Install build tools (Python + node-gyp), ' +
        'or run on Node >= 24.7.0 (whose built-in `crypto.argon2` needs no ' +
        'install at all), or install the optional `hash-wasm` package for a ' +
        'pure-WASM Argon2id fallback (slower than native but works everywhere). ' +
        'Alternatively, use *Sync methods (PBKDF2). ' +
        `Native error: ${nativeMsg}. Node built-in error: ${builtinMsg}. ` +
        `WASM error: ${wasmMsg}.`,
      CryptoErrorType.MEMORY_ERROR,
      'ARGON2_NOT_AVAILABLE'
    );
  }
}

/**
 * Lazily load an Argon2id hasher (native preferred, then Node's built-in
 * `crypto.argon2`, then the hash-wasm fallback) using an in-flight-promise
 * pattern that coalesces concurrent first-callers and lets transient failures
 * recover on the next call.
 *
 * Behaviour:
 *
 *   - First call (cache empty): stores a new in-flight load attempt in
 *     the cache slot and awaits its promise. On success the attempt stays
 *     cached forever — subsequent callers `await` an already-settled
 *     promise (no re-import). On rejection the cache slot is cleared back
 *     to `null` so the NEXT caller starts a fresh load.
 *   - Concurrent first-callers: read the same in-flight attempt from the
 *     cache, await its promise, and either all resolve to the same module
 *     or all reject with the same error. No duplicate `await import`.
 *   - Caller after a previous failure: cache is `null`, so this call
 *     behaves exactly like a first-time call. Transient failures (e.g.
 *     temporary FS permission errors during a parallel build-tool install)
 *     can recover on the next attempt rather than being stuck for the
 *     process lifetime.
 *
 * The cache-clear step uses a "compare-and-swap" pattern: only clear if
 * the slot still holds *our* attempt. This function fills the slot only
 * when it is empty, and clears it only while it still holds this call's
 * own, already-settled attempt, so nothing on the load path can displace a
 * pending attempt. The one thing that can is
 * {@link __resetArgon2ModuleCacheForTesting} (reachable through the
 * `/crypto-manager` subpath), after which a fresh call may start a new
 * attempt. The check stops the displaced attempt's late rejection from
 * evicting that fresh attempt. It compares attempt records, never promises
 * (the module-private `Argon2LoadAttempt` type records why).
 *
 * Why a function instead of inline in `deriveKey`: extracting it makes the
 * caching logic testable and keeps `deriveKey` readable.
 */
export async function loadArgon2(): Promise<Argon2Hasher> {
  // Fast path: someone already started (or finished) the load. Reuse it.
  const cached = argon2ModuleCache;
  if (cached !== null) {
    return cached.hasher;
  }

  // Slow path: start a load. Store the attempt in the cache slot BEFORE
  // awaiting so concurrent callers landing here join it rather than
  // starting their own. The local `attempt` is this call's ownership token
  // for the compare-and-swap below.
  const attempt: Argon2LoadAttempt = { hasher: importArgon2Hasher() };
  argon2ModuleCache = attempt;

  try {
    return await attempt.hasher;
  } catch (err) {
    // Clear the cache slot, but ONLY if it still holds THIS attempt. Nothing
    // on the load path replaces a pending attempt; only the reset hook can,
    // while this load is pending, and a fresh `loadArgon2()` may then have
    // stored its own attempt. Clearing unconditionally would evict that fresh
    // attempt and make the next caller start a duplicate import.
    //
    // Compare the attempt records, and never `await` here: awaiting the
    // rejected promise would re-throw before the slot is cleared and cache
    // this failure for the life of the process.
    if (argon2ModuleCache === attempt) {
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
 * lazily-loaded native / Node-built-in / WASM hasher. The caller has already
 * NFC-normalised `password` (engine contract), so this hashes the exact string
 * it is given. All three providers produce exactly `hashLength` bytes for these
 * parameters.
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
 * SHA-256, and the CSPRNG, and by the native → Node built-in → WASM Argon2id
 * loader above.
 */
export const nodeEngine: CryptoEngine = {
  randomBytes: nodeRandomBytes,
  deriveArgon2id: nodeDeriveArgon2id,
  aeadEncrypt: nodeAeadEncrypt,
  aeadDecrypt: nodeAeadDecrypt,
  sha256: nodeSha256,
};
