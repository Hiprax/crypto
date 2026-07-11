/**
 * Web (SubtleCrypto + hash-wasm) implementation of the {@link CryptoEngine}
 * contract for @hiprax/crypto.
 *
 * ISOMORPHIC ISOLATION: this module is part of the BROWSER import graph, so it
 * imports ZERO `node:` builtins and references ZERO Node globals (`Buffer`,
 * `process`). It reaches only Web-platform primitives — `globalThis.crypto`
 * (Web Crypto: `getRandomValues` + `subtle`) — plus a lazily
 * dynamic-`import()`ed `hash-wasm` for Argon2id (Web Crypto has no Argon2id).
 * Its only static imports are the pure `./types.js` (`CryptoError`) and the
 * type-only `./engine.js` interface, both themselves Node-free. A static
 * ESLint gate (`no-restricted-globals` / `no-restricted-imports`) plus a grep
 * for `node:` keep it that way; the hard esbuild `platform:'browser'` bundle
 * gate lands in Phase 7.
 *
 * Every Web-Crypto-specific quirk is hidden HERE so the shared core assembles
 * the byte-identical wire format for both runtimes:
 *
 *  1. **Tag split / join (C‖T).** Web Crypto's AES-GCM APPENDS the 16-byte auth
 *     tag to the ciphertext on encrypt and expects it appended on decrypt. The
 *     {@link CryptoEngine} contract returns/takes the tag SEPARATELY (matching
 *     Node's `getAuthTag()` / `setAuthTag()`), so `aeadEncrypt` slices the
 *     trailing 16 bytes off as the tag and `aeadDecrypt` re-joins
 *     `ciphertext‖tag` before calling `subtle.decrypt`. For the same
 *     `(key, iv, aad, plaintext)`, the ciphertext and tag produced here are
 *     byte-identical to the Node engine's (proven by the cross-engine interop
 *     tests) — this is what lets one wire format round-trip across Node and the
 *     browser.
 *
 *  2. **Async-only, one-shot.** `subtle.*` and hash-wasm are async, and there
 *     is no streaming (Web Crypto AES-GCM is one-shot); the browser build is
 *     the async in-memory subset by construction.
 *
 *  3. **Argon2id via hash-wasm.** `subtle` has no Argon2id, so the pure-WASM
 *     `hash-wasm` supplies it — RFC 9106 Argon2id, bit-identical raw output to
 *     the native `argon2` the Node engine prefers (same KAT), which is why a
 *     ciphertext derived under one engine decrypts under the other. The import
 *     is lazy (inside {@link loadArgon2id}) so merely importing this module
 *     never compiles the WASM, and an unavailable `hash-wasm` surfaces as the
 *     same `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` the Node engine
 *     throws.
 */

import { CryptoError, CryptoErrorType } from './types.js';
import type { CryptoEngine } from './engine.js';

/** AES-GCM algorithm name for the Web Crypto `subtle` API. */
const AES_GCM = 'AES-GCM';

/**
 * GCM authentication-tag length. MUST stay 128 bits / 16 bytes: the wire
 * format splits and re-joins the tag at a fixed 16-byte offset, and Web Crypto
 * only appends a 128-bit tag when `tagLength: 128` is requested.
 */
const GCM_TAG_LENGTH_BITS = 128;
const GCM_TAG_LENGTH_BYTES = 16;

/**
 * Web Crypto's `getRandomValues` throws `QuotaExceededError` for a single
 * request larger than 65536 bytes, whereas Node's `crypto.randomBytes` has no
 * such cap. To keep the two engines drop-in interchangeable, large requests are
 * filled in <= 65536-byte chunks. (In practice the core only ever asks for 32-
 * and 12-byte values, but the engine honours the interface's unbounded
 * `randomBytes(length)` contract.)
 */
const MAX_RANDOM_BYTES_PER_CALL = 65536;

/**
 * Argon2id derivation parameter shape, sourced from the {@link CryptoEngine}
 * contract so the Web engine and the interface cannot drift (mirrors the Node
 * engine's `Argon2DeriveParams`).
 */
type Argon2DeriveParams = Parameters<CryptoEngine['deriveArgon2id']>[2];

/**
 * Minimal shape of the single `hash-wasm` export the Web engine uses. Declared
 * locally (never imported at the top level) so importing this module does not
 * eagerly pull in `hash-wasm` or its WASM payload — the real import is the lazy
 * dynamic `import('hash-wasm')` inside {@link loadArgon2id}.
 *
 * Parameter mapping to the {@link CryptoEngine} params: `memorySize` =
 * `memoryCost` (KiB), `iterations` = `timeCost`, `parallelism` / `hashLength`
 * identical; `outputType: 'binary'` yields a raw `Uint8Array` of `hashLength`
 * bytes. This is the RFC 9106 Argon2id reference, bit-identical to native
 * `argon2` for the same tuple.
 */
type HashWasmArgon2id = (options: {
  password: string;
  salt: Uint8Array;
  iterations: number;
  parallelism: number;
  memorySize: number;
  hashLength: number;
  outputType: 'binary';
}) => Promise<Uint8Array>;

/**
 * Lazily import `hash-wasm` and return its `argon2id` function.
 *
 * Any failure to load the module (absent optional dependency, bundler
 * exclusion, …) OR a loaded module that does not expose an `argon2id` function
 * surfaces as `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` — the exact
 * code/type the Node engine throws when neither Argon2 provider is available,
 * so the shared core's error handling is identical across runtimes.
 *
 * A CALL-time failure of `argon2id` itself (e.g. a WASM `CompileError` under a
 * strict CSP that omits `'wasm-unsafe-eval'`, or a `RangeError` growing WASM
 * memory) is deliberately NOT caught here: it propagates and the core wraps it
 * as `KEY_DERIVATION_FAILED`, mirroring how a native hash failure behaves in
 * the Node engine.
 */
async function loadArgon2id(): Promise<HashWasmArgon2id> {
  try {
    // hash-wasm ships ESM with `argon2id` as a named export; some interop
    // layers surface it under `.default`. Handle both shapes (mirrors the Node
    // engine's `importHashWasmArgon2`).
    const mod = (await import('hash-wasm')) as {
      argon2id?: HashWasmArgon2id;
      default?: { argon2id?: HashWasmArgon2id };
    };
    const fn =
      typeof mod.argon2id === 'function'
        ? mod.argon2id
        : typeof mod.default?.argon2id === 'function'
          ? mod.default.argon2id
          : null;
    if (fn === null) {
      throw new Error('`hash-wasm` loaded but exposes no `argon2id` export');
    }
    return fn;
  } catch (error) {
    throw new CryptoError(
      'Argon2id is unavailable in this environment: the optional `hash-wasm` ' +
        'package could not be loaded. Ensure `hash-wasm` is installed and ' +
        'included in your bundle — it provides a pure-WASM Argon2id that works ' +
        'in browsers and Node. ' +
        `Import error: ${error instanceof Error ? error.message : String(error)}.`,
      CryptoErrorType.MEMORY_ERROR,
      'ARGON2_NOT_AVAILABLE'
    );
  }
}

/**
 * {@link CryptoEngine.randomBytes} — Web Crypto CSPRNG. Synchronous. Fills the
 * output in <= 65536-byte chunks so a request larger than Web Crypto's per-call
 * cap still succeeds (see {@link MAX_RANDOM_BYTES_PER_CALL}).
 */
function webRandomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += MAX_RANDOM_BYTES_PER_CALL) {
    const end = Math.min(offset + MAX_RANDOM_BYTES_PER_CALL, length);
    // `getRandomValues` fills the view in place; the view aliases `out`.
    globalThis.crypto.getRandomValues(out.subarray(offset, end));
  }
  return out;
}

/**
 * {@link CryptoEngine.deriveArgon2id} — derive a raw Argon2id key via the
 * lazily-loaded `hash-wasm`. The caller has already NFC-normalised `password`
 * (engine contract), so this hashes the exact string it is given. `hash-wasm`
 * reads a `Uint8Array` salt respecting its `byteOffset`, so a subarray view
 * (as the core passes on decrypt) derives the same key as a compacted copy.
 */
async function webDeriveArgon2id(
  password: string,
  salt: Uint8Array,
  params: Argon2DeriveParams
): Promise<Uint8Array> {
  const argon2id = await loadArgon2id();
  return argon2id({
    password,
    salt,
    iterations: params.timeCost,
    parallelism: params.parallelism,
    memorySize: params.memoryCost,
    hashLength: params.hashLength,
    outputType: 'binary',
  });
}

/**
 * Import a raw 32-byte AES-256 key into an opaque Web Crypto {@link CryptoKey}
 * for the given usage, then SCRUB the transient raw-key copy the engine holds.
 *
 * `subtle.importKey('raw', …)` copies the key bytes into a `CryptoKey` we can
 * no longer reach — and therefore can never zero. To bound the lifetime of the
 * only plaintext key bytes the ENGINE itself owns, we import from a PRIVATE
 * copy and zero that copy the instant `importKey` has consumed it (`finally`,
 * so a rejecting import scrubs too; `importKey` copies its `keyData`
 * synchronously at call time, so scrubbing after the await cannot corrupt the
 * derived `CryptoKey`).
 *
 * We deliberately do NOT mutate the caller's `key` buffer: it is caller-owned
 * (the shared core scrubs it immediately after `aeadEncrypt` / `aeadDecrypt`
 * returns), and zeroing it here would (a) diverge from the Node engine, which
 * never mutates it — breaking drop-in interchangeability — and (b) corrupt the
 * round-trip / cross-engine patterns that legitimately reuse one key buffer
 * across calls, a browser-only footgun. The engine's job is to leave behind no
 * key material OF ITS OWN; the raw key's owner scrubs the original.
 */
async function importAesGcmKey(
  key: Uint8Array,
  usage: 'encrypt' | 'decrypt'
): Promise<CryptoKey> {
  const rawKey = new Uint8Array(key);
  try {
    return await globalThis.crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: AES_GCM },
      false,
      [usage]
    );
  } finally {
    rawKey.fill(0);
  }
}

/**
 * Narrow the generic `Uint8Array` to the `Uint8Array<ArrayBuffer>` that Web
 * Crypto's `BufferSource`-typed parameters (`iv` / `additionalData` / digest
 * input) require.
 *
 * The engine contract hands us `Uint8Array` (`Uint8Array<ArrayBufferLike>`,
 * which also admits a `SharedArrayBuffer` backing), but `subtle`'s typed
 * parameters exclude `SharedArrayBuffer`. Every buffer reaching this engine
 * originates from the pure codec / format layer or the core's `randomBytes`
 * and is backed by a plain `ArrayBuffer`, never a `SharedArrayBuffer`, so the
 * narrowing is sound. This is a purely compile-time adjustment for the TS 5.7+
 * generic TypedArray types — it emits nothing and copies nothing.
 */
function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

/**
 * {@link CryptoEngine.aeadEncrypt} — AES-256-GCM encrypt via Web Crypto. Web
 * Crypto appends the 16-byte tag (`C‖T`); the engine contract returns it
 * SEPARATELY, so the trailing tag is split off here. For empty plaintext the
 * result is exactly the 16-byte tag and the ciphertext is empty.
 */
async function webAeadEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  const cryptoKey = await importAesGcmKey(key, 'encrypt');
  const combined = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      {
        name: AES_GCM,
        iv: asBufferSource(iv),
        additionalData: asBufferSource(aad),
        tagLength: GCM_TAG_LENGTH_BITS,
      },
      cryptoKey,
      asBufferSource(plaintext)
    )
  );
  const splitAt = combined.length - GCM_TAG_LENGTH_BYTES;
  const ciphertext = combined.slice(0, splitAt);
  const tag = combined.slice(splitAt);
  return { ciphertext, tag };
}

/**
 * {@link CryptoEngine.aeadDecrypt} — AES-256-GCM decrypt + tag verify via Web
 * Crypto. The separate `ciphertext` and `tag` are re-joined (`C‖T`) for
 * `subtle.decrypt`. Any authentication failure — wrong key/IV/AAD, tampered
 * ciphertext, or a corrupted tag — surfaces as a generic
 * `CryptoError(DECRYPTION_FAILED)` so the failure modes are indistinguishable
 * (no decryption oracle), matching the Node engine.
 */
async function webAeadDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  try {
    const cryptoKey = await importAesGcmKey(key, 'decrypt');
    // Re-join ciphertext‖tag for Web Crypto's appended-tag convention.
    const joined = new Uint8Array(ciphertext.length + tag.length);
    joined.set(ciphertext, 0);
    joined.set(tag, ciphertext.length);
    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: AES_GCM,
          iv: asBufferSource(iv),
          additionalData: asBufferSource(aad),
          tagLength: GCM_TAG_LENGTH_BITS,
        },
        cryptoKey,
        joined
      )
    );
  } catch (error) {
    throw new CryptoError(
      `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      CryptoErrorType.DECRYPTION_FAILED,
      'DECRYPTION_FAILED'
    );
  }
}

/**
 * {@link CryptoEngine.sha256} — SHA-256 digest via `subtle.digest`. Returns a
 * fresh 32-byte `Uint8Array`.
 */
async function webSha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    asBufferSource(data)
  );
  return new Uint8Array(digest);
}

/**
 * The Web {@link CryptoEngine}, backed by Web Crypto (`globalThis.crypto`) for
 * AES-256-GCM, SHA-256, and the CSPRNG, and by the lazily-loaded `hash-wasm`
 * Argon2id. Runs unchanged in the browser (secure context) and in Node 22+
 * (which also exposes `globalThis.crypto`), so it is fully testable without a
 * browser.
 */
export const webEngine: CryptoEngine = {
  randomBytes: webRandomBytes,
  deriveArgon2id: webDeriveArgon2id,
  aeadEncrypt: webAeadEncrypt,
  aeadDecrypt: webAeadDecrypt,
  sha256: webSha256,
};
