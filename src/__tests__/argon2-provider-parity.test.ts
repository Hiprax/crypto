/**
 * Real-provider Argon2id known-answer parity tests (Phase 2).
 *
 * These tests are the REAL evidence that the three interchangeable Argon2id
 * providers — native `argon2`, the runtime's own `crypto.argon2` (Node >=
 * 24.7.0) and pure-WASM `hash-wasm` — implement the RFC 9106 reference
 * identically and therefore produce bit-identical raw key material for the
 * same input tuple. Ciphertext round-tripping between hosts that happen to
 * resolve different providers depends on exactly that.
 *
 * Unlike the wiring tests in `argon2-lazy-load.test.ts` (which mock both
 * providers with a fixed constant to check only the adapter's parameter
 * pass-through and Buffer conversion), THIS file registers NO module mocks
 * at all: it runs the genuine, locally-installed KDFs and compares their
 * output against a vector computed live from both providers at
 * implementation time.
 *
 * Availability gating (Core Principle 4): `argon2` is a native optional
 * dependency; on a host where its prebuild and node-gyp both failed, the
 * library's documented behaviour is graceful fallback. So each test uses
 * the "probe IS the call" pattern — the real derivation runs inside a
 * try/catch and, on throw, performs a logged early-return SKIP rather than
 * failing the suite. A bare `import('argon2')` is NOT a sufficient probe: a
 * broken native `.node` binding still imports (the JS wrapper loads the
 * binding lazily), so only an actual hash attempt distinguishes "available"
 * from "present but broken". `hash-wasm` is pure WASM and expected to be
 * present, but is gated the same way for symmetry. The built-in is gated on
 * `typeof crypto.argon2Sync === 'function'` instead, because its absence is a
 * runtime-version fact rather than an install outcome: it landed in Node
 * 24.7.0 and this package supports Node >= 22.
 */
import { describe, it, expect } from '@jest/globals';
import crypto from 'node:crypto';
import { argon2id } from 'hash-wasm';
import {
  CryptoManager,
  __resetArgon2ModuleCacheForTesting,
  __peekArgon2ProviderForTesting,
} from '../crypto-manager';

// ----------------------------------------------------------------------------
// Known-answer vector.
// ----------------------------------------------------------------------------
//
// Computed live at implementation time from the REAL installed providers —
// argon2@0.44.0 (native) AND hash-wasm@4.12.0 (pure WASM) — with the exact
// parameters below. Both providers produced this identical 32-byte output;
// the value is NEVER authored from memory.
//
//   password    = 'parity-vector-password'  (ASCII; NFC is a no-op)
//   salt        = 32 bytes, values 0x00..0x1f
//   memoryCost  = 4096 KiB (4 MiB)
//   timeCost    = 2
//   parallelism = 1
//   hashLength  = 32
//
// Re-verified 2026-09-21 after the optional `argon2` dependency moved to
// ^0.45.1: the native adapter still resolves `provider === 'native'` and still
// derives this exact vector, so the value above is a cross-VERSION invariant
// too, not only a cross-provider one. The version recorded above is the one
// the vector was first computed from; it is history, not a pin.
const KAT_HEX =
  '79fce5dc8932db4e5d85f8d32c1d8f2206188c3c1bcbe5ef555bab13c595567b';
const KAT_PASSWORD = 'parity-vector-password';
const KAT_SALT = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const KAT_MEMORY_COST = 4096;
const KAT_TIME_COST = 2;
const KAT_PARALLELISM = 1;
const KAT_HASH_LENGTH = 32;

describe('Argon2id cross-provider known-answer parity (real providers, no mocks)', () => {
  it('native argon2 derives the pinned KAT vector', async () => {
    // Probe IS the call: run the real derivation through the library's
    // native adapter. The cache is reset first so provider selection is
    // observable via the peek hook afterwards.
    __resetArgon2ModuleCacheForTesting();
    const manager = new CryptoManager({
      memoryCost: KAT_MEMORY_COST,
      timeCost: KAT_TIME_COST,
      parallelism: KAT_PARALLELISM,
    });

    let derivedHex: string;
    try {
      const key = await manager.deriveKey(KAT_PASSWORD, KAT_SALT);
      derivedHex = key.toString('hex');
    } catch (err) {
      // Both providers genuinely unavailable — the documented graceful
      // fallback state. Skip rather than fail (Core Principle 4).
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] Argon2id unavailable, skipping native KAT: ${String(err)}`
      );
      return;
    }

    // Only trust this as the NATIVE vector when native actually ran. On a
    // broken-native/working-WASM host deriveKey succeeds via the fallback,
    // in which case this native-specific assertion must not run — the
    // WASM test below still covers that host. Honest provider claim.
    const provider = await __peekArgon2ProviderForTesting();
    if (provider !== 'native') {
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] native argon2 unavailable (resolved provider: ${String(
          provider
        )}); native KAT covered by the hash-wasm test`
      );
      return;
    }

    expect(derivedHex).toBe(KAT_HEX);
  });

  it('hash-wasm argon2id derives the pinned KAT vector', async () => {
    // Probe IS the call: invoke the real hash-wasm `argon2id` directly with
    // the exact parameter mapping the library's WASM adapter uses
    // (iterations=timeCost, memorySize=memoryCost, outputType='binary').
    let derivedHex: string;
    try {
      const out = await argon2id({
        password: KAT_PASSWORD,
        salt: KAT_SALT,
        iterations: KAT_TIME_COST,
        parallelism: KAT_PARALLELISM,
        memorySize: KAT_MEMORY_COST,
        hashLength: KAT_HASH_LENGTH,
        outputType: 'binary',
      });
      derivedHex = Buffer.from(out).toString('hex');
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] hash-wasm unavailable, skipping WASM KAT: ${String(err)}`
      );
      return;
    }

    expect(derivedHex).toBe(KAT_HEX);
  });

  it('node built-in crypto.argon2 derives the pinned KAT vector', async () => {
    // Probe IS the call, with one difference from its two siblings: the
    // built-in's absence is a runtime-VERSION fact, not an install outcome, so
    // it is cheap and honest to test for the function up front rather than to
    // catch a throw. It landed in Node 24.7.0 and this package supports
    // Node >= 22.
    if (typeof crypto.argon2Sync !== 'function') {
      // eslint-disable-next-line no-console
      console.warn(
        '[skip] node:crypto.argon2Sync unavailable (Node < 24.7.0), ' +
          'skipping built-in KAT'
      );
      return;
    }

    // Called directly, with the exact parameter mapping `engine.node.ts`'s
    // `importNodeBuiltinArgon2` uses: `memory` counts 1 KiB blocks (the same
    // unit as this library's `memoryCost`), `passes` is the time cost and
    // `tagLength` is the output length. Going through the primitive rather
    // than through the library is what makes this a statement about NODE
    // rather than about our adapter — the adapter's own wiring is pinned in
    // `argon2-node-builtin.test.ts` and `argon2-lazy-load.test.ts`.
    const derived = crypto.argon2Sync('argon2id', {
      message: KAT_PASSWORD,
      nonce: KAT_SALT,
      parallelism: KAT_PARALLELISM,
      tagLength: KAT_HASH_LENGTH,
      memory: KAT_MEMORY_COST,
      passes: KAT_TIME_COST,
    });

    expect(Buffer.from(derived).toString('hex')).toBe(KAT_HEX);
  });

  it('node built-in and hash-wasm agree at the awkward memory/parallelism tuples', async () => {
    // The KAT above uses a comfortable, round parameter set. What actually
    // decides whether the providers are interchangeable IN THE FIELD is their
    // behaviour at the edges of the parameter space, because each ciphertext
    // carries its own KDF parameters in its header and a decrypting host may
    // resolve a different provider than the encrypting one did. Three tuples,
    // each chosen for a specific hazard:
    //
    //   (m=8,  p=1)  the exact `memoryCost === 8 * parallelism` floor. This
    //                library's constructor and `parseHeader` both enforce
    //                ">=", while `@types/node`'s JSDoc for `memory` says
    //                "must be greater than `8 * parallelism`". If the built-in
    //                were really strictly greater, a stored ciphertext at
    //                exactly the floor would decrypt under native and
    //                hash-wasm and throw ERR_OUT_OF_RANGE under the built-in.
    //                It does not: the JSDoc wording is loose, and this case is
    //                what keeps that answer from having to be re-probed.
    //   (m=9,  p=1)  not a multiple of `4 * parallelism`. Node documents that
    //                `memory` is rounded down to such a multiple; the two
    //                providers must round the same way or diverge silently.
    //   (m=100,p=7)  the same rounding question with p > 1, where the multiple
    //                is 28 and the floor is 56 — so it is simultaneously
    //                above the floor and mid-interval.
    //
    // Both sides are COMPUTED here. Hard-coding a digest would turn a parity
    // claim into a second known-answer test and would pin whichever provider
    // the author happened to run.
    if (typeof crypto.argon2Sync !== 'function') {
      // eslint-disable-next-line no-console
      console.warn(
        '[skip] node:crypto.argon2Sync unavailable (Node < 24.7.0), ' +
          'skipping awkward-parameter parity'
      );
      return;
    }

    const tuples: ReadonlyArray<{ memory: number; parallelism: number }> = [
      { memory: 8, parallelism: 1 },
      { memory: 9, parallelism: 1 },
      { memory: 100, parallelism: 7 },
    ];

    const builtinHexes: string[] = [];
    for (const { memory, parallelism } of tuples) {
      const builtin = crypto.argon2Sync('argon2id', {
        message: KAT_PASSWORD,
        nonce: KAT_SALT,
        parallelism,
        tagLength: KAT_HASH_LENGTH,
        memory,
        passes: KAT_TIME_COST,
      });
      const builtinHex = Buffer.from(builtin).toString('hex');

      let wasmHex: string;
      try {
        const out = await argon2id({
          password: KAT_PASSWORD,
          salt: KAT_SALT,
          iterations: KAT_TIME_COST,
          parallelism,
          memorySize: memory,
          hashLength: KAT_HASH_LENGTH,
          outputType: 'binary',
        });
        wasmHex = Buffer.from(out).toString('hex');
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(
          `[skip] hash-wasm unavailable, skipping awkward-parameter parity: ${String(err)}`
        );
        return;
      }

      // The claim: bit-for-bit agreement, at a tuple neither provider's
      // documentation promises anything comfortable about.
      expect(wasmHex).toBe(builtinHex);
      expect(builtinHex).toHaveLength(KAT_HASH_LENGTH * 2);
      builtinHexes.push(builtinHex);
    }

    expect(builtinHexes).toHaveLength(tuples.length);

    // NEGATIVES, and without them the agreement above would be worth little.
    // Each tuple must produce its OWN digest: if `memory` or `parallelism`
    // were being dropped on the floor by both providers, every row would
    // agree and every row would be the same bytes. And none of them may be
    // the comfortable KAT vector, which is the one digest an implementation
    // that ignored these parameters entirely would be most likely to return.
    expect(new Set(builtinHexes).size).toBe(tuples.length);
    expect(builtinHexes).not.toContain(KAT_HEX);
  });
});
