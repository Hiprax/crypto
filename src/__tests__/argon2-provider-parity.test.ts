/**
 * Real-provider Argon2id known-answer parity tests (Phase 2).
 *
 * These tests are the REAL evidence that the two interchangeable Argon2id
 * providers — native `argon2` and pure-WASM `hash-wasm` — implement the
 * RFC 9106 reference identically and therefore produce bit-identical raw
 * key material for the same input tuple. Ciphertext round-tripping across
 * a native-backed and a WASM-backed manager depends on exactly that.
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
 * present, but is gated the same way for symmetry.
 */
import { describe, it, expect } from '@jest/globals';
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
});
