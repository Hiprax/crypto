/**
 * Golden cross-provider ciphertext test (Phase 2).
 *
 * This is the second half of the real Argon2id parity evidence (the first
 * being the known-answer vectors in `argon2-provider-parity.test.ts`). It
 * proves the fallback chain end-to-end: a v1 ciphertext produced by the
 * REAL native `argon2` provider decrypts correctly through the library's
 * REAL `hash-wasm` fallback adapter — no fixed-output mock anywhere in the
 * derivation path.
 *
 * Why a DEDICATED file (and not `argon2-lazy-load.test.ts`): Jest's
 * `jest.unstable_mockModule` factory registrations are FILE-scoped and
 * survive `jest.resetModules()` — only between-file teardown clears them
 * (verified against jest-runtime 30.4.2). Every test in
 * `argon2-lazy-load.test.ts` registers a `hash-wasm` mock, which would leak
 * into this test and replace the real WASM KDF, defeating its purpose. So
 * this file registers EXACTLY ONE mock — `argon2` set to import-throw, to
 * force the fallback — and NEVER mocks `hash-wasm`.
 *
 * The golden ciphertext below was generated at implementation time by a
 * one-off script against the freshly built `dist/`, importing
 * `CryptoManager` and `__peekArgon2ProviderForTesting` from
 * `dist/crypto-manager.js` (the test hooks are not re-exported by
 * `dist/index.js`). The script asserted `__peekArgon2ProviderForTesting()`
 * resolved `'native'` before the value was trusted, so this string is
 * genuinely native-produced. Encryption uses a fresh random salt+IV per
 * call, so this is one pinned instance rather than a reproducible vector.
 */
import { describe, it, expect, jest } from '@jest/globals';

// The golden ciphertext, produced by the native argon2 provider under
// managerOptions { memoryCost: 4096, timeCost: 2, parallelism: 1 } for
// plaintext 'cross-provider parity round-trip' and password
// 'ParityR0und!Trip#2026'. See the file header for provenance.
const GOLDEN_CIPHERTEXT =
  'SFBDUgEAAAAQAAAAAAIAAQAAAAAAAC8M5k0nnBlvqtSLLKaL0kkpvBJ4-XOACNT-a249vFH_w831GSVsi8b8uszVxG1VpjDV1c7PfpCTRFGPaMvDzuVUO9UKtCczWsdy9Pgj2QQIt3fk6oiRU0e4QIHM';
const GOLDEN_PASSWORD = 'ParityR0und!Trip#2026';
const GOLDEN_PLAINTEXT = 'cross-provider parity round-trip';

describe('golden native-produced ciphertext decrypts through the real hash-wasm fallback', () => {
  it('decryptText yields the expected plaintext with provider === wasm', async () => {
    // Force the native import to fail so the loader falls through to the
    // REAL hash-wasm provider. hash-wasm is deliberately NOT mocked.
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const manager = new CryptoManager({
      memoryCost: 4096,
      timeCost: 2,
      parallelism: 1,
    });

    let decrypted: string;
    try {
      decrypted = await manager.decryptText(GOLDEN_CIPHERTEXT, GOLDEN_PASSWORD);
    } catch (err) {
      // Availability gate: only a genuinely-absent hash-wasm (both
      // providers unavailable → ARGON2_NOT_AVAILABLE) is a legitimate
      // reason to skip. Any other failure is a real regression.
      if (
        err instanceof CryptoError &&
        (err as InstanceType<typeof CryptoError>).code ===
          'ARGON2_NOT_AVAILABLE'
      ) {
        // eslint-disable-next-line no-console
        console.warn(
          '[skip] hash-wasm unavailable, skipping golden cross-provider decrypt'
        );
        return;
      }
      throw err;
    }

    expect(decrypted).toBe(GOLDEN_PLAINTEXT);
    expect(await __peekArgon2ProviderForTesting()).toBe('wasm');
  });
});
