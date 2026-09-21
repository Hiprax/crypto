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
import crypto from 'node:crypto';

/**
 * Run `fn` with Node's built-in `crypto.argon2` temporarily absent, restoring
 * it in a `finally` whatever happens.
 *
 * WHY THIS EXISTS. `engine.node.ts` tries three Argon2id providers in the order
 * native `argon2` → the runtime's built-in `crypto.argon2` (Node >= 24.7.0) →
 * `hash-wasm`. This file's whole purpose is the REAL, unmocked `hash-wasm`
 * adapter, and it reaches it by making the native import throw. On any Node
 * >= 24.7 the chain would now stop at the built-in and `hash-wasm` would never
 * run, so the case would silently stop testing the thing it is named after.
 * Hiding the built-in is the repair; relaxing the `'wasm'` assertion would not
 * be — that deletes the coverage and leaves a green suite.
 *
 * WHY THE DESCRIPTOR DANCE, and not `jest.replaceProperty`. That helper refuses
 * outright here: `` Cannot replace the `argon2` property because it is a
 * function. Use jest.spyOn(object, 'argon2') instead. `` A spy cannot express
 * "this property does not exist", which is exactly the condition under test, so
 * the property descriptor is saved, the property deleted, and the descriptor
 * put back. `crypto.argon2` is `{ writable, configurable, enumerable }`, so the
 * round trip is exact. On a Node older than 24.7 the descriptor is `undefined`,
 * the delete is a no-op, and nothing is restored — the suite behaves exactly as
 * it did before the third provider existed.
 *
 * WHY IT IS DUPLICATED rather than shared with `argon2-lazy-load.test.ts`.
 * Jest's `testMatch` is `['**\/__tests__/**\/*.ts', …]`, and
 * `testPathIgnorePatterns` excludes only `browser/`, so ANY `.ts` file placed
 * under `src/__tests__/` is collected as a suite and fails with "Your test
 * suite must contain at least one test". A shared helper module would therefore
 * have to live outside this directory and be added to the gate surface. The
 * duplication is deliberate; do not "simplify" it into a shared file.
 */
async function withNodeBuiltinArgon2Hidden<T>(
  fn: () => Promise<T>
): Promise<T> {
  const descriptor = Object.getOwnPropertyDescriptor(crypto, 'argon2');
  if (descriptor !== undefined) {
    delete (crypto as { argon2?: typeof crypto.argon2 }).argon2;
  }
  try {
    return await fn();
  } finally {
    if (descriptor !== undefined) {
      Object.defineProperty(crypto, 'argon2', descriptor);
    }
  }
}

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
    // Force the native import to fail so the loader falls through. hash-wasm is
    // deliberately NOT mocked — the REAL WASM adapter is the subject. The
    // built-in `crypto.argon2` sits BETWEEN the two in the chain, so it is
    // hidden for the duration or it, not hash-wasm, would answer the call.
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });

    await withNodeBuiltinArgon2Hidden(async () => {
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
        decrypted = await manager.decryptText(
          GOLDEN_CIPHERTEXT,
          GOLDEN_PASSWORD
        );
      } catch (err) {
        // Availability gate: only a genuinely-absent hash-wasm (all three
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
});
