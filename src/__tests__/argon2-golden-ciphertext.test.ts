/**
 * Golden cross-provider ciphertext test (Phase 2).
 *
 * This is the second half of the real Argon2id parity evidence (the first
 * being the known-answer vectors in `argon2-provider-parity.test.ts`). It
 * proves the fallback chain end-to-end: a v1 ciphertext produced by the
 * REAL native `argon2` provider decrypts correctly through each of the
 * library's two REAL fallback adapters — no fixed-output mock anywhere in the
 * derivation path. One case per fallback:
 *
 *   - `provider === 'wasm'`: the built-in is hidden, so the chain reaches
 *     `hash-wasm`. This is the original case and the reason the file exists.
 *   - `provider === 'node'`: the built-in is left in place, so the chain stops
 *     at the runtime's own `crypto.argon2`. Added with the third provider.
 *
 * Between them they say the thing that actually matters about a three-provider
 * chain: a stored ciphertext whose key the native addon derived is recovered,
 * byte-for-byte, by a key some OTHER implementation derived — whichever one
 * the host happens to resolve. A decrypt that merely succeeds proves nothing
 * here, so each case asserts which provider answered.
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
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import crypto from 'node:crypto';

// Registered at MODULE scope, not inside a case, and that placement is
// deliberate. Both cases below need the native import to fail, so a
// per-case registration would make each of them depend on the other having
// already run — `jest -t` on either one alone would then resolve the REAL
// native addon and assert the wrong provider. Registrations are file-scoped
// and survive `jest.resetModules()` (see the file header), so one call here
// covers every case for the life of the suite. `hash-wasm` is deliberately
// never registered: the real WASM adapter is one of the two subjects.
jest.unstable_mockModule('argon2', () => {
  throw new Error("Cannot find module 'argon2'");
});

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

describe('golden native-produced ciphertext decrypts through the real fallback providers', () => {
  beforeEach(() => {
    // A fresh module registry per case, so neither one inherits the other's
    // resolved provider. The `argon2` mock registered at module scope is NOT
    // cleared by this (see the file header).
    jest.resetModules();
  });

  it('decryptText yields the expected plaintext with provider === wasm', async () => {
    // The native import fails (mocked at module scope), so the loader falls
    // through. hash-wasm is deliberately NOT mocked — the REAL WASM adapter is
    // the subject. The built-in `crypto.argon2` sits BETWEEN the two in the
    // chain, so it is hidden for the duration or it, not hash-wasm, would
    // answer the call.
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
      // NEGATIVE: the built-in did not quietly answer in hash-wasm's place,
      // which is precisely what would happen if the wrapper above were
      // removed as redundant.
      expect(await __peekArgon2ProviderForTesting()).not.toBe('node');
    });
  });

  it('decryptText yields the expected plaintext with provider === node', async () => {
    // The sibling of the case above, and the one the third provider needed:
    // the SAME committed ciphertext, whose key the native addon derived, must
    // be recoverable from a key the RUNTIME derived. Nothing is hidden here —
    // native still fails, so the chain stops at the built-in, one link before
    // hash-wasm.
    if (typeof crypto.argon2 !== 'function') {
      // eslint-disable-next-line no-console
      console.warn(
        '[skip] node:crypto.argon2 unavailable (Node < 24.7.0), skipping ' +
          'the built-in golden cross-provider decrypt'
      );
      return;
    }

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

    const decrypted = await manager.decryptText(
      GOLDEN_CIPHERTEXT,
      GOLDEN_PASSWORD
    );

    expect(decrypted).toBe(GOLDEN_PLAINTEXT);
    // Asserted explicitly: a decrypt that merely succeeds says nothing about
    // WHICH implementation derived the key, and this case exists only to say
    // that it was the built-in.
    expect(await __peekArgon2ProviderForTesting()).toBe('node');

    // NEGATIVES. Neither neighbour in the chain answered — native is mocked
    // away and hash-wasm sits behind the built-in — and the recovery is not
    // some password-independent artefact of the format.
    expect(await __peekArgon2ProviderForTesting()).not.toBe('native');
    expect(await __peekArgon2ProviderForTesting()).not.toBe('wasm');
    await expect(
      manager.decryptText(GOLDEN_CIPHERTEXT, `${GOLDEN_PASSWORD}x`)
    ).rejects.toBeInstanceOf(CryptoError);
  });
});
