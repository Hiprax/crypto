/**
 * The Node built-in Argon2id provider, exercised in isolation.
 *
 * `engine.node.ts` tries three Argon2id providers in the order native
 * `argon2` -> the runtime's own `crypto.argon2` (added in Node 24.7.0, needs
 * no install) -> `hash-wasm`. `argon2-lazy-load.test.ts` pins the ORDERING of
 * that chain and the adapter's parameter NAMES (against a recording stub);
 * this file pins the middle link's SEMANTICS against the real runtime
 * primitive, which is a different claim and is not implied by either of those.
 *
 * The load-bearing case is the known-answer vector. `crypto.argon2`'s
 * `memory` is documented as "memory cost in 1KiB blocks" — the same unit as
 * this library's `memoryCost` — and its `passes` / `tagLength` are two
 * unrelated small integers sitting next to each other in the same object
 * literal. Reading KiB as bytes, or transposing those two fields, produces a
 * DIFFERENT DIGEST rather than an error: the derivation succeeds, the key is
 * 32 bytes, the round-trip inside a single process still works, and only a
 * ciphertext written by one provider and read by another ever notices. A
 * known-answer assertion is the only thing that catches it, so it is asserted
 * against the project's pinned cross-provider vector rather than against
 * anything this file computes.
 *
 * Scope note: everything here runs the REAL built-in. The adapter's error
 * branches and its behaviour on a runtime that has no built-in at all are
 * covered by the stub-driven cases in `argon2-lazy-load.test.ts`, which run on
 * every supported runtime — including the Node 22 leg where CI measures
 * coverage and where this file mostly skips.
 */
import {
  describe,
  it,
  expect,
  jest,
  beforeEach,
  afterEach,
} from '@jest/globals';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

/**
 * Run `fn` with Node's built-in `crypto.argon2` temporarily absent, restoring
 * it in a `finally` whatever happens.
 *
 * WHY THE DESCRIPTOR DANCE, and not `jest.replaceProperty`. That helper
 * refuses outright here: `` Cannot replace the `argon2` property because it is
 * a function. Use jest.spyOn(object, 'argon2') instead. `` A spy cannot
 * express "this property does not exist", which is exactly the condition under
 * test, so the property descriptor is saved, the property deleted, and the
 * descriptor put back. `crypto.argon2` is `{ writable, configurable,
 * enumerable }`, so the round trip is exact. On a Node older than 24.7 the
 * descriptor is `undefined`, the delete is a no-op and nothing is restored.
 *
 * WHY IT IS DUPLICATED rather than shared with `argon2-lazy-load.test.ts` and
 * `argon2-golden-ciphertext.test.ts`, which both carry their own copy. Jest's
 * `testMatch` is `['**\/__tests__/**\/*.ts', …]` and `testPathIgnorePatterns`
 * excludes only `browser/`, so ANY `.ts` file placed under `src/__tests__/` is
 * collected as a suite and fails with "Your test suite must contain at least
 * one test". A shared helper module would have to live outside this directory
 * and be added to the gate surface. The duplication is deliberate; do not
 * "simplify" it into a shared file.
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

/**
 * Availability gate for the cases that need a REAL built-in. Returns `true`
 * (and logs the repo's `[skip]` line) when this runtime predates Node 24.7.0,
 * so the caller can early-return instead of failing.
 */
function skipWithoutBuiltin(what: string): boolean {
  if (typeof crypto.argon2 === 'function') {
    return false;
  }
  // eslint-disable-next-line no-console
  console.warn(
    `[skip] node:crypto.argon2 unavailable (Node < 24.7.0); ${what}`
  );
  return true;
}

// ----------------------------------------------------------------------------
// The pinned cross-provider known-answer vector.
// ----------------------------------------------------------------------------
//
// Identical to the constants in `argon2-provider-parity.test.ts`, on purpose:
// that file proves native `argon2` and `hash-wasm` both derive this value, and
// this one proves the runtime's built-in joins them. Restating the tuple here
// keeps each suite readable on its own; the value itself is never authored
// from memory — it was computed from the real providers and is re-derived by
// all three of them on every run.
//
//   password    = 'parity-vector-password'  (ASCII, so NFC is a no-op)
//   salt        = 32 bytes, values 0x00..0x1f
//   memoryCost  = 4096 KiB (4 MiB)     timeCost = 2
//   parallelism = 1                    hashLength = 32
const KAT_HEX =
  '79fce5dc8932db4e5d85f8d32c1d8f2206188c3c1bcbe5ef555bab13c595567b';
const KAT_PASSWORD = 'parity-vector-password';
const KAT_SALT = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const KAT_COST = { memoryCost: 4096, timeCost: 2, parallelism: 1 } as const;

/** A second salt, used only to prove a key-equality assertion is not vacuous. */
const OTHER_SALT = Buffer.alloc(32, 0x5a);

/** The message fragment `README.md` quotes byte-for-byte. */
const FRIENDLY_MESSAGE_FRAGMENT =
  'argon2 native module unavailable. Install build tools';

/**
 * Register both OPTIONAL providers as unloadable, and hand back a counter for
 * the `hash-wasm` factory.
 *
 * The counter is the negative that matters in this file: the built-in sits
 * between native and `hash-wasm`, so "the built-in answered" is only half the
 * claim — the other half is that the chain STOPPED there and never imported
 * the provider behind it. A factory that is never invoked leaves the counter
 * at zero; one that is invoked throws, which would surface as
 * `ARGON2_NOT_AVAILABLE` rather than a quiet fallback.
 */
function mockBothOptionalProvidersUnavailable(): { wasmFactoryCalls: number } {
  const state = { wasmFactoryCalls: 0 };
  jest.unstable_mockModule('argon2', () => {
    throw new Error("Cannot find module 'argon2'");
  });
  jest.unstable_mockModule('hash-wasm', () => {
    state.wasmFactoryCalls += 1;
    throw new Error("Cannot find module 'hash-wasm'");
  });
  return state;
}

describe('Node built-in crypto.argon2 provider', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('derives the pinned KAT vector, which is what proves memory is KiB and passes/tagLength are not transposed', async () => {
    if (skipWithoutBuiltin('the built-in cannot derive the KAT vector here')) {
      return;
    }
    const wasm = mockBothOptionalProvidersUnavailable();

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    try {
      const manager = new CryptoManager(KAT_COST);
      const key = await manager.deriveKey(KAT_PASSWORD, KAT_SALT);

      // The assertion the whole file exists for. `memory` read as bytes, or
      // `passes` and `tagLength` swapped, still yields 32 plausible-looking
      // bytes; only this comparison distinguishes them.
      expect(key.toString('hex')).toBe(KAT_HEX);
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);

      // The provider tag: the built-in, not something else that happened to
      // produce a key.
      expect(await __peekArgon2ProviderForTesting()).toBe('node');

      // NEGATIVES. The chain stopped at the built-in, so the provider behind
      // it was never even imported, and neither of the other two tags is what
      // answered.
      expect(wasm.wasmFactoryCalls).toBe(0);
      expect(await __peekArgon2ProviderForTesting()).not.toBe('wasm');
      expect(await __peekArgon2ProviderForTesting()).not.toBe('native');
    } finally {
      __resetArgon2ModuleCacheForTesting();
    }
  });

  it('derives byte-identical key material to the native addon for the same fixed salt', async () => {
    if (skipWithoutBuiltin('cannot compare the built-in against native here')) {
      return;
    }
    const wasm = mockBothOptionalProvidersUnavailable();

    // The REAL native addon, loaded through Node's own CJS loader rather than
    // through Jest's registry. That is the whole trick: `createRequire` sits
    // outside the registry, so it returns the genuine `argon2` package even
    // though this file has just registered a failing mock for that exact
    // specifier — which is what lets one case hold both providers at once
    // without depending on the order the cases happen to run in.
    let nativeKey: Buffer;
    try {
      const requireCjs = createRequire(import.meta.url);
      const nativeModule = requireCjs('argon2') as {
        hash(
          password: string,
          options: Record<string, unknown>
        ): Promise<Uint8Array>;
      };
      // The same mapping `importNativeArgon2` uses; `type: 2` is Argon2id.
      nativeKey = Buffer.from(
        await nativeModule.hash(KAT_PASSWORD, {
          type: 2,
          memoryCost: KAT_COST.memoryCost,
          timeCost: KAT_COST.timeCost,
          parallelism: KAT_COST.parallelism,
          hashLength: 32,
          salt: KAT_SALT,
          raw: true,
        })
      );
    } catch (err) {
      // `argon2` is an optional NATIVE dependency: absent, or present with a
      // broken binding, is a supported host state. Probe IS the call, so a
      // throw here is the probe failing, not a regression.
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] native argon2 unavailable, skipping built-in/native byte equality: ${String(err)}`
      );
      return;
    }

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    try {
      const manager = new CryptoManager(KAT_COST);
      const builtinKey = await manager.deriveKey(KAT_PASSWORD, KAT_SALT);
      expect(await __peekArgon2ProviderForTesting()).toBe('node');

      // The claim: two independent implementations of RFC 9106, one inside the
      // runtime and one a compiled addon, agree bit-for-bit. This is what
      // makes a ciphertext portable between hosts that resolve different
      // providers.
      expect(builtinKey.equals(nativeKey)).toBe(true);
      expect(builtinKey.toString('hex')).toBe(nativeKey.toString('hex'));

      // NEGATIVE, and the reason this is not a vacuous comparison: the salt is
      // genuinely plumbed through, so changing it changes the key. Without
      // this, an adapter that ignored `nonce` entirely would still pass the
      // equality above.
      const otherKey = await manager.deriveKey(KAT_PASSWORD, OTHER_SALT);
      expect(otherKey.equals(nativeKey)).toBe(false);

      // NEGATIVE: still no `hash-wasm` import anywhere in the two derivations.
      expect(wasm.wasmFactoryCalls).toBe(0);
    } finally {
      __resetArgon2ModuleCacheForTesting();
    }
  });

  it('round-trips encryptText/decryptText through the engine entry point with the built-in resolved', async () => {
    if (skipWithoutBuiltin('cannot round-trip through the built-in here')) {
      return;
    }
    // There are TWO distinct entries into `loadArgon2()` in the Node build:
    // `CryptoManager.deriveKey` calls it directly (that is what the two cases
    // above exercise), while the in-memory text/bytes/container paths reach it
    // through `CryptoCore.deriveKeyBytes` -> `nodeEngine.deriveArgon2id`. This
    // case covers the second one, so "the built-in works" is not a claim about
    // one call site only.
    const wasm = mockBothOptionalProvidersUnavailable();

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    try {
      const manager = new CryptoManager(KAT_COST);
      const plaintext = 'built-in provider round-trip';
      const ciphertext = await manager.encryptText(plaintext, KAT_PASSWORD);

      expect(await __peekArgon2ProviderForTesting()).toBe('node');
      expect(await manager.decryptText(ciphertext, KAT_PASSWORD)).toBe(
        plaintext
      );

      // NEGATIVES. The ciphertext is not the plaintext in disguise; the key
      // really is password-derived, so a different password does not open it;
      // and `hash-wasm` was never reached across any of these derivations.
      //
      // The first one searches the DECODED bytes, not the base64url string,
      // and the difference is the whole value of the assertion. `plaintext`
      // contains spaces, which the base64url alphabet cannot produce, so
      // `expect(ciphertext).not.toContain(plaintext)` would be true of every
      // possible input and could never fail — decoration rather than a test.
      // Against the decoded payload it is a real claim: replace the AEAD with
      // a passthrough and this line goes red.
      expect(Buffer.from(ciphertext, 'base64url').includes(plaintext)).toBe(
        false
      );
      await expect(
        manager.decryptText(ciphertext, `${KAT_PASSWORD}-wrong`)
      ).rejects.toBeInstanceOf(CryptoError);
      expect(wasm.wasmFactoryCalls).toBe(0);
    } finally {
      __resetArgon2ModuleCacheForTesting();
    }
  });

  it('rejects with ARGON2_NOT_AVAILABLE naming all three causes when the built-in is hidden as well', async () => {
    // Deliberately NOT availability-gated. Hiding a property that is already
    // absent is a no-op, so this case asserts exactly the same thing on a
    // Node 22 host as on a Node 24 one — which is worth having, because the
    // rest of this file skips there. `argon2-lazy-load.test.ts` leaves its
    // "built-in is absent" case ungated for the same reason.
    const wasm = mockBothOptionalProvidersUnavailable();

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    try {
      await withNodeBuiltinArgon2Hidden(async () => {
        const manager = new CryptoManager(KAT_COST);

        let caught: unknown;
        let resolved = false;
        try {
          await manager.encryptText('nothing should come back', KAT_PASSWORD);
          resolved = true;
        } catch (err) {
          caught = err;
        }

        // NEGATIVE first: no ciphertext was produced by a chain with no
        // working provider.
        expect(resolved).toBe(false);
        expect(caught).toBeInstanceOf(CryptoError);
        const error = caught as InstanceType<typeof CryptoError>;
        expect(error.type).toBe(CryptoErrorType.MEMORY_ERROR);
        expect(error.code).toBe('ARGON2_NOT_AVAILABLE');

        // The opening sentence is load-bearing text: `README.md` quotes the
        // message byte-for-byte.
        expect(error.message).toContain(FRIENDLY_MESSAGE_FRAGMENT);

        // All three causes are diagnosed, each under its own label, so a
        // reader can tell which link of the chain failed and why.
        expect(error.message).toContain(
          "Native error: Cannot find module 'argon2'"
        );
        expect(error.message).toContain(
          'Node built-in error: `node:crypto` exposes no `argon2` function'
        );
        expect(error.message).toContain(
          "WASM error: Cannot find module 'hash-wasm'"
        );

        // The built-in was genuinely the second link tried, not skipped: the
        // third one was reached, which only happens after the second throws.
        expect(wasm.wasmFactoryCalls).toBe(1);

        // NEGATIVE: the rejection is not cached, so the next caller retries.
        expect(await __peekArgon2ProviderForTesting()).toBeNull();
      });
    } finally {
      __resetArgon2ModuleCacheForTesting();
    }
  });
});
