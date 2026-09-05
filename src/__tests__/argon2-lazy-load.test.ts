/**
 * Tests for the lazy-load behaviour of the `argon2` native dependency
 * (Task 9 + Task 4 + Task 17). These tests simulate the production scenario
 * where the optional `argon2` dependency was either skipped during install
 * (e.g. because the user has no C++ toolchain), fails to load at runtime,
 * or where multiple async calls race for the first load.
 *
 * The lazy-load contract under test:
 *   1. Constructing a CryptoManager and using only sync (PBKDF2) methods
 *      MUST succeed even when neither `argon2` nor `hash-wasm` can be
 *      loaded.
 *   2. The first async (Argon2id) operation triggers loading: native
 *      `argon2` is tried first; if it fails, `hash-wasm` is tried; if both
 *      fail, the call rejects with `CryptoError(MEMORY_ERROR,
 *      'ARGON2_NOT_AVAILABLE')` and an actionable message.
 *   3. (Task 4 in-flight-promise pattern.) Concurrent first-callers
 *      share a single load attempt (no duplicate dynamic imports under
 *      load). On success the resolved hasher is cached forever; on
 *      failure the cache clears so the next caller can retry —
 *      transient failures recover.
 *   4. (Task 17 fallback.) When native fails but `hash-wasm` is
 *      available, the loader falls back to WASM. The two providers
 *      MUST produce bit-identical raw key bytes for identical inputs
 *      (RFC 9106 Argon2id — verified by the parity test below).
 *
 * Implementation notes:
 *   - We use `jest.unstable_mockModule(...)` BEFORE importing
 *     CryptoManager so the mock is in place when the dynamic
 *     `await import('argon2')` / `await import('hash-wasm')` resolves.
 *   - The CryptoManager module is imported via `await import(...)` so
 *     the test runs in jest's ESM mode. Each `describe` block uses
 *     `jest.resetModules()` + a fresh `import()` to make the mock state
 *     observable.
 *   - The exported `__resetArgon2ModuleCacheForTesting` helper wipes the
 *     module-level cache between tests so a previous successful or
 *     failed load doesn't leak into the next test case.
 */
import { jest } from '@jest/globals';

const FRIENDLY_MESSAGE_FRAGMENT =
  'argon2 native module unavailable. Install build tools';

/**
 * Mock factory for `hash-wasm` that throws — used to simulate "neither
 * native nor WASM is available". Many of the existing tests originally
 * only mocked `argon2`; with the Task 17 fallback, those tests now also
 * need to mock `hash-wasm` to keep verifying the "both fail" path. We
 * extract the helper here for readability.
 */
function mockHashWasmUnavailable(): void {
  jest.unstable_mockModule('hash-wasm', () => {
    throw new Error("Cannot find module 'hash-wasm'");
  });
}

describe('argon2 lazy-load (Task 9)', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('does NOT load argon2 at import time (top-level import is lazy)', async () => {
    // Mock argon2 to record load attempts. If the module is loaded
    // eagerly during `import('../crypto-manager')`, the factory fires
    // immediately. If the import is lazy (the contract under test), the
    // factory does not fire until the first async-encryption call.
    const loadProbe = jest.fn(() => ({
      hash: jest.fn(),
      argon2id: 2,
    }));
    jest.unstable_mockModule('argon2', loadProbe);
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    // Just constructing — no async crypto operation yet.
    const cm = new CryptoManager();
    expect(cm).toBeInstanceOf(CryptoManager);

    expect(loadProbe).not.toHaveBeenCalled();
  });

  it('does NOT load argon2 when only sync (PBKDF2) methods are used', async () => {
    const loadProbe = jest.fn(() => ({
      hash: jest.fn(),
      argon2id: 2,
    }));
    jest.unstable_mockModule('argon2', loadProbe);
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    const plaintext = 'hello sync';

    const ciphertext = cm.encryptTextSync(plaintext, password);
    expect(typeof ciphertext).toBe('string');
    expect(cm.decryptTextSync(ciphertext, password)).toBe(plaintext);

    // The full sync round-trip must not have loaded argon2.
    expect(loadProbe).not.toHaveBeenCalled();
  });

  it('loads argon2 lazily on first async deriveKey/encryptText call', async () => {
    const hash = jest.fn(async () =>
      // 32 bytes of constant data so the test is deterministic.
      Buffer.alloc(32, 0xab)
    );
    const loadProbe = jest.fn(() => ({
      hash,
      argon2id: 2,
    }));
    jest.unstable_mockModule('argon2', loadProbe);
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';

    // Before any async call: not loaded.
    expect(loadProbe).not.toHaveBeenCalled();

    const ciphertext = await cm.encryptText('hello async', password);
    expect(typeof ciphertext).toBe('string');

    // After first async call: loaded exactly once.
    expect(loadProbe).toHaveBeenCalledTimes(1);
    expect(hash).toHaveBeenCalled();

    // Second call: still loaded once (cached).
    await cm.encryptText('hello again', password);
    expect(loadProbe).toHaveBeenCalledTimes(1);
  });

  it('throws CryptoError(MEMORY_ERROR, ARGON2_NOT_AVAILABLE) when both argon2 AND hash-wasm cannot be loaded (deriveKey)', async () => {
    // Simulate `MODULE_NOT_FOUND` for BOTH providers — only then does the
    // friendly error fire. After Task 17 the loader's first fallback is
    // hash-wasm, so failing only `argon2` would silently succeed via
    // WASM. To preserve the original "argon2 NOT_AVAILABLE" semantics we
    // must mock both.
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    const salt = cm.generateSecureRandom(32);

    await expect(cm.deriveKey(password, salt)).rejects.toThrow(CryptoError);

    try {
      await cm.deriveKey(password, salt);
      throw new Error('Expected deriveKey to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
      expect(e.message).toContain(FRIENDLY_MESSAGE_FRAGMENT);
      expect(e.message).toContain('PBKDF2');
      // Task 17: error message points users at hash-wasm too.
      expect(e.message).toContain('hash-wasm');
    }
  });

  it('throws CryptoError(MEMORY_ERROR, ARGON2_NOT_AVAILABLE) from encryptText when both providers are missing', async () => {
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';

    try {
      await cm.encryptText('hello', password);
      throw new Error('Expected encryptText to throw ARGON2_NOT_AVAILABLE');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
    }
  });

  it('on failure the cache clears so the next call can retry (Task 4 — transient recovery)', async () => {
    // Task 4: replaces the previous "cache the failure sentinel forever"
    // behaviour. A failed load no longer permanently disables async
    // crypto for the process — the cache slot is cleared on rejection
    // and the NEXT caller starts a fresh import attempt. This lets
    // transient failures (e.g. a temporary FS permission glitch on
    // Windows during a build-tool install) recover within the same
    // process.
    let nativeFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      throw new Error("Cannot find module 'argon2'");
    });
    // Both providers must fail for the cache-clear retry semantics to
    // be observable via deriveKey rejection.
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    const salt = cm.generateSecureRandom(32);

    await expect(cm.deriveKey(password, salt)).rejects.toThrow(
      'argon2 native module unavailable'
    );
    const callsAfterFirst = nativeFactoryCalls;
    expect(callsAfterFirst).toBe(1);

    // Second call: cache was cleared on the previous rejection, so a
    // fresh import attempt happens.
    await expect(cm.deriveKey(password, salt)).rejects.toThrow(
      'argon2 native module unavailable'
    );
    expect(nativeFactoryCalls).toBe(2);

    // Third call: same — every call retries until success.
    await expect(cm.deriveKey(password, salt)).rejects.toThrow(
      'argon2 native module unavailable'
    );
    expect(nativeFactoryCalls).toBe(3);
  });

  it('concurrent first-callers share a single import (Task 4 — coalescing)', async () => {
    // Task 4 in-flight-promise pattern: when multiple async crypto
    // calls race to be the first to need argon2, exactly ONE
    // `import('argon2')` runs. All concurrent callers `await` the same
    // in-flight promise.
    let factoryCalls = 0;
    const hash = jest.fn(async () => Buffer.alloc(32, 0x42));
    jest.unstable_mockModule('argon2', () => {
      factoryCalls += 1;
      return {
        hash,
        argon2id: 2,
      };
    });
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';

    // Fire many parallel deriveKey calls — they should all race to be
    // the first to call loadArgon2(). The in-flight promise pattern
    // means only ONE actual import runs.
    const salts = Array.from({ length: 20 }, () => cm.generateSecureRandom(32));
    const results = await Promise.all(
      salts.map(salt => cm.deriveKey(password, salt))
    );

    // All calls succeed (each gets back a 32-byte buffer).
    expect(results).toHaveLength(20);
    for (const key of results) {
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    }

    // Crucially: only ONE module factory call across all 20 concurrent
    // first-callers.
    expect(factoryCalls).toBe(1);
  });

  it('concurrent first-callers all see the same rejection (Task 4 — failure coalescing)', async () => {
    // Symmetric to the success-coalescing test: when both providers
    // fail, every concurrent first-caller awaiting the in-flight
    // promise sees the same friendly CryptoError. After all concurrent
    // callers have settled, the cache is clear and a NEXT call can
    // attempt a fresh import.
    let nativeFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      throw new Error("Cannot find module 'argon2'");
    });
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';

    // 20 concurrent calls, each expected to reject.
    const salts = Array.from({ length: 20 }, () => cm.generateSecureRandom(32));
    const settled = await Promise.allSettled(
      salts.map(salt => cm.deriveKey(password, salt))
    );

    expect(settled).toHaveLength(20);
    for (const result of settled) {
      expect(result.status).toBe('rejected');
      if (result.status === 'rejected') {
        expect(result.reason).toBeInstanceOf(CryptoError);
        const e = result.reason as InstanceType<typeof CryptoError>;
        expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
        expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
      }
    }

    // Only ONE import attempt for the burst.
    expect(nativeFactoryCalls).toBe(1);

    // ...but a subsequent call retries (cache cleared on rejection).
    await expect(
      cm.deriveKey(password, cm.generateSecureRandom(32))
    ).rejects.toThrow('argon2 native module unavailable');
    expect(nativeFactoryCalls).toBe(2);
  });

  it('first call fails, second call succeeds — transient recovery (Task 4)', async () => {
    // Models the canonical transient-failure scenario: the very first
    // import attempt throws (e.g. ephemeral FS issue), and a subsequent
    // call after the failure ends up actually loading the module
    // successfully. The cache slot must NOT be poisoned; the second
    // call must observe a fresh import that resolves cleanly.
    let factoryCalls = 0;
    const hash = jest.fn(async () => Buffer.alloc(32, 0x99));
    jest.unstable_mockModule('argon2', () => {
      factoryCalls += 1;
      if (factoryCalls === 1) {
        // Simulate a transient failure on the first call only.
        throw new Error('ENOSPC: temporary disk full');
      }
      return {
        hash,
        argon2id: 2,
      };
    });
    // hash-wasm must also fail on the first attempt so the loader
    // surfaces the friendly error rather than silently falling back.
    let wasmFactoryCalls = 0;
    jest.unstable_mockModule('hash-wasm', () => {
      wasmFactoryCalls += 1;
      throw new Error("Cannot find module 'hash-wasm'");
    });

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const { CryptoError } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    const salt = cm.generateSecureRandom(32);

    // First call: native fails, wasm fails, friendly error surfaces.
    await expect(cm.deriveKey(password, salt)).rejects.toThrow(CryptoError);
    expect(factoryCalls).toBe(1);
    expect(wasmFactoryCalls).toBe(1);

    // Second call: cache was cleared on the first rejection, so a fresh
    // import runs. This time the (mocked) native module loads
    // successfully — no need to fall through to wasm.
    const key = await cm.deriveKey(password, salt);
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(key.length).toBe(32);
    expect(factoryCalls).toBe(2);

    // Third call: now uses the cached resolved promise — no further
    // import attempts.
    await cm.deriveKey(password, salt);
    expect(factoryCalls).toBe(2);
  });

  it('sync (PBKDF2) methods still work after a failed argon2 load', async () => {
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    const salt = cm.generateSecureRandom(32);

    // Argon2id path fails as expected:
    await expect(cm.deriveKey(password, salt)).rejects.toThrow(
      'argon2 native module unavailable'
    );

    // ...but the PBKDF2 path is wholly unaffected.
    const plaintext = 'sync still works after argon2 load failure';
    const ciphertext = cm.encryptTextSync(plaintext, password);
    expect(cm.decryptTextSync(ciphertext, password)).toBe(plaintext);

    const key = cm.deriveKeySync(password, salt);
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(key.length).toBe(32);
  });

  it('handles argon2 modules exported as a CJS namespace (no .default property)', async () => {
    // Node's CJS-ESM interop sometimes exposes a CJS module via
    // `import('foo')` as a synthetic namespace whose top-level fields
    // are the named exports and whose `.default` is the same object.
    // Other times (especially for older runtimes / jest) the namespace
    // has the named exports directly without a `.default` field. Our
    // loader must handle both. This test covers the no-.default
    // shape — the loader must fall back to the namespace itself.
    const hash = jest.fn(async () => Buffer.alloc(32, 0x12));
    jest.unstable_mockModule('argon2', () => ({
      hash,
      argon2id: 2,
    }));
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    await cm.encryptText('hi', 'MySecureP@ssw0rd123!');
    expect(hash).toHaveBeenCalled();
  });
});

describe('argon2 fallback: hash-wasm (Task 17)', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('uses native argon2 when both are available (native preferred)', async () => {
    // Both providers mocked as available. The loader must pick native
    // FIRST and never touch hash-wasm; this matches the documented
    // "native preferred for performance" contract.
    const nativeHash = jest.fn(async () => Buffer.alloc(32, 0xa1));
    const wasmArgon2id = jest.fn(async () => new Uint8Array(32).fill(0xb2));
    jest.unstable_mockModule('argon2', () => ({
      hash: nativeHash,
      argon2id: 2,
    }));
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasmArgon2id,
    }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    const ciphertext = await cm.encryptText('hello native', password);
    const decrypted = await cm.decryptText(ciphertext, password);
    expect(decrypted).toBe('hello native');

    // Provider tag confirms native was used.
    const provider = await __peekArgon2ProviderForTesting();
    expect(provider).toBe('native');

    // hash-wasm was never invoked.
    expect(nativeHash).toHaveBeenCalled();
    expect(wasmArgon2id).not.toHaveBeenCalled();
  });

  it('falls back to hash-wasm when native argon2 is unavailable', async () => {
    // Native fails, WASM succeeds. The loader must transparently fall
    // through and the encrypt/decrypt round trip must succeed.
    const wasmArgon2id = jest.fn(async () => new Uint8Array(32).fill(0xc3));
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasmArgon2id,
    }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    const ciphertext = await cm.encryptText('hello wasm', password);
    const decrypted = await cm.decryptText(ciphertext, password);
    expect(decrypted).toBe('hello wasm');

    // Provider tag confirms WASM was used.
    const provider = await __peekArgon2ProviderForTesting();
    expect(provider).toBe('wasm');

    // hash-wasm was invoked twice (encrypt + decrypt) with the same
    // 32-byte raw output target.
    expect(wasmArgon2id).toHaveBeenCalledTimes(2);
    // Verify parameter mapping: hash-wasm gets `iterations` (timeCost),
    // `memorySize` (memoryCost), `parallelism`, and `outputType:
    // 'binary'`.
    const lastCall = wasmArgon2id.mock.calls[0]?.[0] as
      | {
          iterations: number;
          memorySize: number;
          parallelism: number;
          hashLength: number;
          outputType: string;
        }
      | undefined;
    expect(lastCall).toBeDefined();
    if (lastCall !== undefined) {
      expect(lastCall.outputType).toBe('binary');
      expect(lastCall.hashLength).toBe(32);
      expect(typeof lastCall.iterations).toBe('number');
      expect(typeof lastCall.memorySize).toBe('number');
      expect(typeof lastCall.parallelism).toBe('number');
    }
  });

  it('falls back to hash-wasm when hash-wasm exposes a CJS namespace shape (no .default)', async () => {
    // Some module-resolution paths surface hash-wasm via a synthetic
    // namespace whose top-level field IS the named export. Our loader
    // must handle both the `.default`-wrapped and direct shapes — same
    // pattern as the native argon2 normalisation.
    const wasmArgon2id = jest.fn(async () => new Uint8Array(32).fill(0xd4));
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasmArgon2id,
    }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    await cm.encryptText('hi via namespace', password);

    expect(wasmArgon2id).toHaveBeenCalled();
    const provider = await __peekArgon2ProviderForTesting();
    expect(provider).toBe('wasm');
  });

  it('falls back to hash-wasm when hash-wasm exposes a .default-wrapped shape', async () => {
    // Mirror the previous test for the `.default`-wrapped shape that
    // some bundlers / interop shims produce.
    const wasmArgon2id = jest.fn(async () => new Uint8Array(32).fill(0xe5));
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({
      default: {
        argon2id: wasmArgon2id,
      },
    }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';
    await cm.encryptText('hi via .default', password);

    expect(wasmArgon2id).toHaveBeenCalled();
    const provider = await __peekArgon2ProviderForTesting();
    expect(provider).toBe('wasm');
  });

  it('throws ARGON2_NOT_AVAILABLE when BOTH providers fail to load', async () => {
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => {
      throw new Error("Cannot find module 'hash-wasm'");
    });

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';

    try {
      await cm.encryptText('boom', password);
      throw new Error('Expected encryptText to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
      // Friendly message points users at all three fix paths.
      expect(e.message).toContain('argon2 native module unavailable');
      expect(e.message).toContain('hash-wasm');
      expect(e.message).toContain('PBKDF2');
    }
  });

  it('adapter wiring: both provider adapters pass a fixed key through unchanged (mocked)', async () => {
    // SCOPE: this test verifies the ADAPTER WIRING only — that the native
    // and WASM adapters pass parameters through and convert their output to
    // a Buffer identically. Both providers are mocked to return the same
    // fixed constant, so it does NOT exercise a real Argon2id computation
    // and is NOT itself evidence of RFC 9106 parity.
    //
    // The REAL cross-provider parity evidence (unmocked known-answer
    // vectors from the genuine argon2 + hash-wasm installs, and a golden
    // native-produced ciphertext decrypted through the real WASM fallback)
    // lives in `argon2-provider-parity.test.ts` and
    // `argon2-golden-ciphertext.test.ts`.
    //
    // We mock both providers with a fixed output to keep this wiring check
    // deterministic and fast (a real Argon2 derivation at these params
    // would dominate the suite).
    const FIXED_OUTPUT = Buffer.from(
      'e368bb157114953b17017a398bcf20d9a8800227cfdbc5d38eb6564111e8a188',
      'hex'
    );
    const nativeHash = jest.fn(async () => Buffer.from(FIXED_OUTPUT));
    const wasmArgon2id = jest.fn(async () => new Uint8Array(FIXED_OUTPUT));
    jest.unstable_mockModule('argon2', () => ({
      hash: nativeHash,
      argon2id: 2,
    }));
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasmArgon2id,
    }));

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');

    const password = 'MySecureP@ssw0rd123!';
    const salt = Buffer.alloc(32, 0x42);

    // Pass 1: native. Cache + use, then capture the derived key.
    __resetArgon2ModuleCacheForTesting();
    const nativeCm = new CryptoManager({
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
    const nativeKey = await nativeCm.deriveKey(password, salt);

    // Pass 2: simulate native unavailable so the loader falls through
    // to wasm. Reset modules + cache to force a re-import attempt.
    jest.resetModules();
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasmArgon2id,
    }));
    const m2 = await import('../crypto-manager');
    m2.__resetArgon2ModuleCacheForTesting();
    const wasmCm = new m2.CryptoManager({
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
    const wasmKey = await wasmCm.deriveKey(password, salt);

    // Bit-for-bit equality. Any drift here breaks ciphertext
    // round-tripping across native/WASM environments.
    expect(Buffer.compare(nativeKey, wasmKey)).toBe(0);
    expect(nativeKey.equals(FIXED_OUTPUT)).toBe(true);
    expect(wasmKey.equals(FIXED_OUTPUT)).toBe(true);
  });

  it('adapter wiring: a v1 ciphertext round-trips across the two mocked provider adapters', async () => {
    // SCOPE: wiring only. Encrypt with native-mocked, decrypt with
    // WASM-mocked, both producing the same FIXED key — this checks that the
    // parameter mapping and output handling line up across the adapters, not
    // that a real Argon2id computation agrees across providers. The genuine
    // cross-provider decrypt evidence (native-produced ciphertext through the
    // real WASM fallback) lives in `argon2-golden-ciphertext.test.ts`; the
    // real known-answer vectors live in `argon2-provider-parity.test.ts`.
    // If the parameter mapping or output handling drifts, this test fails.
    const FIXED_KEY = Buffer.alloc(32, 0xa5);
    const nativeHash = jest.fn(async () => Buffer.from(FIXED_KEY));
    const wasmArgon2id = jest.fn(async () => new Uint8Array(FIXED_KEY));

    // Pass 1: native encrypt.
    jest.unstable_mockModule('argon2', () => ({
      hash: nativeHash,
      argon2id: 2,
    }));
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasmArgon2id,
    }));
    const m1 = await import('../crypto-manager');
    m1.__resetArgon2ModuleCacheForTesting();
    const cm1 = new m1.CryptoManager();
    const ciphertext = await cm1.encryptText(
      'cross-runtime hello',
      'MySecureP@ssw0rd123!'
    );

    // Pass 2: simulate native unavailable so wasm runs decryption.
    jest.resetModules();
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasmArgon2id,
    }));
    const m2 = await import('../crypto-manager');
    m2.__resetArgon2ModuleCacheForTesting();
    const cm2 = new m2.CryptoManager();
    const decrypted = await cm2.decryptText(ciphertext, 'MySecureP@ssw0rd123!');

    expect(decrypted).toBe('cross-runtime hello');
  });
});

describe('ARGON2_NOT_AVAILABLE passes through the decrypt-path KDF remap (Task 1.2d)', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('decryptText surfaces MEMORY_ERROR / ARGON2_NOT_AVAILABLE, NOT DECRYPTION_FAILED', async () => {
    // The decrypt-path remap re-types ONLY derivation-failure CryptoErrors
    // (ENCRYPTION_FAILED + KEY_DERIVATION_FAILED). ARGON2_NOT_AVAILABLE is a
    // MEMORY_ERROR raised when neither provider can load, and it must reach
    // the caller untouched. We craft a well-formed v1 Argon2id blob so the
    // decrypt path reaches key derivation (which fails on the missing
    // provider) BEFORE any GCM work — no real KDF output is required.
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    mockHashWasmUnavailable();

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    const { packHeader, KDF_ID_ARGON2ID } = await import('../format');
    __resetArgon2ModuleCacheForTesting();

    // [header][salt: 32][iv: 12][tag: 16][ciphertext] — the text wire layout.
    // memoryCost 4096 clears the DoS caps and the RFC 9106 8×parallelism floor.
    const header = packHeader(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 4096,
      timeCost: 2,
      parallelism: 1,
    });
    const salt = Buffer.alloc(32, 0x11);
    const iv = Buffer.alloc(12, 0x22);
    const tag = Buffer.alloc(16, 0x33);
    const body = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const blob = Buffer.concat([header, salt, iv, tag, body]).toString(
      'base64url'
    );

    const cm = new CryptoManager();
    const password = 'MySecureP@ssw0rd123!';

    try {
      await cm.decryptText(blob, password);
      throw new Error('Expected decryptText to throw ARGON2_NOT_AVAILABLE');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
      // Explicitly assert it was NOT remapped to a decryption error.
      expect(e.type).not.toBe(CryptoErrorType.DECRYPTION_FAILED);
    }
  });
});

/**
 * Phase 7 — CJS/ESM interop of BOTH optional providers, and the guarantee that
 * a rejected load is never retained in the module-level cache.
 *
 * `engine.node.ts` reaches `argon2` and `hash-wasm` through lazy dynamic
 * `import()`s, and the shape of the resulting namespace is decided by the
 * consumer's runtime and bundler, not by us: a CJS package may surface its API
 * on the namespace itself, or under `.default`, depending on the interop layer
 * in play. Each shape is a separate normalisation branch, and the installed
 * packages only ever exhibit ONE of them — so a module mock is the only way to
 * exercise the others. That mock is the ONLY fake here; the loader, the
 * adapters and `CryptoManager` are all real.
 *
 * SCOPE, stated as bluntly as the sibling "adapter wiring" tests do: with both
 * providers mocked to return a fixed constant, these cases pin the ADAPTER —
 * namespace normalisation, parameter mapping, `Buffer` conversion, the provider
 * tag, and the native-before-WASM ordering. They are NOT evidence of RFC 9106
 * parity; that lives in `argon2-provider-parity.test.ts` (real known-answer
 * vectors) and `argon2-golden-ciphertext.test.ts` (a native-produced golden
 * decrypted through the real WASM fallback).
 */
describe('provider module-shape normalisation + rejected-cache retry (Phase 7)', () => {
  /**
   * The fixed 32-byte "derived key" both mocked providers return. Pinned as hex
   * so an adapter that truncates, re-encodes, or swaps byte order goes red on
   * the exact bytes rather than merely on a length check.
   */
  const PINNED_KEY_HEX =
    '0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdeffedcba9876543210';
  const PINNED_KEY = Buffer.from(PINNED_KEY_HEX, 'hex');

  /** Cheap, explicit KDF params so every mapping assertion is exact. */
  const COST = { memoryCost: 4096, timeCost: 2, parallelism: 1 } as const;
  const PASSWORD = 'MySecureP@ssw0rd123!';
  const SALT = Buffer.alloc(32, 0x5a);

  /** Exact option bag `engine.node.ts` hands to the native `argon2.hash`. */
  type NativeHashOptions = {
    type: number;
    memoryCost: number;
    timeCost: number;
    parallelism: number;
    hashLength: number;
    salt: Buffer;
    raw: true;
  };

  /** Exact option bag `engine.node.ts` hands to `hash-wasm`'s `argon2id`. */
  type WasmArgon2idOptions = {
    password: string;
    salt: Buffer;
    iterations: number;
    parallelism: number;
    memorySize: number;
    hashLength: number;
    outputType: 'binary';
  };

  /** A native `hash` that records its arguments and returns {@link PINNED_KEY}. */
  function recordingNativeHash(): {
    hash: (password: string, options: NativeHashOptions) => Promise<Buffer>;
    calls: Array<{ password: string; options: NativeHashOptions }>;
  } {
    const calls: Array<{ password: string; options: NativeHashOptions }> = [];
    const hash = async (
      password: string,
      options: NativeHashOptions
    ): Promise<Buffer> => {
      calls.push({ password, options: { ...options } });
      return Buffer.from(PINNED_KEY);
    };
    return { hash, calls };
  }

  /** A `hash-wasm` `argon2id` that records its arguments and returns {@link PINNED_KEY}. */
  function recordingWasmArgon2id(): {
    argon2id: (options: WasmArgon2idOptions) => Promise<Uint8Array>;
    calls: WasmArgon2idOptions[];
  } {
    const calls: WasmArgon2idOptions[] = [];
    const argon2id = async (
      options: WasmArgon2idOptions
    ): Promise<Uint8Array> => {
      calls.push({ ...options });
      return new Uint8Array(PINNED_KEY);
    };
    return { argon2id, calls };
  }

  /** Assert the native adapter mapped every field onto the `argon2` option names. */
  function expectNativeMapping(options: NativeHashOptions): void {
    // Argon2id variant id, hardcoded so constructing a manager never loads the
    // native module.
    expect(options.type).toBe(2);
    expect(options.memoryCost).toBe(COST.memoryCost);
    expect(options.timeCost).toBe(COST.timeCost);
    expect(options.parallelism).toBe(COST.parallelism);
    expect(options.hashLength).toBe(32);
    expect(options.raw).toBe(true);
    expect(Buffer.isBuffer(options.salt)).toBe(true);
    expect(options.salt.equals(SALT)).toBe(true);
  }

  /** Assert the WASM adapter mapped every field onto the `hash-wasm` option names. */
  function expectWasmMapping(options: WasmArgon2idOptions): void {
    expect(options.password).toBe(PASSWORD);
    expect(options.memorySize).toBe(COST.memoryCost);
    expect(options.iterations).toBe(COST.timeCost);
    expect(options.parallelism).toBe(COST.parallelism);
    expect(options.hashLength).toBe(32);
    expect(options.outputType).toBe('binary');
    expect(Buffer.from(options.salt).equals(SALT)).toBe(true);
  }

  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('normalises a native `argon2` that ships its API under `.default`', async () => {
    // The CJS-through-ESM interop shape: the whole module object hangs off
    // `.default` and the namespace itself has no `hash`. The loader must unwrap
    // it; without the unwrap the adapter would call `undefined` and the load
    // would fall through to WASM.
    const native = recordingNativeHash();
    let wasmFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => ({
      default: { hash: native.hash },
    }));
    jest.unstable_mockModule('hash-wasm', () => {
      wasmFactoryCalls += 1;
      return { argon2id: recordingWasmArgon2id().argon2id };
    });

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    expect(await __peekArgon2ProviderForTesting()).toBe('native');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(native.calls.length).toBe(1);
    const call = native.calls[0];
    expect(call).toBeDefined();
    if (call !== undefined) {
      expect(call.password).toBe(PASSWORD);
      expectNativeMapping(call.options);
    }
    // NEGATIVE: native succeeded, so the WASM module must never be imported.
    expect(wasmFactoryCalls).toBe(0);
  });

  it('normalises a native `argon2` that ships its API on the namespace', async () => {
    // The other legitimate shape: named exports directly on the namespace, no
    // `.default` at all. Same provider tag, same derived bytes, same mapping.
    const native = recordingNativeHash();
    let wasmFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => ({ hash: native.hash }));
    jest.unstable_mockModule('hash-wasm', () => {
      wasmFactoryCalls += 1;
      return { argon2id: recordingWasmArgon2id().argon2id };
    });

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    expect(await __peekArgon2ProviderForTesting()).toBe('native');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(native.calls.length).toBe(1);
    const call = native.calls[0];
    expect(call).toBeDefined();
    if (call !== undefined) expectNativeMapping(call.options);
    expect(wasmFactoryCalls).toBe(0);
  });

  it('falls back to a namespace-shaped `hash-wasm`, having tried native FIRST', async () => {
    const wasm = recordingWasmArgon2id();
    let nativeFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({ argon2id: wasm.argon2id }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    // Ordering is part of the contract: native is preferred for performance, so
    // it must be ATTEMPTED even on a host where it cannot load.
    expect(nativeFactoryCalls).toBe(1);
    expect(await __peekArgon2ProviderForTesting()).toBe('wasm');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(wasm.calls.length).toBe(1);
    const call = wasm.calls[0];
    expect(call).toBeDefined();
    if (call !== undefined) expectWasmMapping(call);
  });

  it('falls back to a `.default`-wrapped `hash-wasm`, having tried native FIRST', async () => {
    const wasm = recordingWasmArgon2id();
    let nativeFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({
      default: { argon2id: wasm.argon2id },
    }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    expect(nativeFactoryCalls).toBe(1);
    expect(await __peekArgon2ProviderForTesting()).toBe('wasm');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(wasm.calls.length).toBe(1);
    const call = wasm.calls[0];
    expect(call).toBeDefined();
    if (call !== undefined) expectWasmMapping(call);
  });

  it('prefers the namespace `argon2id` when `.default.argon2id` is not callable', async () => {
    // A namespace can legitimately carry BOTH a usable named export and a
    // `.default` that is a re-export shim rather than the module object. The
    // WASM normalisation is therefore a `typeof … === 'function'` test on
    // `.default.argon2id`, not a truthiness test on `.default`: preferring the
    // truthy-but-useless `.default` here would call `undefined` and blow up.
    const wasm = recordingWasmArgon2id();
    let nativeFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: wasm.argon2id,
      default: { argon2id: 'not-a-function' },
    }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    expect(nativeFactoryCalls).toBe(1);
    expect(await __peekArgon2ProviderForTesting()).toBe('wasm');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    // NEGATIVE: the useless `.default` was never taken — the real function ran
    // exactly once and no "is not a function" TypeError surfaced.
    expect(wasm.calls.length).toBe(1);
  });

  it('never caches a rejected load: a later attempt can resolve to a DIFFERENT provider', async () => {
    // The cache slot holds the in-flight promise so concurrent first-callers
    // coalesce, and clears it on rejection so a transient failure does not
    // disable async crypto for the process lifetime. Here the SECOND attempt
    // succeeds through a different provider than the first attempt reached,
    // which is only possible if the rejected promise was genuinely discarded.
    //
    // This case deliberately does NOT call `jest.resetModules()` between the
    // attempts — that would wipe the module-scope cache that IS the subject —
    // so it relies on a jest behaviour worth naming: a mock factory that THROWS
    // is re-invoked on a subsequent `import()` within the same registry, which
    // is what lets the factory-call counters below distinguish a fresh attempt
    // from a cached one. If a future jest release memoises a throwing factory,
    // this test breaks on the counters rather than on the contract.
    const wasm = recordingWasmArgon2id();
    let nativeFactoryCalls = 0;
    let wasmFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => {
      wasmFactoryCalls += 1;
      if (wasmFactoryCalls === 1) {
        throw new Error('EACCES: transient permission error');
      }
      return { argon2id: wasm.argon2id };
    });

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);

    // Attempt 1: both providers fail.
    try {
      await cm.deriveKey(PASSWORD, SALT);
      throw new Error('Expected the first deriveKey to reject');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
    }
    expect(nativeFactoryCalls).toBe(1);
    expect(wasmFactoryCalls).toBe(1);
    // No provider is reported. On its own this cannot distinguish an empty
    // cache from a cached rejection (the peek hook maps both to `null`); what
    // proves the slot was actually cleared is attempt 2 below, which observes a
    // FRESH pair of imports.
    expect(await __peekArgon2ProviderForTesting()).toBeNull();

    // Attempt 2: fresh imports; native still fails, WASM now loads.
    const key = await cm.deriveKey(PASSWORD, SALT);
    expect(nativeFactoryCalls).toBe(2);
    expect(wasmFactoryCalls).toBe(2);
    expect(await __peekArgon2ProviderForTesting()).toBe('wasm');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);

    // Attempt 3: NEGATIVE — a resolved load is cached forever, so no further
    // import of either provider happens.
    const key2 = await cm.deriveKey(PASSWORD, SALT);
    expect(key2.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(nativeFactoryCalls).toBe(2);
    expect(wasmFactoryCalls).toBe(2);
    expect(wasm.calls.length).toBe(2);
  });

  it('reports no provider while an in-flight load is on its way to rejecting', async () => {
    // `__peekArgon2ProviderForTesting` reads the cache slot synchronously, so
    // it can observe the still-pending promise of a load that is about to fail.
    // It must resolve to `null` rather than rejecting — otherwise every test
    // that inspects the provider after a failure would blow up with an
    // unhandled rejection instead of reporting "nothing cached".
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    mockHashWasmUnavailable();

    const { loadArgon2, __resetArgon2ModuleCacheForTesting } =
      await import('../engine.node');
    const { __peekArgon2ProviderForTesting } =
      await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    // Start the load WITHOUT awaiting it; the cache slot now holds the pending
    // promise. Peek reads that slot before the loader clears it.
    const loading = loadArgon2();
    const peeked = __peekArgon2ProviderForTesting();

    await expect(loading).rejects.toThrow(FRIENDLY_MESSAGE_FRAGMENT);
    await expect(peeked).resolves.toBeNull();
  });

  // ---------------------------------------------------------------------------
  // A module that LOADS but exposes no callable hasher.
  //
  // Both loaders exist to cope with non-standard module shapes, and until now
  // only ONE of them checked that the shape it picked was actually usable.
  // `importNativeArgon2` preferred `.default` on bare truthiness, so a namespace
  // like `{ hash: fn, default: {} }` resolved the EMPTY object, tagged it
  // `provider: 'native'`, and `loadArgon2` cached that resolved promise for the
  // lifetime of the process. Every later call then threw
  // `CryptoError(ENCRYPTION_FAILED, 'KEY_DERIVATION_FAILED')` with the internal
  // text "resolved.hash is not a function" — and `hash-wasm` was never tried,
  // even when installed and working.
  //
  // The contract these tests pin: a loader picks a candidate only when its
  // entry point is callable, and THROWS when neither candidate is, so
  // `importArgon2Hasher`'s existing try/catch falls through to the next
  // provider and — if that also fails — names both causes in one
  // `ARGON2_NOT_AVAILABLE`. That is what `engine.web.ts`'s `loadArgon2id`
  // already did; these tests make the two engines agree.
  // ---------------------------------------------------------------------------

  it('prefers the namespace `hash` when `.default` is present but exposes no callable `hash`', async () => {
    // `{ hash: fn, default: {} }` — the shape that used to resolve the empty
    // `.default` and poison the cache. `.default` is still preferred whenever
    // it IS usable, which is what the next test pins, so this changes nothing
    // for the real, CJS-shaped `argon2` package.
    const native = recordingNativeHash();
    let wasmFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => ({
      hash: native.hash,
      default: {},
    }));
    jest.unstable_mockModule('hash-wasm', () => {
      wasmFactoryCalls += 1;
      return { argon2id: recordingWasmArgon2id().argon2id };
    });

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    expect(await __peekArgon2ProviderForTesting()).toBe('native');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(native.calls.length).toBe(1);
    const call = native.calls[0];
    expect(call).toBeDefined();
    if (call !== undefined) {
      expect(call.password).toBe(PASSWORD);
      expectNativeMapping(call.options);
    }
    // NEGATIVE: the usable native hasher was found, so WASM was never imported.
    expect(wasmFactoryCalls).toBe(0);
  });

  it('keeps `.default` ahead of the namespace when BOTH expose a callable `hash`', async () => {
    // Ordering is a contract, not an accident. The real `argon2` is CJS, so
    // Node's interop hangs the module object off `.default` AND copies its
    // named exports onto the namespace — both candidates are callable there.
    // `.default` IS the module object, so it must keep winning; selecting the
    // namespace instead would silently change which object the adapter calls
    // on the genuine package. Without this test the two orderings are
    // indistinguishable (every other mock here supplies only one candidate).
    const NAMESPACE_KEY_HEX =
      'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const fromDefault = recordingNativeHash();
    const namespaceCalls: string[] = [];
    // Only `password` is needed to tell the two candidates apart, so the
    // options bag is deliberately not declared (the project lints unused
    // parameters as errors and a suppression is not an option here).
    const namespaceHash = async (password: string): Promise<Buffer> => {
      namespaceCalls.push(password);
      return Buffer.from(NAMESPACE_KEY_HEX, 'hex');
    };
    jest.unstable_mockModule('argon2', () => ({
      hash: namespaceHash,
      default: { hash: fromDefault.hash },
    }));
    mockHashWasmUnavailable();

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    expect(await __peekArgon2ProviderForTesting()).toBe('native');
    // The two candidates return DIFFERENT bytes, so the key itself says which
    // one ran — `.default` did.
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(fromDefault.calls.length).toBe(1);
    // NEGATIVE: the namespace `hash` was never called, and its bytes never
    // reached the caller.
    expect(namespaceCalls).toEqual([]);
    expect(key.toString('hex')).not.toBe(NAMESPACE_KEY_HEX);
  });

  it('falls through to hash-wasm when `argon2` resolves to a `.default` with no callable `hash`', async () => {
    // Nothing in this namespace can hash. The load must FAIL rather than
    // resolve an uncallable hasher, so the WASM fallback gets its turn — the
    // whole point of having a fallback.
    const wasm = recordingWasmArgon2id();
    let nativeFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      return { default: {} };
    });
    jest.unstable_mockModule('hash-wasm', () => ({ argon2id: wasm.argon2id }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    // Native was ATTEMPTED (ordering is part of the contract) and rejected.
    expect(nativeFactoryCalls).toBe(1);
    // NEGATIVE: the cache does NOT hold a broken 'native' hasher.
    expect(await __peekArgon2ProviderForTesting()).toBe('wasm');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(wasm.calls.length).toBe(1);
    const call = wasm.calls[0];
    expect(call).toBeDefined();
    if (call !== undefined) expectWasmMapping(call);
  });

  it('falls through to hash-wasm when `argon2` resolves to a namespace with no `hash` at all', async () => {
    // The `.default`-less variant of the same defect: `'default' in mod` was
    // false, so the empty namespace itself was resolved and tagged 'native'.
    const wasm = recordingWasmArgon2id();
    let nativeFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      nativeFactoryCalls += 1;
      return {};
    });
    jest.unstable_mockModule('hash-wasm', () => ({ argon2id: wasm.argon2id }));

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);
    const key = await cm.deriveKey(PASSWORD, SALT);

    expect(nativeFactoryCalls).toBe(1);
    expect(await __peekArgon2ProviderForTesting()).toBe('wasm');
    expect(key.toString('hex')).toBe(PINNED_KEY_HEX);
    expect(wasm.calls.length).toBe(1);
    const call = wasm.calls[0];
    expect(call).toBeDefined();
    if (call !== undefined) expectWasmMapping(call);
  });

  it('reports ARGON2_NOT_AVAILABLE, not KEY_DERIVATION_FAILED, when `hash-wasm` exposes no callable `argon2id`', async () => {
    // The mirror case, and the one that made the two engines disagree: for the
    // identical module shape `engine.web.ts` reported the actionable
    // MEMORY_ERROR / ARGON2_NOT_AVAILABLE while the Node engine reported
    // ENCRYPTION_FAILED / KEY_DERIVATION_FAILED with an internal variable name
    // in the message. They must now agree.
    let wasmFactoryCalls = 0;
    jest.unstable_mockModule('argon2', () => {
      throw new Error("Cannot find module 'argon2'");
    });
    jest.unstable_mockModule('hash-wasm', () => {
      wasmFactoryCalls += 1;
      return { default: {} };
    });

    const {
      CryptoManager,
      __resetArgon2ModuleCacheForTesting,
      __peekArgon2ProviderForTesting,
    } = await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);

    let caught: unknown;
    let resolved = false;
    try {
      await cm.deriveKey(PASSWORD, SALT);
      resolved = true;
    } catch (err) {
      caught = err;
    }
    // The thing that must NOT have happened: a key came back from a hasher
    // that cannot hash.
    expect(resolved).toBe(false);
    expect(caught).toBeInstanceOf(CryptoError);
    const error = caught as InstanceType<typeof CryptoError>;
    expect(error.type).toBe(CryptoErrorType.MEMORY_ERROR);
    expect(error.code).toBe('ARGON2_NOT_AVAILABLE');
    // NEGATIVE: not the misleading call-time failure this used to surface.
    expect(error.code).not.toBe('KEY_DERIVATION_FAILED');
    expect(error.message).not.toContain('is not a function');
    // The composed message names the WASM cause in the engine-web wording.
    expect(error.message).toContain(
      '`hash-wasm` loaded but exposes no `argon2id` export'
    );
    expect(wasmFactoryCalls).toBe(1);
    // A rejected load is never cached.
    expect(await __peekArgon2ProviderForTesting()).toBeNull();
  });

  it('names BOTH uncallable providers in one ARGON2_NOT_AVAILABLE', async () => {
    // Neither module is missing — both load and both are useless. The friendly
    // error must still be the actionable one, and must carry both diagnoses so
    // the reader can tell "not installed" from "installed but broken".
    jest.unstable_mockModule('argon2', () => ({}));
    jest.unstable_mockModule('hash-wasm', () => ({}));

    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');
    __resetArgon2ModuleCacheForTesting();

    const cm = new CryptoManager(COST);

    let caught: unknown;
    let resolved = false;
    try {
      await cm.encryptText('both providers are hollow', PASSWORD);
      resolved = true;
    } catch (err) {
      caught = err;
    }
    expect(resolved).toBe(false);
    expect(caught).toBeInstanceOf(CryptoError);
    const error = caught as InstanceType<typeof CryptoError>;
    expect(error.type).toBe(CryptoErrorType.MEMORY_ERROR);
    expect(error.code).toBe('ARGON2_NOT_AVAILABLE');
    expect(error.message).toContain(
      '`argon2` loaded but exposes no `hash` function'
    );
    expect(error.message).toContain(
      '`hash-wasm` loaded but exposes no `argon2id` export'
    );
    // The actionable guidance is still there.
    expect(error.message).toContain(FRIENDLY_MESSAGE_FRAGMENT);
    expect(error.message).toContain('PBKDF2');
  });
});
