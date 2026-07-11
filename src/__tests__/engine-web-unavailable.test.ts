/**
 * Web engine `ARGON2_NOT_AVAILABLE` failure-path test (Phase 5).
 *
 * Verifies the documented contract: when `hash-wasm` cannot be imported, the
 * Web engine's `deriveArgon2id` rejects with
 * `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` — the exact code AND type
 * the Node engine throws when neither Argon2 provider is available — so the
 * shared core's error handling is identical across runtimes. A CALL-time WASM
 * failure is deliberately NOT remapped here (it propagates for the core to wrap
 * as `KEY_DERIVATION_FAILED`); this test covers only the IMPORT-failure path.
 *
 * Mocking notes (mirrors `argon2-lazy-load.test.ts`):
 *   - `jest.unstable_mockModule('hash-wasm', …)` is registered BEFORE the
 *     dynamic `import('../engine.web')`, so the engine's lazy
 *     `import('hash-wasm')` resolves to the failing mock.
 *   - `CryptoError`/`CryptoErrorType` are dynamically imported from `../types`
 *     AFTER `jest.resetModules()` so the `instanceof` check compares against the
 *     SAME module instance the freshly-imported engine throws.
 *   - Registering a module mock makes this file order-sensitive, so it lives in
 *     its own file, away from the real-provider `engine-web.test.ts`.
 *
 * Run via `npm test` (sets `NODE_OPTIONS=--experimental-vm-modules`); a bare
 * `npx jest` breaks the ESM-mock loader.
 */
import { jest } from '@jest/globals';

const SALT = new Uint8Array(32);
const PARAMS = {
  memoryCost: 4096,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
} as const;

describe('webEngine.deriveArgon2id when hash-wasm is unavailable', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('rejects with CryptoError(MEMORY_ERROR, ARGON2_NOT_AVAILABLE) on import failure', async () => {
    jest.unstable_mockModule('hash-wasm', () => {
      throw new Error("Cannot find module 'hash-wasm'");
    });

    const { webEngine } = await import('../engine.web');
    const { CryptoError, CryptoErrorType } = await import('../types');

    await expect(
      webEngine.deriveArgon2id('MySecureP@ssw0rd123!', SALT, PARAMS)
    ).rejects.toThrow(CryptoError);

    try {
      await webEngine.deriveArgon2id('MySecureP@ssw0rd123!', SALT, PARAMS);
      throw new Error('Expected deriveArgon2id to reject');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
      // Actionable message points users at the fix (install/bundle hash-wasm).
      expect(e.message).toContain('hash-wasm');
    }
  });
});
