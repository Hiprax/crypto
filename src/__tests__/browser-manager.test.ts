/**
 * Browser `CryptoManager` tests (Phase 6 — browser-entry), run under Node 22+.
 *
 * The browser manager (`src/crypto-manager.browser.ts`) injects the Web engine
 * (SubtleCrypto + hash-wasm), which is fully exercisable in Node 22+ (it exposes
 * `globalThis.crypto` and can load the same pure-WASM `hash-wasm`), so these run
 * WITHOUT a real browser. The real-headless-Chromium suite arrives in Phase 9;
 * the cross-runtime Node↔browser interop lives in Phase 8. This file verifies
 * the browser build in isolation:
 *
 *   1. The inherited isomorphic API round-trips (`encryptBytes`/`decryptBytes`
 *      and `encryptText`/`decryptText`) over the Web engine, and the output is
 *      the shared v1 wire format (magic header, Argon2id, embedded params).
 *   2. The browser default is the lighter 32 MiB Argon2id profile, classified
 *      as `MEDIUM` by `getSecurityLevel()`.
 *   3. Every Node-only method is a throwing stub → `UNSUPPORTED_IN_BROWSER`.
 *   4. Constructor option-validation (shared with the Node build via
 *      `CryptoCore`) is byte-for-byte identical, including the weak
 *      `defaultPassphrase` → `WEAK_PASSWORD` rejection.
 *
 * Availability gating (Core Principle 4): `hash-wasm` is an optional dependency.
 * The crypto round-trips use the "probe IS the call" pattern — if hash-wasm
 * genuinely cannot load, `deriveArgon2id` throws `ARGON2_NOT_AVAILABLE` and the
 * test SKIPS (logged) rather than fails. The default/level, stub-throw, and
 * constructor-validation tests need no KDF and always run.
 */
import { describe, it, expect } from '@jest/globals';
import {
  CryptoManager,
  SECURITY_THRESHOLDS,
  isValidPassword,
} from '../crypto-manager.browser';
import { CryptoError, CryptoErrorType, SecurityLevel } from '../types';
import { utf8Encode, utf8Decode, bytesToHex } from '../codec';
import { FORMAT_VERSION, KDF_ID_ARGON2ID, HEADER_LENGTH } from '../format-core';

// Test-only low-cost Argon2id profile so many hash-wasm derivations stay cheap
// while still exercising the REAL KDF path. Never lower production parameters
// this far — the browser production default is 32 MiB (see the level tests).
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

// A 20+ character passphrase (passes the NIST passphrase acceptance rule) and a
// distinct wrong one for the negative-path assertion.
const PASSWORD = 'correct horse battery staple';
const WRONG_PASSWORD = 'incorrect zebra piano lantern';

/** True when an error is the documented "Argon2id unavailable" graceful state. */
function isArgon2Unavailable(err: unknown): boolean {
  return (
    err instanceof CryptoError &&
    (err as InstanceType<typeof CryptoError>).code === 'ARGON2_NOT_AVAILABLE'
  );
}

/**
 * Handle an Argon2id-unavailable error at a test's catch site. Any OTHER error
 * propagates. In CI the optional `hash-wasm` dependency MUST be installed (the
 * browser build's Argon2id has no native fallback), so a missing provider is a
 * hard failure rather than a silent skip; on a genuinely-unsupported local dev
 * host we log a graceful skip and the caller `return`s. Mirrors the CI guard in
 * interop/property-bytes/container/engine-web.
 */
function skipOrThrowArgon2Unavailable(err: unknown, context: string): void {
  if (!isArgon2Unavailable(err)) throw err;
  if (process.env.CI) {
    throw new Error(
      `hash-wasm Argon2id failed to load in CI; ${context} cannot be silently ` +
        `skipped. Ensure the optional hash-wasm dependency is installed.`,
      { cause: err }
    );
  }
  // eslint-disable-next-line no-console
  console.warn(
    `[skip] hash-wasm Argon2id unavailable; ${context} skipped: ${String(err)}`
  );
}

/** Deterministic-but-varied filler bytes for a given length. */
function fillerBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = (i * 31 + 7) & 0xff;
  }
  return out;
}

/**
 * Assert that a synchronous call throws the browser build's Node-only rejection:
 * `CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER')`.
 */
function expectUnsupported(thunk: () => unknown): void {
  let thrown: unknown;
  try {
    thunk();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(CryptoError);
  const e = thrown as InstanceType<typeof CryptoError>;
  expect(e.type).toBe(CryptoErrorType.INVALID_INPUT);
  expect(e.code).toBe('UNSUPPORTED_IN_BROWSER');
  // The message must point callers at the supported in-memory API.
  expect(e.message).toMatch(/encryptBytes|decryptBytes|encryptText/);
}

/**
 * Async counterpart of {@link expectUnsupported} for the `Promise`-typed
 * Node-only methods (`deriveKey`, `encryptFile`, `decryptFile`), which REJECT
 * (rather than throw synchronously) so `.catch()`/`await` behave as they do on
 * the Node build.
 */
async function expectUnsupportedAsync(
  invoke: () => Promise<unknown>
): Promise<void> {
  let thrown: unknown;
  try {
    await invoke();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(CryptoError);
  const e = thrown as InstanceType<typeof CryptoError>;
  expect(e.type).toBe(CryptoErrorType.INVALID_INPUT);
  expect(e.code).toBe('UNSUPPORTED_IN_BROWSER');
  expect(e.message).toMatch(/encryptBytes|decryptBytes|encryptText/);
}

describe('browser CryptoManager — isomorphic round-trip (Web engine)', () => {
  const cm = new CryptoManager(LOW_COST);

  it('encryptBytes/decryptBytes round-trips across edge sizes', async () => {
    const sizes = [0, 1, 15, 16, 17, 1024];
    try {
      for (const size of sizes) {
        const data = fillerBytes(size);
        const ciphertext = await cm.encryptBytes(data, PASSWORD);
        // Output is the shared v1 wire format: magic header up front.
        expect(ciphertext.length).toBeGreaterThanOrEqual(HEADER_LENGTH);
        const back = await cm.decryptBytes(ciphertext, PASSWORD);
        expect(bytesToHex(back)).toBe(bytesToHex(data));
      }
    } catch (err) {
      skipOrThrowArgon2Unavailable(err, 'browser byte round-trip');
      return;
    }
  }, 30000);

  it('encryptText/decryptText round-trips ASCII, Unicode, and the empty string', async () => {
    const samples = ['', 'hello world', 'café — 日本語 — 🔐 mixed unicode'];
    try {
      for (const text of samples) {
        const ciphertext = await cm.encryptText(text, PASSWORD);
        expect(typeof ciphertext).toBe('string');
        const back = await cm.decryptText(ciphertext, PASSWORD);
        expect(back).toBe(text);
      }
    } catch (err) {
      skipOrThrowArgon2Unavailable(err, 'browser text round-trip');
      return;
    }
  }, 30000);

  it('produces a v1 Argon2id header that embeds the instance KDF params', async () => {
    try {
      const ciphertext = await cm.encryptText('inspect me', PASSWORD);
      const header = cm.inspectHeader(ciphertext);
      expect(header).not.toBeNull();
      // Non-null asserted above.
      const parsed = header as NonNullable<typeof header>;
      expect(parsed.version).toBe(FORMAT_VERSION);
      expect(parsed.kdfId).toBe(KDF_ID_ARGON2ID);
      expect(parsed.headerLen).toBe(HEADER_LENGTH);
      expect(parsed.params.kind).toBe('argon2id');
      if (parsed.params.kind === 'argon2id') {
        expect(parsed.params.memoryCost).toBe(LOW_COST.memoryCost);
        expect(parsed.params.timeCost).toBe(LOW_COST.timeCost);
        expect(parsed.params.parallelism).toBe(LOW_COST.parallelism);
      }
    } catch (err) {
      skipOrThrowArgon2Unavailable(err, 'browser header shape');
      return;
    }
  }, 30000);

  it('fails to decrypt under the wrong password (generic DECRYPTION_FAILED)', async () => {
    let ciphertext: string;
    try {
      ciphertext = await cm.encryptText('secret', PASSWORD);
    } catch (err) {
      skipOrThrowArgon2Unavailable(err, 'browser wrong-password');
      return;
    }
    await expect(cm.decryptText(ciphertext, WRONG_PASSWORD)).rejects.toThrow(
      CryptoError
    );
  }, 30000);
});

describe('browser CryptoManager — 32 MiB default → MEDIUM security level', () => {
  it('defaults Argon2id to the 32 MiB browser profile', () => {
    const cm = new CryptoManager();
    const params = cm.getParameters();
    expect(params.argon2Options.memoryCost).toBe(2 ** 15); // 32 MiB
    expect(params.argon2Options.timeCost).toBe(3);
    expect(params.argon2Options.parallelism).toBe(1);
    // Argon2id numeric type identifier (matches native `argon2id === 2`).
    expect(params.argon2Options.type).toBe(2);
    expect(params.algorithm).toBe('aes-256-gcm');
  });

  it('classifies the default configuration as MEDIUM', () => {
    const cm = new CryptoManager();
    // 32 MiB is below the HIGH 128 MiB threshold, so the honest classification
    // is MEDIUM — the browser trades memory for mobile reliability.
    expect(cm.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
  });

  it('re-exports SECURITY_THRESHOLDS and isValidPassword unchanged', () => {
    expect(SECURITY_THRESHOLDS.HIGH.memoryCost).toBe(2 ** 17);
    expect(SECURITY_THRESHOLDS.ULTRA.memoryCost).toBe(2 ** 19);
    expect(SECURITY_THRESHOLDS.MEDIUM.memoryCost).toBe(2 ** 14);
    expect(Object.isFrozen(SECURITY_THRESHOLDS)).toBe(true);
    expect(isValidPassword(PASSWORD)).toBe(true);
    expect(isValidPassword('weak')).toBe(false);
  });
});

describe('browser CryptoManager — Node-only methods throw UNSUPPORTED_IN_BROWSER', () => {
  const mgr = new CryptoManager();

  // Each Node-only method rejects the operation with
  // CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER'): the synchronous
  // methods throw synchronously, and the async methods (deriveKey, encryptFile,
  // decryptFile) reject — matching each method's Node call contract.
  it('generateSecureRandom throws', () => {
    expectUnsupported(() => mgr.generateSecureRandom(16));
  });

  it('deriveKey rejects', async () => {
    await expectUnsupportedAsync(() =>
      mgr.deriveKey(PASSWORD, new Uint8Array(32))
    );
  });

  it('deriveKeySync throws', () => {
    expectUnsupported(() => mgr.deriveKeySync(PASSWORD, new Uint8Array(32)));
  });

  it('encryptData throws', () => {
    expectUnsupported(() =>
      mgr.encryptData(new Uint8Array(3), new Uint8Array(32), new Uint8Array(12))
    );
  });

  it('decryptData throws', () => {
    expectUnsupported(() =>
      mgr.decryptData(
        new Uint8Array(3),
        new Uint8Array(32),
        new Uint8Array(12),
        new Uint8Array(16)
      )
    );
  });

  it('encryptTextSync throws', () => {
    expectUnsupported(() => mgr.encryptTextSync('hello', PASSWORD));
  });

  it('decryptTextSync throws', () => {
    expectUnsupported(() => mgr.decryptTextSync('hello', PASSWORD));
  });

  it('encryptFile rejects', async () => {
    await expectUnsupportedAsync(() =>
      mgr.encryptFile('in.bin', 'out.enc', PASSWORD)
    );
  });

  it('decryptFile rejects', async () => {
    await expectUnsupportedAsync(() =>
      mgr.decryptFile('in.enc', 'out.bin', PASSWORD)
    );
  });

  it('encryptFileSync throws', () => {
    expectUnsupported(() => mgr.encryptFileSync('in.bin', 'out.enc', PASSWORD));
  });

  it('decryptFileSync throws', () => {
    expectUnsupported(() => mgr.decryptFileSync('in.enc', 'out.bin', PASSWORD));
  });

  it('still exposes the inherited isomorphic + tooling methods', () => {
    // Sanity: the stubs must not have shadowed the inherited surface.
    expect(typeof mgr.encryptBytes).toBe('function');
    expect(typeof mgr.decryptBytes).toBe('function');
    expect(typeof mgr.encryptText).toBe('function');
    expect(typeof mgr.decryptText).toBe('function');
    expect(typeof mgr.inspectHeader).toBe('function');
    expect(typeof mgr.validatePassword).toBe('function');
    expect(mgr.validatePassword(PASSWORD)).toBe(true);
    // secureClear works on a plain Uint8Array (browser key material).
    const buf = utf8Encode('scrub me');
    mgr.secureClear(buf);
    expect(bytesToHex(buf)).toBe('00'.repeat(buf.length));
    expect(utf8Decode(new Uint8Array(0))).toBe('');
  });
});

describe('browser CryptoManager — constructor validation is identical to Node', () => {
  /** Assert `new CryptoManager(options)` throws a specific CryptoError. */
  function expectConstructError(
    build: () => unknown,
    type: CryptoErrorType,
    code: string
  ): void {
    let thrown: unknown;
    try {
      build();
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(CryptoError);
    const e = thrown as InstanceType<typeof CryptoError>;
    expect(e.type).toBe(type);
    expect(e.code).toBe(code);
  }

  it('rejects a weak defaultPassphrase with WEAK_PASSWORD', () => {
    expectConstructError(
      () => new CryptoManager({ defaultPassphrase: 'weak' }),
      CryptoErrorType.INVALID_PASSWORD,
      'WEAK_PASSWORD'
    );
  });

  it('accepts a weak defaultPassphrase when skipPasswordValidation is set', () => {
    const cm = new CryptoManager({
      defaultPassphrase: 'weak',
      skipPasswordValidation: true,
    });
    expect(cm.hasDefaultPassphrase()).toBe(true);
  });

  it('accepts a strong defaultPassphrase and reports it configured', () => {
    const cm = new CryptoManager({ defaultPassphrase: PASSWORD });
    expect(cm.hasDefaultPassphrase()).toBe(true);
  });

  it('rejects a non-positive memoryCost with INVALID_MEMORY_COST', () => {
    expectConstructError(
      () => new CryptoManager({ memoryCost: -1 }),
      CryptoErrorType.INVALID_INPUT,
      'INVALID_MEMORY_COST'
    );
  });

  it('enforces the Argon2id memoryCost >= 8*parallelism floor', () => {
    expectConstructError(
      () => new CryptoManager({ memoryCost: 4, parallelism: 1 }),
      CryptoErrorType.INVALID_INPUT,
      'MEMORY_COST_TOO_SMALL'
    );
  });

  it('rejects a non-string aad with INVALID_AAD', () => {
    expectConstructError(
      () => new CryptoManager({ aad: 123 as unknown as string }),
      CryptoErrorType.INVALID_INPUT,
      'INVALID_AAD'
    );
  });

  it('rejects an invalid legacyMode with INVALID_LEGACY_MODE', () => {
    expectConstructError(
      () =>
        new CryptoManager({
          legacyMode: 'nope' as unknown as 'auto',
        }),
      CryptoErrorType.INVALID_INPUT,
      'INVALID_LEGACY_MODE'
    );
  });

  it('constructs with no options and reports the browser defaults', () => {
    const cm = new CryptoManager();
    expect(cm.hasDefaultPassphrase()).toBe(false);
    expect(cm.getLegacyMode()).toBe('auto');
  });
});
