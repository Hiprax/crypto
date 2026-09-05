/**
 * Module-interop tests for the Web engine's `hash-wasm` resolution branch
 * (`loadArgon2id` in `src/engine.web.ts`).
 *
 * `engine.web.ts` reaches its Argon2id implementation through a LAZY dynamic
 * `import('hash-wasm')`, and it must cope with every shape that import can
 * legitimately take: a native-ESM namespace exposing `argon2id` as a NAMED
 * export, and an interop/bundler shim that buries the same function under
 * `.default`. Those two branches, the "module loaded but exposes nothing
 * usable" branch, and the deliberate NON-catch of a CALL-time WASM failure are
 * what this file pins. They are unreachable from the real-provider suite
 * (`engine-web.test.ts`) because the installed `hash-wasm` only ever presents
 * ONE of the shapes — the module shape is precisely the thing we cannot vary
 * without a module mock.
 *
 * What is faked, and why (Core Principle: mock only what cannot be exercised
 * honestly): `jest.unstable_mockModule('hash-wasm', …)` is the ONLY fake. It
 * stands in for the optional third-party module whose EXPORT SHAPE is the
 * variable under test. The unit under test — `webEngine` / `CryptoCore` — is
 * always the real one, and in the shape tests the mocked module's `argon2id`
 * delegates to the REAL `hash-wasm` `argon2id` captured before any mock is
 * registered, so the derived key is a genuine RFC 9106 Argon2id output and a
 * mis-mapped parameter (e.g. `memorySize` fed from `timeCost`) produces a
 * different key and goes red.
 *
 * Oracles: the pinned RFC 9106 Argon2id known-answer tuple already used by
 * `engine-web.test.ts`, `engine-node.test.ts` and
 * `argon2-provider-parity.test.ts`, PLUS an independent live derivation from
 * `nodeEngine` (which prefers the NATIVE `argon2` addon, a different
 * implementation entirely).
 *
 * Run via `npm test` (which sets `NODE_OPTIONS=--experimental-vm-modules`);
 * a bare `npx jest` breaks the ESM-mock loader and these mocks silently do
 * nothing.
 */
import {
  describe,
  it,
  expect,
  beforeAll,
  beforeEach,
  afterEach,
  jest,
} from '@jest/globals';
import { bytesToHex } from '../codec';

// ----------------------------------------------------------------------------
// Argon2id known-answer vector — byte-identical to the tuple pinned in
// engine-web.test.ts / engine-node.test.ts / argon2-provider-parity.test.ts.
//
//   password    = 'parity-vector-password'  (ASCII; NFC is a no-op)
//   salt        = 32 bytes, values 0x00..0x1f
//   memoryCost  = 4096 KiB (4 MiB), timeCost = 2, parallelism = 1, len = 32
// ----------------------------------------------------------------------------
const KAT_HEX =
  '79fce5dc8932db4e5d85f8d32c1d8f2206188c3c1bcbe5ef555bab13c595567b';
const KAT_PASSWORD = 'parity-vector-password';
const KAT_SALT = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
const KAT_PARAMS = {
  memoryCost: 4096,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
} as const;

/** A password that satisfies the composition rule, for the manager-level case. */
const STRONG_PASSWORD = 'MySecureP@ssw0rd123!';

/** Exact option bag `engine.web.ts` hands to `hash-wasm`'s `argon2id`. */
type HashWasmArgon2idOptions = {
  password: string;
  salt: Uint8Array;
  iterations: number;
  parallelism: number;
  memorySize: number;
  hashLength: number;
  outputType: 'binary';
};

type HashWasmArgon2id = (
  options: HashWasmArgon2idOptions
) => Promise<Uint8Array>;

/**
 * The REAL `hash-wasm` `argon2id`, captured in `beforeAll` BEFORE any module
 * mock exists, so the shape tests can hand the genuine implementation back to
 * the engine through an arbitrary export shape. `null` when the optional
 * dependency cannot be loaded on this host.
 */
let realArgon2id: HashWasmArgon2id | null = null;
/** Why `realArgon2id` is null, for the skip/hard-fail message. */
let realArgon2idError: unknown = null;

/**
 * An INDEPENDENT live oracle: the same tuple derived through `nodeEngine`,
 * which prefers the native `argon2` addon (a different implementation from
 * hash-wasm). `null` when no Argon2 provider is available at all.
 */
let nodeOracleHex: string | null = null;
/** Why `nodeOracleHex` is null, for the skip/hard-fail message. */
let nodeOracleError: unknown = null;

beforeAll(async () => {
  // Captured BEFORE any `jest.unstable_mockModule` call in this file, so these
  // are the genuine modules, not mocks.
  try {
    const mod = (await import('hash-wasm')) as {
      argon2id?: HashWasmArgon2id;
      default?: { argon2id?: HashWasmArgon2id };
    };
    if (typeof mod.argon2id === 'function') {
      realArgon2id = mod.argon2id;
    } else if (typeof mod.default?.argon2id === 'function') {
      realArgon2id = mod.default.argon2id;
    } else {
      realArgon2idError = new Error(
        '`hash-wasm` loaded but exposes no `argon2id`'
      );
    }
  } catch (err) {
    realArgon2idError = err;
  }

  try {
    const { nodeEngine } = await import('../engine.node');
    nodeOracleHex = bytesToHex(
      await nodeEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, KAT_PARAMS)
    );
  } catch (err) {
    nodeOracleError = err;
  }
});

/**
 * Availability gate for the two live Argon2 providers, mirroring the
 * `skipOrThrowArgon2Unavailable` convention in `engine-web.test.ts`: in CI the
 * optional dependencies MUST be installed, so a missing provider is a hard
 * failure and can never silently no-op these assertions; on a dev host that
 * genuinely cannot build/load them we log a skip and the caller returns.
 *
 * @returns the real `hash-wasm` `argon2id` and the node oracle hex, or `null`
 *   when the caller should skip.
 */
function liveProvidersOrSkip(
  context: string
): { argon2id: HashWasmArgon2id; nodeHex: string } | null {
  if (realArgon2id !== null && nodeOracleHex !== null) {
    return { argon2id: realArgon2id, nodeHex: nodeOracleHex };
  }
  const reason =
    realArgon2id === null
      ? `hash-wasm unavailable: ${String(realArgon2idError)}`
      : `node Argon2 provider unavailable: ${String(nodeOracleError)}`;
  if (process.env.CI) {
    throw new Error(
      `Argon2id providers must be installed in CI; ${context} cannot be ` +
        `silently skipped. ${reason}`
    );
  }
  // eslint-disable-next-line no-console
  console.warn(`[skip] ${context} skipped: ${reason}`);
  return null;
}

/**
 * Wrap an `argon2id` implementation so the exact option bag the engine passed
 * is recorded. Recording the bag is what makes the parameter mapping
 * (`memorySize` <- `memoryCost`, `iterations` <- `timeCost`) assertable
 * independently of the derived bytes.
 *
 * The snapshot is taken BEFORE delegating because the real `hash-wasm`
 * normalises its argument object IN PLACE (it replaces `password`/`salt` with
 * byte buffers), so a stored reference would show post-call values.
 */
function recordingArgon2id(impl: HashWasmArgon2id): {
  fn: HashWasmArgon2id;
  calls: HashWasmArgon2idOptions[];
} {
  const calls: HashWasmArgon2idOptions[] = [];
  const fn = async (options: HashWasmArgon2idOptions): Promise<Uint8Array> => {
    calls.push({ ...options, salt: Uint8Array.from(options.salt) });
    return impl(options);
  };
  return { fn, calls };
}

/** Assert the engine mapped every {@link KAT_PARAMS} field onto hash-wasm's names. */
function expectKatOptionMapping(options: HashWasmArgon2idOptions): void {
  expect(options.password).toBe(KAT_PASSWORD);
  expect(bytesToHex(options.salt)).toBe(bytesToHex(KAT_SALT));
  expect(options.memorySize).toBe(KAT_PARAMS.memoryCost);
  expect(options.iterations).toBe(KAT_PARAMS.timeCost);
  expect(options.parallelism).toBe(KAT_PARAMS.parallelism);
  expect(options.hashLength).toBe(KAT_PARAMS.hashLength);
  expect(options.outputType).toBe('binary');
}

describe('engine.web loadArgon2id — hash-wasm export-shape resolution', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('derives the pinned RFC 9106 KAT when `argon2id` is a NAMED export', async () => {
    const live = liveProvidersOrSkip('named-export resolution');
    if (live === null) return;
    const { fn, calls } = recordingArgon2id(live.argon2id);

    // Native-ESM namespace shape: `argon2id` sits directly on the namespace and
    // there is NO `.default` at all, so only the first resolution branch can
    // possibly find it.
    jest.unstable_mockModule('hash-wasm', () => ({ argon2id: fn }));

    const { webEngine } = await import('../engine.web');
    const key = await webEngine.deriveArgon2id(
      KAT_PASSWORD,
      KAT_SALT,
      KAT_PARAMS
    );

    expect(key.length).toBe(32);
    expect(bytesToHex(key)).toBe(KAT_HEX);
    // Independent oracle: the native `argon2` addon via nodeEngine.
    expect(bytesToHex(key)).toBe(live.nodeHex);
    // The engine went through the mocked module exactly once, with the
    // parameter names hash-wasm expects.
    expect(calls.length).toBe(1);
    const first = calls[0];
    expect(first).toBeDefined();
    if (first !== undefined) expectKatOptionMapping(first);
  });

  it('derives the pinned RFC 9106 KAT when `argon2id` is only under `.default`', async () => {
    const live = liveProvidersOrSkip('.default resolution');
    if (live === null) return;
    const { fn, calls } = recordingArgon2id(live.argon2id);

    // Interop/bundler shim shape: nothing usable on the namespace, the real
    // function is one level down. Only the SECOND resolution branch can find
    // it, so a regression that drops the `.default` fallback goes red here.
    jest.unstable_mockModule('hash-wasm', () => ({
      default: { argon2id: fn },
    }));

    const { webEngine } = await import('../engine.web');
    const key = await webEngine.deriveArgon2id(
      KAT_PASSWORD,
      KAT_SALT,
      KAT_PARAMS
    );

    expect(bytesToHex(key)).toBe(KAT_HEX);
    expect(bytesToHex(key)).toBe(live.nodeHex);
    expect(calls.length).toBe(1);
    const first = calls[0];
    expect(first).toBeDefined();
    if (first !== undefined) expectKatOptionMapping(first);
  });

  it('falls through to `.default.argon2id` when the named export exists but is NOT callable', async () => {
    const live = liveProvidersOrSkip('non-callable named export fallthrough');
    if (live === null) return;
    const { fn, calls } = recordingArgon2id(live.argon2id);

    // A namespace can carry an `argon2id` binding that is not a function (e.g.
    // a re-exported constant, or an interop stub). The resolution is a `typeof
    // … === 'function'` test, not a truthiness test, so it must skip this and
    // take the `.default`.
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: 'not-a-function',
      default: { argon2id: fn },
    }));

    const { webEngine } = await import('../engine.web');
    const key = await webEngine.deriveArgon2id(
      KAT_PASSWORD,
      KAT_SALT,
      KAT_PARAMS
    );

    expect(bytesToHex(key)).toBe(KAT_HEX);
    expect(calls.length).toBe(1);
  });

  it('reports ARGON2_NOT_AVAILABLE when the module exposes no `argon2id` at all', async () => {
    // The module LOADS fine — this is not an import failure — but carries
    // nothing usable. The engine must still surface the same actionable
    // `MEMORY_ERROR` / `ARGON2_NOT_AVAILABLE` pair the Node engine uses, so the
    // shared core's error handling is runtime-independent.
    jest.unstable_mockModule('hash-wasm', () => ({
      sha256: (): void => undefined,
    }));

    const { webEngine } = await import('../engine.web');
    const { CryptoError, CryptoErrorType } = await import('../types');

    try {
      await webEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, KAT_PARAMS);
      throw new Error('Expected deriveArgon2id to reject');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
      // Actionable: names the package to install/bundle and says what was wrong.
      expect(e.message).toContain('hash-wasm');
      expect(e.message).toContain('exposes no `argon2id` export');
      // NEGATIVE: a missing export is an AVAILABILITY failure, never a
      // derivation failure — mislabelling it would send users debugging their
      // password/params instead of their bundle.
      expect(e.code).not.toBe('KEY_DERIVATION_FAILED');
      expect(e.type).not.toBe(CryptoErrorType.ENCRYPTION_FAILED);
    }
  });

  it('reports ARGON2_NOT_AVAILABLE when `.default.argon2id` exists but is NOT callable', async () => {
    // Both branches reject the value, so resolution yields null. This pins that
    // the `.default` branch is also a `typeof … === 'function'` test rather
    // than a truthiness test (a truthy non-function would otherwise be
    // returned and blow up later as a TypeError at call time).
    jest.unstable_mockModule('hash-wasm', () => ({
      default: { argon2id: 42 },
    }));

    const { webEngine } = await import('../engine.web');
    const { CryptoError, CryptoErrorType } = await import('../types');

    try {
      await webEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, KAT_PARAMS);
      throw new Error('Expected deriveArgon2id to reject');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.MEMORY_ERROR);
      expect(e.code).toBe('ARGON2_NOT_AVAILABLE');
      expect(e.message).toContain('exposes no `argon2id` export');
      // NEGATIVE: must not surface as a raw TypeError from calling a number.
      expect(e.message).not.toContain('is not a function');
    }
  });
});

describe('engine.web loadArgon2id — a CALL-time WASM failure is not swallowed', () => {
  const CALL_TIME_MESSAGE =
    'CompileError: WebAssembly.instantiate(): wasm-unsafe-eval blocked by CSP';

  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('propagates the raw error out of webEngine.deriveArgon2id (not ARGON2_NOT_AVAILABLE)', async () => {
    // The module resolves fine and `argon2id` IS a function; it fails only when
    // CALLED. That is a derivation failure, not an availability failure, and it
    // happens outside `loadArgon2id`'s try/catch by design — remapping it would
    // tell a user with a strict CSP to "install hash-wasm", which is already
    // installed.
    let callCount = 0;
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: async (): Promise<Uint8Array> => {
        callCount += 1;
        throw new Error(CALL_TIME_MESSAGE);
      },
    }));

    const { webEngine } = await import('../engine.web');
    const { CryptoError } = await import('../types');

    try {
      await webEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, KAT_PARAMS);
      throw new Error('Expected deriveArgon2id to reject');
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe(CALL_TIME_MESSAGE);
      // NEGATIVE: the engine must NOT have converted it into the availability
      // error, i.e. it must not be a CryptoError at this layer at all.
      expect(err).not.toBeInstanceOf(CryptoError);
      expect((err as Error).message).not.toContain('could not be loaded');
    }
    // Resolution succeeded, so the function really was reached and invoked.
    expect(callCount).toBe(1);
  });

  it('surfaces through the browser CryptoManager as KEY_DERIVATION_FAILED', async () => {
    // End-to-end through the real `CryptoCore`: a non-CryptoError from the
    // engine is wrapped as ENCRYPTION_FAILED / KEY_DERIVATION_FAILED, exactly
    // as a native hash failure behaves in Node. Nothing but `hash-wasm` is
    // mocked; the manager, the core and the Web Crypto primitives are real.
    let callCount = 0;
    jest.unstable_mockModule('hash-wasm', () => ({
      argon2id: async (): Promise<Uint8Array> => {
        callCount += 1;
        throw new Error(CALL_TIME_MESSAGE);
      },
    }));

    const { CryptoManager } = await import('../crypto-manager.browser');
    const { CryptoError, CryptoErrorType } = await import('../types');

    const cm = new CryptoManager({
      memoryCost: KAT_PARAMS.memoryCost,
      timeCost: KAT_PARAMS.timeCost,
      parallelism: KAT_PARAMS.parallelism,
    });

    try {
      await cm.encryptBytes(new Uint8Array([1, 2, 3]), STRONG_PASSWORD);
      throw new Error('Expected encryptBytes to reject');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.ENCRYPTION_FAILED);
      expect(e.code).toBe('KEY_DERIVATION_FAILED');
      // The underlying cause is preserved in the message, so the CSP problem is
      // diagnosable from the thrown error alone.
      expect(e.message).toContain(CALL_TIME_MESSAGE);
      // NEGATIVE: never mislabelled as "the optional package is missing".
      expect(e.code).not.toBe('ARGON2_NOT_AVAILABLE');
      expect(e.type).not.toBe(CryptoErrorType.MEMORY_ERROR);
    }
    expect(callCount).toBe(1);
  });
});
