/**
 * v2 container-mode tests (Phase 10 — container-mode).
 *
 * The container is an additive envelope format (magic "HPCR", version 0x02)
 * defined on `CryptoCore`, so it is inherited by BOTH runtime managers. Like
 * the interop suite, this file drives BOTH engines under Node 22+: the Node
 * `CryptoManager` (native `argon2` → `hash-wasm` + `node:crypto`) and the
 * browser `CryptoManager` (SubtleCrypto + hash-wasm), which is fully
 * exercisable in Node. It pins:
 *
 *   1. Round-trip identity (± metadata) on each engine, and cross-engine
 *      interop both directions (one wire format — a container sealed in Node
 *      opens in the browser build and vice-versa).
 *   2. Metadata confidentiality — filename/mime/payload bytes never appear in
 *      cleartext in the output.
 *   3. Tamper resistance — a single-bit flip of ANY segment throws.
 *   4. End-to-end integrity — a payload whose embedded SHA-256 does not match
 *      is rejected with `CONTAINER_INTEGRITY_FAILED`.
 *   5. Version isolation — a v2 container fed to `decryptBytes`/`decryptText`
 *      throws (a thrown `CryptoError`, asserted in default `auto` mode), and
 *      `decryptContainer` rejects a v0/v1 blob.
 *   6. Parser robustness — a fast-check fuzz over truncated/mutated v2 headers
 *      never crashes and always yields a typed `CryptoError`.
 *   7. Byte layout — a checked-in deterministic v2 snapshot.
 *
 * Availability gating (Core Principle 4): `hash-wasm` powers the browser (Web
 * engine) Argon2id. A single `beforeAll` probe runs one real Web-engine
 * derivation; if hash-wasm cannot load, `webEngineReady` flips to false and the
 * browser-dependent assertions are skipped (logged) rather than failed. The
 * Node engine is assumed available, exactly as the rest of the suite assumes.
 *
 * Why a low-cost CryptoManager: Argon2id at the production default is hundreds
 * of ms per derivation. These tests only need the KDF to be CORRECT, so they
 * use the LOW tier (`memoryCost: 2^14 = 16 MiB`, `timeCost: 1`). TEST-ONLY —
 * never lower production parameters this far.
 */
import {
  describe,
  it,
  expect,
  beforeAll,
  afterEach,
  jest,
} from '@jest/globals';
import nodeCrypto from 'node:crypto';
import fc from 'fast-check';
import { CryptoManager as NodeCryptoManager } from '../crypto-manager';
import { CryptoManager as BrowserCryptoManager } from '../crypto-manager.browser';
import { CryptoError, CryptoErrorType } from '../types';
import {
  parseV2Container,
  parseV2Meta,
  serializeV2Meta,
  CONTAINER_VERSION,
} from '../core';
import type { ParsedV2Container } from '../core';
import { utf8Encode, bytesToHex, bytesToBase64url } from '../codec';
import {
  HEADER_LENGTH,
  KDF_ID_ARGON2ID,
  MAX_ARGON2_MEMORY_COST,
  MAX_ARGON2_TIME_COST,
  MAX_ARGON2_PARALLELISM,
} from '../format-core';

// Argon2id at production cost is slow; these run the real KDF at the LOW tier.
jest.setTimeout(120_000);

// Test-only low-cost Argon2id profile. Passed to BOTH managers so they encrypt
// at IDENTICAL parameters (the browser default would otherwise be 32 MiB vs the
// Node 128 MiB). Never use in production.
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

// A 20+ character passphrase (NIST passphrase acceptance rule) plus a distinct
// one for the wrong-password negatives.
const PASSWORD = 'correct horse battery staple';
const WRONG_PASSWORD = 'incorrect zebra piano lantern';

/** True when an error is the documented "Argon2id unavailable" graceful state. */
function isArgon2Unavailable(err: unknown): boolean {
  return (
    err instanceof CryptoError &&
    (err as InstanceType<typeof CryptoError>).code === 'ARGON2_NOT_AVAILABLE'
  );
}

/** Byte-equality helper (fast memcmp via Buffer — harness-side only). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a).equals(Buffer.from(b));
}

/** Substring search: does `haystack` contain the byte sequence `needle`? */
function bytesContains(haystack: Uint8Array, needle: Uint8Array): boolean {
  return Buffer.from(haystack).indexOf(Buffer.from(needle)) !== -1;
}

/** Deterministic-but-varied filler bytes for a given length. */
function fillerBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = (i * 31 + 7) & 0xff;
  }
  return out;
}

/** Flip a single bit at `offset`, returning a NEW array (input untouched). */
function flipBitAt(buf: Uint8Array, offset: number): Uint8Array {
  const out = Uint8Array.from(buf);
  out[offset] = (out[offset] ?? 0) ^ 0x01;
  return out;
}

/** Run `fn`, classifying the outcome as returned-value or thrown-error. */
function safelyRun<T>(
  fn: () => T
): { ok: true; value: T } | { ok: false; error: unknown } {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, error };
  }
}

// ---------------------------------------------------------------------------
// Web-engine availability probe (shared by every browser-dependent assertion).
// ---------------------------------------------------------------------------
let webEngineReady = false;
beforeAll(async () => {
  try {
    const probe = new BrowserCryptoManager(LOW_COST);
    const ct = await probe.encryptContainer(
      new Uint8Array([1, 2, 3]),
      PASSWORD
    );
    await probe.decryptContainer(ct, PASSWORD);
    webEngineReady = true;
  } catch (err) {
    if (isArgon2Unavailable(err)) {
      // In CI the optional hash-wasm dependency MUST be installed so the
      // browser-engine container assertions cannot silently no-op. Graceful
      // [skip] is reserved for genuinely-unsupported local dev hosts.
      if (process.env.CI) {
        throw new Error(
          `hash-wasm Argon2id failed to load in CI; the browser-engine ` +
            `container assertions cannot be silently skipped. Ensure the ` +
            `optional hash-wasm dependency is installed.`,
          { cause: err }
        );
      }
      webEngineReady = false;
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] hash-wasm Argon2id unavailable; browser-side container ` +
          `assertions will be skipped: ${String(err)}`
      );
    } else {
      throw err;
    }
  }
}, 60_000);

// ===========================================================================
// 1 + 2. Round-trip identity (± metadata) on each engine.
// ===========================================================================
const ENGINES: Array<{
  label: string;
  make: () => NodeCryptoManager | BrowserCryptoManager;
  gated: boolean;
}> = [
  {
    label: 'Node engine',
    make: () => new NodeCryptoManager(LOW_COST),
    gated: false,
  },
  {
    label: 'Web engine',
    make: () => new BrowserCryptoManager(LOW_COST),
    gated: true,
  },
];

describe.each(ENGINES)(
  'v2 container round-trip — $label',
  ({ make, gated }) => {
    const mgr = make();

    it('round-trips across edge sizes (0/1/15/16/17/large), no metadata', async () => {
      if (gated && !webEngineReady) return;
      for (const size of [0, 1, 15, 16, 17, 4096]) {
        const data = new Uint8Array(nodeCrypto.randomBytes(size));
        const container = await mgr.encryptContainer(data, PASSWORD);
        // Output is a v2 container: magic "HPCR" + version byte 0x02.
        expect(Buffer.from(container.subarray(0, 4)).toString('ascii')).toBe(
          'HPCR'
        );
        expect(container[4]).toBe(CONTAINER_VERSION);
        const { data: back, meta } = await mgr.decryptContainer(
          container,
          PASSWORD
        );
        expect(bytesEqual(back, data)).toBe(true);
        expect(meta).toEqual({ size });
      }
    });

    it('round-trips WITH filename + mime and returns them verbatim', async () => {
      if (gated && !webEngineReady) return;
      const data = utf8Encode('café — 世界 — 🔐 payload');
      const container = await mgr.encryptContainer(data, PASSWORD, {
        filename: 'réport final.pdf',
        mime: 'application/pdf',
      });
      const { data: back, meta } = await mgr.decryptContainer(
        container,
        PASSWORD
      );
      expect(bytesEqual(back, data)).toBe(true);
      expect(meta).toEqual({
        filename: 'réport final.pdf',
        mime: 'application/pdf',
        size: data.length,
      });
    });

    it('round-trips with filename-only and mime-only metadata', async () => {
      if (gated && !webEngineReady) return;
      const data = fillerBytes(48);

      const fnOnly = await mgr.decryptContainer(
        await mgr.encryptContainer(data, PASSWORD, { filename: 'only.bin' }),
        PASSWORD
      );
      expect(fnOnly.meta).toEqual({ filename: 'only.bin', size: 48 });

      const mimeOnly = await mgr.decryptContainer(
        await mgr.encryptContainer(data, PASSWORD, {
          mime: 'application/octet-stream',
        }),
        PASSWORD
      );
      expect(mimeOnly.meta).toEqual({
        mime: 'application/octet-stream',
        size: 48,
      });
    });

    it('round-trips an empty-string filename as a present zero-length field', async () => {
      if (gated && !webEngineReady) return;
      // An explicit empty string is "present" (flag bit set, zero-length body),
      // distinct from an omitted field — and must round-trip back to ''.
      const data = fillerBytes(24);
      const container = await mgr.encryptContainer(data, PASSWORD, {
        filename: '',
      });
      const { data: back, meta } = await mgr.decryptContainer(
        container,
        PASSWORD
      );
      expect(bytesEqual(back, data)).toBe(true);
      expect(meta).toEqual({ filename: '', size: 24 });
    });

    it('uses the configured defaultPassphrase when no password is passed', async () => {
      if (gated && !webEngineReady) return;
      // `gated` distinguishes the two builds (false = Node, true = browser).
      const cm = gated
        ? new BrowserCryptoManager({ ...LOW_COST, defaultPassphrase: PASSWORD })
        : new NodeCryptoManager({ ...LOW_COST, defaultPassphrase: PASSWORD });
      const data = fillerBytes(40);
      const container = await cm.encryptContainer(data);
      const { data: back } = await cm.decryptContainer(container);
      expect(bytesEqual(back, data)).toBe(true);
    });

    it('produces distinct containers for the same input (fresh salt/DEK/IVs)', async () => {
      if (gated && !webEngineReady) return;
      const data = utf8Encode('same input, twice');
      const a = await mgr.encryptContainer(data, PASSWORD);
      const b = await mgr.encryptContainer(data, PASSWORD);
      expect(bytesEqual(a, b)).toBe(false);
    });

    it('rejects the wrong password with a CryptoError', async () => {
      if (gated && !webEngineReady) return;
      const container = await mgr.encryptContainer(fillerBytes(64), PASSWORD);
      await expect(
        mgr.decryptContainer(container, WRONG_PASSWORD)
      ).rejects.toThrow(CryptoError);
    });

    it('does NOT mutate the caller-supplied plaintext buffer', async () => {
      if (gated && !webEngineReady) return;
      const data = fillerBytes(64);
      const snapshot = Uint8Array.from(data);
      await mgr.encryptContainer(data, PASSWORD);
      expect(bytesEqual(data, snapshot)).toBe(true);
    });
  }
);

// ===========================================================================
// 3. Cross-engine interop — one wire format round-trips Node <-> browser.
// ===========================================================================
describe('v2 container cross-engine interop (Node <-> browser)', () => {
  const node = new NodeCryptoManager(LOW_COST);
  const browser = new BrowserCryptoManager(LOW_COST);

  it('a Node-sealed container opens in the browser build (± metadata)', async () => {
    if (!webEngineReady) return;
    for (const size of [0, 1, 17, 5000]) {
      const data = new Uint8Array(nodeCrypto.randomBytes(size));
      const container = await node.encryptContainer(data, PASSWORD, {
        filename: 'from-node.dat',
        mime: 'application/x-node',
      });
      const { data: back, meta } = await browser.decryptContainer(
        container,
        PASSWORD
      );
      expect(bytesEqual(back, data)).toBe(true);
      expect(meta).toEqual({
        filename: 'from-node.dat',
        mime: 'application/x-node',
        size,
      });
    }
  });

  it('a browser-sealed container opens in the Node build (± metadata)', async () => {
    if (!webEngineReady) return;
    for (const size of [0, 16, 4096]) {
      const data = new Uint8Array(nodeCrypto.randomBytes(size));
      const container = await browser.encryptContainer(data, PASSWORD, {
        filename: 'from-browser.dat',
      });
      const { data: back, meta } = await node.decryptContainer(
        container,
        PASSWORD
      );
      expect(bytesEqual(back, data)).toBe(true);
      expect(meta).toEqual({ filename: 'from-browser.dat', size });
    }
  });

  it('a cross-runtime container survives a wrong password / tamper on the other build', async () => {
    if (!webEngineReady) return;
    const nodeCt = await node.encryptContainer(fillerBytes(64), PASSWORD);
    await expect(
      browser.decryptContainer(nodeCt, WRONG_PASSWORD)
    ).rejects.toThrow(CryptoError);
    // Tamper the payload auth tag (last 16 bytes) — GCM must fail on the browser.
    await expect(
      browser.decryptContainer(flipBitAt(nodeCt, nodeCt.length - 1), PASSWORD)
    ).rejects.toThrow(CryptoError);
  });
});

// ===========================================================================
// 4. Metadata (and payload) confidentiality.
// ===========================================================================
describe('v2 container — metadata is confidential', () => {
  const node = new NodeCryptoManager(LOW_COST);

  it('never emits filename/mime/payload bytes in cleartext', async () => {
    const filename = 'ULTRA-SECRET-FILENAME-90210.dat';
    const mime = 'application/x-super-secret-mime-type';
    const payload = 'THIS-PAYLOAD-PLAINTEXT-MUST-NOT-APPEAR-IN-THE-CONTAINER';
    const container = await node.encryptContainer(
      utf8Encode(payload),
      PASSWORD,
      { filename, mime }
    );
    expect(bytesContains(container, utf8Encode(filename))).toBe(false);
    expect(bytesContains(container, utf8Encode(mime))).toBe(false);
    expect(bytesContains(container, utf8Encode(payload))).toBe(false);
  });
});

// ===========================================================================
// 4b. `aad` cross-application domain separation (containers honour the
//     configured context string exactly like the v1 path).
// ===========================================================================
describe('v2 container — the `aad` option provides cross-application domain separation', () => {
  it('a container sealed under one `aad` cannot be opened by a manager with a different `aad` (same password + params)', async () => {
    const appA = new NodeCryptoManager({ ...LOW_COST, aad: 'application-A' });
    const appB = new NodeCryptoManager({ ...LOW_COST, aad: 'application-B' });
    const container = await appA.encryptContainer(fillerBytes(48), PASSWORD, {
      filename: 'secret.dat',
    });
    // Same password AND identical Argon2id params (⇒ byte-identical header), so
    // the ONLY thing separating the two apps is the bound `aad` context string.
    // The DEK-unwrap GCM tag must reject the foreign `aad`.
    await expect(appB.decryptContainer(container, PASSWORD)).rejects.toThrow(
      CryptoError
    );
    // Sanity: the originating app still opens its own container.
    const { data } = await appA.decryptContainer(container, PASSWORD);
    expect(data.length).toBe(48);
  });

  it('the default `aad` round-trips (no custom aad required for the common case)', async () => {
    const cm = new NodeCryptoManager(LOW_COST);
    const container = await cm.encryptContainer(fillerBytes(32), PASSWORD);
    const { data } = await cm.decryptContainer(container, PASSWORD);
    expect(data.length).toBe(32);
  });
});

// ===========================================================================
// 5. Tamper resistance — a single-bit flip of ANY segment throws.
// ===========================================================================
describe('v2 container — single-bit tamper of every segment rejects', () => {
  const node = new NodeCryptoManager(LOW_COST);
  let container: Uint8Array;
  let parsed: ParsedV2Container;

  beforeAll(async () => {
    container = await node.encryptContainer(fillerBytes(64), PASSWORD, {
      filename: 'a.txt',
      mime: 'text/plain',
    });
    parsed = parseV2Container(container);
  });

  // Absolute byte offsets are resolved from the parsed segment views at
  // run-time (each view's byteOffset is absolute — the container starts at
  // offset 0 in its own buffer).
  const offsetOf = (segment: string): number => {
    switch (segment) {
      case 'header magic':
        return 0;
      case 'header version':
        return 4;
      case 'header reserved (AAD-bound)':
        return 16;
      case 'salt':
        return parsed.salt.byteOffset;
      case 'kekIv':
        return parsed.kekIv.byteOffset;
      case 'wrappedDek':
        return parsed.wrappedDek.byteOffset;
      case 'kekTag':
        return parsed.kekTag.byteOffset;
      case 'metaLen field':
        return parsed.metaIv.byteOffset + parsed.metaIv.length;
      case 'metaIv':
        return parsed.metaIv.byteOffset;
      case 'encMeta':
        return parsed.encMeta.byteOffset;
      case 'metaTag':
        return parsed.metaTag.byteOffset;
      case 'dataIv':
        return parsed.dataIv.byteOffset;
      case 'encData':
        return parsed.encData.byteOffset;
      case 'dataTag':
        return parsed.dataTag.byteOffset;
      default:
        throw new Error(`unknown segment ${segment}`);
    }
  };

  const segments = [
    'header magic',
    'header version',
    'header reserved (AAD-bound)',
    'salt',
    'kekIv',
    'wrappedDek',
    'kekTag',
    'metaLen field',
    'metaIv',
    'encMeta',
    'metaTag',
    'dataIv',
    'encData',
    'dataTag',
  ];

  it.each(segments)(
    'rejects a single-bit tamper in the %s segment',
    async segment => {
      const tampered = flipBitAt(container, offsetOf(segment));
      await expect(node.decryptContainer(tampered, PASSWORD)).rejects.toThrow(
        CryptoError
      );
    }
  );
});

// ===========================================================================
// 6. End-to-end integrity — the embedded SHA-256 is verified after decrypt.
// ===========================================================================
describe('v2 container — CONTAINER_INTEGRITY_FAILED on hash mismatch', () => {
  afterEach(() => jest.restoreAllMocks());

  it('rejects a container whose embedded plaintext-hash is wrong', async () => {
    // Import the SAME nodeEngine instance the manager uses, then force its
    // sha256 to return a BOGUS digest DURING ENCRYPT only (so the sealed-in
    // hash is wrong). After restore, decrypt recomputes the REAL hash of the
    // payload; the mismatch must surface as CONTAINER_INTEGRITY_FAILED, NOT as
    // a GCM auth failure (the bogus hash is itself authenticated inside the
    // metadata segment, so every GCM tag still verifies).
    const { nodeEngine } = await import('../engine.node');
    const cm = new NodeCryptoManager(LOW_COST);

    const spy = jest
      .spyOn(nodeEngine, 'sha256')
      .mockResolvedValue(new Uint8Array(32).fill(0xee));
    const container = await cm.encryptContainer(fillerBytes(80), PASSWORD, {
      filename: 'tampered-hash.bin',
    });
    spy.mockRestore();

    let thrown: unknown;
    try {
      await cm.decryptContainer(container, PASSWORD);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(CryptoError);
    expect((thrown as CryptoError).type).toBe(
      CryptoErrorType.DECRYPTION_FAILED
    );
    expect((thrown as CryptoError).code).toBe('CONTAINER_INTEGRITY_FAILED');
  });
});

// ===========================================================================
// 7. Version isolation — v2 and v1 mutually reject.
// ===========================================================================
describe('v2 container — version isolation from v0/v1', () => {
  const node = new NodeCryptoManager(LOW_COST);

  it('decryptBytes rejects a v2 container (thrown CryptoError, auto mode)', async () => {
    const container = await node.encryptContainer(utf8Encode('x'), PASSWORD);
    await expect(node.decryptBytes(container, PASSWORD)).rejects.toThrow(
      CryptoError
    );
  });

  it('decryptText rejects a v2 container as base64url (thrown CryptoError, auto mode)', async () => {
    const container = await node.encryptContainer(utf8Encode('x'), PASSWORD);
    await expect(
      node.decryptText(bytesToBase64url(container), PASSWORD)
    ).rejects.toThrow(CryptoError);
  });

  it('strict legacyMode surfaces UNSUPPORTED_VERSION for a v2 container', async () => {
    const strict = new NodeCryptoManager({ ...LOW_COST, legacyMode: 'strict' });
    const container = await strict.encryptContainer(utf8Encode('x'), PASSWORD);
    let thrown: unknown;
    try {
      await strict.decryptBytes(container, PASSWORD);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(CryptoError);
    expect((thrown as CryptoError).code).toBe('UNSUPPORTED_VERSION');
  });

  it('decryptContainer rejects a v1 ciphertext (thrown CryptoError)', async () => {
    const v1 = await node.encryptBytes(utf8Encode('x'), PASSWORD);
    await expect(node.decryptContainer(v1, PASSWORD)).rejects.toThrow(
      CryptoError
    );
  });

  it('decryptContainer rejects a v0-like (no-magic) blob', async () => {
    const junk = new Uint8Array(nodeCrypto.randomBytes(200));
    junk[0] = 0x00; // guarantee no accidental "HPCR" magic
    await expect(node.decryptContainer(junk, PASSWORD)).rejects.toThrow(
      CryptoError
    );
  });
});

// ===========================================================================
// 8. Input validation on encrypt (fast — these fail before any KDF work).
// ===========================================================================
describe('v2 container — encrypt input validation', () => {
  const node = new NodeCryptoManager(LOW_COST);

  it('rejects non-Uint8Array data with INVALID_DATA', async () => {
    await expect(
      node.encryptContainer('nope' as unknown as Uint8Array, PASSWORD)
    ).rejects.toMatchObject({ code: 'INVALID_DATA' });
  });

  it('requires a password (INVALID_PASSWORD)', async () => {
    await expect(node.encryptContainer(fillerBytes(8))).rejects.toMatchObject({
      code: 'INVALID_PASSWORD',
    });
  });

  it('rejects a weak password (WEAK_PASSWORD)', async () => {
    await expect(
      node.encryptContainer(fillerBytes(8), 'weak')
    ).rejects.toMatchObject({ code: 'WEAK_PASSWORD' });
  });

  it('rejects a non-string filename (INVALID_CONTAINER_META)', async () => {
    await expect(
      node.encryptContainer(fillerBytes(8), PASSWORD, {
        filename: 123 as unknown as string,
      })
    ).rejects.toMatchObject({ code: 'INVALID_CONTAINER_META' });
  });

  it('rejects an oversized filename (CONTAINER_METADATA_TOO_LARGE)', async () => {
    await expect(
      node.encryptContainer(fillerBytes(8), PASSWORD, {
        filename: 'a'.repeat(70_000),
      })
    ).rejects.toMatchObject({ code: 'CONTAINER_METADATA_TOO_LARGE' });
  });

  it('rejects non-Uint8Array container on decrypt (INVALID_ENCRYPTED_DATA)', async () => {
    await expect(
      node.decryptContainer('nope' as unknown as Uint8Array, PASSWORD)
    ).rejects.toMatchObject({ code: 'INVALID_ENCRYPTED_DATA' });
  });
});

// ===========================================================================
// 9. Parser robustness — fast-check fuzz over the pure structural parser.
//
// parseV2Container is the PRE-authentication surface (it runs before any KDF),
// so it must never throw a non-CryptoError and never hang. Pumping random and
// magic-prefixed byte arrays through it proves the DoS-bounded contract.
// ===========================================================================
describe('parseV2Container fuzzing harness', () => {
  const FUZZ_CONFIG: fc.Parameters = {
    numRuns: 1000,
    endOnFailure: true,
    seed: 0x2c0ffee,
  };

  const KNOWN_CONTAINER_CODES = new Set<string>([
    'INVALID_CONTAINER_INPUT',
    'TRUNCATED_CONTAINER',
    'CONTAINER_INVALID_MAGIC',
    'CONTAINER_UNSUPPORTED_VERSION',
    'CONTAINER_UNSUPPORTED_KDF',
    'CONTAINER_INVALID_HEADER_PARAM',
    'CONTAINER_KDF_PARAMS_OUT_OF_BOUNDS',
  ]);
  const KNOWN_CONTAINER_TYPES = new Set<CryptoErrorType>([
    CryptoErrorType.INVALID_INPUT,
    CryptoErrorType.DECRYPTION_FAILED,
  ]);

  function assertWellFormed(result: ParsedV2Container): void {
    expect(result.header.length).toBe(HEADER_LENGTH);
    expect(result.salt.length).toBe(32);
    expect(result.kekIv.length).toBe(12);
    expect(result.wrappedDek.length).toBe(32);
    expect(result.kekTag.length).toBe(16);
    expect(result.metaIv.length).toBe(12);
    expect(result.metaTag.length).toBe(16);
    expect(result.dataIv.length).toBe(12);
    expect(result.dataTag.length).toBe(16);
    expect(result.encMeta.length).toBeGreaterThanOrEqual(0);
    expect(result.encData.length).toBeGreaterThanOrEqual(0);
    const { memoryCost, timeCost, parallelism } = result.argonParams;
    expect(memoryCost).toBeGreaterThan(0);
    expect(memoryCost).toBeLessThanOrEqual(MAX_ARGON2_MEMORY_COST);
    expect(timeCost).toBeGreaterThan(0);
    expect(timeCost).toBeLessThanOrEqual(MAX_ARGON2_TIME_COST);
    expect(parallelism).toBeGreaterThan(0);
    expect(parallelism).toBeLessThanOrEqual(MAX_ARGON2_PARALLELISM);
    // RFC 9106 floor holds for any successfully-parsed container header.
    expect(memoryCost).toBeGreaterThanOrEqual(8 * parallelism);
  }

  function checkOutcome(
    outcome:
      | { ok: true; value: ParsedV2Container }
      | { ok: false; error: unknown }
  ): void {
    if (outcome.ok) {
      assertWellFormed(outcome.value);
    } else {
      expect(outcome.error).toBeInstanceOf(CryptoError);
      const err = outcome.error as CryptoError;
      expect(KNOWN_CONTAINER_TYPES.has(err.type)).toBe(true);
      expect(KNOWN_CONTAINER_CODES.has(err.code)).toBe(true);
    }
  }

  it('random bytes: returns a valid ParsedV2Container OR throws a known CryptoError', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 1024 }), bytes => {
        checkOutcome(safelyRun(() => parseV2Container(Uint8Array.from(bytes))));
      }),
      FUZZ_CONFIG
    );
  });

  it('magic+version-prefixed bytes: deeper param/length branches stay safe', () => {
    // Force "HPCR" + version 0x02 + kdfId 0x00 so the fuzzer reaches the KDF
    // param and metaLen-length branches instead of bouncing off the magic
    // check. Length >= the fixed overhead so metaLen is always reachable.
    const arb = fc
      .uint8Array({ minLength: 174, maxLength: 1024 })
      .map(bytes => {
        const buf = Uint8Array.from(bytes);
        buf[0] = 0x48; // H
        buf[1] = 0x50; // P
        buf[2] = 0x43; // C
        buf[3] = 0x52; // R
        buf[4] = CONTAINER_VERSION; // 0x02
        buf[5] = KDF_ID_ARGON2ID; // 0x00
        return buf;
      });
    fc.assert(
      fc.property(arb, buf => {
        checkOutcome(safelyRun(() => parseV2Container(buf)));
      }),
      FUZZ_CONFIG
    );
  });

  it('truncating a real container below the fixed overhead always throws TRUNCATED_CONTAINER', async () => {
    const node = new NodeCryptoManager(LOW_COST);
    const container = await node.encryptContainer(fillerBytes(32), PASSWORD);
    for (let len = 0; len < 174; len += 7) {
      const outcome = safelyRun(() =>
        parseV2Container(container.subarray(0, len))
      );
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) {
        expect(outcome.error).toBeInstanceOf(CryptoError);
        expect((outcome.error as CryptoError).code).toBe('TRUNCATED_CONTAINER');
      }
    }
  });
});

// ===========================================================================
// 10. Metadata codec — round-trip + malformed-block rejection + fuzz.
//
// parseV2Meta only ever sees GCM-authenticated bytes in production, but it is
// defensively strict; these tests pin the format and cover its reject paths.
// ===========================================================================
describe('serializeV2Meta / parseV2Meta', () => {
  const SHA = new Uint8Array(32).fill(0x7e);

  it('round-trips all fields', () => {
    const bytes = serializeV2Meta({
      size: 123456,
      sha256: SHA,
      filename: utf8Encode('document.txt'),
      mime: utf8Encode('text/plain'),
    });
    const parsed = parseV2Meta(bytes);
    expect(parsed.size).toBe(123456);
    expect(bytesToHex(parsed.sha256)).toBe(bytesToHex(SHA));
    expect(parsed.filename).toBe('document.txt');
    expect(parsed.mime).toBe('text/plain');
  });

  it('round-trips with no optional fields (37-byte fixed block)', () => {
    const bytes = serializeV2Meta({
      size: 0,
      sha256: SHA,
      filename: undefined,
      mime: undefined,
    });
    expect(bytes.length).toBe(37);
    const parsed = parseV2Meta(bytes);
    expect(parsed.size).toBe(0);
    expect(parsed.filename).toBeUndefined();
    expect(parsed.mime).toBeUndefined();
  });

  it('returns a fresh sha256 copy independent of the source block', () => {
    const bytes = serializeV2Meta({
      size: 1,
      sha256: SHA,
      filename: undefined,
      mime: undefined,
    });
    const parsed = parseV2Meta(bytes);
    bytes.fill(0); // scrub the source
    expect(bytesToHex(parsed.sha256)).toBe(bytesToHex(SHA));
  });

  it('rejects a block shorter than the fixed prefix', () => {
    expect(() => parseV2Meta(new Uint8Array(36))).toThrow(CryptoError);
    try {
      parseV2Meta(new Uint8Array(36));
    } catch (err) {
      expect((err as CryptoError).code).toBe('CONTAINER_METADATA_MALFORMED');
    }
  });

  it('rejects a truncated length prefix', () => {
    // flags = filename present, but only 1 byte where the u16 length must be.
    const block = new Uint8Array(38);
    block[0] = 0x01;
    expect(() => parseV2Meta(block)).toThrow(CryptoError);
  });

  it('rejects a length prefix that overruns the block', () => {
    // flags = filename present; declared length 100 but no bytes follow.
    const block = new Uint8Array(39);
    block[0] = 0x01;
    new DataView(block.buffer).setUint16(37, 100, false);
    try {
      parseV2Meta(block);
      throw new Error('expected parseV2Meta to throw');
    } catch (err) {
      expect((err as CryptoError).code).toBe('CONTAINER_METADATA_MALFORMED');
    }
  });

  it('rejects unknown flag bits', () => {
    const block = new Uint8Array(37);
    block[0] = 0x04; // undefined flag bit
    try {
      parseV2Meta(block);
      throw new Error('expected parseV2Meta to throw');
    } catch (err) {
      expect((err as CryptoError).code).toBe('CONTAINER_METADATA_MALFORMED');
    }
  });

  it('rejects trailing bytes', () => {
    const block = new Uint8Array(38); // 37-byte prefix, flags=0, + 1 stray byte
    try {
      parseV2Meta(block);
      throw new Error('expected parseV2Meta to throw');
    } catch (err) {
      expect((err as CryptoError).code).toBe('CONTAINER_METADATA_MALFORMED');
    }
  });

  it('fuzz: random bytes parse cleanly OR throw CONTAINER_METADATA_MALFORMED', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), bytes => {
        const outcome = safelyRun(() => parseV2Meta(Uint8Array.from(bytes)));
        if (outcome.ok) {
          expect(outcome.value.sha256.length).toBe(32);
          expect(Number.isInteger(outcome.value.size)).toBe(true);
        } else {
          expect(outcome.error).toBeInstanceOf(CryptoError);
          expect((outcome.error as CryptoError).code).toBe(
            'CONTAINER_METADATA_MALFORMED'
          );
        }
      }),
      { numRuns: 1000, endOnFailure: true, seed: 0x5eed }
    );
  });
});

// ===========================================================================
// 11. Deterministic byte-layout snapshot for the v2 container.
//
// Mocks argon2 (fixed KEK) and the engine CSPRNG (distinct-per-call bytes) so
// the container is fully deterministic; SHA-256 and AES-GCM stay real (both are
// byte-stable). Any field re-order, endian flip, or offset shift diffs the
// checked-in snapshot loudly.
// ===========================================================================
describe('v2 container byte-layout snapshot', () => {
  const SNAP_PASSWORD = 'SnapshotContainerP@ssw0rd123!';

  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
    jest.restoreAllMocks();
  });

  it('produces a stable v2 byte layout for fixed input + KDF + CSPRNG', async () => {
    // Mock native argon2 so the KEK is a fixed 32 bytes of 0xCC, isolating the
    // snapshot from the real Argon2id implementation.
    jest.unstable_mockModule('argon2', () => ({
      argon2id: 2,
      hash: jest.fn(async () => Buffer.alloc(32, 0xcc)),
    }));
    const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
      await import('../crypto-manager');
    const coreMod = await import('../core');
    // Spy the SAME engine instance the dynamically-imported manager uses.
    const { nodeEngine } = await import('../engine.node');
    __resetArgon2ModuleCacheForTesting();

    // Distinct-per-call deterministic CSPRNG (order: salt, DEK, kekIv, metaIv,
    // dataIv). Distinct fills avoid degenerate IV/key reuse while staying
    // reproducible, so the checked-in snapshot is stable.
    let callIndex = 0;
    jest
      .spyOn(nodeEngine, 'randomBytes')
      .mockImplementation((length: number) => {
        const bytes = new Uint8Array(length).fill((0xa0 + callIndex) & 0xff);
        callIndex += 1;
        return bytes;
      });

    const cm = new CryptoManager(LOW_COST);
    const data = utf8Encode('snapshot-container-payload');
    const container = await cm.encryptContainer(data, SNAP_PASSWORD, {
      filename: 'note.txt',
      mime: 'text/plain',
    });
    const buf = Buffer.from(container);

    // ---- format-version + magic guard rails (fire before the hex diff) ----
    expect(buf.subarray(0, 4).toString('ascii')).toBe('HPCR');
    expect(buf.readUInt8(4)).toBe(CONTAINER_VERSION); // 0x02
    expect(buf.readUInt8(5)).toBe(KDF_ID_ARGON2ID); // 0x00
    // salt + DEK + 3 IVs were drawn (no CSPRNG use on decrypt).
    expect(callIndex).toBe(5);

    // ---- whole-container byte-layout snapshot ----
    expect(buf.toString('hex')).toMatchSnapshot('v2 container full hex dump');

    // ---- structural decomposition (doubles as a wire-format spec) ----
    const parsed = coreMod.parseV2Container(container);
    expect(Buffer.from(parsed.header).toString('hex')).toMatchSnapshot(
      'v2 header (22 bytes)'
    );
    expect(Buffer.from(parsed.salt).toString('hex')).toMatchSnapshot(
      'v2 salt (32 bytes)'
    );
    expect(Buffer.from(parsed.kekIv).toString('hex')).toMatchSnapshot(
      'v2 kekIv (12 bytes)'
    );
    expect(Buffer.from(parsed.wrappedDek).toString('hex')).toMatchSnapshot(
      'v2 wrappedDek (32 bytes)'
    );
    expect(Buffer.from(parsed.kekTag).toString('hex')).toMatchSnapshot(
      'v2 kekTag (16 bytes)'
    );
    expect(Buffer.from(parsed.metaIv).toString('hex')).toMatchSnapshot(
      'v2 metaIv (12 bytes)'
    );
    expect(parsed.encMeta.length).toMatchSnapshot('v2 encMeta length');
    expect(Buffer.from(parsed.encMeta).toString('hex')).toMatchSnapshot(
      'v2 encMeta body'
    );
    expect(Buffer.from(parsed.metaTag).toString('hex')).toMatchSnapshot(
      'v2 metaTag (16 bytes)'
    );
    expect(Buffer.from(parsed.dataIv).toString('hex')).toMatchSnapshot(
      'v2 dataIv (12 bytes)'
    );
    expect(Buffer.from(parsed.encData).toString('hex')).toMatchSnapshot(
      'v2 encData body'
    );
    expect(Buffer.from(parsed.dataTag).toString('hex')).toMatchSnapshot(
      'v2 dataTag (16 bytes)'
    );

    // The payload ciphertext length equals the plaintext length (GCM streams).
    expect(parsed.encData.length).toBe(data.length);

    // ---- round-trip sanity under the same mocks ----
    const { data: back, meta } = await cm.decryptContainer(
      container,
      SNAP_PASSWORD
    );
    expect(Buffer.from(back).toString('utf8')).toBe(
      'snapshot-container-payload'
    );
    expect(meta).toEqual({
      filename: 'note.txt',
      mime: 'text/plain',
      size: data.length,
    });
  });
});
