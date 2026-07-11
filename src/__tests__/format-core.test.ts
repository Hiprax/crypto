/**
 * Tests for the pure `Uint8Array`/`DataView` format layer (`src/format-core.ts`).
 *
 * `format-core.ts` holds the real header logic; `format.ts` is a thin Node
 * `Buffer` wrapper over it. These tests assert two things the split must
 * guarantee:
 *
 *   1. **Byte identity** — `format-core.packHeader` produces byte-for-byte the
 *      same header as the `format.ts` wrapper, for both KDFs and many params.
 *   2. **Pooled-buffer safety** — `parseHeader` reads through
 *      `new DataView(buf.buffer, buf.byteOffset, buf.byteLength)`, so it parses
 *      a header living at a NON-ZERO `byteOffset` (a `subarray()` view or a
 *      Node-pooled `Buffer`) correctly. A regression to `new DataView(buf.buffer)`
 *      would read from the start of the shared backing store and fail here.
 *
 * Plus: parity of every constant/type/error code with `format.ts`, round-trip
 * pack->parse, and the full documented error-code set.
 */
import { describe, it, expect } from '@jest/globals';
import { CryptoError, CryptoErrorType } from '../types';
import {
  packHeader as packHeaderCore,
  parseHeader as parseHeaderCore,
  hasMagic as hasMagicCore,
  MAGIC_BYTES as MAGIC_BYTES_CORE,
  HEADER_LENGTH,
  MAGIC_LENGTH,
  FORMAT_VERSION,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  MAX_ARGON2_MEMORY_COST,
  MAX_ARGON2_TIME_COST,
  MAX_ARGON2_PARALLELISM,
  MAX_PBKDF2_ITERATIONS,
} from '../format-core';
import {
  packHeader as packHeaderBuf,
  parseHeader as parseHeaderBuf,
  hasMagic as hasMagicBuf,
  MAGIC_BYTES as MAGIC_BYTES_BUF,
  HEADER_LENGTH as HEADER_LENGTH_BUF,
} from '../format';

/** A representative spread of Argon2id header params. */
const ARGON2_CASES = [
  { memoryCost: 8, timeCost: 1, parallelism: 1 },
  { memoryCost: 2 ** 14, timeCost: 3, parallelism: 1 },
  { memoryCost: 2 ** 17, timeCost: 3, parallelism: 1 },
  { memoryCost: 2 ** 19, timeCost: 4, parallelism: 4 },
  { memoryCost: MAX_ARGON2_MEMORY_COST, timeCost: 100, parallelism: 64 },
] as const;

/** A representative spread of PBKDF2 iteration counts. */
const PBKDF2_CASES = [1, 1000, 100000, 600000, MAX_PBKDF2_ITERATIONS] as const;

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

describe('format-core: constant parity with format.ts', () => {
  it('shares identical numeric constants', () => {
    expect(HEADER_LENGTH).toBe(HEADER_LENGTH_BUF);
    expect(HEADER_LENGTH).toBe(22);
    expect(MAGIC_LENGTH).toBe(4);
    expect(FORMAT_VERSION).toBe(0x01);
    expect(KDF_ID_ARGON2ID).toBe(0x00);
    expect(KDF_ID_PBKDF2_SHA256).toBe(0x01);
    expect(MAX_ARGON2_MEMORY_COST).toBe(2 ** 22);
    expect(MAX_ARGON2_TIME_COST).toBe(100);
    expect(MAX_ARGON2_PARALLELISM).toBe(64);
    expect(MAX_PBKDF2_ITERATIONS).toBe(10_000_000);
  });

  it('MAGIC_BYTES is the ASCII "HPCR" bytes as a plain Uint8Array', () => {
    expect(Array.from(MAGIC_BYTES_CORE)).toEqual([0x48, 0x50, 0x43, 0x52]);
    expect(MAGIC_BYTES_CORE).toBeInstanceOf(Uint8Array);
    // The wrapper re-exports a byte-identical Node Buffer copy.
    expect(Buffer.isBuffer(MAGIC_BYTES_BUF)).toBe(true);
    expect(bytesEqual(MAGIC_BYTES_CORE, MAGIC_BYTES_BUF)).toBe(true);
  });
});

describe('format-core: packHeader byte-identity with format.ts', () => {
  it('produces byte-identical Argon2id headers', () => {
    for (const params of ARGON2_CASES) {
      const core = packHeaderCore(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        ...params,
      });
      const buf = packHeaderBuf(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        ...params,
      });
      expect(core.length).toBe(HEADER_LENGTH);
      expect(bytesEqual(core, buf)).toBe(true);
    }
  });

  it('produces byte-identical PBKDF2 headers', () => {
    for (const iterations of PBKDF2_CASES) {
      const core = packHeaderCore(KDF_ID_PBKDF2_SHA256, {
        kind: 'pbkdf2-sha256',
        iterations,
      });
      const buf = packHeaderBuf(KDF_ID_PBKDF2_SHA256, {
        kind: 'pbkdf2-sha256',
        iterations,
      });
      expect(core.length).toBe(HEADER_LENGTH);
      expect(bytesEqual(core, buf)).toBe(true);
    }
  });

  it('the core packHeader returns a plain Uint8Array, the wrapper a Buffer', () => {
    const core = packHeaderCore(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 14,
      timeCost: 1,
      parallelism: 1,
    });
    const buf = packHeaderBuf(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 14,
      timeCost: 1,
      parallelism: 1,
    });
    expect(core).toBeInstanceOf(Uint8Array);
    expect(Buffer.isBuffer(core)).toBe(false);
    expect(Buffer.isBuffer(buf)).toBe(true);
  });

  it('zero-fills the reserved bytes for both KDFs', () => {
    const argon = packHeaderCore(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 1,
      timeCost: 1,
      parallelism: 1,
    });
    // Argon2id uses 10 of 16 param bytes; the last 6 must be zero.
    for (let i = 6 + 10; i < 6 + 16; i += 1) {
      expect(argon[i]).toBe(0);
    }
    const pbkdf2 = packHeaderCore(KDF_ID_PBKDF2_SHA256, {
      kind: 'pbkdf2-sha256',
      iterations: 1,
    });
    // PBKDF2 uses 4 of 16 param bytes; the last 12 must be zero.
    for (let i = 6 + 4; i < 6 + 16; i += 1) {
      expect(pbkdf2[i]).toBe(0);
    }
  });
});

describe('format-core: pack -> parse round-trip', () => {
  it('round-trips Argon2id params', () => {
    for (const params of ARGON2_CASES) {
      const header = packHeaderCore(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        ...params,
      });
      const parsed = parseHeaderCore(header);
      expect(parsed.version).toBe(FORMAT_VERSION);
      expect(parsed.kdfId).toBe(KDF_ID_ARGON2ID);
      expect(parsed.headerLen).toBe(HEADER_LENGTH);
      expect(parsed.params).toEqual({ kind: 'argon2id', ...params });
    }
  });

  it('round-trips PBKDF2 iterations', () => {
    for (const iterations of PBKDF2_CASES) {
      const header = packHeaderCore(KDF_ID_PBKDF2_SHA256, {
        kind: 'pbkdf2-sha256',
        iterations,
      });
      const parsed = parseHeaderCore(header);
      expect(parsed.kdfId).toBe(KDF_ID_PBKDF2_SHA256);
      expect(parsed.params).toEqual({ kind: 'pbkdf2-sha256', iterations });
    }
  });

  it('the core and wrapper parse to deep-equal results', () => {
    const header = packHeaderCore(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 17,
      timeCost: 3,
      parallelism: 2,
    });
    expect(parseHeaderCore(header)).toEqual(
      parseHeaderBuf(Buffer.from(header))
    );
  });
});

describe('format-core: pooled-buffer / non-zero byteOffset safety', () => {
  it('parses a header at a non-zero byteOffset in a shared Uint8Array', () => {
    const header = packHeaderCore(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
    // Place the header inside a larger backing store at offset 7 and hand
    // parseHeader the subarray view — this is exactly the shape a pooled
    // Node Buffer or a `.subarray()` slice has.
    const backing = new Uint8Array(64);
    backing.fill(0xcd); // poison the surrounding bytes
    backing.set(header, 7);
    const view = backing.subarray(7, 7 + HEADER_LENGTH);
    expect(view.byteOffset).toBe(7);
    expect(view.length).toBe(HEADER_LENGTH);

    const parsed = parseHeaderCore(view);
    expect(parsed.params).toEqual({
      kind: 'argon2id',
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
    expect(hasMagicCore(view)).toBe(true);
  });

  it('parses a header from a pooled Node Buffer (non-zero byteOffset)', () => {
    const header = packHeaderCore(KDF_ID_PBKDF2_SHA256, {
      kind: 'pbkdf2-sha256',
      iterations: 600000,
    });
    const backingBuf = Buffer.alloc(64, 0xcd);
    Buffer.from(header).copy(backingBuf, 5);
    const pooled = backingBuf.subarray(5, 5 + HEADER_LENGTH);
    expect(pooled.byteOffset).toBe(5);

    // Both the core parser and the wrapper must read the right region.
    expect(parseHeaderCore(pooled).params).toEqual({
      kind: 'pbkdf2-sha256',
      iterations: 600000,
    });
    expect(parseHeaderBuf(pooled).params).toEqual({
      kind: 'pbkdf2-sha256',
      iterations: 600000,
    });
    expect(hasMagicBuf(pooled)).toBe(true);
  });

  it('parses a plain Uint8Array header (byteOffset 0)', () => {
    const header = packHeaderCore(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 15,
      timeCost: 3,
      parallelism: 1,
    });
    const plain = Uint8Array.from(header);
    expect(plain.byteOffset).toBe(0);
    expect(plain).toBeInstanceOf(Uint8Array);
    expect(Buffer.isBuffer(plain)).toBe(false);
    expect(parseHeaderCore(plain).params).toEqual({
      kind: 'argon2id',
      memoryCost: 2 ** 15,
      timeCost: 3,
      parallelism: 1,
    });
  });
});

describe('format-core: hasMagic', () => {
  it('detects the magic on Uint8Array, Buffer, and views', () => {
    expect(hasMagicCore(new Uint8Array([0x48, 0x50, 0x43, 0x52]))).toBe(true);
    expect(hasMagicCore(new Uint8Array([0x48, 0x50, 0x43]))).toBe(false); // too short
    expect(hasMagicCore(new Uint8Array([0x58, 0x58, 0x58, 0x58]))).toBe(false);
    expect(hasMagicCore(new Uint8Array(0))).toBe(false);
    expect(hasMagicCore(Buffer.from('HPCR'))).toBe(true);
    expect(hasMagicCore(Buffer.from('nope'))).toBe(false);
  });
});

describe('format-core: preserved error codes and types', () => {
  function craftHeader(): Buffer {
    // Valid Argon2id header as a mutable Buffer for negative-case tweaks.
    return Buffer.from(
      packHeaderCore(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        memoryCost: 2 ** 14,
        timeCost: 3,
        parallelism: 1,
      })
    );
  }

  function expectCryptoError(
    fn: () => unknown,
    code: string,
    type?: CryptoErrorType
  ): void {
    expect(fn).toThrow(CryptoError);
    try {
      fn();
    } catch (error) {
      expect(error).toBeInstanceOf(CryptoError);
      expect((error as CryptoError).code).toBe(code);
      if (type !== undefined) {
        expect((error as CryptoError).type).toBe(type);
      }
    }
  }

  it('INVALID_HEADER_INPUT for a non-Uint8Array input', () => {
    expectCryptoError(
      () => parseHeaderCore([] as unknown as Uint8Array),
      'INVALID_HEADER_INPUT',
      CryptoErrorType.INVALID_INPUT
    );
  });

  it('TRUNCATED_HEADER for a short input', () => {
    expectCryptoError(
      () => parseHeaderCore(new Uint8Array(HEADER_LENGTH - 1)),
      'TRUNCATED_HEADER',
      CryptoErrorType.INVALID_INPUT
    );
  });

  it('INVALID_MAGIC for a full-length header without the magic', () => {
    expectCryptoError(
      () => parseHeaderCore(new Uint8Array(HEADER_LENGTH)),
      'INVALID_MAGIC',
      CryptoErrorType.DECRYPTION_FAILED
    );
  });

  it('UNSUPPORTED_VERSION for a bad version byte', () => {
    const buf = craftHeader();
    buf.writeUInt8(0x99, MAGIC_LENGTH);
    expectCryptoError(
      () => parseHeaderCore(buf),
      'UNSUPPORTED_VERSION',
      CryptoErrorType.DECRYPTION_FAILED
    );
  });

  it('UNSUPPORTED_KDF for an unknown kdfId byte', () => {
    const buf = craftHeader();
    buf.writeUInt8(0x77, MAGIC_LENGTH + 1);
    expectCryptoError(
      () => parseHeaderCore(buf),
      'UNSUPPORTED_KDF',
      CryptoErrorType.DECRYPTION_FAILED
    );
  });

  it('INVALID_HEADER_PARAM for zero Argon2id params', () => {
    const buf = Buffer.from(
      packHeaderCore(KDF_ID_ARGON2ID, {
        kind: 'argon2id',
        memoryCost: 1,
        timeCost: 1,
        parallelism: 1,
      })
    );
    buf.fill(0, 6); // zero the whole 16-byte param block
    expectCryptoError(
      () => parseHeaderCore(buf),
      'INVALID_HEADER_PARAM',
      CryptoErrorType.DECRYPTION_FAILED
    );
  });

  it('INVALID_HEADER_PARAM for the RFC 9106 memoryCost < 8*parallelism floor', () => {
    const buf = craftHeader();
    buf.writeUInt32BE(8, 6); // memoryCost = 8
    buf.writeUInt32BE(1, 10); // timeCost = 1
    buf.writeUInt16BE(64, 14); // parallelism = 64 -> floor 512 > 8
    expectCryptoError(
      () => parseHeaderCore(buf),
      'INVALID_HEADER_PARAM',
      CryptoErrorType.DECRYPTION_FAILED
    );
  });

  it('KDF_PARAMS_OUT_OF_BOUNDS for Argon2id memoryCost above the cap', () => {
    const buf = craftHeader();
    buf.writeUInt32BE(MAX_ARGON2_MEMORY_COST + 1, 6);
    buf.writeUInt32BE(1, 10);
    buf.writeUInt16BE(1, 14);
    expectCryptoError(
      () => parseHeaderCore(buf),
      'KDF_PARAMS_OUT_OF_BOUNDS',
      CryptoErrorType.INVALID_INPUT
    );
  });

  it('KDF_PARAMS_OUT_OF_BOUNDS for PBKDF2 iterations above the cap', () => {
    const buf = Buffer.from(
      packHeaderCore(KDF_ID_PBKDF2_SHA256, {
        kind: 'pbkdf2-sha256',
        iterations: 1000,
      })
    );
    buf.writeUInt32BE(MAX_PBKDF2_ITERATIONS + 1, 6);
    expectCryptoError(
      () => parseHeaderCore(buf),
      'KDF_PARAMS_OUT_OF_BOUNDS',
      CryptoErrorType.INVALID_INPUT
    );
  });

  it('HEADER_KDF_MISMATCH when packHeader kdfId and params.kind disagree', () => {
    expectCryptoError(
      () =>
        packHeaderCore(KDF_ID_ARGON2ID, {
          kind: 'pbkdf2-sha256',
          iterations: 1,
        }),
      'HEADER_KDF_MISMATCH',
      CryptoErrorType.INVALID_INPUT
    );
    expectCryptoError(
      () =>
        packHeaderCore(KDF_ID_PBKDF2_SHA256, {
          kind: 'argon2id',
          memoryCost: 1,
          timeCost: 1,
          parallelism: 1,
        }),
      'HEADER_KDF_MISMATCH',
      CryptoErrorType.INVALID_INPUT
    );
  });

  it('UNSUPPORTED_KDF when packHeader is given an unknown kdfId', () => {
    expectCryptoError(
      () =>
        packHeaderCore(0x09 as unknown as typeof KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 1,
          timeCost: 1,
          parallelism: 1,
        }),
      'UNSUPPORTED_KDF',
      CryptoErrorType.INVALID_INPUT
    );
  });

  it('INVALID_HEADER_PARAM when packHeader gets an out-of-range u32/u16', () => {
    expectCryptoError(
      () =>
        packHeaderCore(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 0xffffffff + 1,
          timeCost: 3,
          parallelism: 1,
        }),
      'INVALID_HEADER_PARAM',
      CryptoErrorType.INVALID_INPUT
    );
    expectCryptoError(
      () =>
        packHeaderCore(KDF_ID_ARGON2ID, {
          kind: 'argon2id',
          memoryCost: 1,
          timeCost: 1,
          parallelism: 0x10000,
        }),
      'INVALID_HEADER_PARAM',
      CryptoErrorType.INVALID_INPUT
    );
  });
});

describe('format.ts wrapper: preserves the Buffer-only input contract', () => {
  it('wrapper hasMagic/parseHeader reject a plain Uint8Array; core accepts it', () => {
    const header = packHeaderCore(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 14,
      timeCost: 3,
      parallelism: 1,
    });
    const plain = Uint8Array.from(header); // genuine Uint8Array, NOT a Buffer
    expect(Buffer.isBuffer(plain)).toBe(false);

    // The Node Buffer wrapper keeps its ORIGINAL contract: a non-Buffer input
    // is rejected exactly as before (false / INVALID_HEADER_INPUT).
    expect(hasMagicBuf(plain as unknown as Buffer)).toBe(false);
    expect(() => parseHeaderBuf(plain as unknown as Buffer)).toThrow(
      CryptoError
    );
    try {
      parseHeaderBuf(plain as unknown as Buffer);
    } catch (error) {
      expect((error as CryptoError).code).toBe('INVALID_HEADER_INPUT');
      expect((error as CryptoError).type).toBe(CryptoErrorType.INVALID_INPUT);
    }

    // The pure core INTENTIONALLY accepts any Uint8Array (isomorphic use).
    expect(hasMagicCore(plain)).toBe(true);
    expect(parseHeaderCore(plain).params).toEqual({
      kind: 'argon2id',
      memoryCost: 2 ** 14,
      timeCost: 3,
      parallelism: 1,
    });

    // A real Buffer round-trips through the wrapper as it always has.
    const asBuffer = Buffer.from(header);
    expect(hasMagicBuf(asBuffer)).toBe(true);
    expect(parseHeaderBuf(asBuffer).params).toEqual({
      kind: 'argon2id',
      memoryCost: 2 ** 14,
      timeCost: 3,
      parallelism: 1,
    });
  });
});
