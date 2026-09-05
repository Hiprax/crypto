/**
 * Tests for the pure, isomorphic codec (`src/codec.ts`).
 *
 * The codec is the single source of truth for base64url / hex / UTF-8
 * transcoding used by both the Node and browser builds. It uses ONLY
 * `Uint8Array` / `TextEncoder` / `TextDecoder` (no Node `Buffer`), so these
 * tests pin its output to be BYTE-FOR-BYTE identical to Node's built-in
 * byte-buffer operations. Node's `Buffer` is used here purely as the trusted
 * oracle — the codec itself never touches it.
 *
 * Coverage:
 *   - `bytesToBase64url` equals `Buffer.from(b).toString('base64url')`.
 *   - `base64urlToBytes` equals `new Uint8Array(Buffer.from(s,'base64url'))`
 *     for canonical input, and round-trips every `Uint8Array`.
 *   - `isValidBase64url` agrees with the historical Node round-trip validator
 *     for arbitrary strings (incl. padding / bad chars / bad length) and never
 *     throws.
 *   - `isValidBase64url` is exactly equivalent to the historical
 *     decode-then-re-encode definition it replaced, i.e.
 *     `isValidBase64url(s) === (bytesToBase64url(base64urlToBytes(s)) === s &&
 *     s.length > 0)`, at every `length % 4` residue and for the traps a naive
 *     structural check falls into (a code unit >= 256 whose low byte aliases
 *     an alphabet character, the standard-alphabet `+` / `/`, and testing the
 *     final character's UTF-16 CODE UNIT instead of its decoded 6-bit SEXTET).
 *   - The chunked encoder is byte-identical to Buffer across its internal
 *     flush boundary and neither mutates nor retains its input.
 *   - `bytesToHex`, `utf8Encode`, `utf8Decode`, `concatBytes` equal their
 *     Node counterparts, incl. padding boundaries (lengths 0..3) and
 *     multi-byte Unicode.
 */
import { describe, it, expect } from '@jest/globals';
import fc from 'fast-check';
import {
  bytesToBase64url,
  base64urlToBytes,
  isValidBase64url,
  bytesToHex,
  utf8Encode,
  utf8Decode,
  concatBytes,
} from '../codec';

const FC_RUNS = { numRuns: 600 } as const;

const B64URL_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Compare two byte arrays by value. */
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

/**
 * The historical `utils.isValidBase64Url` implementation, reproduced here as
 * the oracle the delegated codec must match exactly (including the falsy /
 * non-string short-circuit and the "never throw" contract).
 */
function oracleIsValidBase64Url(str: string): boolean {
  if (!str || typeof str !== 'string') {
    return false;
  }
  try {
    const decoded = Buffer.from(str, 'base64url');
    return decoded.toString('base64url') === str;
  } catch {
    return false;
  }
}

/**
 * Code units that stress every branch of the decoder's leniency contract AND
 * every trap in the canonical-form check: both base64 alphabets, `=`, ASCII
 * whitespace / line wrapping, stray punctuation, code units >= 256 whose LOW
 * BYTE aliases an alphabet character or `=`, a surrogate pair, and lone
 * surrogate halves.
 */
const ADVERSARIAL_CODE_UNITS: number[] = [
  0x41,
  0x42,
  0x51,
  0x79,
  0x7a,
  0x30,
  0x39, // A B Q y z 0 9
  0x2d,
  0x5f, // - _ (the URL-safe alphabet)
  // + / : the standard alphabet. The LENIENT decoder accepts these as aliases;
  // the CANONICAL encoder never emits them.
  0x2b,
  0x2f,
  0x3d, // =
  0x20,
  0x09,
  0x0a,
  0x0d, // space, tab, LF, CR
  0x21,
  0x40,
  0x23, // ! @ #
  // U+0141 has low byte 0x41 ('A'); U+013D has low byte 0x3D ('=').
  0x0141,
  0x013d,
  0xd83d,
  0xde00, // the surrogate pair of U+1F600
  0xd800,
  0xdfff, // lone surrogate halves
];

/** Arbitrary string drawn from {@link ADVERSARIAL_CODE_UNITS}. */
const arbAdversarialString = fc
  .array(fc.constantFrom(...ADVERSARIAL_CODE_UNITS), {
    minLength: 0,
    maxLength: 32,
  })
  .map(codes => String.fromCharCode(...codes));

/**
 * The historical `isValidBase64url` definition: decode, re-encode, compare.
 * `isValidBase64url` is now an O(n) structural scan, and the ONLY thing that
 * makes that safe is that it accepts exactly the same set of strings this
 * round trip does. Expressed with the codec's OWN encoder / decoder (each
 * independently pinned to `Buffer` elsewhere in this file), plus the
 * `s.length > 0` clause the original `!s` short-circuit contributed.
 */
function oracleCanonicalRoundTrip(s: string): boolean {
  return bytesToBase64url(base64urlToBytes(s)) === s && s.length > 0;
}

describe('codec: bytesToBase64url', () => {
  it('matches Buffer base64url for random bytes (fast-check)', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), bytes => {
        const expected = Buffer.from(bytes).toString('base64url');
        expect(bytesToBase64url(bytes)).toBe(expected);
      }),
      FC_RUNS
    );
  });

  it('matches Buffer base64url at padding boundaries (lengths 0..5)', () => {
    for (let len = 0; len <= 5; len += 1) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i += 1) {
        bytes[i] = (i * 97 + 13) & 0xff;
      }
      expect(bytesToBase64url(bytes)).toBe(
        Buffer.from(bytes).toString('base64url')
      );
    }
  });

  it('produces no padding and the URL-safe alphabet', () => {
    // Bytes chosen to force the base64 `+` (0x3e) and `/` (0x3f) sextets,
    // which base64url must emit as `-` and `_` with no `=` padding.
    expect(bytesToBase64url(new Uint8Array([0xfb]))).toBe('-w'); // '+w' -> '-w'
    expect(bytesToBase64url(new Uint8Array([0xff]))).toBe('_w'); // '/w' -> '_w'
    expect(bytesToBase64url(new Uint8Array([0xff, 0xff]))).toBe('__8');
    expect(bytesToBase64url(new Uint8Array(0))).toBe('');
  });

  it('matches known RFC 4648 vectors', () => {
    const vectors: Array<[string, string]> = [
      ['', ''],
      ['f', 'Zg'],
      ['fo', 'Zm8'],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg'],
      ['fooba', 'Zm9vYmE'],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [text, expected] of vectors) {
      expect(bytesToBase64url(utf8Encode(text))).toBe(expected);
    }
  });

  it('matches Buffer base64url for a large payload', () => {
    const bytes = new Uint8Array(100_000);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = (i * 31) & 0xff;
    }
    expect(bytesToBase64url(bytes)).toBe(
      Buffer.from(bytes).toString('base64url')
    );
  });

  it('matches Buffer base64url over 0..4096-byte inputs (fast-check)', () => {
    // Wider than the 512-byte property above. Note 4096 bytes encodes to 5462
    // characters, still BELOW the 8192-character flush threshold, so this
    // property exercises the triple loop at depth but never a flush; the flush
    // itself is covered by the boundary test below.
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 4096 }), bytes => {
        expect(bytesToBase64url(bytes)).toBe(
          Buffer.from(bytes).toString('base64url')
        );
      }),
      FC_RUNS
    );
  });

  it('is byte-identical to Buffer across the internal flush boundary', () => {
    // The encoder emits into a scratch buffer flushed every 8192 output
    // characters, i.e. every 6144 input bytes. An off-by-one in the flush
    // condition, a scratch length that is not a multiple of 4, or a tail
    // written past the scratch would corrupt or truncate output at exactly
    // these lengths and nowhere else, which a random-length property can miss.
    // Cover both sides of the first TWO boundaries and every `len % 3`.
    const lengths: number[] = [];
    for (let len = 6140; len <= 6150; len += 1) {
      lengths.push(len);
    }
    for (let len = 12284; len <= 12294; len += 1) {
      lengths.push(len);
    }
    for (const len of lengths) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i += 1) {
        bytes[i] = (i * 31 + 7) & 0xff;
      }
      expect(bytesToBase64url(bytes)).toBe(
        Buffer.from(bytes).toString('base64url')
      );
    }
  });

  it('does not mutate its input and emits no padding or standard-alphabet character', () => {
    const bytes = new Uint8Array(9000);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = (i * 251 + 3) & 0xff;
    }
    const snapshot = Uint8Array.from(bytes);
    const encoded = bytesToBase64url(bytes);
    // Negative assertions: nothing was written back into the caller's buffer,
    // and no character outside the canonical URL-safe alphabet was emitted.
    expect(bytesEqual(bytes, snapshot)).toBe(true);
    expect(encoded).not.toMatch(/[=+/]/);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('emits only alphabet characters for out-of-contract array-like input', () => {
    // `bytesToBase64url` is a public export of both entry points, so a plain
    // JavaScript caller can hand it an array-like whose elements fall outside
    // 0..255. It must still emit only base64url characters, never a NUL from
    // an out-of-range lookup into the 64-entry alphabet table. Each of these
    // exercises a DIFFERENT table index: the two tail branches and the main
    // triple loop.
    // The expected strings are GOLDEN VALUES captured from the previous
    // implementation, so this also pins that the rewrite changed no output
    // byte even outside the declared type.
    const outOfRange: Array<[number[], string]> = [
      [[300], 'LA'], // remainder 1: a per-byte `b0 >> 2` would index 75
      [[-1], '_w'], // remainder 1: negative element
      [[0, 4096], 'EAA'], // remainder 2: a per-byte `b1 >> 4` would index 256
      [[300, 4096], 'PAA'], // remainder 2: both tail lookups out of range
      [[300, 4096, 70000], 'PRFw'], // remainder 0: the main triple loop
      [[1_000_000_000], 'AA'], // remainder 1: overflows int32 shifts
    ];
    for (const [elements, expected] of outOfRange) {
      const encoded = bytesToBase64url(elements as unknown as Uint8Array);
      expect(encoded).toBe(expected);
      // Negative: no NUL, and nothing outside the alphabet, may leak through
      // an out-of-range lookup into the 64-entry table.
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(encoded).not.toContain('\u0000');
    }
  });

  it('is unaffected by the size of the preceding call (per-call scratch)', () => {
    // What this pins is that NO state survives between calls: a large encode
    // followed by a small one (and vice versa) is exactly as correct as either
    // alone. A module-scope scratch sized on first use overflows or truncates
    // here. (It does NOT, and cannot, prove the memory-hygiene half of the
    // per-call rationale — that a correctly-sliced shared buffer would still
    // retain the last payload's characters. That property is unobservable
    // from outside; it is why the allocation is per call, not something a
    // test can assert.)
    const big = new Uint8Array(20_000);
    for (let i = 0; i < big.length; i += 1) {
      big[i] = (i * 13 + 5) & 0xff;
    }
    const small = new Uint8Array([0x01]);
    const bigExpected = Buffer.from(big).toString('base64url');
    const smallExpected = Buffer.from(small).toString('base64url');
    // ORDER IS LOAD-BEARING: the SMALL encode must come first. A module-scope
    // scratch sized on first use would then be 2 entries long, and the `big`
    // call below would silently drop every write past index 1 and emit a
    // 2-character string. If the big call came first, that same broken
    // implementation would size the scratch to 8192 and pass.
    expect(bytesToBase64url(small)).toBe(smallExpected);
    expect(bytesToBase64url(big)).toBe(bigExpected);
    expect(bytesToBase64url(new Uint8Array(0))).toBe('');
    expect(bytesToBase64url(small)).toBe(smallExpected);
    expect(bytesToBase64url(big)).toBe(bigExpected);
  });
});

describe('codec: base64urlToBytes', () => {
  it('round-trips every Uint8Array through encode -> decode (fast-check)', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), bytes => {
        const roundTripped = base64urlToBytes(bytesToBase64url(bytes));
        expect(bytesEqual(roundTripped, bytes)).toBe(true);
      }),
      FC_RUNS
    );
  });

  it('equals Buffer decode for canonical base64url (fast-check)', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), bytes => {
        const s = Buffer.from(bytes).toString('base64url');
        const mine = base64urlToBytes(s);
        const viaBuffer = new Uint8Array(Buffer.from(s, 'base64url'));
        expect(bytesEqual(mine, viaBuffer)).toBe(true);
      }),
      FC_RUNS
    );
  });

  it('accepts optional `=` padding (canonical output has none)', () => {
    // Standard-base64 padded forms decode to the same bytes as the unpadded
    // base64url form.
    expect(bytesEqual(base64urlToBytes('Zg=='), utf8Encode('f'))).toBe(true);
    expect(bytesEqual(base64urlToBytes('Zg'), utf8Encode('f'))).toBe(true);
    expect(bytesEqual(base64urlToBytes('Zm8='), utf8Encode('fo'))).toBe(true);
  });

  it('decodes empty string to empty bytes', () => {
    expect(base64urlToBytes('').length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Lenient decode parity with Node's `Buffer.from(s, 'base64url')`.
  //
  // The codec's documented contract (module JSDoc + PLAN.md) is byte-for-byte
  // equality with `new Uint8Array(Buffer.from(s, 'base64url'))` for ALL input,
  // not just canonical strings. Node's decoder is lenient: it terminates at
  // `=`, SKIPS whitespace / line wrapping / stray non-alphabet characters
  // (rather than truncating at them), and accepts the standard `+`/`/` alphabet
  // as an alias for `-`/`_`. These tests pin that leniency — the async
  // `decryptText` path relies on it to remain able to decode a ciphertext that
  // was line-wrapped or normalised to standard base64 in transit, exactly as
  // the pre-isomorphic `Buffer.from`-based path did.
  // ---------------------------------------------------------------------------
  describe('lenient decode (byte-parity with Buffer for non-canonical input)', () => {
    it('equals Buffer decode over a mixed alphabet incl. whitespace / +/ / = (fast-check)', () => {
      // A rich alphabet that stresses every leniency branch: both base64
      // alphabets, `=` padding, all ASCII whitespace, stray punctuation, and
      // non-ASCII code points.
      const mixed = 'ABCXYZabcxyz0129-_+/=!@.,*# \t\n\r\fé世'.split('');
      const arbMixed = fc
        .array(fc.constantFrom(...mixed), { minLength: 0, maxLength: 48 })
        .map(chars => chars.join(''));
      fc.assert(
        fc.property(arbMixed, s => {
          const mine = base64urlToBytes(s);
          const viaBuffer = new Uint8Array(Buffer.from(s, 'base64url'));
          expect(bytesEqual(mine, viaBuffer)).toBe(true);
        }),
        FC_RUNS
      );
    });

    it('equals Buffer decode over full-range code units incl. >=256 aliases and surrogates (fast-check)', () => {
      // Node's decoder truncates each UTF-16 code unit to its low 8 bits BEFORE
      // classifying it, so a character >= 256 whose low byte aliases a base64
      // char (or `=`) is meaningful (e.g. U+0141 'Ł' -> low byte 0x41 'A';
      // U+013D -> low byte 0x3D terminates; the surrogate half 0xD83D -> 0x3D
      // terminates too). A naive "skip all non-ASCII" decoder would DIVERGE
      // here — this property pins full byte-for-byte parity with Node over the
      // whole code-unit range, incl. lone/paired surrogates.
      const poolCodes: number[] = [];
      for (const c of B64URL_ALPHABET) poolCodes.push(c.charCodeAt(0));
      poolCodes.push(0x2b, 0x2f, 0x3d, 0x20, 0x09, 0x0a, 0x0d); // + / = ws
      for (let b = 0; b < 0x100; b += 13) poolCodes.push(0x100 + b); // >=256 aliases
      poolCodes.push(0xd83d, 0xde00, 0xd800, 0xdfff); // surrogate halves
      const arbUnit = fc
        .constantFrom(...poolCodes)
        .map(code => String.fromCharCode(code));
      const arbStr = fc
        .array(arbUnit, { minLength: 0, maxLength: 40 })
        .map(units => units.join(''));
      fc.assert(
        fc.property(arbStr, s => {
          const mine = base64urlToBytes(s);
          const viaBuffer = new Uint8Array(Buffer.from(s, 'base64url'));
          expect(bytesEqual(mine, viaBuffer)).toBe(true);
        }),
        { numRuns: 3000 }
      );

      // Explicit aliasing / surrogate-termination cases that a "skip all
      // non-ASCII" decoder gets wrong (would produce different byte lengths).
      const aliasCases = [
        'ŁŁŁŁ', // ŁŁŁŁ -> "AAAA" -> 3 zero bytes
        'QQ\u{1F600}QQ', // 😀 low byte 0x3D terminates -> "QQ" -> 1 byte
        'QQĽQQ', // Ľ low byte 0x3D terminates -> "QQ"
      ];
      for (const s of aliasCases) {
        expect(
          bytesEqual(
            base64urlToBytes(s),
            new Uint8Array(Buffer.from(s, 'base64url'))
          )
        ).toBe(true);
      }
    });

    it('skips interior whitespace / line wrapping instead of truncating', () => {
      // A ciphertext line-wrapped for MIME/PEM/YAML transport must decode to
      // the same bytes as the unwrapped form (Node skips the whitespace).
      const canonical = 'SGVsbG8gd29ybGQ'; // "Hello world"
      const expected = new Uint8Array(Buffer.from(canonical, 'base64url'));
      const wrapped = 'SGVsbG8g\nd29ybGQ';
      const spaced = 'SGVs bG8g d29y bGQ';
      const crlf = 'SGVsbG8g\r\nd29ybGQ';
      expect(bytesEqual(base64urlToBytes(wrapped), expected)).toBe(true);
      expect(bytesEqual(base64urlToBytes(spaced), expected)).toBe(true);
      expect(bytesEqual(base64urlToBytes(crlf), expected)).toBe(true);
      // Also byte-equal to Node for each mangled form.
      for (const s of [wrapped, spaced, crlf]) {
        expect(
          bytesEqual(
            base64urlToBytes(s),
            new Uint8Array(Buffer.from(s, 'base64url'))
          )
        ).toBe(true);
      }
    });

    it('accepts the standard base64 alphabet (+ and /) as -/_ aliases', () => {
      // 0x6b 0xef 0xdb encodes as url-safe "a-_b" and standard "a+/b".
      const bytes = new Uint8Array([0x6b, 0xef, 0xdb]);
      expect(bytesEqual(base64urlToBytes('a-_b'), bytes)).toBe(true);
      expect(bytesEqual(base64urlToBytes('a+/b'), bytes)).toBe(true);
      expect(
        bytesEqual(
          base64urlToBytes('a+/b'),
          new Uint8Array(Buffer.from('a+/b', 'base64url'))
        )
      ).toBe(true);
    });

    it('terminates at the first `=` (matches Node), ignoring trailing data', () => {
      // "YW=Jj": Node decodes only "YW" (1 byte 'a') and stops at '='.
      expect(bytesEqual(base64urlToBytes('YW=Jj'), utf8Encode('a'))).toBe(true);
      expect(
        bytesEqual(
          base64urlToBytes('YW=Jj'),
          new Uint8Array(Buffer.from('YW=Jj', 'base64url'))
        )
      ).toBe(true);
      // Canonical padded forms still decode to their unpadded bytes.
      expect(bytesEqual(base64urlToBytes('Zm9vYg=='), utf8Encode('foob'))).toBe(
        true
      );
    });

    it('skips a leading/trailing run of whitespace', () => {
      const canonical = 'Zm9vYmFy'; // "foobar"
      const expected = utf8Encode('foobar');
      expect(bytesEqual(base64urlToBytes('  Zm9vYmFy'), expected)).toBe(true);
      expect(bytesEqual(base64urlToBytes('Zm9vYmFy\n'), expected)).toBe(true);
      expect(bytesEqual(base64urlToBytes(' \tZm9vYmFy\r\n'), expected)).toBe(
        true
      );
      // Byte-equal to Node.
      expect(
        bytesEqual(
          base64urlToBytes(' \tZm9vYmFy\r\n'),
          new Uint8Array(Buffer.from(' \tZm9vYmFy\r\n', 'base64url'))
        )
      ).toBe(true);
      void canonical;
    });

    it('equals Buffer decode over arbitrary binary strings (fast-check)', () => {
      // Unrestricted UTF-16: whatever the generator produces, the decoder must
      // agree with Node byte-for-byte rather than diverging on some code unit
      // the curated pools above happen not to contain.
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 256, unit: 'binary' }),
          s => {
            expect(
              bytesEqual(
                base64urlToBytes(s),
                new Uint8Array(Buffer.from(s, 'base64url'))
              )
            ).toBe(true);
          }
        ),
        FC_RUNS
      );
    });

    it('equals Buffer decode over the adversarial alphabet (fast-check)', () => {
      fc.assert(
        fc.property(arbAdversarialString, s => {
          expect(
            bytesEqual(
              base64urlToBytes(s),
              new Uint8Array(Buffer.from(s, 'base64url'))
            )
          ).toBe(true);
        }),
        { numRuns: 3000 }
      );
    });

    it('never throws, for any string (fast-check + explicit extremes)', () => {
      // Negative contract: the decoder has NO rejection path at all. Every
      // string, however malformed, yields bytes — that is what lets
      // `decryptText` fail on the authentication tag rather than on a parse.
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 256, unit: 'binary' }),
          s => {
            expect(() => base64urlToBytes(s)).not.toThrow();
          }
        ),
        FC_RUNS
      );
      const extremes = [
        '',
        '=',
        '===',
        'A',
        '\u0000',
        '\ud800',
        '\udfff',
        ' '.repeat(1000),
        '='.repeat(1000),
        'A'.repeat(100_000),
      ];
      for (const s of extremes) {
        expect(() => base64urlToBytes(s)).not.toThrow();
        expect(
          bytesEqual(
            base64urlToBytes(s),
            new Uint8Array(Buffer.from(s, 'base64url'))
          )
        ).toBe(true);
      }
    });

    it('discards a trailing sextet that cannot complete a byte', () => {
      // 5 alphabet characters carry 30 bits: 3 whole bytes plus 6 orphan bits
      // that Node drops. A decoder that kept them would return 4 bytes.
      const five = 'Zm9vY';
      const decoded = base64urlToBytes(five);
      expect(decoded.length).toBe(3);
      expect(
        bytesEqual(decoded, new Uint8Array(Buffer.from(five, 'base64url')))
      ).toBe(true);
      // A single orphan character carries nothing at all.
      expect(base64urlToBytes('A').length).toBe(0);
      // Skipped characters do not count towards the sextet total, so the
      // orphan is still the 5th ALPHABET character, not the 5th code unit.
      expect(base64urlToBytes('Zm 9v Y').length).toBe(3);
    });
  });
});

describe('codec: isValidBase64url', () => {
  it('agrees with the historical Node validator over binary strings (fast-check)', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 256 }), s => {
        expect(isValidBase64url(s)).toBe(oracleIsValidBase64Url(s));
      }),
      FC_RUNS
    );
  });

  it('agrees with the historical Node validator over arbitrary UTF-16 (fast-check)', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 256, unit: 'binary' }),
        s => {
          expect(isValidBase64url(s)).toBe(oracleIsValidBase64Url(s));
        }
      ),
      FC_RUNS
    );
  });

  it('agrees with the historical Node validator over alphabet-only strings (fast-check)', () => {
    const arbAlphabetString = fc
      .array(fc.constantFrom(...B64URL_ALPHABET.split('')), {
        minLength: 0,
        maxLength: 40,
      })
      .map(chars => chars.join(''));
    fc.assert(
      fc.property(arbAlphabetString, s => {
        expect(isValidBase64url(s)).toBe(oracleIsValidBase64Url(s));
      }),
      FC_RUNS
    );
  });

  it('returns true for canonical encodings of random bytes (fast-check)', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 256 }), bytes => {
        const s = bytesToBase64url(bytes);
        // Empty input encodes to '' which the validator rejects (falsy
        // short-circuit, matching the historical util); every non-empty
        // canonical string must validate.
        expect(isValidBase64url(s)).toBe(s.length > 0);
      }),
      FC_RUNS
    );
  });

  it('rejects known non-canonical / invalid inputs', () => {
    expect(isValidBase64url('')).toBe(false); // empty
    expect(isValidBase64url('A')).toBe(false); // length % 4 === 1
    expect(isValidBase64url('AB')).toBe(false); // non-zero trailing bits
    expect(isValidBase64url('Zg==')).toBe(false); // padding is not canonical
    expect(isValidBase64url('Zm9v!')).toBe(false); // out-of-alphabet char
    expect(isValidBase64url('Zm+v')).toBe(false); // standard-base64 '+'
    expect(isValidBase64url('a b')).toBe(false); // whitespace
    expect(isValidBase64url('Zm9v')).toBe(true); // canonical "foo"
  });

  it('never throws for any input', () => {
    const inputs = ['', 'A', '===', '\u0000', '💥', 'Zm9v', 'a'.repeat(1000)];
    for (const s of inputs) {
      expect(() => isValidBase64url(s)).not.toThrow();
    }
  });

  // -------------------------------------------------------------------------
  // Equivalence with the decode-then-re-encode definition this function
  // replaced. `isValidBase64url` is now an O(n), allocation-free structural
  // scan; these properties are the guarantee that the swap changed no answer.
  // -------------------------------------------------------------------------
  describe('canonical-form equivalence with the round-trip definition', () => {
    it('equals the round trip over arbitrary binary strings (fast-check)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 256, unit: 'binary' }),
          s => {
            expect(isValidBase64url(s)).toBe(oracleCanonicalRoundTrip(s));
          }
        ),
        FC_RUNS
      );
    });

    it('equals the round trip over the adversarial alphabet (fast-check)', () => {
      // This generator is what catches the two structural traps: a code unit
      // >= 256 whose low byte aliases an alphabet character, and the
      // standard-alphabet `+` / `/` that the LENIENT decoder accepts but the
      // canonical encoder never emits.
      fc.assert(
        fc.property(arbAdversarialString, s => {
          expect(isValidBase64url(s)).toBe(oracleCanonicalRoundTrip(s));
        }),
        { numRuns: 3000 }
      );
    });

    it('equals the round trip over canonical encodings of random bytes (fast-check)', () => {
      fc.assert(
        fc.property(fc.uint8Array({ minLength: 0, maxLength: 256 }), bytes => {
          const s = bytesToBase64url(bytes);
          expect(isValidBase64url(s)).toBe(oracleCanonicalRoundTrip(s));
          expect(isValidBase64url(s)).toBe(s.length > 0);
        }),
        FC_RUNS
      );
    });

    it('classifies every length 0..5 exactly as the round trip does', () => {
      // One canonical and one non-canonical string at each reachable length,
      // covering all four `length % 4` residues.
      const cases: Array<[string, boolean]> = [
        ['', false], // length 0: the falsy short-circuit
        ['A', false], // length 1: %4 === 1, cannot carry a whole byte
        ['Zg', true], // length 2: %4 === 2, canonical encoding of 'f'
        ['AB', false], // length 2: last sextet 1 -> low 4 bits non-zero
        ['Zm8', true], // length 3: %4 === 3, canonical encoding of 'fo'
        ['AAB', false], // length 3: last sextet 1 -> low 2 bits non-zero
        ['Zm9v', true], // length 4: %4 === 0, canonical encoding of 'foo'
        ['Zm9vY', false], // length 5: %4 === 1
      ];
      for (const [s, expected] of cases) {
        expect(isValidBase64url(s)).toBe(expected);
        expect(isValidBase64url(s)).toBe(oracleCanonicalRoundTrip(s));
        expect(isValidBase64url(s)).toBe(oracleIsValidBase64Url(s));
      }
    });

    it('tests the final character by its SEXTET value, not its code unit', () => {
      // The tail-bit condition is about the DECODED 6-bit value of the last
      // character, never its UTF-16 code unit. Implementing it as
      // `s.charCodeAt(L - 1) & 0x0f` (or `& 0x03`) is wrong in BOTH
      // directions, and each of these four strings catches one direction:
      //
      //  'Zg'  last 'g' = code 0x67 (low 4 bits 0x7), sextet 32 (low 4 bits 0)
      //        -> canonical; a code-unit test would reject it.
      //  'A0'  last '0' = code 0x30 (low 4 bits 0), sextet 52 (low 4 bits 4)
      //        -> NOT canonical; a code-unit test would accept it.
      //  'AAA' last 'A' = code 0x41 (low 2 bits 1), sextet 0 (low 2 bits 0)
      //        -> canonical; a code-unit test would reject it.
      //  'AAD' last 'D' = code 0x44 (low 2 bits 0), sextet 3 (low 2 bits 3)
      //        -> NOT canonical; a code-unit test would accept it.
      const cases: Array<[string, boolean]> = [
        ['Zg', true],
        ['A0', false],
        ['AAA', true],
        ['AAD', false],
      ];
      for (const [s, expected] of cases) {
        expect(isValidBase64url(s)).toBe(expected);
        expect(isValidBase64url(s)).toBe(oracleCanonicalRoundTrip(s));
      }
    });

    it('rejects the standard-alphabet and >= 256 aliases the decoder accepts', () => {
      // The decoder maps '+'/'/' onto '-'/'_' and truncates every code unit to
      // its low 8 bits, so all of these DECODE fine — but none of them can be
      // encoder OUTPUT, so none is canonical.
      const nonCanonical = [
        // 'a+/b' decodes to exactly the same bytes as the canonical 'a-_b'
        // asserted below; only the alphabet differs.
        'a+/b',
        'Zm+v', // a single standard-alphabet character is enough
        '\u0141\u0141\u0141\u0141', // low bytes spell 'AAAA'
        'Q\u0141QQ', // one aliasing unit inside an otherwise canonical string
        'Zg==', // padding
        'a=', // padding
        'a b', // interior whitespace
        'Zm9v\n', // trailing newline
        ' Zm9v', // leading whitespace
        'Zm9v!', // stray punctuation
      ];
      for (const s of nonCanonical) {
        expect(isValidBase64url(s)).toBe(false);
        expect(isValidBase64url(s)).toBe(oracleCanonicalRoundTrip(s));
        // Negative: rejecting it here must NOT make the decoder reject it too.
        expect(() => base64urlToBytes(s)).not.toThrow();
      }
      // The URL-safe form of the alias case IS canonical, which is what makes
      // the rejections above a real distinction rather than a blanket no.
      expect(isValidBase64url('a-_b')).toBe(true);
      expect(oracleCanonicalRoundTrip('a-_b')).toBe(true);
      expect(isValidBase64url('Zm-v')).toBe(true);
    });

    it('never throws and returns false for non-string input', () => {
      fc.assert(
        fc.property(arbAdversarialString, s => {
          expect(() => isValidBase64url(s)).not.toThrow();
        }),
        FC_RUNS
      );
      const notStrings = [
        undefined,
        null,
        0,
        1,
        NaN,
        {},
        [],
        new String('Zm9v'),
      ];
      for (const value of notStrings) {
        expect(() =>
          isValidBase64url(value as unknown as string)
        ).not.toThrow();
        expect(isValidBase64url(value as unknown as string)).toBe(false);
      }
    });
  });
});

describe('codec: bytesToHex', () => {
  it('matches Buffer hex for random bytes (fast-check)', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), bytes => {
        expect(bytesToHex(bytes)).toBe(Buffer.from(bytes).toString('hex'));
      }),
      FC_RUNS
    );
  });

  it('emits lowercase, two digits per byte', () => {
    expect(bytesToHex(new Uint8Array([0x00, 0x0f, 0xff, 0xa5]))).toBe(
      '000fffa5'
    );
    expect(bytesToHex(new Uint8Array(0))).toBe('');
  });
});

describe('codec: utf8Encode / utf8Decode', () => {
  it('encode matches Buffer utf8 bytes for arbitrary strings (fast-check)', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 256, unit: 'binary' }),
        s => {
          const mine = utf8Encode(s);
          const viaBuffer = new Uint8Array(Buffer.from(s, 'utf8'));
          expect(bytesEqual(mine, viaBuffer)).toBe(true);
        }
      ),
      FC_RUNS
    );
  });

  it('decode matches Buffer utf8 string for arbitrary bytes (fast-check)', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 512 }), bytes => {
        expect(utf8Decode(bytes)).toBe(Buffer.from(bytes).toString('utf8'));
      }),
      FC_RUNS
    );
  });

  it('round-trips multi-byte Unicode literals', () => {
    const samples = [
      '',
      'hello',
      'café',
      'é', // e + combining acute (NFD)
      '日本語',
      'Ω≈ç√∫',
      '🔐🇺🇳👩‍💻',
      'mixed 123 !@# 日本 🔥',
    ];
    for (const s of samples) {
      expect(utf8Decode(utf8Encode(s))).toBe(s);
      // Also byte-identical to Node's utf8 encoding.
      expect(
        bytesEqual(utf8Encode(s), new Uint8Array(Buffer.from(s, 'utf8')))
      ).toBe(true);
    }
  });

  it('preserves a leading UTF-8 BOM (does NOT strip it), matching Node', () => {
    // A default `new TextDecoder()` would strip a leading U+FEFF; Node's
    // `Buffer.toString('utf8')` keeps it. The codec must match Node so text
    // whose plaintext legitimately begins with a BOM round-trips intact.
    const bomThenA = new Uint8Array([0xef, 0xbb, 0xbf, 0x41]);
    expect(utf8Decode(bomThenA)).toBe(Buffer.from(bomThenA).toString('utf8'));
    expect(utf8Decode(bomThenA)).toBe('﻿A');
    expect(utf8Decode(bomThenA).length).toBe(2);

    const bomOnly = new Uint8Array([0xef, 0xbb, 0xbf]);
    expect(utf8Decode(bomOnly)).toBe(Buffer.from(bomOnly).toString('utf8'));
    expect(utf8Decode(bomOnly)).toBe('﻿');

    // Full round-trip of a string that starts with a BOM.
    const withBom = '﻿hello world';
    expect(utf8Decode(utf8Encode(withBom))).toBe(withBom);
  });
});

describe('codec: concatBytes', () => {
  it('matches Buffer.concat for random arrays of byte arrays (fast-check)', () => {
    fc.assert(
      fc.property(
        fc.array(fc.uint8Array({ minLength: 0, maxLength: 64 }), {
          minLength: 0,
          maxLength: 8,
        }),
        parts => {
          const mine = concatBytes(...parts);
          const viaBuffer = new Uint8Array(
            Buffer.concat(parts.map(p => Buffer.from(p)))
          );
          expect(bytesEqual(mine, viaBuffer)).toBe(true);
        }
      ),
      FC_RUNS
    );
  });

  it('handles zero parts and empty parts', () => {
    expect(concatBytes().length).toBe(0);
    expect(concatBytes(new Uint8Array(0), new Uint8Array(0)).length).toBe(0);
    const joined = concatBytes(
      new Uint8Array([1, 2]),
      new Uint8Array(0),
      new Uint8Array([3])
    );
    expect(Array.from(joined)).toEqual([1, 2, 3]);
  });

  it('returns a new array that does not alias its inputs', () => {
    const a = new Uint8Array([1, 2, 3]);
    const out = concatBytes(a);
    out[0] = 99;
    expect(a[0]).toBe(1); // input untouched
  });
});
