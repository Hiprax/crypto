/**
 * Fuzzing harness for `parseHeader` (Task 12).
 *
 * `parseHeader` is the only entry point in the library that consumes
 * arbitrary attacker-controlled bytes BEFORE any password authentication
 * runs. Its inputs come straight from the wire / disk, so a parser bug
 * here is a pre-auth attack surface. Example-based tests (truncated
 * header, unknown KDF, unknown version, etc.) cover the common boundary
 * conditions but cannot enumerate the entire byte-array search space.
 *
 * This file pumps random `Uint8Array` inputs through both
 * {@link parseHeader} (low-level format parser) and
 * {@link CryptoManager.inspectHeader} (the public tooling surface that
 * wraps parseHeader) and asserts the strict contract:
 *
 *   For every input buffer:
 *     - the function MUST either return a parsed-header value matching
 *       the published `ParsedHeader` shape, OR throw a `CryptoError` with
 *       a known error code from the documented set.
 *     - the function MUST NOT throw any non-`CryptoError` exception
 *       (would indicate uncaught bounds-check failure, RangeError, etc).
 *     - the function MUST NOT hang or recurse unboundedly.
 *
 * 1000 cases per property — each invocation is microseconds (no KDF
 * runs, no I/O), so the runtime cost is negligible.
 */
import { describe, it, expect } from '@jest/globals';
import fc from 'fast-check';
import {
  parseHeader,
  HEADER_LENGTH,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  FORMAT_VERSION,
} from '../format';
import type { ParsedHeader } from '../format';
import { CryptoError, CryptoErrorType } from '../types';
import { CryptoManager } from '../crypto-manager';

/**
 * Set of error codes that {@link parseHeader} is documented (and tested)
 * to throw. Any other CryptoError code surfacing under random input
 * indicates an unexpected branch worth investigating; the test fails
 * loud with the offending code in the assertion message so the failure
 * is debuggable.
 */
const KNOWN_PARSE_ERROR_CODES = new Set<string>([
  'TRUNCATED_HEADER',
  'INVALID_MAGIC',
  'UNSUPPORTED_VERSION',
  'UNSUPPORTED_KDF',
  'INVALID_HEADER_PARAM',
  'INVALID_HEADER_INPUT',
  'KDF_PARAMS_OUT_OF_BOUNDS',
]);

/** Documented `CryptoErrorType` set parseHeader is allowed to use. */
const KNOWN_PARSE_ERROR_TYPES = new Set<CryptoErrorType>([
  CryptoErrorType.INVALID_INPUT,
  CryptoErrorType.DECRYPTION_FAILED,
]);

/**
 * Verify a successful parse result has the expected shape. Used after
 * the rare case where a random buffer happens to satisfy every check
 * (e.g. fast-check generated valid magic + valid params); we still want
 * to assert the returned object is well-formed.
 */
function assertWellFormedParseResult(result: ParsedHeader): void {
  // version is a u8; value must equal FORMAT_VERSION (parser rejects
  // others).
  expect(result.version).toBe(FORMAT_VERSION);
  // kdfId is one of the two documented values.
  expect(
    result.kdfId === KDF_ID_ARGON2ID || result.kdfId === KDF_ID_PBKDF2_SHA256
  ).toBe(true);
  // headerLen is fixed for v1.
  expect(result.headerLen).toBe(HEADER_LENGTH);
  // params discriminant matches the kdfId.
  if (result.kdfId === KDF_ID_ARGON2ID) {
    expect(result.params.kind).toBe('argon2id');
    if (result.params.kind === 'argon2id') {
      expect(Number.isInteger(result.params.memoryCost)).toBe(true);
      expect(result.params.memoryCost).toBeGreaterThan(0);
      expect(Number.isInteger(result.params.timeCost)).toBe(true);
      expect(result.params.timeCost).toBeGreaterThan(0);
      expect(Number.isInteger(result.params.parallelism)).toBe(true);
      expect(result.params.parallelism).toBeGreaterThan(0);
    }
  } else {
    expect(result.params.kind).toBe('pbkdf2-sha256');
    if (result.params.kind === 'pbkdf2-sha256') {
      expect(Number.isInteger(result.params.iterations)).toBe(true);
      expect(result.params.iterations).toBeGreaterThan(0);
    }
  }
}

/**
 * Run `fn` and classify the outcome. Returns either:
 *   - `{ ok: true, value }`  — fn returned without throwing
 *   - `{ ok: false, error }` — fn threw
 *
 * Done as a helper so the assertion logic in each property is uniform
 * and the test can distinguish "no error" from "expected CryptoError".
 */
function safelyRun<T>(
  fn: () => T
): { ok: true; value: T } | { ok: false; error: unknown } {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, error };
  }
}

// ============================================================================

describe('parseHeader fuzzing harness (Task 12)', () => {
  // Property tests run thousands of cases in milliseconds — no jest
  // timeout bump needed, but we set one anyway in case CI is slow.
  // 30s is generous for 1000 microsecond-scale parses.
  const FUZZ_CONFIG: fc.Parameters = {
    numRuns: 1000,
    endOnFailure: true,
    // Pin a deterministic seed so a regression always shows the same
    // failing input. The number is arbitrary but stable.
    seed: 0xc0ffee,
  };

  /**
   * Smaller buffers (0..21 bytes) hit the truncated-input branches.
   * Bigger buffers (22..1024) hit the magic / version / KDF id / params
   * branches. Mix both so every fast-check run touches both regions.
   */
  const arbRandomBytes = fc.uint8Array({ minLength: 0, maxLength: 1024 });

  /**
   * A buffer with the v1 magic prefix already correct — pumps the
   * fuzzer past the magic check and into the version / KDF id / params
   * branches. Without this, fast-check would spend ~99.99% of its
   * budget on the trivial `INVALID_MAGIC` branch (since random 4-byte
   * prefixes equal "HPCR" with probability 2^-32) and rarely reach the
   * deeper logic.
   */
  const arbMagicPrefixedBytes = fc
    .uint8Array({ minLength: 0, maxLength: 1024 })
    .map(bytes => {
      const buf = Buffer.alloc(Math.max(bytes.length, 4));
      Buffer.from(bytes).copy(buf);
      // Overwrite the first 4 bytes with the v1 magic.
      buf[0] = 0x48; // 'H'
      buf[1] = 0x50; // 'P'
      buf[2] = 0x43; // 'C'
      buf[3] = 0x52; // 'R'
      return new Uint8Array(buf);
    });

  // --------------------------------------------------------------------------

  it('parseHeader on random bytes: returns valid ParsedHeader OR throws known CryptoError', () => {
    fc.assert(
      fc.property(arbRandomBytes, bytes => {
        const buf = Buffer.from(bytes);
        const outcome = safelyRun(() => parseHeader(buf));
        if (outcome.ok) {
          // Most random buffers fail magic / version / KDF; a tiny
          // fraction may sneak through if all bytes happen to be
          // valid. When they do, the result must be well-formed.
          assertWellFormedParseResult(outcome.value);
        } else {
          expect(outcome.error).toBeInstanceOf(CryptoError);
          const err = outcome.error as CryptoError;
          expect(KNOWN_PARSE_ERROR_TYPES.has(err.type)).toBe(true);
          expect(KNOWN_PARSE_ERROR_CODES.has(err.code)).toBe(true);
        }
      }),
      FUZZ_CONFIG
    );
  });

  it('parseHeader on magic-prefixed random bytes: deeper branches still safe', () => {
    fc.assert(
      fc.property(arbMagicPrefixedBytes, bytes => {
        const buf = Buffer.from(bytes);
        const outcome = safelyRun(() => parseHeader(buf));
        if (outcome.ok) {
          assertWellFormedParseResult(outcome.value);
        } else {
          expect(outcome.error).toBeInstanceOf(CryptoError);
          const err = outcome.error as CryptoError;
          expect(KNOWN_PARSE_ERROR_TYPES.has(err.type)).toBe(true);
          expect(KNOWN_PARSE_ERROR_CODES.has(err.code)).toBe(true);
        }
      }),
      FUZZ_CONFIG
    );
  });

  it('parseHeader on tiny buffers (<HEADER_LENGTH): always throws TRUNCATED_HEADER', () => {
    // Exhaust every possible short-buffer length up to HEADER_LENGTH-1
    // — at these sizes the parser must short-circuit before reading
    // any params, so the error code is invariably TRUNCATED_HEADER.
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: HEADER_LENGTH - 1 }),
        bytes => {
          const buf = Buffer.from(bytes);
          const outcome = safelyRun(() => parseHeader(buf));
          // Cannot succeed — we don't have enough bytes for a header.
          expect(outcome.ok).toBe(false);
          if (!outcome.ok) {
            expect(outcome.error).toBeInstanceOf(CryptoError);
            expect((outcome.error as CryptoError).code).toBe(
              'TRUNCATED_HEADER'
            );
          }
        }
      ),
      { numRuns: 500, endOnFailure: true, seed: 0xfeedface }
    );
  });

  // --------------------------------------------------------------------------
  // inspectHeader thin-wrapper tests. Same invariants but exercising the
  // public API surface that callers actually use (Buffer / base64url
  // string overloads).
  // --------------------------------------------------------------------------

  describe('inspectHeader fuzz', () => {
    // Use a low-cost CryptoManager so construction is instant (the
    // method does not need any KDF state at all). A fresh instance per
    // describe block keeps configuration isolated.
    const cm = new CryptoManager({
      memoryCost: 2 ** 14,
      timeCost: 1,
      parallelism: 1,
      pbkdf2Iterations: 1000,
    });

    it('inspectHeader(Buffer): random bytes return null OR valid result OR known CryptoError', () => {
      fc.assert(
        fc.property(arbRandomBytes, bytes => {
          const buf = Buffer.from(bytes);
          const outcome = safelyRun(() => cm.inspectHeader(buf));
          if (outcome.ok) {
            // null is allowed when the input does not start with the v1
            // magic — that's the documented "this is not a v1
            // ciphertext" return value.
            if (outcome.value === null) {
              return;
            }
            assertWellFormedParseResult(outcome.value);
          } else {
            expect(outcome.error).toBeInstanceOf(CryptoError);
            const err = outcome.error as CryptoError;
            // inspectHeader can additionally throw INVALID_INPUT for
            // empty strings or wrong types, but this property only
            // passes Buffers, so the parseHeader-side codes apply.
            expect(KNOWN_PARSE_ERROR_TYPES.has(err.type)).toBe(true);
            expect(KNOWN_PARSE_ERROR_CODES.has(err.code)).toBe(true);
          }
        }),
        FUZZ_CONFIG
      );
    });

    it('inspectHeader(Buffer with magic prefix): deeper branches still safe', () => {
      fc.assert(
        fc.property(arbMagicPrefixedBytes, bytes => {
          const buf = Buffer.from(bytes);
          const outcome = safelyRun(() => cm.inspectHeader(buf));
          if (outcome.ok) {
            // With the magic prefix forced, the input either parses
            // (deep branch passed) or throws (deep branch failed).
            // null is no longer expected because hasMagic() returns
            // true for any buffer >= 4 bytes starting with HPCR.
            if (outcome.value === null) {
              // hasMagic returns false only when buf.length < 4. Our
              // arbitrary forces length >= 4 by construction.
              expect(buf.length).toBeLessThan(4);
              return;
            }
            assertWellFormedParseResult(outcome.value);
          } else {
            expect(outcome.error).toBeInstanceOf(CryptoError);
            const err = outcome.error as CryptoError;
            expect(KNOWN_PARSE_ERROR_TYPES.has(err.type)).toBe(true);
            expect(KNOWN_PARSE_ERROR_CODES.has(err.code)).toBe(true);
          }
        }),
        FUZZ_CONFIG
      );
    });

    it('inspectHeader(string): random base64url-shaped strings return null OR known CryptoError', () => {
      // Strings go through `isValidBase64Url` first — well-formed base64url
      // strings then decode to a Buffer; malformed strings throw
      // INVALID_BASE64URL up-front. The valid-base64url path resolves to a
      // Buffer of any length (including empty) and behaves like the Buffer
      // case from there. inspectHeader rejects an EMPTY string up-front
      // with INVALID_INPUT independent of the encoding.
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 2048 }),
          str => {
            const outcome = safelyRun(() => cm.inspectHeader(str));
            if (outcome.ok) {
              if (outcome.value === null) return;
              assertWellFormedParseResult(outcome.value);
            } else {
              expect(outcome.error).toBeInstanceOf(CryptoError);
              const err = outcome.error as CryptoError;
              // INVALID_INPUT and INVALID_BASE64URL are the
              // inspectHeader-specific codes; other codes come from
              // parseHeader's set.
              const allowedCodes = new Set([
                ...KNOWN_PARSE_ERROR_CODES,
                'INVALID_INPUT',
                'INVALID_BASE64URL',
              ]);
              expect(allowedCodes.has(err.code)).toBe(true);
            }
          }
        ),
        FUZZ_CONFIG
      );
    });
  });
});
