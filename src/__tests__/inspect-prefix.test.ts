/**
 * `inspectHeader` header-prefix tests (Phase 3 — inspect-prefix), Node 22+.
 *
 * A v1 header is 22 bytes at the very front of the record, but
 * `CryptoCore.inspectHeader` used to base64url-decode the ENTIRE input string
 * to read them — so inspecting the header of a multi-megabyte ciphertext
 * allocated (and threw away) the whole plaintext-sized byte array. The decode
 * is now narrowed to the first `HEADER_B64URL_PREFIX_CHARS` (32) characters.
 *
 * 32 is the smallest multiple of 4 at or above `ceil(22 * 4 / 3) = 30`, so the
 * slice is a whole number of base64 quanta and decodes to exactly 24 bytes —
 * two more than the header needs. Because the WHOLE string has already been
 * proven canonical by `isValidBase64url` at that point, a quantum-aligned
 * prefix of it is itself canonical and its decode is a byte-exact prefix of
 * the full decode; `hasMagic` reads bytes 0-3 and `parseHeader` reads bytes
 * 0-21, so neither can tell the difference.
 *
 * This file pins that equivalence rather than the optimisation's timing:
 *
 *   1. **Result identity.** For every shape of input — v1/Argon2id text,
 *      v1/PBKDF2 (sync) text, a v0-shaped string with no magic, the 4-, 31-,
 *      32- and 34-character boundaries, and a >= 1 MiB ciphertext — the value
 *      `inspectHeader` returns is deep-equal to what a full decode produces,
 *      field for field.
 *   2. **Bounded work.** The argument actually handed to the decode seam is
 *      `min(input.length, 32)` characters, quantum-aligned, and yields at
 *      least the 22 header bytes. This is the assertion that would have to be
 *      deleted to un-fix the defect, so it is stated as an exact length, not
 *      as "smaller than the input".
 *   3. **The contract did NOT narrow with the decode.** The canonical check
 *      still runs over the whole string: a string whose first 32 characters
 *      are a perfectly good header but whose TAIL is malformed or
 *      non-canonical must still throw `INVALID_BASE64URL`, not quietly report
 *      a header. Two independent tail defects are covered (a non-alphabet
 *      character, and a final character carrying non-zero discarded bits),
 *      plus the `length % 4 === 1` shape.
 *   4. **Every other branch is untouched.** Empty string -> `INVALID_INPUT`,
 *      non-string/non-`Uint8Array` -> `INVALID_INPUT`, `Uint8Array` inputs
 *      read as-is with no decode at all, a truncated header ->
 *      `TRUNCATED_HEADER`, and a v2 container (bytes or string) ->
 *      `UNSUPPORTED_VERSION`.
 *
 * The seam is observed with a test-local subclass that overrides the
 * documented `protected decodeBase64url` extension point and delegates with
 * `super` — the same technique `codec-seam.test.ts` uses. Nothing about the
 * unit under test is mocked; `inspectHeader` runs its real body.
 */
import { describe, it, expect } from '@jest/globals';
import { CryptoManager } from '../crypto-manager';
import { CryptoManager as BrowserCryptoManager } from '../crypto-manager.browser';
import { CryptoError, CryptoErrorType } from '../types';
import { bytesToBase64url, base64urlToBytes, isValidBase64url } from '../codec';
import type { ParsedHeader } from '../format-core';
import {
  FORMAT_VERSION,
  HEADER_LENGTH,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  hasMagic,
  parseHeader,
} from '../format-core';

/**
 * The prefix width `inspectHeader` is expected to decode. Mirrors the
 * module-private `HEADER_B64URL_PREFIX_CHARS` in `src/core.ts`; restated here
 * (rather than exported for the test's benefit) so the test states the
 * expected value independently of the implementation.
 */
const EXPECTED_PREFIX_CHARS = 32;

/** Bytes a 32-character base64url prefix decodes to. */
const EXPECTED_PREFIX_BYTES = 24;

/** Test-only low-cost Argon2id profile. Never use in production. */
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

/** Test-only low PBKDF2 iteration count, so the sync path stays fast. */
const LOW_PBKDF2_ITERATIONS = 1000;

/** 28 characters — accepted by the NIST passphrase rule (>= 20 chars). */
const PASSWORD = 'correct horse battery staple';

/** v1 TEXT wire layout `[header:22][salt:32][iv:12][tag:16][ciphertext]`. */
const V1_FIXED_OVERHEAD = HEADER_LENGTH + 32 + 12 + 16; // 82

/** Plaintext size for the "large ciphertext" case: 1 MiB. */
const LARGE_PLAINTEXT_BYTES = 1024 * 1024;

/**
 * Node manager whose decode seam RECORDS the exact string it was handed and
 * the length it produced, then delegates to the real implementation via
 * `super`. The seam is `CryptoCore`'s documented extension point (the Node
 * build already overrides it with `Buffer`), so supplying an implementation
 * through it is a supported use, not a mock of the unit under test:
 * `inspectHeader`'s own body — the empty check, the canonical check, the
 * slice, `hasMagic`, `parseHeader` — runs unmodified.
 */
class DecodeRecorder extends CryptoManager {
  public readonly decodedInputs: string[] = [];
  public readonly decodedByteLengths: number[] = [];

  protected override decodeBase64url(s: string): Uint8Array {
    const bytes = super.decodeBase64url(s);
    this.decodedInputs.push(s);
    this.decodedByteLengths.push(bytes.length);
    return bytes;
  }
}

/** Browser-build counterpart, which keeps the PURE codec behind the seam. */
class BrowserDecodeRecorder extends BrowserCryptoManager {
  public readonly decodedInputs: string[] = [];

  protected override decodeBase64url(s: string): Uint8Array {
    const bytes = super.decodeBase64url(s);
    this.decodedInputs.push(s);
    return bytes;
  }
}

/**
 * Independent oracle: what `inspectHeader` returned before the prefix change,
 * computed straight from the pure codec and the pure format layer rather than
 * from any manager instance.
 *
 * @param s - a canonical base64url string
 * @returns the parsed header, or `null` when the full decode lacks the magic
 */
function fullDecodeReference(s: string): ParsedHeader | null {
  const full = base64urlToBytes(s);
  return hasMagic(full) ? parseHeader(full) : null;
}

/** Capture a thrown value without letting a non-throw pass silently. */
function captureThrow(fn: () => unknown): unknown {
  const NOTHING = Symbol('nothing thrown');
  let thrown: unknown = NOTHING;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).not.toBe(NOTHING);
  return thrown;
}

/** Assert a captured value is a `CryptoError` with an exact type and code. */
function expectCryptoError(
  thrown: unknown,
  type: CryptoErrorType,
  code: string
): void {
  expect(thrown).toBeInstanceOf(CryptoError);
  const err = thrown as CryptoError;
  expect({ type: err.type, code: err.code }).toEqual({ type, code });
}

/**
 * Deterministic pseudo-random bytes (xorshift32); the seed is a literal so
 * every run produces the identical payload.
 */
function seededBytes(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed >>> 0;
  for (let i = 0; i < length; i += 1) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

const node = new CryptoManager({
  ...LOW_COST,
  pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
});

describe('inspectHeader — header-prefix decoding (Phase 3)', () => {
  // Built once and shared read-only: every fixture below is a string, and
  // `inspectHeader` never mutates its input.
  const syncCiphertext = node.encryptTextSync('inspect me', PASSWORD);
  const syncBytes = base64urlToBytes(syncCiphertext);
  const largeCiphertext = node.encryptTextSync(
    'y'.repeat(LARGE_PLAINTEXT_BYTES),
    PASSWORD
  );
  // A v0-shaped record: 82 bytes of non-magic data, i.e. the legacy
  // [salt][iv][tag][body] layout with no header at all.
  const v0Ciphertext = bytesToBase64url(
    seededBytes(V1_FIXED_OVERHEAD, 0x0d05_0082)
  );

  /** `bytesToBase64url` of the first `n` bytes of the sync ciphertext. */
  const prefixOf = (n: number): string =>
    bytesToBase64url(syncBytes.subarray(0, n));

  it('states its fixtures: canonical strings at the 4 / 31 / 32 / 34-character boundaries', () => {
    // Guards the rest of the file: if these lengths ever stop being what the
    // boundary cases claim, the boundary tests below would silently test
    // something else. 3 -> 4, 23 -> 31, 24 -> 32 and 25 -> 34 characters are
    // the four base64 lengths that bracket the 32-character prefix (33 is
    // impossible: `length % 4 === 1` carries no whole byte).
    expect([
      prefixOf(3).length,
      prefixOf(23).length,
      prefixOf(24).length,
      prefixOf(25).length,
    ]).toEqual([4, 31, 32, 34]);
    for (const n of [3, 23, 24, 25]) {
      expect(isValidBase64url(prefixOf(n))).toBe(true);
    }
    expect(largeCiphertext.length).toBeGreaterThan(LARGE_PLAINTEXT_BYTES);
    expect(isValidBase64url(largeCiphertext)).toBe(true);
    expect(isValidBase64url(v0Ciphertext)).toBe(true);
  });

  describe('bounded decode work', () => {
    it('decodes at most 32 characters of a >= 1 MiB ciphertext and still reports the full-decode header', () => {
      const recorder = new DecodeRecorder({
        ...LOW_COST,
        pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
      });

      const parsed = recorder.inspectHeader(largeCiphertext);

      // The header is real and complete...
      expect(parsed).toEqual({
        version: FORMAT_VERSION,
        kdfId: KDF_ID_PBKDF2_SHA256,
        headerLen: HEADER_LENGTH,
        params: {
          kind: 'pbkdf2-sha256',
          iterations: LOW_PBKDF2_ITERATIONS,
        },
      });
      // ...and identical, field for field, to a full decode of the same string.
      expect(parsed).toEqual(fullDecodeReference(largeCiphertext));

      // THE assertion this phase exists for: exactly one decode, of exactly
      // the 32-character prefix, yielding 24 bytes.
      expect(recorder.decodedInputs).toEqual([
        largeCiphertext.slice(0, EXPECTED_PREFIX_CHARS),
      ]);
      expect(recorder.decodedByteLengths).toEqual([EXPECTED_PREFIX_BYTES]);

      // NEGATIVE — the seam must NOT have seen the whole 1.4M-character
      // string, and must not have been called a second time with it.
      expect(recorder.decodedInputs).not.toContain(largeCiphertext);
      const seen = recorder.decodedInputs[0] ?? '';
      expect(seen.length).toBeLessThan(largeCiphertext.length);

      // The prefix must carry the header outright, not by luck: it is quantum
      // aligned and decodes to more bytes than `parseHeader` reads.
      expect(seen.length % 4).toBe(0);
      expect(recorder.decodedByteLengths[0] ?? 0).toBeGreaterThanOrEqual(
        HEADER_LENGTH
      );

      // And the ciphertext is still fully decryptable — a header read must
      // return the header, and nothing else about the record may change.
      expect(node.decryptTextSync(largeCiphertext, PASSWORD)).toHaveLength(
        LARGE_PLAINTEXT_BYTES
      );
    });

    it('decodes min(length, 32) characters for every input shape, and returns the full-decode result', async () => {
      const argon2Ciphertext = await node.encryptText('argon2 text', PASSWORD);

      const cases: Array<{ name: string; input: string }> = [
        { name: 'v1 Argon2id text ciphertext', input: argon2Ciphertext },
        { name: 'v1 PBKDF2 (sync) text ciphertext', input: syncCiphertext },
        { name: 'v0 legacy ciphertext (no magic)', input: v0Ciphertext },
        { name: '4-character string (3 bytes, no magic)', input: prefixOf(3) },
        { name: '31-character string (23 bytes)', input: prefixOf(23) },
        { name: '32-character string (24 bytes)', input: prefixOf(24) },
        { name: '34-character string (25 bytes)', input: prefixOf(25) },
        { name: '>= 1 MiB ciphertext', input: largeCiphertext },
      ];

      for (const { name, input } of cases) {
        const recorder = new DecodeRecorder({
          ...LOW_COST,
          pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
        });

        const parsed = recorder.inspectHeader(input);

        // Identity with the full decode, stated per case so a failure names
        // the shape that broke.
        expect({ name, parsed }).toEqual({
          name,
          parsed: fullDecodeReference(input),
        });
        // Bounded work, stated as the exact rule rather than an inequality.
        expect({ name, decoded: recorder.decodedInputs }).toEqual({
          name,
          decoded: [
            input.slice(0, Math.min(input.length, EXPECTED_PREFIX_CHARS)),
          ],
        });
      }
    });

    it('returns null for a long v0 ciphertext without decoding past the prefix', () => {
      const recorder = new DecodeRecorder({
        ...LOW_COST,
        pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
      });

      // The "no magic" verdict must be reachable from the prefix alone; a
      // 110-character v0 record is well past the 32-character cut.
      expect(recorder.inspectHeader(v0Ciphertext)).toBeNull();
      expect(v0Ciphertext.length).toBeGreaterThan(EXPECTED_PREFIX_CHARS);
      expect(recorder.decodedInputs).toEqual([
        v0Ciphertext.slice(0, EXPECTED_PREFIX_CHARS),
      ]);
    });

    it('decodes the prefix on the browser build too, which runs the pure codec', () => {
      const browser = new BrowserDecodeRecorder(LOW_COST);

      const parsed = browser.inspectHeader(largeCiphertext);

      // Same header, same bounded decode — `inspectHeader` lives on
      // `CryptoCore`, so the browser build inherits the fix rather than
      // needing its own.
      expect(parsed).toEqual(fullDecodeReference(largeCiphertext));
      expect(browser.decodedInputs).toEqual([
        largeCiphertext.slice(0, EXPECTED_PREFIX_CHARS),
      ]);
      expect(browser.decodedInputs).not.toContain(largeCiphertext);
    });

    it('does not decode anything at all when given bytes', () => {
      const recorder = new DecodeRecorder({
        ...LOW_COST,
        pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
      });

      const parsed = recorder.inspectHeader(syncBytes);

      expect(parsed).toEqual(fullDecodeReference(syncCiphertext));
      // NEGATIVE — the byte path is unchanged: no slicing, no decoding.
      expect(recorder.decodedInputs).toEqual([]);
    });
  });

  describe('whole-string validation survives the narrowed decode', () => {
    it('rejects a string whose header prefix is valid but whose tail holds a non-alphabet character', () => {
      const poisoned = `${syncCiphertext.slice(0, 100)}!!`;

      // Premise: the first 32 characters really are a decodable v1 header, so
      // an implementation that validated only the prefix would happily return
      // one here.
      expect(fullDecodeReference(syncCiphertext.slice(0, 32))?.version).toBe(
        FORMAT_VERSION
      );

      const thrown = captureThrow(() => node.inspectHeader(poisoned));
      expectCryptoError(
        thrown,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_BASE64URL'
      );
    });

    it('rejects a string whose final character carries non-zero discarded bits', () => {
      // 34 characters: `length % 4 === 2`, so the last character's low 4 bits
      // are dropped by the decoder and MUST be zero in canonical form. 'B' is
      // sextet 1, so they are not. The leading 32 characters are an untouched
      // real header.
      const nonCanonical = `${syncCiphertext.slice(0, 32)}AB`;
      expect(nonCanonical).toHaveLength(34);
      expect(isValidBase64url(nonCanonical)).toBe(false);

      const thrown = captureThrow(() => node.inspectHeader(nonCanonical));
      expectCryptoError(
        thrown,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_BASE64URL'
      );
    });

    it('rejects a string whose length is 1 mod 4 even though its prefix parses', () => {
      const stray = syncCiphertext.slice(0, 33);
      expect(stray.length % 4).toBe(1);

      const thrown = captureThrow(() => node.inspectHeader(stray));
      expectCryptoError(
        thrown,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_BASE64URL'
      );
    });

    it('never reaches the decode seam when the string fails validation', () => {
      const recorder = new DecodeRecorder({
        ...LOW_COST,
        pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
      });

      expect(() => recorder.inspectHeader('')).toThrow(CryptoError);
      expect(() => recorder.inspectHeader('!!!!')).toThrow(CryptoError);
      expect(() =>
        recorder.inspectHeader(`${syncCiphertext.slice(0, 100)}!!`)
      ).toThrow(CryptoError);

      // NEGATIVE — rejection happens before any decoding, prefix or otherwise.
      expect(recorder.decodedInputs).toEqual([]);
    });
  });

  describe('unchanged error and edge branches', () => {
    it('throws INVALID_INPUT for the empty string', () => {
      const thrown = captureThrow(() => node.inspectHeader(''));
      expectCryptoError(thrown, CryptoErrorType.INVALID_INPUT, 'INVALID_INPUT');
    });

    it('throws INVALID_BASE64URL for a malformed string rather than reporting v0', () => {
      const thrown = captureThrow(() => node.inspectHeader('!!!!'));
      expectCryptoError(
        thrown,
        CryptoErrorType.INVALID_INPUT,
        'INVALID_BASE64URL'
      );
      // NEGATIVE — it must NOT have returned null. That is exactly what a
      // decode-first implementation produces here, as the oracle shows:
      // '!!!!' decodes to zero bytes, which carry no magic.
      expect(fullDecodeReference('!!!!')).toBeNull();
    });

    it('throws INVALID_INPUT for input that is neither a string nor a Uint8Array', () => {
      const thrown = captureThrow(() =>
        node.inspectHeader(123 as unknown as string)
      );
      expectCryptoError(thrown, CryptoErrorType.INVALID_INPUT, 'INVALID_INPUT');
    });

    it('throws TRUNCATED_HEADER for a magic-bearing string shorter than the header', () => {
      // 8 characters -> 6 bytes, which begin with "HPCR" but stop well short
      // of the 22-byte header. Below the prefix cut, so this exercises the
      // "decode the whole (short) string" branch.
      const truncated = prefixOf(6);
      expect(truncated).toHaveLength(8);

      const thrown = captureThrow(() => node.inspectHeader(truncated));
      expectCryptoError(
        thrown,
        CryptoErrorType.INVALID_INPUT,
        'TRUNCATED_HEADER'
      );
      // The oracle agrees: a full decode of the same string throws the very
      // same error, so narrowing the decode changed nothing here.
      expectCryptoError(
        captureThrow(() => fullDecodeReference(truncated)),
        CryptoErrorType.INVALID_INPUT,
        'TRUNCATED_HEADER'
      );
    });

    it('throws UNSUPPORTED_VERSION for a v2 container, as bytes and as a string', async () => {
      const container = await node.encryptContainer(
        Uint8Array.from([1, 2, 3, 4]),
        PASSWORD
      );
      const containerText = bytesToBase64url(container);
      const recorder = new DecodeRecorder({
        ...LOW_COST,
        pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
      });

      // Bytes: no decode involved.
      expectCryptoError(
        captureThrow(() => recorder.inspectHeader(container)),
        CryptoErrorType.DECRYPTION_FAILED,
        'UNSUPPORTED_VERSION'
      );
      expect(recorder.decodedInputs).toEqual([]);

      // String: the version byte lives at offset 4, so the prefix decode is
      // enough to reject it — the container body is never decoded.
      expect(containerText.length).toBeGreaterThan(EXPECTED_PREFIX_CHARS);
      expectCryptoError(
        captureThrow(() => recorder.inspectHeader(containerText)),
        CryptoErrorType.DECRYPTION_FAILED,
        'UNSUPPORTED_VERSION'
      );
      expect(recorder.decodedInputs).toEqual([
        containerText.slice(0, EXPECTED_PREFIX_CHARS),
      ]);
    });

    it('reports Argon2id parameters from the prefix of a long Argon2id ciphertext', async () => {
      const ciphertext = await node.encryptText(
        'x'.repeat(200 * 1024),
        PASSWORD
      );
      const recorder = new DecodeRecorder({
        ...LOW_COST,
        pbkdf2Iterations: LOW_PBKDF2_ITERATIONS,
      });

      expect(recorder.inspectHeader(ciphertext)).toEqual({
        version: FORMAT_VERSION,
        kdfId: KDF_ID_ARGON2ID,
        headerLen: HEADER_LENGTH,
        params: {
          kind: 'argon2id',
          memoryCost: LOW_COST.memoryCost,
          timeCost: LOW_COST.timeCost,
          parallelism: LOW_COST.parallelism,
        },
      });
      expect(recorder.decodedInputs).toEqual([
        ciphertext.slice(0, EXPECTED_PREFIX_CHARS),
      ]);
    });
  });
});
