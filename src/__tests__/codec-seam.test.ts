/**
 * Codec-seam tests (Phase 2 — codec-seam), run under Node 22+.
 *
 * `CryptoCore` now reaches base64url through two overridable protected
 * methods, `encodeBase64url` / `decodeBase64url`, whose default bodies are the
 * pure isomorphic codec (`src/codec.ts`). The Node `CryptoManager` overrides
 * both with `Buffer`'s native base64url; the browser `CryptoManager`
 * deliberately does not and keeps running the pure reference implementation.
 *
 * That split is only safe if the override is an **implementation swap behind
 * an identical byte contract** rather than a second implementation of the
 * format. This file is what makes that claim testable. It pins:
 *
 *   1. **Encode byte-identity.** For a table of byte inputs (empty, every
 *      length residue, header-sized, 1 KiB, 64 KiB+, all-`0x00`, all-`0xff`,
 *      seeded pseudo-random, a non-zero-`byteOffset` view, and a real
 *      `Buffer`), the Node override returns a string equal, character for
 *      character, to `bytesToBase64url` — and equal to what the browser
 *      manager's seam returns. A single differing character would mean text
 *      encrypted in Node could not be decrypted in a browser.
 *   2. **Non-mutation.** Neither seam writes to its input; `encryptText` still
 *      owns and scrubs that buffer afterwards.
 *   3. **Decode parity, leniency included.** `Buffer.from(s, 'base64url')` and
 *      `base64urlToBytes(s)` agree on padded, whitespace-wrapped,
 *      standard-alphabet, `=`-terminated, non-alphabet-polluted and
 *      non-Latin-1 input — the leniency that lets `decryptText` accept a
 *      line-wrapped ciphertext. Expected bytes are stated as literals,
 *      derived by hand from the base64 alphabet, not from either
 *      implementation.
 *   4. **Cross-manager round-trips.** Node-encrypted text decrypts in the
 *      browser build and vice-versa across every payload size, which is the
 *      end-to-end statement of (1) and (3) together.
 *   5. **Pooled-view safety.** The Node decode returns a `Buffer` that is a
 *      view into a larger shared backing store for small results, and a
 *      standalone allocation for large ones; both regimes are exercised. A
 *      deliberately poisoned backing store proves the parsing path reads from
 *      `byteOffset` and not from the start of the pool.
 *   6. **`inspectHeader` still behaves.** It now decodes through the seam;
 *      its contract (`INVALID_INPUT` / `INVALID_BASE64URL` / `null` for v0 /
 *      parsed header otherwise) is unchanged, and the string and byte paths
 *      agree.
 *
 * Availability gating (as in `interop.test.ts`): `hash-wasm` is an optional
 * dependency powering the browser engine's Argon2id. A single `beforeAll`
 * probe runs one real Web-engine derivation; if it genuinely cannot load, the
 * browser-KDF assertions skip (logged) rather than fail — except under `CI`,
 * where a missing provider is a hard failure. The seam-level assertions (1),
 * (2), (3) and (5) need no KDF at all and always run.
 */
import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { CryptoManager as NodeCryptoManager } from '../crypto-manager';
import { CryptoManager as BrowserCryptoManager } from '../crypto-manager.browser';
import { CryptoError } from '../types';
import {
  bytesToBase64url,
  base64urlToBytes,
  isValidBase64url,
  utf8Encode,
} from '../codec';
import { FORMAT_VERSION, HEADER_LENGTH, KDF_ID_ARGON2ID } from '../format-core';

// Test-only low-cost Argon2id profile, identical for BOTH managers so the two
// builds encrypt at the same parameters (the browser default would otherwise
// be 32 MiB against Node's 128 MiB). Never use in production.
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

// A 20+ character passphrase (NIST passphrase acceptance rule) and a distinct
// wrong one for the negative path.
const PASSWORD = 'correct horse battery staple';
const WRONG_PASSWORD = 'incorrect zebra piano lantern';

/** v1 TEXT wire layout `[header:22][salt:32][iv:12][tag:16][ciphertext]`. */
const V1_FIXED_OVERHEAD = HEADER_LENGTH + 32 + 12 + 16; // 82

/**
 * Largest decoded length for which `Buffer.from(s, 'base64url')` — what the
 * Node `decodeBase64url` override calls — still returns a view into Node's
 * shared internal buffer pool rather than a standalone allocation. Above it,
 * the returned buffer owns its whole backing store.
 *
 * **Discovered at run time, deliberately.** Two reasons a literal would be
 * wrong. First, `Buffer.poolSize`'s default has differed across Node releases
 * (it measures 65536 on the v24.19.0 this suite was developed against), so any
 * byte count baked in here is a claim about one runtime. Second, and less
 * obviously, `Buffer.poolSize >>> 1` is not the crossover either: Node pools
 * `Buffer.from(string, encoding)` based on the length of the STRING, not of
 * the decoded result, and base64 spends 4 characters per 3 bytes — so the
 * crossover in decoded bytes lands near three quarters of that figure (24575
 * bytes against a `Buffer.poolSize >>> 1` of 32768 on v24.19.0). A hard-coded
 * constant would put every "straddling" case on the same side of the real
 * line and quietly stop testing the pooled regime at all.
 */
const LARGEST_POOLED_DECODE = ((): number => {
  const isPooled = (byteLength: number): boolean => {
    const decoded = Buffer.from(
      bytesToBase64url(new Uint8Array(byteLength)),
      'base64url'
    );
    return decoded.buffer.byteLength > decoded.byteLength;
  };
  let pooled = 1;
  let standalone = Buffer.poolSize * 4;
  // Assert the search's premises rather than assuming them. Without these, a
  // Node that stopped pooling `Buffer.from(string)` entirely would make the
  // search return 1 and the boundary test would fail later with a baffling
  // size comparison instead of naming the cause.
  if (!isPooled(pooled) || isPooled(standalone)) {
    throw new Error(
      `codec-seam: cannot bracket the Buffer pool crossover — isPooled(${pooled})=` +
        `${String(isPooled(pooled))}, isPooled(${standalone})=${String(isPooled(standalone))}. ` +
        "Node's string-allocation pooling behaviour has changed; revisit " +
        'LARGEST_POOLED_DECODE and the pooled-view assertions that use it.'
    );
  }
  while (pooled + 1 < standalone) {
    const mid = (pooled + standalone) >> 1;
    if (isPooled(mid)) {
      pooled = mid;
    } else {
      standalone = mid;
    }
  }
  return pooled;
})();

/**
 * Test-local subclass that exposes the two protected seam methods so they can
 * be compared directly against the pure codec. Deliberately a TEST-only
 * widening: the production classes keep them `protected`, because they are an
 * internal extension point and not part of the published surface.
 */
class NodeSeamProbe extends NodeCryptoManager {
  public callEncode(bytes: Uint8Array): string {
    return this.encodeBase64url(bytes);
  }

  public callDecode(s: string): Uint8Array {
    return this.decodeBase64url(s);
  }
}

/** Browser counterpart of {@link NodeSeamProbe} (pure-codec path). */
class BrowserSeamProbe extends BrowserCryptoManager {
  public callEncode(bytes: Uint8Array): string {
    return this.encodeBase64url(bytes);
  }

  public callDecode(s: string): Uint8Array {
    return this.decodeBase64url(s);
  }
}

/**
 * Node manager whose seam methods RECORD their arguments and then delegate to
 * the real ones with `super`. This is not a mock of the unit under test: the
 * seam is the class's documented extension point, and supplying an
 * implementation through it is exactly what the Node build and any future
 * runtime does. It exists to pin that the public text API actually goes
 * THROUGH the seam — a call site that quietly reverts to the module-level
 * codec would be byte-identical (so no other test in this file could see it)
 * while silently costing the Node build its native fast path.
 */
class RecordingSeam extends NodeCryptoManager {
  public readonly encodedLengths: number[] = [];
  public readonly decodedInputs: string[] = [];

  protected override encodeBase64url(bytes: Uint8Array): string {
    this.encodedLengths.push(bytes.length);
    return super.encodeBase64url(bytes);
  }

  protected override decodeBase64url(s: string): Uint8Array {
    this.decodedInputs.push(s);
    return super.decodeBase64url(s);
  }
}

/**
 * Deterministic pseudo-random bytes (xorshift32). Tests must pin randomness,
 * so the seed is a literal and every run produces the identical payload.
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

/** Byte-equality with a failure message that names the first differing index. */
function expectBytesEqual(
  actual: Uint8Array,
  expected: Uint8Array,
  what: string
): void {
  expect({ what, length: actual.length }).toEqual({
    what,
    length: expected.length,
  });
  let firstDiff = -1;
  for (let i = 0; i < expected.length; i += 1) {
    if (actual[i] !== expected[i]) {
      firstDiff = i;
      break;
    }
  }
  expect({ what, firstDifferingIndex: firstDiff }).toEqual({
    what,
    firstDifferingIndex: -1,
  });
}

/** Assert two byte arrays differ somewhere (the positive form of a tamper). */
function expectBytesDiffer(actual: Uint8Array, other: Uint8Array): void {
  let differs = actual.length !== other.length;
  for (let i = 0; !differs && i < actual.length; i += 1) {
    differs = actual[i] !== other[i];
  }
  expect({ differs }).toEqual({ differs: true });
}

/** Parse a hex literal into bytes (for the hand-derived decode expectations). */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** True when an error is the documented "Argon2id unavailable" graceful state. */
function isArgon2Unavailable(err: unknown): boolean {
  return (
    err instanceof CryptoError &&
    (err as InstanceType<typeof CryptoError>).code === 'ARGON2_NOT_AVAILABLE'
  );
}

// ---------------------------------------------------------------------------
// Byte inputs for the encode seam. Chosen to cover: the empty input; all three
// length residues mod 3 (which select the 4-char body, the 2-char tail and the
// 3-char tail); the 22-byte header size; a length that crosses the pure
// encoder's 8192-character scratch-flush boundary many times; the two extreme
// byte values (which exercise the high and low bits of every sextet); a seeded
// pseudo-random payload; and BOTH branches of the Node override — a plain
// `Uint8Array` at a non-zero `byteOffset` (the no-copy view branch, which is
// the hot one for `encryptText`) and a real `Buffer` (the `isBuffer` branch).
// ---------------------------------------------------------------------------
const BYTE_CASES: Array<{ name: string; bytes: Uint8Array }> = [
  { name: 'empty (0 bytes)', bytes: new Uint8Array(0) },
  { name: '1 byte (residue 1 -> 2-char tail)', bytes: Uint8Array.from([0xa5]) },
  {
    name: '2 bytes (residue 2 -> 3-char tail)',
    bytes: Uint8Array.from([0xa5, 0x5a]),
  },
  {
    name: '3 bytes (residue 0 -> no tail)',
    bytes: Uint8Array.from([0xa5, 0x5a, 0x0f]),
  },
  { name: '4 bytes', bytes: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) },
  { name: '22 bytes (header-sized)', bytes: seededBytes(22, 0x5eed_0022) },
  { name: '100 bytes', bytes: seededBytes(100, 0x5eed_0100) },
  { name: '1024 bytes', bytes: seededBytes(1024, 0x5eed_1024) },
  {
    name: '65537 bytes (crosses the 8192-char scratch flush repeatedly)',
    bytes: seededBytes(65537, 0x5eed_ffff),
  },
  { name: 'all-0x00 (256 bytes)', bytes: new Uint8Array(256) },
  { name: 'all-0xff (256 bytes)', bytes: new Uint8Array(256).fill(0xff) },
  { name: 'seeded pseudo-random (777 bytes)', bytes: seededBytes(777, 0x1234) },
  {
    name: 'view at byteOffset 7 (no-copy branch of the Node override)',
    bytes: seededBytes(67, 0x0ff5_0007).subarray(7),
  },
  {
    name: 'a real Buffer (isBuffer branch of the Node override)',
    bytes: Buffer.from(seededBytes(300, 0xb0ff_e300)),
  },
];

// ---------------------------------------------------------------------------
// Decode-seam inputs. `expectedHex` is derived BY HAND from the base64
// alphabet (documented per case), not captured from either implementation, so
// the table is an independent oracle rather than a snapshot of current
// behavior.
// ---------------------------------------------------------------------------
const DECODE_CASES: Array<{
  name: string;
  input: string;
  expectedHex: string;
}> = [
  {
    // "Hello world" — the reference payload every lenient variant below
    // must also produce.
    name: 'canonical base64url, unpadded',
    input: 'SGVsbG8gd29ybGQ',
    expectedHex: '48656c6c6f20776f726c64',
  },
  {
    // Trailing '=' is padding on an already-complete group: nothing follows.
    name: 'padded with a trailing =',
    input: 'SGVsbG8gd29ybGQ=',
    expectedHex: '48656c6c6f20776f726c64',
  },
  {
    // '+'(62) '/'(63) are the STANDARD-alphabet aliases of '-' and '_':
    // q=42,+=62,7=59,/=63 -> 101010 111110 111011 111111 -> ab ee ff.
    name: 'standard alphabet (+ and /) accepted as aliases',
    input: 'q+7/',
    expectedHex: 'abeeff',
  },
  {
    name: 'url-safe alphabet (- and _) for the same three bytes',
    input: 'q-7_',
    expectedHex: 'abeeff',
  },
  {
    // Line breaks are skipped, not fatal — this is what lets `decryptText`
    // accept a ciphertext that was wrapped by an email client or a config file.
    name: 'LF and CRLF line wrapping skipped',
    input: 'SGVsbG8g\nd29y\r\nbGQ',
    expectedHex: '48656c6c6f20776f726c64',
  },
  {
    name: 'spaces and tabs skipped',
    input: 'SGVs bG8g\td29ybGQ',
    expectedHex: '48656c6c6f20776f726c64',
  },
  {
    // Every non-alphabet code unit is dropped; the surviving characters spell
    // the canonical string above.
    name: 'arbitrary non-alphabet punctuation skipped',
    input: 'S!G@V#s$b%G^8`g&d29ybGQ',
    expectedHex: '48656c6c6f20776f726c64',
  },
  {
    // '=' TERMINATES: only 'SGVs' (4 chars -> 3 bytes, "Hel") is decoded.
    name: '= terminates decoding mid-string',
    input: 'SGVs=bG8g',
    expectedHex: '48656c',
  },
  {
    // U+0141 truncates to its low 8 bits, 0x41 = 'A' (sextet 0), so the
    // effective input is 'SGVsbG8A': b,G,8,A -> 011011 000110 111100 000000
    // -> 6c 6f 00, appended to "Hel".
    name: 'BMP code unit truncated to its low 8 bits (U+0141 -> "A")',
    input: 'SGVsbG8Ł',
    expectedHex: '48656c6c6f00',
  },
  {
    // U+1F600 is the surrogate pair D83D DE00; the low bytes are 0x3D ('=')
    // and 0x00, so the '=' terminates after 'SGVs' -> "Hel".
    name: 'astral code point truncated per code unit (low byte 0x3D = "=")',
    input: 'SGVs\u{1F600}bG8g',
    expectedHex: '48656c',
  },
  {
    // A lone sextet cannot complete a byte, so it is discarded entirely.
    name: 'single character (incomplete sextet discarded)',
    input: 'A',
    expectedHex: '',
  },
  {
    // 'QQ' -> 010000 010000 -> keeps the first 8 bits: 0x41.
    name: 'two characters yield exactly one byte',
    input: 'QQ',
    expectedHex: '41',
  },
  {
    name: 'empty string decodes to zero bytes',
    input: '',
    expectedHex: '',
  },
];

// ---------------------------------------------------------------------------
// Text payloads for the cross-manager round-trips. Byte lengths mirror
// BYTE_CASES where UTF-8 permits (0xff is not a legal UTF-8 byte, so the
// all-0xff payload is covered at the seam level only), plus three lengths that
// exercise BOTH `Buffer.from(s, 'base64url')` allocation regimes end to end:
// the 1024-byte payload's ciphertext is served from Node's shared internal
// pool (a view at a possibly non-zero `byteOffset`), the 65537-byte payload's
// is a standalone allocation. The boundary itself is pinned separately, by the
// LARGEST_POOLED_DECODE test in the decode-seam block.
// ---------------------------------------------------------------------------
const TEXT_CASES: Array<{ name: string; text: string }> = [
  { name: 'empty string', text: '' },
  { name: '1 byte', text: 'a' },
  { name: '2 bytes', text: 'ab' },
  { name: '3 bytes', text: 'abc' },
  { name: '4 bytes', text: 'abcd' },
  { name: '22 bytes', text: 'x'.repeat(22) },
  { name: '100 bytes', text: 'y'.repeat(100) },
  { name: '1024 bytes', text: 'z'.repeat(1024) },
  {
    name: '96 NUL bytes (all-0x00 payload)',
    text: '\u0000'.repeat(96),
  },
  {
    name: 'multi-byte unicode (2-, 3- and 4-byte sequences + combining mark)',
    text: 'héllo 世界 😀 é',
  },
  {
    name: '65537 bytes (decode lands outside the pool)',
    text: 's'.repeat(65537),
  },
];

describe('base64url codec seam — the Node override cannot change a wire byte', () => {
  jest.setTimeout(180_000);

  const node = new NodeCryptoManager(LOW_COST);
  const browser = new BrowserCryptoManager(LOW_COST);
  const nodeProbe = new NodeSeamProbe(LOW_COST);
  const browserProbe = new BrowserSeamProbe(LOW_COST);

  // Probe IS the call: one real Web-engine round-trip. Flips to false only if
  // hash-wasm genuinely cannot load on this host.
  let webEngineReady = false;
  beforeAll(async () => {
    try {
      const probe = new BrowserCryptoManager(LOW_COST);
      const ct = await probe.encryptBytes(new Uint8Array([1, 2, 3]), PASSWORD);
      await probe.decryptBytes(ct, PASSWORD);
      webEngineReady = true;
    } catch (err) {
      if (isArgon2Unavailable(err)) {
        if (process.env.CI) {
          throw new Error(
            'hash-wasm Argon2id failed to load in CI; the cross-runtime codec ' +
              'seam assertions may not be silently skipped. Ensure the ' +
              'optional hash-wasm dependency is installed.',
            { cause: err }
          );
        }
        webEngineReady = false;
        // eslint-disable-next-line no-console
        console.warn(
          '[skip] hash-wasm Argon2id unavailable; cross-manager round-trip ' +
            `assertions will be skipped: ${String(err)}`
        );
      } else {
        throw err;
      }
    }
  }, 60_000);

  describe('encode seam', () => {
    it.each(BYTE_CASES)(
      '$name: the Node override and the browser seam both emit the pure encoder’s exact string, without touching the input',
      ({ bytes }) => {
        // Independent copy so mutation of the input is detectable.
        const untouched = Uint8Array.from(bytes);
        const pure = bytesToBase64url(bytes);

        const fromNode = nodeProbe.callEncode(bytes);
        const fromBrowser = browserProbe.callEncode(bytes);

        // The wire guarantee: one format, character for character.
        expect(fromNode).toBe(pure);
        expect(fromNode).toBe(fromBrowser);

        // NEGATIVE 1 — neither seam wrote to the caller's buffer. `encryptText`
        // still owns it and scrubs it after encoding; an in-place override
        // would corrupt the ciphertext it is about to return.
        expectBytesEqual(bytes, untouched, 'input buffer after encoding');

        // NEGATIVE 2 — independent of the equality above, so it still fires if
        // BOTH implementations drifted together (e.g. to 'base64' or to a
        // padded/line-wrapped encoder). The output is canonical base64url:
        // no padding, no standard-alphabet characters, no whitespace.
        expect(fromNode).not.toMatch(/[=+/\s]/);
      }
    );

    it('encodes a length that is not a multiple of the scratch chunk without dropping or duplicating a character', () => {
      // 8192 output characters is exactly the pure encoder's flush boundary;
      // 6144 input bytes produce 8192 characters, and 6145 produce 8194 — one
      // full flush plus a 2-character remainder. An off-by-one in either
      // implementation's flush shows up here as a length mismatch.
      for (const inputLength of [6143, 6144, 6145]) {
        const bytes = seededBytes(inputLength, 0x8192);
        const expectedChars = Math.ceil((inputLength * 4) / 3);
        const encoded = nodeProbe.callEncode(bytes);
        expect({ inputLength, chars: encoded.length }).toEqual({
          inputLength,
          chars: expectedChars,
        });
        expect(encoded).toBe(bytesToBase64url(bytes));
      }
    });
  });

  describe('decode seam', () => {
    it.each(DECODE_CASES)(
      '$name: the Node override, the pure decoder, and the hand-derived expectation all agree',
      ({ input, expectedHex }) => {
        const expected = hexToBytes(expectedHex);

        const fromNode = nodeProbe.callDecode(input);
        const fromBrowser = browserProbe.callDecode(input);
        const pure = base64urlToBytes(input);

        // Independent oracle: the bytes stated in the table, not the bytes
        // either implementation happens to produce today.
        expectBytesEqual(fromNode, expected, 'Node override vs hand-derived');
        expectBytesEqual(fromBrowser, expected, 'browser seam vs hand-derived');
        expectBytesEqual(pure, expected, 'pure decoder vs hand-derived');

        // The NEGATIVE is carried by `expectedHex` itself rather than by an
        // extra assertion: every lenient case above contains at least one
        // character that must leave NO trace in the output (a skipped space,
        // an `=` that stops decoding early, the low byte of a surrogate), and
        // the hand-derived expectation is shorter than a decoder that folded
        // those in would produce. A separate length check here would be
        // subsumed by `expectBytesEqual`, which compares lengths first, so it
        // could never fail on its own.
      }
    );

    it('returns a view into a larger shared backing store for a small result, and every consumer honours the offset', async () => {
      // A short ciphertext: 22+32+12+16 + 11 = 93 bytes decoded, far below
      // POOL_THRESHOLD, so Node serves it from the shared internal pool.
      const plaintext = 'Hello world';
      const ciphertext = await node.encryptText(plaintext, PASSWORD);
      const decoded = nodeProbe.callDecode(ciphertext);

      expect(decoded.byteLength).toBe(V1_FIXED_OVERHEAD + 11);
      // The property that makes offset-safety load-bearing: the decode does
      // NOT own its backing store, it is a window into a bigger one.
      expect(decoded.buffer.byteLength).toBeGreaterThan(decoded.byteLength);
      // ...and it decodes to exactly the same bytes as the pure decoder.
      expectBytesEqual(
        decoded,
        base64urlToBytes(ciphertext),
        'pooled decode vs pure decode'
      );

      // End-to-end through the real API, on both builds.
      await expect(node.decryptText(ciphertext, PASSWORD)).resolves.toBe(
        plaintext
      );
      if (webEngineReady) {
        await expect(browser.decryptText(ciphertext, PASSWORD)).resolves.toBe(
          plaintext
        );
      }
    });

    it('decodes identically on both sides of the pooled/standalone allocation boundary', () => {
      const below = LARGEST_POOLED_DECODE;
      const above = LARGEST_POOLED_DECODE + 1;
      // Deterministic content, so the only variable is the length.
      const bytesBelow = seededBytes(below, 0x900_1ed);
      const bytesAbove = seededBytes(above, 0x900_1ee);

      const decodedBelow = nodeProbe.callDecode(bytesToBase64url(bytesBelow));
      const decodedAbove = nodeProbe.callDecode(bytesToBase64url(bytesAbove));

      // The boundary is real: one side is a window into a bigger store, the
      // other owns its store outright. If this ever stops holding, the
      // discovered constant has drifted and the "pooled" cases elsewhere in
      // this file would silently stop testing the pooled path.
      expect(decodedBelow.buffer.byteLength).toBeGreaterThan(
        decodedBelow.byteLength
      );
      expect(decodedAbove.buffer.byteLength).toBe(decodedAbove.byteLength);

      // ...and the allocation regime changes nothing about the bytes.
      expectBytesEqual(decodedBelow, bytesBelow, 'pooled decode');
      expectBytesEqual(decodedAbove, bytesAbove, 'standalone decode');
    });

    it('parses from byteOffset, not from the start of the backing store, even when the preceding bytes are a decoy header', async () => {
      // Deterministic stand-in for the pooled buffer above: the same ciphertext
      // placed at byteOffset 7 inside a larger array whose first bytes are a
      // DECOY v1 header ("HPCR" + version 0x7f). Any consumer that built a
      // DataView over the whole backing store instead of the view's own range
      // would read version 0x7f and throw UNSUPPORTED_VERSION.
      const plaintext = 'offset-sensitive payload';
      const ciphertext = await node.encryptText(plaintext, PASSWORD);
      const real = base64urlToBytes(ciphertext);

      const backing = new Uint8Array(7 + real.length);
      backing.set(utf8Encode('HPCR'), 0);
      backing[4] = 0x7f; // decoy version
      backing[5] = 0x7f; // decoy kdfId
      backing[6] = 0x7f;
      backing.set(real, 7);
      const view = backing.subarray(7);
      expect(view.byteOffset).toBe(7);

      await expect(node.decryptBytes(view, PASSWORD)).resolves.toEqual(
        utf8Encode(plaintext)
      );

      const fromView = node.inspectHeader(view);
      expect(fromView).toEqual(node.inspectHeader(real));
      // NEGATIVE — the decoy bytes were not read: a version-0x7f header would
      // have thrown, and the parsed version is the real one.
      expect(fromView?.version).toBe(FORMAT_VERSION);
      expect(fromView?.kdfId).toBe(KDF_ID_ARGON2ID);
    });
  });

  describe('cross-manager round-trips through the seam', () => {
    it.each(TEXT_CASES)(
      '$name: Node-encrypted text decrypts in the browser build and vice-versa',
      async ({ text }) => {
        if (!webEngineReady) return;

        const fromNode = await node.encryptText(text, PASSWORD);
        const fromBrowser = await browser.encryptText(text, PASSWORD);

        await expect(browser.decryptText(fromNode, PASSWORD)).resolves.toBe(
          text
        );
        await expect(node.decryptText(fromBrowser, PASSWORD)).resolves.toBe(
          text
        );

        // NEGATIVE 1 — the two ciphertexts must NOT be equal. Each carries a
        // fresh random salt and IV, so an equality here would mean the
        // encryptor became deterministic (catastrophic for GCM).
        expect(fromNode).not.toBe(fromBrowser);

        // NEGATIVE 2 — the Node-produced string is canonical base64url. It is
        // the value a caller stores; padding or a standard-alphabet character
        // would be a wire-format change even though it still decodes locally.
        expect(fromNode).not.toMatch(/[=+/\s]/);
        expect(fromNode).toBe(bytesToBase64url(base64urlToBytes(fromNode)));
      }
    );

    it('rejects the wrong password on a ciphertext that crossed runtimes, on both builds', async () => {
      if (!webEngineReady) return;
      const fromNode = await node.encryptText('crossing payload', PASSWORD);
      const fromBrowser = await browser.encryptText(
        'crossing payload',
        PASSWORD
      );

      await expect(
        browser.decryptText(fromNode, WRONG_PASSWORD)
      ).rejects.toThrow(CryptoError);
      await expect(
        node.decryptText(fromBrowser, WRONG_PASSWORD)
      ).rejects.toThrow(CryptoError);
    });

    it('still rejects a single-character tamper of a Node-encoded ciphertext', async () => {
      const ciphertext = await node.encryptText('x'.repeat(64), PASSWORD);

      // Character 90 sits inside the 16-byte GCM tag (bytes 66-81 -> characters
      // 88-109) and therefore inside a COMPLETE 4-character group, where all 6
      // bits of the character are significant. That matters: in the final group
      // of a ciphertext whose length is not a multiple of 3, the last
      // character's low bits are don't-care padding, so swapping it can leave
      // the decoded bytes untouched and the test would pass or fail depending
      // on the run's random salt.
      const index = 90;
      const replacement = ciphertext[index] === 'A' ? 'B' : 'A';
      const tampered =
        ciphertext.slice(0, index) + replacement + ciphertext.slice(index + 1);

      // The tamper is real (a decoded byte actually changed) ...
      expectBytesDiffer(
        base64urlToBytes(tampered),
        base64urlToBytes(ciphertext)
      );
      // ... and the input is still well-formed base64url, so the rejection
      // below comes from GCM authentication and not from the decoder.
      expect(isValidBase64url(tampered)).toBe(true);

      await expect(node.decryptText(tampered, PASSWORD)).rejects.toThrow(
        CryptoError
      );
    });
  });

  describe('the public API is routed through the seam', () => {
    it('encryptText encodes through the seam exactly once, and decodes nothing', async () => {
      const recorder = new RecordingSeam(LOW_COST);
      const text = 'routed through the seam';

      const ciphertext = await recorder.encryptText(text, PASSWORD);

      // Exactly one encode, of the assembled v1 ciphertext (header + salt + iv
      // + tag + body). The length is the full wire record, which is what makes
      // this the hot call the native encoder exists for.
      expect(recorder.encodedLengths).toEqual([
        V1_FIXED_OVERHEAD + utf8Encode(text).length,
      ]);
      // NEGATIVE — the encrypt path must not decode anything.
      expect(recorder.decodedInputs).toEqual([]);
      // Provenance is established by `encodedLengths` above; this only adds
      // that whatever the seam returned is canonical base64url.
      expect(ciphertext).toBe(bytesToBase64url(base64urlToBytes(ciphertext)));
    });

    it('decryptText decodes through the seam exactly once, and encodes nothing', async () => {
      const text = 'routed through the seam';
      const ciphertext = await node.encryptText(text, PASSWORD);

      const recorder = new RecordingSeam(LOW_COST);
      await expect(recorder.decryptText(ciphertext, PASSWORD)).resolves.toBe(
        text
      );

      expect(recorder.decodedInputs).toEqual([ciphertext]);
      // NEGATIVE — the decrypt path must not encode anything.
      expect(recorder.encodedLengths).toEqual([]);
    });

    it('inspectHeader decodes through the seam, on a prefix of the ciphertext string', async () => {
      const ciphertext = await node.encryptText('inspected', PASSWORD);

      const recorder = new RecordingSeam(LOW_COST);
      const parsed = recorder.inspectHeader(ciphertext);

      expect(parsed?.version).toBe(FORMAT_VERSION);
      expect(recorder.decodedInputs).toHaveLength(1);
      // Asserted as "a prefix of the ciphertext" rather than "the whole
      // string": the header is always at the front, so this holds both today
      // (whole string) and once the decode is narrowed to the header prefix.
      const seen = recorder.decodedInputs[0] ?? '';
      expect(ciphertext.startsWith(seen)).toBe(true);
      expect(seen.length).toBeGreaterThan(0);
      // NEGATIVE — inspecting a header must never encode.
      expect(recorder.encodedLengths).toEqual([]);
    });

    it('does not reach the seam at all when input validation rejects first', async () => {
      const recorder = new RecordingSeam(LOW_COST);

      await expect(
        recorder.encryptText(null as unknown as string, PASSWORD)
      ).rejects.toThrow(CryptoError);
      await expect(recorder.decryptText('', PASSWORD)).rejects.toThrow(
        CryptoError
      );
      expect(() => recorder.inspectHeader('')).toThrow(CryptoError);
      expect(() => recorder.inspectHeader('!!!!')).toThrow(CryptoError);

      // NEGATIVE — every one of those failed before any codec work happened.
      expect(recorder.encodedLengths).toEqual([]);
      expect(recorder.decodedInputs).toEqual([]);
    });
  });

  describe('inspectHeader over the seam', () => {
    it('returns the same parsed header from the string path and the byte path', async () => {
      const ciphertext = await node.encryptText('inspect me', PASSWORD);
      const fromString = node.inspectHeader(ciphertext);
      const fromBytes = node.inspectHeader(base64urlToBytes(ciphertext));

      expect(fromString).toEqual(fromBytes);
      expect(fromString).toEqual({
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
      // Both builds read the same header from the same string.
      expect(browser.inspectHeader(ciphertext)).toEqual(fromString);
    });

    it('returns null for a v0-shaped string (no magic) rather than throwing', () => {
      // 82 bytes of non-magic data: the v0 layout is [salt][iv][tag][body]
      // with no header, so `inspectHeader` must report "no v1 header".
      const v0Like = bytesToBase64url(seededBytes(82, 0x0d05_0082));
      expect(node.inspectHeader(v0Like)).toBeNull();
    });

    it('throws INVALID_BASE64URL for a malformed string instead of silently reporting v0', () => {
      let thrown: unknown;
      try {
        node.inspectHeader('!!!!');
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(CryptoError);
      expect((thrown as InstanceType<typeof CryptoError>).code).toBe(
        'INVALID_BASE64URL'
      );
      // NEGATIVE — it must NOT have returned null (which is what a decode-first
      // implementation would produce, since '!!!!' decodes to zero bytes).
      expect(thrown).not.toBeUndefined();
    });

    it('throws INVALID_INPUT for the empty string', () => {
      let thrown: unknown;
      try {
        node.inspectHeader('');
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(CryptoError);
      expect((thrown as InstanceType<typeof CryptoError>).code).toBe(
        'INVALID_INPUT'
      );
    });
  });
});
