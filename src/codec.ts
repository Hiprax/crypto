/**
 * Pure, runtime-agnostic byte/string codecs for @hiprax/crypto.
 *
 * This module depends on nothing but `Uint8Array`, `TextEncoder`, and
 * `TextDecoder`, so the exact same code runs unchanged in Node and the
 * browser (no Node global, no Node builtin). Every function is
 * byte-for-byte compatible with the equivalent Node byte-buffer operation:
 *
 *   - `bytesToBase64url(b)`  === `<node-buffer>.from(b).toString('base64url')`
 *   - `base64urlToBytes(s)`  === `new Uint8Array(<node-buffer>.from(s, 'base64url'))`
 *   - `bytesToHex(b)`        === `<node-buffer>.from(b).toString('hex')`
 *   - `utf8Encode(s)`        === `new Uint8Array(<node-buffer>.from(s, 'utf8'))`
 *   - `utf8Decode(b)`        === `<node-buffer>.from(b).toString('utf8')`
 *   - `concatBytes(...p)`    === `<node-buffer>.concat(p)`
 *
 * base64url uses the URL-safe alphabet (`-`/`_` instead of `+`/`/`) and emits
 * NO padding, exactly matching the canonical form the equivalent Node encoder
 * produces. Decoding is byte-for-byte compatible with Node's lenient
 * `Buffer.from(s, 'base64url')`: it terminates at `=`, skips whitespace / line
 * wrapping / stray non-alphabet characters, and accepts the standard `+`/`/`
 * alphabet as well (see {@link base64urlToBytes}). {@link isValidBase64url}
 * remains a strict canonical check via decode-then-re-encode equality.
 */

/** URL-safe base64 alphabet; index 0..63 maps to the sextet value. */
const B64URL_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Reverse lookup indexed by a BYTE value (0..255) -> 6-bit sextet value, or -1
 * for any byte that is not a base64 alphabet character. {@link base64urlToBytes}
 * indexes this with `codeUnit & 0xFF`, mirroring Node's base64 decoder, which
 * truncates each UTF-16 code unit to its low 8 bits before classifying it. A
 * full 256-entry table means every low byte is a valid index (no `undefined`).
 */
const B64URL_REV: number[] = new Array<number>(256).fill(-1);
for (let index = 0; index < B64URL_CHARS.length; index += 1) {
  B64URL_REV[B64URL_CHARS.charCodeAt(index)] = index;
}
// Node's `Buffer.from(s, 'base64url')` decoder ALSO accepts the STANDARD
// base64 alphabet (`+` and `/`) as aliases for the URL-safe `-` and `_`. Map
// them to the same sextet values so {@link base64urlToBytes} stays
// byte-for-byte compatible with Node for standard-alphabet input too (e.g. a
// ciphertext normalised from base64url to standard base64 in transit).
B64URL_REV[0x2b] = 62; // '+' decodes as '-'
B64URL_REV[0x2f] = 63; // '/' decodes as '_'

const utf8Encoder = new TextEncoder();
// `ignoreBOM: true` KEEPS a leading U+FEFF byte-order mark as a real code point
// instead of silently stripping it. This is counterintuitively named but is
// what makes `utf8Decode` byte-for-byte match Node's `toString('utf8')`, which
// never strips a BOM. `fatal` stays false so invalid sequences become U+FFFD,
// also matching Node.
const utf8Decoder = new TextDecoder('utf-8', { ignoreBOM: true });

/**
 * Encode bytes as a canonical, unpadded base64url string.
 *
 * @param bytes - input bytes
 * @returns URL-safe base64 string with no padding
 */
export function bytesToBase64url(bytes: Uint8Array): string {
  let out = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += B64URL_CHARS.charAt((triple >> 18) & 0x3f);
    out += B64URL_CHARS.charAt((triple >> 12) & 0x3f);
    if (i + 1 < len) {
      out += B64URL_CHARS.charAt((triple >> 6) & 0x3f);
    }
    if (i + 2 < len) {
      out += B64URL_CHARS.charAt(triple & 0x3f);
    }
  }
  return out;
}

/**
 * Decode a base64url string to bytes, byte-for-byte compatible with Node's
 * `Buffer.from(s, 'base64url')` for EVERY input (pinned by the fast-check
 * parity property in `codec.test.ts`, which fuzzes the full UTF-16 code-unit
 * range incl. surrogate pairs). The decoder reproduces Node's lenient decoder
 * exactly:
 *
 *   - Each UTF-16 code unit is truncated to its low 8 bits (`codeUnit & 0xFF`)
 *     BEFORE classification — so a character >= 256 whose low byte aliases a
 *     base64 char or `=` behaves like that byte (e.g. U+0141 `Ł` (low byte
 *     0x41) decodes as `A`, and a code unit whose low byte is 0x3D terminates).
 *   - A `=` padding byte terminates decoding (Node stops at the first `=`);
 *     everything after it is ignored.
 *   - Any byte outside the base64 alphabet — ASCII whitespace (spaces, tabs,
 *     and the CR/LF injected by MIME / PEM / 76-column / YAML-folded transport)
 *     or stray punctuation — is SKIPPED and decoding continues, rather than
 *     ending the scan.
 *   - Both the URL-safe (`-`/`_`) and the standard (`+`/`/`) base64 alphabets
 *     are accepted (see the reverse-map aliases above).
 *   - A trailing sextet that does not complete a whole byte is discarded.
 *
 * This leniency is what lets `decryptText` accept a ciphertext that was
 * line-wrapped or normalised to standard base64 in transit — the same inputs
 * the pre-isomorphic Node path (which decoded via `Buffer.from`) tolerated.
 * {@link isValidBase64url} still returns `true` ONLY for a canonical,
 * unpadded, URL-safe string, because a non-canonical input re-encodes to a
 * different (canonical) string and fails the round-trip equality.
 *
 * @param s - base64url-encoded string (canonical or leniently-encoded)
 * @returns decoded bytes
 */
export function base64urlToBytes(s: string): Uint8Array {
  // Collect the 6-bit value of each base64 alphabet character, matching Node's
  // decoder exactly: truncate every code unit to its low 8 bits, stop at `=`,
  // skip any non-alphabet byte (whitespace / line wrapping / stray
  // punctuation), and accept both base64 alphabets.
  const sextets: number[] = [];
  for (let i = 0; i < s.length; i += 1) {
    // Node classifies each UTF-16 code unit by its low 8 bits (so e.g. a
    // surrogate half 0xD83D, low byte 0x3D, terminates just like '=').
    const byte = s.charCodeAt(i) & 0xff;
    if (byte === 0x3d) {
      // '=' padding marks the end of the encoded data.
      break;
    }
    // `byte` is always 0..255 and the table is fully populated, so the lookup
    // never yields `undefined` at runtime; `?? -1` satisfies
    // `noUncheckedIndexedAccess` without a runtime branch.
    const value = B64URL_REV[byte] ?? -1;
    if (value < 0) {
      // Whitespace or any non-alphabet byte: skip it and keep scanning.
      continue;
    }
    sextets.push(value);
  }

  const n = sextets.length;
  const out = new Uint8Array((n * 3) >> 2);
  let oi = 0;
  let i = 0;
  for (; i + 4 <= n; i += 4) {
    const c0 = sextets[i] ?? 0;
    const c1 = sextets[i + 1] ?? 0;
    const c2 = sextets[i + 2] ?? 0;
    const c3 = sextets[i + 3] ?? 0;
    out[oi] = (c0 << 2) | (c1 >> 4);
    out[oi + 1] = ((c1 & 0x0f) << 4) | (c2 >> 2);
    out[oi + 2] = ((c2 & 0x03) << 6) | c3;
    oi += 3;
  }
  const remaining = n - i;
  if (remaining === 2) {
    const c0 = sextets[i] ?? 0;
    const c1 = sextets[i + 1] ?? 0;
    out[oi] = (c0 << 2) | (c1 >> 4);
  } else if (remaining === 3) {
    const c0 = sextets[i] ?? 0;
    const c1 = sextets[i + 1] ?? 0;
    const c2 = sextets[i + 2] ?? 0;
    out[oi] = (c0 << 2) | (c1 >> 4);
    out[oi + 1] = ((c1 & 0x0f) << 4) | (c2 >> 2);
  }
  return out;
}

/**
 * Validate a base64url string via a canonical round-trip.
 *
 * Returns `true` only when the input is already in the exact canonical form
 * {@link bytesToBase64url} produces (URL-safe alphabet, no padding, no
 * non-canonical trailing bits). This matches the historical Node round-trip
 * validator (`decode-then-re-encode equals input`) and never throws.
 *
 * @param s - candidate base64url string
 * @returns true if `s` is canonical base64url
 */
export function isValidBase64url(s: string): boolean {
  if (!s || typeof s !== 'string') {
    return false;
  }
  try {
    return bytesToBase64url(base64urlToBytes(s)) === s;
  } catch {
    return false;
  }
}

/**
 * Encode bytes as a lowercase hex string (two hex digits per byte).
 *
 * @param bytes - input bytes
 * @returns lowercase hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Encode a string to its UTF-8 byte representation.
 *
 * @param s - input string
 * @returns UTF-8 bytes
 */
export function utf8Encode(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

/**
 * Decode UTF-8 bytes back to a string. Invalid sequences are replaced with
 * U+FFFD and a leading byte-order mark (U+FEFF) is preserved, both matching
 * the equivalent Node `toString('utf8')` byte-for-byte.
 *
 * @param bytes - UTF-8 bytes
 * @returns decoded string
 */
export function utf8Decode(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

/**
 * Concatenate byte arrays into a single new `Uint8Array`.
 *
 * @param parts - byte arrays to join, in order
 * @returns a new `Uint8Array` containing every part's bytes
 */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
