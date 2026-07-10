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
 * produces. Decoding accepts optional trailing `=` padding and reproduces the
 * canonical round-trip behaviour used by {@link isValidBase64url}.
 */

/** URL-safe base64 alphabet; index 0..63 maps to the sextet value. */
const B64URL_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Reverse lookup: ASCII code point (0..127) -> 6-bit sextet value, or -1 for
 * any code point that is not a base64url alphabet character. Code points >=
 * 128 index out of range and read back as `undefined` (handled by callers).
 */
const B64URL_REV: number[] = new Array<number>(128).fill(-1);
for (let index = 0; index < B64URL_CHARS.length; index += 1) {
  B64URL_REV[B64URL_CHARS.charCodeAt(index)] = index;
}

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
 * Decode a base64url string to bytes.
 *
 * A trailing run of `=` padding is accepted and ignored. Scanning stops at
 * the first character outside the base64url alphabet (that character and any
 * bytes after it are dropped), and any trailing sextet that does not complete
 * a whole byte is discarded — together these reproduce the canonical
 * round-trip semantics of the equivalent Node base64url decode, so a string
 * survives {@link isValidBase64url} only when it is already canonical.
 *
 * @param s - base64url-encoded string
 * @returns decoded bytes
 */
export function base64urlToBytes(s: string): Uint8Array {
  // Strip a trailing run of '=' padding (0x3d).
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x3d) {
    end -= 1;
  }

  // Collect the 6-bit value of each leading base64url character.
  const sextets: number[] = [];
  for (let i = 0; i < end; i += 1) {
    const value = B64URL_REV[s.charCodeAt(i)];
    if (value === undefined || value < 0) {
      break;
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
