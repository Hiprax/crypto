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
 * remains a strict CANONICAL check: it returns `true` for exactly the strings
 * {@link bytesToBase64url} can emit (it is now a single structural scan rather
 * than a decode-then-re-encode round trip, but the accepted set is identical).
 */

/** URL-safe base64 alphabet; index 0..63 maps to the sextet value. */
const B64URL_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Forward lookup indexed by a 6-bit sextet value (0..63) -> the UTF-16 code
 * unit of the base64url character that encodes it. Holding the alphabet as
 * char CODES (rather than calling `String.prototype.charAt`, which allocates a
 * one-character string per output character) is what lets
 * {@link bytesToBase64url} emit whole chunks through `String.fromCharCode`.
 *
 * This table is module-scoped deliberately: it is the fixed, public base64url
 * alphabet, never caller data, so retaining it leaks nothing. The per-call
 * OUTPUT scratch buffer is the opposite case — see {@link bytesToBase64url}.
 */
const B64URL_CODES = new Uint8Array(64);
for (let index = 0; index < B64URL_CHARS.length; index += 1) {
  B64URL_CODES[index] = B64URL_CHARS.charCodeAt(index);
}

/**
 * Reverse lookup indexed by a BYTE value (0..255) -> 6-bit sextet value, or -1
 * for any byte that is not a base64 alphabet character. {@link base64urlToBytes}
 * indexes this with `codeUnit & 0xFF`, mirroring Node's base64 decoder, which
 * truncates each UTF-16 code unit to its low 8 bits before classifying it. A
 * full 256-entry table means every low byte is a valid index (no `undefined`).
 */
const B64URL_REV = new Int8Array(256).fill(-1);
for (let index = 0; index < B64URL_CHARS.length; index += 1) {
  B64URL_REV[B64URL_CHARS.charCodeAt(index)] = index;
}
// Node's `Buffer.from(s, 'base64url')` decoder ALSO accepts the STANDARD
// base64 alphabet (`+` and `/`) as aliases for the URL-safe `-` and `_`. Map
// them to the same sextet values so {@link base64urlToBytes} stays
// byte-for-byte compatible with Node for standard-alphabet input too (e.g. a
// ciphertext normalised from base64url to standard base64 in transit).
// NOTE: {@link isValidBase64url} must therefore reject `+` and `/` EXPLICITLY —
// the lenient decoder accepts them, but the canonical encoder never emits them.
B64URL_REV[0x2b] = 62; // '+' decodes as '-'
B64URL_REV[0x2f] = 63; // '/' decodes as '_'

/** ASCII code unit of `+`, a standard-alphabet alias the canonical form bans. */
const CHAR_PLUS = 0x2b;
/** ASCII code unit of `/`, a standard-alphabet alias the canonical form bans. */
const CHAR_SLASH = 0x2f;
/** ASCII code unit of `=`; terminates a lenient decode. */
const CHAR_EQUALS = 0x3d;

const utf8Encoder = new TextEncoder();
// `ignoreBOM: true` KEEPS a leading U+FEFF byte-order mark as a real code point
// instead of silently stripping it. This is counterintuitively named but is
// what makes `utf8Decode` byte-for-byte match Node's `toString('utf8')`, which
// never strips a BOM. `fatal` stays false so invalid sequences become U+FFFD,
// also matching Node.
const utf8Decoder = new TextDecoder('utf-8', { ignoreBOM: true });

/**
 * base64 quanta (4 output characters each) emitted per `String.fromCharCode`
 * flush. 2048 quanta = 8192 characters: large enough that the per-flush
 * concatenation cost is amortised, and comfortably below the engine
 * argument-count limit for `Function.prototype.apply`.
 */
const B64_ENCODE_CHUNK_QUANTA = 2048;

/**
 * Output characters emitted per flush.
 *
 * Being a multiple of 4 is LOAD-BEARING: it means a flush only ever happens on
 * a whole-quantum boundary, which is what guarantees the 1-/2-byte tail always
 * fits in the scratch slots left over after the main loop. Deriving it from a
 * quanta count makes that structural rather than a rule someone has to
 * remember when tuning the number.
 */
const B64_ENCODE_CHUNK = B64_ENCODE_CHUNK_QUANTA * 4;

/**
 * Flush the first `count` code units of `scratch` into a string.
 *
 * `String.fromCharCode.apply` accepts any array-like of numbers at runtime and
 * is dramatically faster than per-character string concatenation, but its
 * declared signature is `(...codes: number[])`, which `strictBindCallApply`
 * will not satisfy from a typed array. The cast is a typing bridge only; no
 * runtime conversion happens.
 *
 * @param scratch - buffer of UTF-16 code units
 * @param count - how many leading entries of `scratch` to emit
 * @returns the decoded string chunk
 */
function flushCharCodes(scratch: Uint16Array, count: number): string {
  const view = count === scratch.length ? scratch : scratch.subarray(0, count);
  return String.fromCharCode.apply(null, view as unknown as number[]);
}

/**
 * Encode bytes as a canonical, unpadded base64url string.
 *
 * Single pass over the input: each 3-byte group becomes 4 alphabet code units
 * in a scratch buffer that is flushed to the output string every
 * {@link B64_ENCODE_CHUNK} characters, with the 1-byte (2 chars) and 2-byte
 * (3 chars) tails handled separately so no padding is emitted.
 *
 * The scratch buffer is allocated PER CALL on purpose. `bytesToBase64url` is a
 * public export of both entry points and callers routinely hand it key
 * material or plaintext; a module-scope buffer would retain the base64
 * characters of the last-encoded payload for the lifetime of the process,
 * contradicting the `secureClear` hygiene this library documents. One typed
 * array per call is still vastly cheaper than the per-character string
 * concatenation it replaces.
 *
 * @param bytes - input bytes
 * @returns URL-safe base64 string with no padding
 */
export function bytesToBase64url(bytes: Uint8Array): string {
  const len = bytes.length;
  if (len === 0) {
    return '';
  }

  const remainder = len % 3;
  const outLength =
    ((len - remainder) / 3) * 4 + (remainder === 0 ? 0 : remainder + 1);
  const capacity = outLength < B64_ENCODE_CHUNK ? outLength : B64_ENCODE_CHUNK;
  const scratch = new Uint16Array(capacity);

  let out = '';
  let si = 0;
  const tripleEnd = len - remainder;
  for (let i = 0; i < tripleEnd; i += 3) {
    const triple =
      ((bytes[i] ?? 0) << 16) |
      ((bytes[i + 1] ?? 0) << 8) |
      (bytes[i + 2] ?? 0);
    scratch[si] = B64URL_CODES[(triple >> 18) & 0x3f] ?? 0;
    scratch[si + 1] = B64URL_CODES[(triple >> 12) & 0x3f] ?? 0;
    scratch[si + 2] = B64URL_CODES[(triple >> 6) & 0x3f] ?? 0;
    scratch[si + 3] = B64URL_CODES[triple & 0x3f] ?? 0;
    si += 4;
    if (si === capacity) {
      out += flushCharCodes(scratch, si);
      si = 0;
    }
  }

  // Tails: `capacity` is a multiple of 4 whenever it is capped at
  // B64_ENCODE_CHUNK, and `si` only advances in steps of 4, so at most
  // `capacity - 4` slots are used here — always room for the 2 or 3 tail
  // characters. When the whole output fits in the scratch, `capacity` IS
  // `outLength`, which reserves those slots exactly.
  //
  // The tail is built from the SAME zero-padded `triple` the main loop uses,
  // rather than from a per-byte decomposition. Two reasons, both load-bearing:
  // the `& 0x3f` masks are then intrinsic, so no element can index past the
  // 64-entry table and make `?? 0` emit a NUL (a character outside the
  // alphabet this function documents itself as producing); and it is
  // expression-for-expression what the previous implementation computed, so
  // the output is byte-identical for EVERY input — including the
  // out-of-contract array-likes a JavaScript caller can pass to what is a
  // public export of both entry points.
  if (remainder !== 0) {
    const b0 = bytes[tripleEnd] ?? 0;
    const b1 = remainder === 2 ? (bytes[tripleEnd + 1] ?? 0) : 0;
    const triple = (b0 << 16) | (b1 << 8);
    scratch[si] = B64URL_CODES[(triple >> 18) & 0x3f] ?? 0;
    scratch[si + 1] = B64URL_CODES[(triple >> 12) & 0x3f] ?? 0;
    si += 2;
    if (remainder === 2) {
      scratch[si] = B64URL_CODES[(triple >> 6) & 0x3f] ?? 0;
      si += 1;
    }
  }

  if (si > 0) {
    out += flushCharCodes(scratch, si);
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
 * unpadded, URL-safe string.
 *
 * Implementation: ONE pass over the input collects every accepted sextet into
 * a `Uint8Array` scratch sized at the input length (its maximum possible
 * count), then the exact-sized output is filled from it four sextets at a
 * time. The scratch replaces the `number[]` accumulator this function used to
 * grow one `push` at a time.
 *
 * @param s - base64url-encoded string (canonical or leniently-encoded)
 * @returns decoded bytes
 */
export function base64urlToBytes(s: string): Uint8Array {
  const len = s.length;
  const sextets = new Uint8Array(len);
  let n = 0;
  for (let i = 0; i < len; i += 1) {
    // Node classifies each UTF-16 code unit by its low 8 bits (so e.g. a
    // surrogate half 0xD83D, low byte 0x3D, terminates just like '=').
    const byte = s.charCodeAt(i) & 0xff;
    if (byte === CHAR_EQUALS) {
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
    sextets[n] = value;
    n += 1;
  }

  const out = new Uint8Array((n * 3) >> 2);
  let oi = 0;
  let i = 0;
  const quadEnd = n - (n & 3);
  for (; i < quadEnd; i += 4) {
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
  // `remaining === 1` is a trailing sextet that cannot complete a byte: Node
  // discards it, and so does the `(n * 3) >> 2` output length above.
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
 * Validate a base64url string via its canonical form.
 *
 * Returns `true` only when the input is already in the exact canonical form
 * {@link bytesToBase64url} produces (URL-safe alphabet, no padding, no
 * non-canonical trailing bits) — i.e. exactly when
 * `bytesToBase64url(base64urlToBytes(s)) === s` and `s` is non-empty. That
 * round trip is what this function used to compute; it is now the equivalent
 * O(n), allocation-free structural scan:
 *
 *   1. Every code unit must be an ASCII character of the URL-safe alphabet.
 *      A code unit >= 256 is rejected outright, because the LENIENT decoder
 *      would alias it to its low byte (`Ł` -> `A`) and re-encode to a
 *      different string. `=` (padding), whitespace, and the standard-alphabet
 *      `+` / `/` are rejected for the same reason: none of them can appear in
 *      encoder output.
 *   2. `length % 4 === 1` is impossible — one leftover character carries no
 *      whole byte, so it could never have been emitted.
 *   3. The final character's DISCARDED TAIL BITS must be zero, stated in terms
 *      of its decoded 6-BIT SEXTET VALUE (never its UTF-16 code unit): with 2
 *      leftover characters the low 4 bits of the last sextet are dropped, with
 *      3 leftover characters the low 2 bits are. A non-zero tail means the
 *      string decodes and re-encodes to a DIFFERENT final character.
 *
 * Never throws, and returns `false` for empty or non-string input.
 *
 * @param s - candidate base64url string
 * @returns true if `s` is canonical base64url
 */
export function isValidBase64url(s: string): boolean {
  if (!s || typeof s !== 'string') {
    return false;
  }
  const len = s.length;
  if (len % 4 === 1) {
    return false;
  }
  for (let i = 0; i < len; i += 1) {
    const code = s.charCodeAt(i);
    // The `code > 0xff` half is DELIBERATELY REDUNDANT with the table lookup
    // below: `B64URL_REV` has 256 entries, so a code unit >= 256 already reads
    // as `undefined` there and is rejected. It is spelled out anyway because
    // it is the rule (canonical output is ASCII), because relying on an
    // out-of-range typed-array read returning `undefined` is too subtle to
    // leave implicit, and so that widening the table can never silently start
    // accepting aliases. Mutation-testing note: removing it is an EQUIVALENT
    // mutant, and no test can distinguish it.
    //
    // `+` / `/`, by contrast, MUST be rejected explicitly — the table maps
    // them to real sextet values for the lenient decoder's benefit, but the
    // canonical encoder emits only `-` / `_`.
    if (code > 0xff || code === CHAR_PLUS || code === CHAR_SLASH) {
      return false;
    }
    if ((B64URL_REV[code] ?? -1) < 0) {
      return false;
    }
  }
  const remainder = len % 4;
  if (remainder === 0) {
    return true;
  }
  // Validated above, so this lookup is a real sextet value in 0..63.
  const last = B64URL_REV[s.charCodeAt(len - 1)] ?? 0;
  return remainder === 2 ? (last & 0x0f) === 0 : (last & 0x03) === 0;
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
