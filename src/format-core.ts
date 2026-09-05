/**
 * Pure, runtime-agnostic versioned ciphertext format layer for @hiprax/crypto.
 *
 * This module contains the real header logic and depends on nothing but
 * `Uint8Array` / `DataView` and the shared error types from `./types.js`. It
 * has NO dependency on any Node global or Node builtin, so the exact same
 * code runs unchanged in Node and in the browser. `./format.js` is a thin
 * Node wrapper that re-exports these constants/types and re-wraps the byte
 * primitives back to Node byte buffers so its long-standing public API is
 * preserved.
 *
 * Layout (v1):
 *   [magic:    4 bytes — ASCII "HPCR"]
 *   [version:  1 byte  — 0x01]
 *   [kdfId:    1 byte  — 0 = Argon2id, 1 = PBKDF2-SHA256]
 *   [params:  16 bytes — KDF-specific parameters (see below)]
 *   [salt:    saltLength bytes]
 *   [iv:      ivLength bytes]
 *   ... text body (tag + ciphertext) or file body (ciphertext + tag)
 *
 * KDF parameter blocks (16 bytes, big-endian):
 *
 *   Argon2id (kdfId = 0)
 *     [memoryCost:  4 bytes BE u32]
 *     [timeCost:    4 bytes BE u32]
 *     [parallelism: 2 bytes BE u16]
 *     [reserved:    6 bytes — zero-filled]
 *
 *   PBKDF2-SHA256 (kdfId = 1)
 *     [iterations: 4 bytes BE u32]
 *     [reserved:  12 bytes — zero-filled]
 *
 * Legacy v0 ciphertexts (no header) are still accepted in `'auto'` legacy mode.
 */

import { CryptoError, CryptoErrorType } from './types.js';

/**
 * ASCII "HPCR" — magic bytes that identify v1 ciphertext.
 *
 * Held as a raw `Uint8Array` (the bytes `0x48 0x50 0x43 0x52`) so this module
 * stays free of any Node global. `./format.js` re-exports a Node byte-buffer
 * copy for backward compatibility.
 */
export const MAGIC_BYTES: Uint8Array = new Uint8Array([0x48, 0x50, 0x43, 0x52]);

/** Length of magic bytes (4). */
export const MAGIC_LENGTH = 4;

/** Length of the version byte (1). */
export const VERSION_LENGTH = 1;

/** Length of the KDF identifier byte (1). */
export const KDF_ID_LENGTH = 1;

/** Length of the KDF parameter block (16 bytes — symmetrical regardless of KDF). */
export const KDF_PARAMS_LENGTH = 16;

/** Total v1 header size in bytes (6 fixed + 16 params = 22). */
export const HEADER_LENGTH =
  MAGIC_LENGTH + VERSION_LENGTH + KDF_ID_LENGTH + KDF_PARAMS_LENGTH;

/** Currently supported ciphertext format version. */
export const FORMAT_VERSION = 0x01;

/** Identifier for the Argon2id KDF in the on-disk format. */
export const KDF_ID_ARGON2ID = 0x00;

/** Identifier for the PBKDF2-SHA256 KDF in the on-disk format. */
export const KDF_ID_PBKDF2_SHA256 = 0x01;

/** Inclusive upper bound for u32 fields (memoryCost, timeCost, iterations). */
const U32_MAX = 0xffffffff;

/** Inclusive upper bound for u16 fields (parallelism). */
const U16_MAX = 0xffff;

/**
 * Upper bound on the Argon2id `memoryCost` parameter accepted by
 * {@link parseHeader}. 2^22 KiB == 4 GiB — well above any legitimate
 * configuration's needs (the library default is 128 MiB, the documented
 * `ULTRA` tier is 512 MiB) and small enough that a single decrypt call
 * cannot blow past the runtime's memory limits trying to honour an
 * attacker-supplied header.
 *
 * Caps are enforced at parse time so that **all** consumers (including the
 * tooling-facing `inspectHeader` method) see the same bounded value.
 * This means `inspectHeader` cannot be tricked into returning an absurd
 * `memoryCost` while the decrypt path catches the same input later.
 */
export const MAX_ARGON2_MEMORY_COST = 2 ** 22;

/**
 * Upper bound on the Argon2id `timeCost` parameter accepted by
 * {@link parseHeader}. 100 iterations is well above OWASP's high-security
 * recommendation (3 iterations for 128 MiB memoryCost) and trivially
 * exceeds any realistic configuration.
 */
export const MAX_ARGON2_TIME_COST = 100;

/**
 * Upper bound on the Argon2id `parallelism` parameter accepted by
 * {@link parseHeader}. 64 lanes is far above any sensible value (most
 * Argon2id deployments use 1-4 lanes); larger values give an attacker a
 * lever to amplify memory cost across worker threads.
 */
export const MAX_ARGON2_PARALLELISM = 64;

/**
 * Upper bound on the PBKDF2 `iterations` parameter accepted by
 * {@link parseHeader}. 10 million is roughly 16x the OWASP 2023+
 * recommendation (600 000 for PBKDF2-HMAC-SHA256). Anything beyond this is
 * almost certainly malicious — `crypto.pbkdf2Sync` runs on the main thread
 * and 100M iterations blocks the event loop indefinitely.
 */
export const MAX_PBKDF2_ITERATIONS = 10_000_000;

/**
 * Maximum plaintext length, in bytes, that may be processed by a SINGLE
 * AES-GCM invocation: `2 ** 36 - 32` == 68 719 476 704 bytes (~64 GiB).
 *
 * NIST SP 800-38D §5.2.1.1 ("Input Data") caps the plaintext of one GCM
 * invocation at `2 ** 39 - 256` **bits**, which is `2 ** 36 - 32` bytes. The
 * bound is structural, not conservative padding, and follows directly from
 * the counter block: only its low 32 bits vary. With the standard 96-bit IV,
 * SP 800-38D §7.1 (Algorithm 4) sets the pre-counter block to
 * `J0 = IV ‖ 0^31 ‖ 1` — so `J0` itself occupies counter value 1, and it is
 * `E_K(J0)` that masks the authentication tag. Plaintext is encrypted with
 * `GCTR(inc32(J0), P)`, i.e. starting at counter value 2, which leaves at
 * most `2 ** 32 - 2` sixteen-byte plaintext blocks before the 32-bit field
 * wraps. `16 * (2 ** 32 - 2)` is exactly `2 ** 36 - 32`.
 *
 * Past that point the counter wraps and repeats values already used, which
 * destroys BOTH confidentiality (two plaintext blocks share a keystream
 * block — a two-time pad) and authenticity (the wrap eventually reaches
 * `J0`'s own counter value, handing the attacker the tag mask and with it
 * the ability to forge).
 *
 * Neither OpenSSL's EVP layer nor Node's `crypto.createCipheriv` enforces
 * this limit — an oversized call "succeeds" and returns ciphertext that is
 * simply broken. This library therefore refuses such input up front, with
 * no opt-out: an opt-out would be an opt-in to a broken construction.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
 */
export const MAX_GCM_PLAINTEXT_BYTES = 2 ** 36 - 32;

/**
 * Throw unless `byteLength` fits within a single AES-GCM invocation.
 *
 * Applied at every AES-GCM entry point in the library (in-memory bytes, the
 * low-level `Buffer` primitives, and all four streaming file paths) so an
 * oversized payload is refused BEFORE any key derivation, temp-file creation
 * or cipher construction happens. Values at exactly
 * {@link MAX_GCM_PLAINTEXT_BYTES} are accepted; only strictly larger ones
 * are refused.
 *
 * This is a bound check, not an input validator: `byteLength` is a
 * PRECONDITION of the caller and must be a non-negative finite integer (in
 * this library it is always a `Uint8Array`/`Buffer` `.length` or an
 * `fs.Stats.size`, both of which satisfy that by construction). A `NaN`,
 * negative or fractional argument is not diagnosed — it simply compares
 * false and returns — so do not use this function to sanitise untrusted
 * numbers.
 *
 * @param byteLength - plaintext (or ciphertext body) length in bytes; must be
 *   a non-negative finite integer (see above)
 * @param code - `CryptoError` code to report; defaults to
 *   `'DATA_TOO_LARGE_FOR_GCM'`, the code every call site in this library uses
 * @throws CryptoError `INVALID_INPUT` when `byteLength` exceeds the bound
 */
export function assertGcmPlaintextLimit(
  byteLength: number,
  code: string = 'DATA_TOO_LARGE_FOR_GCM'
): void {
  if (byteLength > MAX_GCM_PLAINTEXT_BYTES) {
    throw new CryptoError(
      `Data is too large for a single AES-GCM invocation: ${byteLength} bytes ` +
        `exceeds the ${MAX_GCM_PLAINTEXT_BYTES}-byte limit set by NIST SP 800-38D ` +
        'section 5.2.1.1. Beyond it the 32-bit GCM block counter wraps and the ' +
        'ciphertext loses both confidentiality and authenticity.',
      CryptoErrorType.INVALID_INPUT,
      code
    );
  }
}

/**
 * KDF identifier as it appears in the v1 header.
 */
export type KdfId = typeof KDF_ID_ARGON2ID | typeof KDF_ID_PBKDF2_SHA256;

/**
 * Parsed Argon2id parameters from a v1 header.
 */
export interface Argon2idHeaderParams {
  kind: 'argon2id';
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

/**
 * Parsed PBKDF2-SHA256 parameters from a v1 header.
 */
export interface Pbkdf2HeaderParams {
  kind: 'pbkdf2-sha256';
  iterations: number;
}

/**
 * Decoded KDF parameter block. Discriminate by `kind`.
 */
export type KdfHeaderParams = Argon2idHeaderParams | Pbkdf2HeaderParams;

/**
 * Result of parsing a v1 header.
 */
export interface ParsedHeader {
  /** Format version (currently always 0x01). */
  version: number;
  /** KDF identifier. */
  kdfId: KdfId;
  /** Decoded KDF parameters. */
  params: KdfHeaderParams;
  /** Total bytes consumed by the header (always HEADER_LENGTH for v1). */
  headerLen: number;
}

/**
 * Construct a big-endian {@link DataView} over the meaningful region of a
 * byte array.
 *
 * **Why the explicit `byteOffset`/`byteLength`:** a `Uint8Array` may be a
 * window into a larger, shared backing store (some runtimes pool small
 * byte-array allocations, and `subarray()` produces views with a non-zero
 * `byteOffset`). A bare `new DataView(bytes.buffer)` would read from the start
 * of the whole backing store — silently corrupting every read/write. Passing
 * `bytes.byteOffset` and `bytes.byteLength` binds the view to exactly this
 * array's region.
 */
function viewOf(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/**
 * Detect whether a byte array begins with the v1 magic bytes ("HPCR").
 *
 * Performs a bounds-checked, O(MAGIC_LENGTH) compare and never reads past
 * the end of the input, so it is safe to call on arbitrarily small inputs.
 *
 * @param buf - candidate ciphertext bytes
 * @returns true if `buf` starts with the v1 magic, false otherwise
 */
export function hasMagic(buf: Uint8Array): boolean {
  if (!(buf instanceof Uint8Array) || buf.length < MAGIC_LENGTH) {
    return false;
  }
  for (let i = 0; i < MAGIC_LENGTH; i += 1) {
    if (buf[i] !== MAGIC_BYTES[i]) {
      return false;
    }
  }
  return true;
}

function validateU32(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new CryptoError(
      `Invalid ${field}: must be an unsigned 32-bit integer (0..${U32_MAX})`,
      CryptoErrorType.INVALID_INPUT,
      'INVALID_HEADER_PARAM'
    );
  }
  return value;
}

function validateU16(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > U16_MAX) {
    throw new CryptoError(
      `Invalid ${field}: must be an unsigned 16-bit integer (0..${U16_MAX})`,
      CryptoErrorType.INVALID_INPUT,
      'INVALID_HEADER_PARAM'
    );
  }
  return value;
}

/**
 * Pack the 6-byte fixed prefix + 16-byte KDF parameter block into a 22-byte
 * `Uint8Array` suitable for prepending to ciphertext.
 *
 * Validates that all parameters fit their declared widths (u32/u16) and
 * throws CryptoError on overflow rather than silently truncating.
 *
 * @param kdfId - 0 (Argon2id) or 1 (PBKDF2-SHA256)
 * @param params - KDF parameters; must match the `kdfId`
 * @returns 22-byte header bytes
 * @throws CryptoError if `kdfId` is unknown or params are out of range
 */
export function packHeader(kdfId: KdfId, params: KdfHeaderParams): Uint8Array {
  const buf = new Uint8Array(HEADER_LENGTH);
  const view = viewOf(buf);
  buf.set(MAGIC_BYTES, 0);
  view.setUint8(MAGIC_LENGTH, FORMAT_VERSION);
  view.setUint8(MAGIC_LENGTH + VERSION_LENGTH, kdfId);

  const paramsOffset = MAGIC_LENGTH + VERSION_LENGTH + KDF_ID_LENGTH;

  if (kdfId === KDF_ID_ARGON2ID) {
    if (params.kind !== 'argon2id') {
      throw new CryptoError(
        `Header KDF mismatch: kdfId=${kdfId} but params.kind=${params.kind}`,
        CryptoErrorType.INVALID_INPUT,
        'HEADER_KDF_MISMATCH'
      );
    }
    view.setUint32(
      paramsOffset,
      validateU32(params.memoryCost, 'memoryCost'),
      false
    );
    view.setUint32(
      paramsOffset + 4,
      validateU32(params.timeCost, 'timeCost'),
      false
    );
    view.setUint16(
      paramsOffset + 8,
      validateU16(params.parallelism, 'parallelism'),
      false
    );
    // Remaining 6 bytes are already zero from `new Uint8Array`.
  } else if (kdfId === KDF_ID_PBKDF2_SHA256) {
    if (params.kind !== 'pbkdf2-sha256') {
      throw new CryptoError(
        `Header KDF mismatch: kdfId=${kdfId} but params.kind=${params.kind}`,
        CryptoErrorType.INVALID_INPUT,
        'HEADER_KDF_MISMATCH'
      );
    }
    view.setUint32(
      paramsOffset,
      validateU32(params.iterations, 'iterations'),
      false
    );
    // Remaining 12 bytes are already zero from `new Uint8Array`.
  } else {
    throw new CryptoError(
      `Unknown KDF identifier: ${kdfId as number}`,
      CryptoErrorType.INVALID_INPUT,
      'UNSUPPORTED_KDF'
    );
  }

  return buf;
}

/**
 * Parse a v1 header from the start of a byte array.
 *
 * The array is read through a bounds-checked {@link DataView} so any
 * truncated input fails fast with a CryptoError rather than producing
 * garbage.
 *
 * **DoS-bound enforcement.** Parameters are also capped against the upper
 * bounds in {@link MAX_ARGON2_MEMORY_COST}, {@link MAX_ARGON2_TIME_COST},
 * {@link MAX_ARGON2_PARALLELISM}, and {@link MAX_PBKDF2_ITERATIONS}. A
 * malicious ciphertext that requests pathologically large KDF work (e.g.
 * memoryCost = 4 GiB or iterations = 100M) is rejected with
 * {@link CryptoErrorType.INVALID_INPUT} / `KDF_PARAMS_OUT_OF_BOUNDS` BEFORE
 * the parse returns, so the call site can never invoke `argon2.hash` /
 * `crypto.pbkdf2Sync` with the malicious values. This applies equally to
 * the decrypt path AND to `inspectHeader` (which calls `parseHeader`), so
 * tooling cannot be tricked into reporting one set of parameters while the
 * actual decrypt path catches a different limit.
 *
 * Caps are deliberately conservative — well above any legitimate caller's
 * needs — and are NOT user-configurable for this reason: the goal is
 * "untrusted-input DoS protection", not "match the decrypt-time KDF cost".
 *
 * **Argon2id cross-field floor.** For Argon2id headers, the parser also
 * enforces RFC 9106 §3.1's mandatory `memoryCost >= 8 * parallelism` floor.
 * The `CryptoManager` constructor enforces the same floor (code
 * `MEMORY_COST_TOO_SMALL`), so no legitimately-produced ciphertext can
 * carry sub-floor params. Without this check, a crafted header with e.g.
 * `memoryCost=8, parallelism=64` would pass all per-field guards, reach
 * `argon2.hash`, and surface as `ENCRYPTION_FAILED / KEY_DERIVATION_FAILED`
 * — an encryption-typed error on a decryption operation. The floor uses
 * `DECRYPTION_FAILED / INVALID_HEADER_PARAM` (same type/code as the
 * zero/negative-param check) so `legacyMode: 'auto'` falls through to the
 * v0 recovery path identically to other malformed-param cases.
 *
 * @param buf - byte array that begins with the v1 header (must contain the magic)
 * @returns parsed header (version, kdfId, params, total bytes consumed)
 * @throws CryptoError on missing/short header, unknown version, unknown KDF,
 *   KDF parameters that exceed the documented upper bounds, or an Argon2id
 *   `memoryCost`/`parallelism` pair that violates the RFC 9106 §3.1 floor
 */
export function parseHeader(buf: Uint8Array): ParsedHeader {
  if (!(buf instanceof Uint8Array)) {
    throw new CryptoError(
      'parseHeader: input must be a Uint8Array',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_HEADER_INPUT'
    );
  }
  if (buf.length < HEADER_LENGTH) {
    throw new CryptoError(
      `Header too short: expected at least ${HEADER_LENGTH} bytes, got ${buf.length}`,
      CryptoErrorType.INVALID_INPUT,
      'TRUNCATED_HEADER'
    );
  }
  if (!hasMagic(buf)) {
    throw new CryptoError(
      'Missing or invalid magic bytes (expected "HPCR")',
      CryptoErrorType.DECRYPTION_FAILED,
      'INVALID_MAGIC'
    );
  }

  const view = viewOf(buf);
  const version = view.getUint8(MAGIC_LENGTH);
  if (version !== FORMAT_VERSION) {
    throw new CryptoError(
      `Unsupported ciphertext format version: 0x${version
        .toString(16)
        .padStart(2, '0')} (this build supports 0x01)`,
      CryptoErrorType.DECRYPTION_FAILED,
      'UNSUPPORTED_VERSION'
    );
  }

  const kdfIdRaw = view.getUint8(MAGIC_LENGTH + VERSION_LENGTH);
  const paramsOffset = MAGIC_LENGTH + VERSION_LENGTH + KDF_ID_LENGTH;

  let params: KdfHeaderParams;
  let kdfId: KdfId;
  if (kdfIdRaw === KDF_ID_ARGON2ID) {
    kdfId = KDF_ID_ARGON2ID;
    const memoryCost = view.getUint32(paramsOffset, false);
    const timeCost = view.getUint32(paramsOffset + 4, false);
    const parallelism = view.getUint16(paramsOffset + 8, false);

    if (memoryCost <= 0 || timeCost <= 0 || parallelism <= 0) {
      throw new CryptoError(
        'Argon2id header parameters must all be positive',
        CryptoErrorType.DECRYPTION_FAILED,
        'INVALID_HEADER_PARAM'
      );
    }
    // Reject pathologically-large parameters that would let an attacker
    // pin gigabytes of RAM or burn CPU for minutes per decrypt call.
    // Bounds are conservative (well above the documented `ULTRA` tier);
    // see MAX_ARGON2_* constants for rationale.
    if (
      memoryCost > MAX_ARGON2_MEMORY_COST ||
      timeCost > MAX_ARGON2_TIME_COST ||
      parallelism > MAX_ARGON2_PARALLELISM
    ) {
      throw new CryptoError(
        `Argon2id header parameters exceed accepted bounds (memoryCost <= ${MAX_ARGON2_MEMORY_COST}, ` +
          `timeCost <= ${MAX_ARGON2_TIME_COST}, parallelism <= ${MAX_ARGON2_PARALLELISM}). ` +
          `Got memoryCost=${memoryCost}, timeCost=${timeCost}, parallelism=${parallelism}.`,
        CryptoErrorType.INVALID_INPUT,
        'KDF_PARAMS_OUT_OF_BOUNDS'
      );
    }
    // Argon2id RFC 9106 §3.1 cross-field constraint: memoryCost >= 8 * parallelism.
    // The constructor enforces the same floor (MEMORY_COST_TOO_SMALL), so no
    // legitimately-produced ciphertext can carry sub-floor params. Without this
    // check, a crafted header (e.g. memoryCost=8, parallelism=64) passes all
    // per-field guards, reaches argon2.hash, and surfaces as
    // ENCRYPTION_FAILED / KEY_DERIVATION_FAILED — an encryption-typed error
    // on a decryption operation. Using DECRYPTION_FAILED / INVALID_HEADER_PARAM
    // (same type/code as the zero/negative-param check above) means
    // legacyMode 'auto' falls through to the v0 recovery path, and
    // strict/reject modes re-throw immediately — both without ENCRYPTION_FAILED.
    const argon2MemFloor = 8 * parallelism;
    if (memoryCost < argon2MemFloor) {
      throw new CryptoError(
        `Argon2id memoryCost (${memoryCost}) must be at least 8 * parallelism ` +
          `(${argon2MemFloor} = 8 × ${parallelism})`,
        CryptoErrorType.DECRYPTION_FAILED,
        'INVALID_HEADER_PARAM'
      );
    }
    params = {
      kind: 'argon2id',
      memoryCost,
      timeCost,
      parallelism,
    };
  } else if (kdfIdRaw === KDF_ID_PBKDF2_SHA256) {
    kdfId = KDF_ID_PBKDF2_SHA256;
    const iterations = view.getUint32(paramsOffset, false);
    if (iterations <= 0) {
      throw new CryptoError(
        'PBKDF2 iterations must be positive',
        CryptoErrorType.DECRYPTION_FAILED,
        'INVALID_HEADER_PARAM'
      );
    }
    if (iterations > MAX_PBKDF2_ITERATIONS) {
      throw new CryptoError(
        `PBKDF2 iterations exceeds accepted bound (iterations <= ${MAX_PBKDF2_ITERATIONS}). ` +
          `Got iterations=${iterations}.`,
        CryptoErrorType.INVALID_INPUT,
        'KDF_PARAMS_OUT_OF_BOUNDS'
      );
    }
    params = {
      kind: 'pbkdf2-sha256',
      iterations,
    };
  } else {
    throw new CryptoError(
      `Unknown KDF identifier in header: 0x${kdfIdRaw
        .toString(16)
        .padStart(2, '0')}`,
      CryptoErrorType.DECRYPTION_FAILED,
      'UNSUPPORTED_KDF'
    );
  }

  return {
    version,
    kdfId,
    params,
    headerLen: HEADER_LENGTH,
  };
}
