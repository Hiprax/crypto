/**
 * Node `Buffer` wrapper around the pure {@link ./format-core.js} format layer.
 *
 * The real header logic — every constant, type, byte layout, and error code —
 * lives in `./format-core.js`, which depends only on `Uint8Array`/`DataView`
 * and runs unchanged in Node and the browser. This module preserves the
 * long-standing, `Buffer`-typed public API that `crypto-manager.ts` and the
 * test suite consume, so the split is fully backward-compatible:
 *
 *   - Constants and types are re-exported verbatim from `format-core.js`.
 *   - `MAGIC_BYTES` is exposed as a `Buffer` (a copy of the core bytes).
 *   - `packHeader`/`parseHeader`/`hasMagic` keep their exact `Buffer`-typed
 *     signatures; `packHeader` returns a `Buffer` (copy of the core bytes).
 *
 * See `./format-core.js` for the full v1 layout documentation.
 */

import {
  MAGIC_BYTES as CORE_MAGIC_BYTES,
  hasMagic as coreHasMagic,
  packHeader as corePackHeader,
  parseHeader as coreParseHeader,
} from './format-core.js';
import type { KdfHeaderParams, KdfId, ParsedHeader } from './format-core.js';
import { CryptoError, CryptoErrorType } from './types.js';

// Re-export all constants unchanged (identical values and types).
export {
  MAGIC_LENGTH,
  VERSION_LENGTH,
  KDF_ID_LENGTH,
  KDF_PARAMS_LENGTH,
  HEADER_LENGTH,
  FORMAT_VERSION,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  MAX_ARGON2_MEMORY_COST,
  MAX_ARGON2_TIME_COST,
  MAX_ARGON2_PARALLELISM,
  MAX_PBKDF2_ITERATIONS,
} from './format-core.js';

// Re-export all types unchanged.
export type {
  KdfId,
  Argon2idHeaderParams,
  Pbkdf2HeaderParams,
  KdfHeaderParams,
  ParsedHeader,
} from './format-core.js';

/**
 * ASCII "HPCR" — magic bytes that identify v1 ciphertext.
 *
 * A `Buffer` copy of the core magic bytes, preserved for backward
 * compatibility with callers that use `Buffer` methods (`.copy`,
 * `.toString('ascii')`, `.equals`, byte indexing).
 */
export const MAGIC_BYTES: Buffer = Buffer.from(CORE_MAGIC_BYTES);

/**
 * Detect whether a buffer begins with the v1 magic bytes ("HPCR").
 *
 * Performs a bounds-checked, O(MAGIC_LENGTH) compare and never reads past
 * the end of the buffer, so it is safe to call on arbitrarily small inputs.
 *
 * @param buf - candidate ciphertext buffer
 * @returns true if `buf` starts with the v1 magic, false otherwise
 */
export function hasMagic(buf: Buffer): boolean {
  // Preserve the original public contract: only a real Node Buffer is
  // accepted. (`format-core.hasMagic` intentionally accepts any Uint8Array
  // for its isomorphic consumers, but this Node wrapper must behave exactly
  // as it always has.)
  if (!Buffer.isBuffer(buf)) {
    return false;
  }
  return coreHasMagic(buf);
}

/**
 * Pack the 6-byte fixed prefix + 16-byte KDF parameter block into a 22-byte
 * Buffer suitable for prepending to ciphertext.
 *
 * Validates that all parameters fit their declared widths (u32/u16) and
 * throws CryptoError on overflow rather than silently truncating.
 *
 * @param kdfId - 0 (Argon2id) or 1 (PBKDF2-SHA256)
 * @param params - KDF parameters; must match the `kdfId`
 * @returns 22-byte header buffer
 * @throws CryptoError if `kdfId` is unknown or params are out of range
 */
export function packHeader(kdfId: KdfId, params: KdfHeaderParams): Buffer {
  return Buffer.from(corePackHeader(kdfId, params));
}

/**
 * Parse a v1 header from the start of a buffer.
 *
 * The buffer is read with bounds-checked methods so any truncated input
 * fails fast with a CryptoError rather than producing garbage.
 *
 * **DoS-bound enforcement.** Parameters are capped against the upper bounds
 * in {@link MAX_ARGON2_MEMORY_COST}, {@link MAX_ARGON2_TIME_COST},
 * {@link MAX_ARGON2_PARALLELISM}, and {@link MAX_PBKDF2_ITERATIONS}. A
 * malicious ciphertext that requests pathologically large KDF work is
 * rejected with `KDF_PARAMS_OUT_OF_BOUNDS` BEFORE the parse returns.
 *
 * **Argon2id cross-field floor.** For Argon2id headers, the parser also
 * enforces RFC 9106 §3.1's mandatory `memoryCost >= 8 * parallelism` floor.
 *
 * @param buf - buffer that begins with the v1 header (must contain the magic)
 * @returns parsed header (version, kdfId, params, total bytes consumed)
 * @throws CryptoError on missing/short header, unknown version, unknown KDF,
 *   KDF parameters that exceed the documented upper bounds, or an Argon2id
 *   `memoryCost`/`parallelism` pair that violates the RFC 9106 §3.1 floor
 */
export function parseHeader(buf: Buffer): ParsedHeader {
  // Preserve the original public contract: reject a non-Buffer input up front
  // with the same `INVALID_HEADER_INPUT` code/message as before.
  // (`format-core.parseHeader` intentionally accepts any Uint8Array for its
  // isomorphic consumers.)
  if (!Buffer.isBuffer(buf)) {
    throw new CryptoError(
      'parseHeader: input must be a Buffer',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_HEADER_INPUT'
    );
  }
  return coreParseHeader(buf);
}
