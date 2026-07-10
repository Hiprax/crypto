import crypto from 'node:crypto';
import { access, constants, stat } from 'node:fs/promises';
import path from 'node:path';
import type { ValidationResult, FileInfo, RetryConfig } from './types.js';
import { CryptoError, CryptoErrorType } from './types.js';
import { isValidBase64url } from './codec.js';

/**
 * Validate if a file exists and is accessible (read).
 *
 * Calls `fs.promises.access(filePath, fs.constants.R_OK)` under the
 * hood, which returns `{ isValid: true }` when the path resolves to a
 * file the current process can open for reading. The check is purely
 * filesystem-level — it does NOT verify file content, MIME type, or
 * format integrity.
 *
 * **Symlink behaviour:** `fs.access` follows symlinks (it operates on
 * the resolved target, not the link itself — POSIX `access(2)`
 * semantics, mirrored on Windows for `R_OK`). A symlink whose target
 * exists and is readable will be reported `{ isValid: true }`; the
 * caller has no way to distinguish "real file at this path" from
 * "symlink pointing somewhere readable". This function does **not**
 * detect symlink-based attacks — e.g. a `filePath` argument supplied
 * by an untrusted source that turns out to be a symlink to
 * `/etc/shadow` (POSIX) or `C:\Windows\System32\config\SAM` (Windows)
 * will still report valid as long as the calling process has read
 * access to the target. Callers that need to defend against
 * symlink-based privilege escalation must additionally `fs.lstat` the
 * path, reject symlinks (or call `fs.realpath` and re-verify the
 * resolved target against an `allowedRoot`), and treat the resolved
 * path as the canonical input. The same caveat applies to
 * {@link validatePath} — see its JSDoc for the analogous note on
 * syntactic-only path validation.
 *
 * @param filePath - Path to the file
 * @returns Promise that resolves to validation result
 */
export async function validateFile(
  filePath: string
): Promise<ValidationResult> {
  if (!filePath || typeof filePath !== 'string') {
    return {
      isValid: false,
      error: 'File path must be a non-empty string',
    };
  }

  try {
    await access(filePath, constants.R_OK);
    return { isValid: true };
  } catch (error) {
    return {
      isValid: false,
      error: `File access error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Options for {@link validatePath}.
 */
export interface ValidatePathOptions {
  /**
   * If provided, the resolved input path must be contained within this
   * resolved root (i.e. equal to it OR start with it followed by
   * `path.sep`). The check is performed AFTER `path.resolve` on both
   * sides so within-drive cross-traversal (e.g. `C:\\Users\\..\\Windows`
   * starting from an `allowedRoot` of `C:\\Users`) is correctly
   * rejected. Comparison is segment-aware so e.g. an `allowedRoot` of
   * `/etc/sec` does NOT match an input of `/etc/secret`.
   *
   * NOTE: This is a syntactic / resolved-string check. It does NOT
   * defend against symlink-based escapes — see the JSDoc on
   * {@link ValidationResult} for details.
   */
  allowedRoot?: string;
}

/**
 * Validate if a path is valid for writing.
 *
 * Performs a purely syntactic check on the supplied path string:
 *
 * - rejects empty / non-string input
 * - rejects null bytes (`\0`) and control characters (codepoints
 *   `< 0x20` or `0x7F`) anywhere in the path
 * - rejects characters that are illegal on Windows filesystems
 *   (`<`, `>`, `:`, `"`, `|`, `?`, `*` — with the Windows drive-letter
 *   prefix stripped before checking so e.g. `C:\\path` is allowed)
 * - rejects path-traversal attempts via literal `..` segments after
 *   `path.normalize`, including Windows drive-relative variants such as
 *   `C:..` — the `C:` prefix is stripped from the first segment before the
 *   `..` scan so e.g. `validatePath('C:..\\Windows')` is correctly rejected
 * - if `options.allowedRoot` is provided, additionally requires that
 *   `path.resolve(filePath)` is contained within
 *   `path.resolve(options.allowedRoot)`. Containment is decided by a
 *   segment-aware prefix match (resolved input either equals the
 *   resolved root OR starts with it followed by `path.sep`), which
 *   prevents e.g. `/etc/sec` from accidentally matching `/etc/secret`
 *   and catches within-drive cross-traversal that the literal-`..`
 *   check on its own cannot detect (because `path.normalize` collapses
 *   internal `..` cancel-outs to a clean path).
 *
 * IMPORTANT: This function does NOT touch the filesystem. It cannot
 * detect or prevent traversal via filesystem **symlinks**. Callers
 * that need symlink-aware containment checks must additionally call
 * `fs.realpath`/`fs.realpathSync` on the resolved path and re-verify
 * the result against their allowed root.
 *
 * @param filePath - Path to validate
 * @param options - Optional validation options. If omitted the
 *                  function behaves identically to the legacy
 *                  single-argument call.
 * @returns Validation result
 */
export function validatePath(
  filePath: string,
  options?: ValidatePathOptions
): ValidationResult {
  if (!filePath || typeof filePath !== 'string') {
    return {
      isValid: false,
      error: 'File path must be a non-empty string',
    };
  }

  // Reject null bytes — Node.js filesystem APIs reject them already, but
  // failing fast here gives a clearer error and prevents the path from
  // ever reaching system calls. Also reject ASCII control characters
  // (`< 0x20`) and DEL (`0x7F`) which are not meaningful in filenames
  // and have historically been used in path-injection attacks.
  for (let i = 0; i < filePath.length; i++) {
    const code = filePath.charCodeAt(i);
    if (code === 0) {
      return {
        isValid: false,
        error: 'File path contains a null byte',
      };
    }
    if (code < 0x20 || code === 0x7f) {
      return {
        isValid: false,
        error: 'File path contains control characters',
      };
    }
  }

  // Check for invalid characters (excluding backslashes for Windows compatibility)
  // Strip Windows drive letter prefix (e.g., "C:") before checking for ":"
  let pathToCheck = filePath;
  if (process.platform === 'win32' && /^[a-zA-Z]:/.test(filePath)) {
    pathToCheck = filePath.slice(2);
  }
  const invalidChars = /[<>:"|?*]/;
  if (invalidChars.test(pathToCheck)) {
    return {
      isValid: false,
      error: 'File path contains invalid characters',
    };
  }

  // Check for path traversal attempts
  const segments = path.normalize(filePath).split(path.sep);
  // On Windows, `path.normalize` keeps a drive specifier glued to whatever
  // follows it — e.g. `path.normalize('C:..\\foo')` → `'C:..'` not `'..'`.
  // The old strict `/^[a-zA-Z]:$/` test only matched bare 'C:' (absolute
  // paths), so drive-relative traversals like 'C:..' were never stripped
  // before the includes('..') check and slipped through undetected.
  //
  // The fix: if `segments[0]` starts with a drive prefix `/^[a-zA-Z]:/`
  // (matching both 'C:' and 'C:..'), strip those two characters before the
  // scan. When stripping leaves an empty string (the 'C:' pure-drive case),
  // drop the segment entirely — identical to the original behaviour for
  // absolute paths. When stripping leaves '..' or any other text, keep it as
  // the first element so includes('..') catches it. POSIX is unaffected
  // because '/^[a-zA-Z]:/' never matches on POSIX paths.
  let checkSegments = segments;
  if (process.platform === 'win32' && /^[a-zA-Z]:/.test(segments[0] ?? '')) {
    const stripped = (segments[0] ?? '').slice(2);
    checkSegments =
      stripped === '' ? segments.slice(1) : [stripped, ...segments.slice(1)];
  }
  if (checkSegments.includes('..')) {
    return {
      isValid: false,
      error: 'Path traversal is not allowed',
    };
  }

  // If an allowedRoot was supplied, enforce resolved-prefix containment.
  // This catches within-drive cross-traversal (e.g. `C:\Users\..\Windows`
  // starting from an `allowedRoot` of `C:\Users`) which the literal-`..`
  // check on its own cannot detect because `path.normalize` collapses
  // internal `..` cancel-outs to a clean path.
  if (options?.allowedRoot !== undefined) {
    const root = options.allowedRoot;
    if (typeof root !== 'string' || root.length === 0) {
      return {
        isValid: false,
        error: 'allowedRoot must be a non-empty string',
      };
    }
    // Reject control chars / null bytes in the root for the same
    // fail-fast reasons as in the input path.
    for (let i = 0; i < root.length; i++) {
      const code = root.charCodeAt(i);
      if (code === 0 || code < 0x20 || code === 0x7f) {
        return {
          isValid: false,
          error: 'allowedRoot contains invalid characters',
        };
      }
    }

    const resolvedInput = path.resolve(filePath);
    const resolvedRoot = path.resolve(root);

    // Strip a single trailing path separator from the resolved root so
    // we don't accidentally fail the equality check on something like
    // `path.resolve('/etc/')` when the input resolves to `/etc`. Note
    // that `path.resolve` on Node.js already normalizes most trailing
    // separators away except in the drive-root case (`C:\`, `/`).
    const stripTrailingSep = (p: string): string => {
      if (p.length > 1 && p.endsWith(path.sep)) {
        return p.slice(0, -1);
      }
      return p;
    };
    const normalizedInput = stripTrailingSep(resolvedInput);
    const normalizedRoot = stripTrailingSep(resolvedRoot);

    // On Windows the filesystem is case-insensitive — compare in a
    // case-insensitive manner so `C:\Users` matches `c:\users`. On
    // POSIX, paths are case-sensitive so we keep the comparison as-is.
    const isWin = process.platform === 'win32';
    const cmpInput = isWin ? normalizedInput.toLowerCase() : normalizedInput;
    const cmpRoot = isWin ? normalizedRoot.toLowerCase() : normalizedRoot;

    // Segment-aware prefix match: resolved input must either be equal
    // to the resolved root, or start with the resolved root followed
    // by exactly `path.sep`. This prevents e.g. `/etc/sec` from
    // matching `/etc/secret`.
    const isInside =
      cmpInput === cmpRoot ||
      cmpInput.startsWith(cmpRoot + path.sep) ||
      // On Windows, also accept a forward slash as a separator since
      // Node.js treats `C:/Users/foo` and `C:\\Users\\foo` as the same
      // path. `path.resolve` already normalizes to backslash on
      // Windows, but be defensive in case any caller hands us a
      // pre-resolved root that uses forward slashes.
      (isWin && cmpInput.startsWith(cmpRoot + '/'));

    if (!isInside) {
      return {
        isValid: false,
        error: 'Path is outside the allowed root',
      };
    }
  }

  return { isValid: true };
}

/**
 * Generate a secure random string
 * @param length - Length of the string (default: 32)
 * @returns Random string
 * @throws CryptoError if length is invalid
 */
export function generateRandomString(length: number = 32): string {
  if (!Number.isInteger(length) || length <= 0 || length > 1024) {
    throw new CryptoError(
      'Invalid length for random string generation. Must be between 1 and 1024.',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_RANDOM_STRING_LENGTH'
    );
  }

  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const maxValid = 248; // Largest multiple of 62 fitting in a byte (248 = 62 * 4)
  let result = '';

  while (result.length < length) {
    const randomBytes = crypto.randomBytes(length - result.length + 16);
    for (let i = 0; i < randomBytes.length && result.length < length; i++) {
      const randomByte = randomBytes[i];
      if (randomByte !== undefined && randomByte < maxValid) {
        result += chars.charAt(randomByte % chars.length);
      }
    }
  }

  return result;
}

/**
 * Format file size in human readable format.
 *
 * Accepts a non-negative byte count and returns a human-readable string
 * scaled to the appropriate unit (`Bytes` / `KB` / `MB` / `GB` / `TB`).
 * The unit ladder caps at TB — values larger than 1024 TB are reported
 * in TB (e.g. `formatFileSize(1024 ** 5) === '1024 TB'`).
 *
 * `formatFileSize(0)` returns `'0 Bytes'` (zero is a legitimate size).
 *
 * Upper bound: any input strictly greater than `Number.MAX_SAFE_INTEGER`
 * (`2 ** 53 - 1`, ≈ 9 PB) throws `FILE_SIZE_TOO_LARGE`. JavaScript
 * numbers above this threshold cannot represent integer byte counts
 * exactly, so the resulting human-readable string would be a
 * mathematical artefact rather than a meaningful display (e.g.
 * `formatFileSize(Number.MAX_VALUE)` would silently return a huge
 * coefficient stuck at the `TB` unit). Failing fast is the correct
 * behaviour for callers passing such values — almost certainly a bug
 * upstream.
 *
 * @param bytes - Size in bytes (must be a finite non-negative number
 *         that is `<= Number.MAX_SAFE_INTEGER`)
 * @returns Formatted size string
 * @throws CryptoError (`INVALID_INPUT` / `NEGATIVE_FILE_SIZE`) if `bytes`
 *         is negative. Negative byte counts are a programming error
 *         rather than "0 bytes" — failing fast surfaces the underlying
 *         bug instead of masking it with a happy answer.
 * @throws CryptoError (`INVALID_INPUT` / `INVALID_FILE_SIZE`) if `bytes`
 *         is not a finite number (NaN, ±Infinity, or non-number).
 * @throws CryptoError (`INVALID_INPUT` / `FILE_SIZE_TOO_LARGE`) if
 *         `bytes` exceeds `Number.MAX_SAFE_INTEGER`.
 */
export function formatFileSize(bytes: number): string {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes)) {
    throw new CryptoError(
      'File size must be a finite number',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_FILE_SIZE'
    );
  }

  if (bytes < 0) {
    throw new CryptoError(
      'File size cannot be negative',
      CryptoErrorType.INVALID_INPUT,
      'NEGATIVE_FILE_SIZE'
    );
  }

  // Upper-bound guard. JS numbers can represent values up to
  // ~1.79e308, but only integers up to Number.MAX_SAFE_INTEGER
  // (2 ** 53 - 1, ~9 PB) are exact byte counts. Above the safe
  // integer boundary, the unit-ladder math produces a meaningless
  // coefficient stuck at TB. Reject rather than silently emit
  // garbage.
  if (bytes > Number.MAX_SAFE_INTEGER) {
    throw new CryptoError(
      'File size exceeds Number.MAX_SAFE_INTEGER',
      CryptoErrorType.INVALID_INPUT,
      'FILE_SIZE_TOO_LARGE'
    );
  }

  if (bytes === 0) {
    return '0 Bytes';
  }

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(k)),
    sizes.length - 1
  );

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Get file extension
 * @param filePath - File path
 * @returns File extension (lowercase)
 * @throws CryptoError (`INVALID_INPUT` / `INVALID_INPUT`) if `filePath` is not a string
 */
export function getFileExtension(filePath: string): string {
  if (typeof filePath !== 'string') {
    throw new CryptoError(
      'File path must be a string',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_INPUT'
    );
  }
  return path.extname(filePath).toLowerCase();
}

/**
 * Check if file is a text file based on extension
 * @param filePath - File path
 * @returns True if text file
 * @throws CryptoError (`INVALID_INPUT` / `INVALID_INPUT`) if `filePath` is not a string
 */
export function isTextFile(filePath: string): boolean {
  if (typeof filePath !== 'string') {
    throw new CryptoError(
      'File path must be a string',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_INPUT'
    );
  }
  const textExtensions = [
    '.txt',
    '.md',
    '.json',
    '.js',
    '.ts',
    '.py',
    '.java',
    '.c',
    '.cpp',
    '.h',
    '.html',
    '.css',
    '.xml',
    '.csv',
    '.log',
    '.yaml',
    '.yml',
    '.toml',
    '.ini',
    '.conf',
    '.cfg',
  ];
  return textExtensions.includes(getFileExtension(filePath));
}

/**
 * Sanitize filename for security.
 *
 * Replaces filesystem-invalid / dangerous characters and collapses
 * whitespace runs to single underscores, then neutralizes any literal
 * `..` sequences that survived (so the result cannot be naively
 * `path.join`'d into a parent directory). The sanitized name is then
 * truncated to 255 characters while preserving the file extension —
 * the truncation removes characters from the **base name**, not the
 * extension, so `'a'.repeat(300) + '.txt'` becomes 251 `a`s + `.txt`
 * rather than losing the extension entirely.
 *
 * If the result would otherwise be empty (e.g. the input was nothing
 * but invalid characters), `'file'` is returned as a safe fallback.
 *
 * @param filename - Original filename
 * @returns Sanitized filename
 */
export function sanitizeFilename(filename: string): string {
  if (!filename || typeof filename !== 'string') {
    return 'file';
  }

  // Remove or replace dangerous characters, then collapse whitespace.
  let result = filename.replace(/[<>:"/\\|?*]/g, '_').replace(/\s+/g, '_');

  // Neutralize any `..` sequences that survived the previous
  // replacements. This prevents a sanitized name from being naively
  // joined into a parent-directory traversal (e.g. `..` → `__`).
  // Loop until convergence so that overlapping sequences like `....`
  // are fully scrubbed (`....` → `__..` → `____`).
  let prev = '';
  while (prev !== result) {
    prev = result;
    result = result.replace(/\.\./g, '__');
  }

  // Truncate to 255 chars while preserving the extension. We use
  // `path.extname` so the same definition of "extension" is applied
  // consistently across the library.
  if (result.length > 255) {
    const ext = path.extname(result);
    if (ext.length > 0 && ext.length < 255) {
      const baseLen = 255 - ext.length;
      const baseName = result.slice(0, result.length - ext.length);
      result = baseName.slice(0, baseLen) + ext;
    } else {
      result = result.slice(0, 255);
    }
  }

  // Final safety: if sanitization produced an empty string (e.g. input
  // was entirely invalid characters that got stripped to nothing),
  // fall back to a known-safe placeholder.
  if (result.length === 0) {
    return 'file';
  }

  return result;
}

/**
 * Create a backup filename.
 *
 * Produces a path of the form
 * `${dir}/${name}_${timestamp}_${rand}${suffix}${ext}` where:
 *
 * - `timestamp` is the current UTC time encoded with `toISOString()` and
 *   colons / fractional-second dot replaced with `-`, truncated to
 *   second precision (e.g. `2026-05-04T12-00-00`). This keeps backup
 *   filenames sortable by lexicographic comparison.
 * - `rand` is a 6-character lowercase hex string sourced from
 *   `crypto.randomBytes(3)`. The random suffix prevents intra-second
 *   collisions when two backups are taken within the same second
 *   (`Date.toISOString()` only gives ms precision and we further
 *   truncate to s precision, so two same-second invocations would
 *   otherwise produce identical paths).
 *
 * The original file extension is preserved at the end of the result so
 * the backup remains recognisable to extension-based tooling.
 *
 * The constructed basename is also passed through {@link sanitizeFilename}
 * before being re-joined with the directory, so the result is
 * guaranteed to be at most 255 characters with the extension preserved.
 * For very long input names (e.g. `'a'.repeat(300) + '.txt'`) the
 * `name` portion is intelligently shortened FIRST so the meaningful
 * tail of the basename — `_${timestamp}_${rand}${suffix}${ext}` — is
 * always retained intact; without that pre-shortening,
 * `sanitizeFilename`'s naive head-keep / tail-drop truncation would
 * eat the timestamp + random discriminator and break the
 * uniqueness/sortability guarantees. The directory portion is
 * unaffected — only the constructed basename is sanitised, so a
 * legitimate caller-supplied directory path containing characters that
 * `sanitizeFilename` would replace (`/`, `\`, etc.) is preserved
 * verbatim.
 *
 * @param originalPath - Original file path
 * @param suffix - Suffix to add (default: '.backup')
 * @returns Backup file path with timestamp and random discriminator
 */
export function createBackupPath(
  originalPath: string,
  suffix: string = '.backup'
): string {
  const dir = path.dirname(originalPath);
  const ext = path.extname(originalPath);
  const name = path.basename(originalPath, ext);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  // 6-character lowercase hex, sourced from 3 random bytes. Plenty of
  // entropy (16M values) to avoid intra-second collisions in any
  // realistic backup-creation rate.
  const rand = crypto.randomBytes(3).toString('hex');

  // Compute the meaningful tail (timestamp + random + suffix + ext)
  // and pre-shorten the user-supplied `name` so that the assembled
  // basename fits within the 255-char cap that `sanitizeFilename`
  // enforces. `sanitizeFilename`'s built-in truncation keeps the head
  // and drops the tail (preserving extension), which would discard
  // the timestamp + random discriminator and break uniqueness — so we
  // do the smart truncation here, then route through
  // `sanitizeFilename` as a final safety net.
  const tail = `_${timestamp}_${rand}${suffix}${ext}`;
  const MAX_BASENAME = 255;
  let shortenedName = name;
  if (shortenedName.length + tail.length > MAX_BASENAME) {
    const allowedNameLen = Math.max(0, MAX_BASENAME - tail.length);
    shortenedName = shortenedName.slice(0, allowedNameLen);
  }

  // Run the constructed basename through sanitizeFilename so the
  // 255-char cap is enforced even when the original `name` is very
  // long, AND any other dangerous-character sanitisation
  // (`<>:"/\\|?*`, whitespace runs, literal `..`) is applied
  // consistently with the rest of the library. We sanitise the
  // basename ONLY — the directory keeps its original separators
  // (sanitizeFilename would replace `/` and `\` with `_`).
  const rawBasename = `${shortenedName}${tail}`;
  const sanitisedBasename = sanitizeFilename(rawBasename);

  return path.join(dir, sanitisedBasename);
}

/**
 * Validate base64 string
 * @param str - String to validate
 * @returns True if valid base64
 */
export function isValidBase64(str: string): boolean {
  if (!str || typeof str !== 'string') {
    return false;
  }

  try {
    // Check if it's valid base64
    const decoded = Buffer.from(str, 'base64');
    const reEncoded = decoded.toString('base64');
    return str === reEncoded;
  } catch {
    return false;
  }
}

/**
 * Validate base64url string (URL-safe base64 without padding)
 * @param str - String to validate
 * @returns True if valid base64url
 */
export function isValidBase64Url(str: string): boolean {
  // Delegates to the pure, isomorphic codec so the base64url round-trip
  // validation has a single source of truth (see `./codec.ts`). Behaviour is
  // unchanged: a canonical base64url string returns true, everything else
  // returns false, and it never throws.
  return isValidBase64url(str);
}

/**
 * Secure string comparison (constant time)
 * @param a - First string
 * @param b - Second string
 * @returns True if strings are equal
 */
export function secureStringCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Compare against a dummy buffer to avoid timing leaks on length
    const dummy = Buffer.alloc(bufA.length);
    crypto.timingSafeEqual(bufA, dummy);
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generate a progress bar
 * @param current - Current value
 * @param total - Total value
 * @param width - Bar width (default: 30)
 * @returns Progress bar string — never throws; clamps out-of-range inputs
 */
export function createProgressBar(
  current: number,
  total: number,
  width: number = 30
): string {
  if (total <= 0) {
    return '[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0%';
  }

  // Clamp to [0, 1]; treat non-finite current or total as 0 progress so the
  // helper never surfaces a raw RangeError or emits "NaN%" in its output.
  const percentage =
    Number.isFinite(current) && Number.isFinite(total)
      ? Math.min(Math.max(current / total, 0), 1)
      : 0;

  // Reject non-integer or non-positive widths (e.g. -3, 15.5, NaN) and fall
  // back to the documented default so repeat() is never called with a bad count.
  const w = Number.isInteger(width) && width > 0 ? width : 30;

  const filled = Math.round(w * percentage);
  const empty = w - filled;

  const filledBar = '█'.repeat(filled);
  const emptyBar = '░'.repeat(empty);

  return `[${filledBar}${emptyBar}] ${Math.round(percentage * 100)}%`;
}

/**
 * Sleep for a specified number of milliseconds
 * @param ms - Milliseconds to sleep
 * @returns Promise that resolves after the specified time
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => globalThis.setTimeout(resolve, ms));
}

/**
 * Default retry policy used by {@link retryWithBackoff} when the
 * caller does not supply an explicit `shouldRetry` predicate.
 *
 * Retries every error EXCEPT `CryptoError`s whose `code` is
 * `WEAK_PASSWORD` or `INVALID_PASSWORD` (or whose `type` is
 * `INVALID_PASSWORD`). These categories are deterministic — repeating
 * the same call with the same arguments cannot make a wrong password
 * become right or a weak password become strong, so retrying only
 * burns CPU (especially expensive when the wrapped function performs
 * Argon2id key derivation) and gives a clock to any attacker that
 * controls the input.
 *
 * @param error - The error captured from the most recent attempt
 * @returns `true` if the error should trigger another retry attempt,
 *          `false` if `retryWithBackoff` should give up immediately.
 */
function defaultShouldRetry(error: Error): boolean {
  if (error instanceof CryptoError) {
    if (error.code === 'WEAK_PASSWORD' || error.code === 'INVALID_PASSWORD') {
      return false;
    }
    if (error.type === CryptoErrorType.INVALID_PASSWORD) {
      return false;
    }
  }
  return true;
}

/**
 * Retry a function with exponential backoff.
 *
 * Calls `fn()` up to `config.maxRetries + 1` times. Between attempts,
 * waits `config.baseDelay * 2 ** attemptIndex` milliseconds (so the
 * delay grows exponentially with each subsequent failure). If every
 * attempt fails, the last captured error is re-thrown.
 *
 * Per-error retry control is available via `config.shouldRetry`. When
 * omitted, a built-in default policy is applied that does NOT retry
 * `CryptoError`s of type `INVALID_PASSWORD` or with code
 * `WEAK_PASSWORD` / `INVALID_PASSWORD` — see
 * {@link defaultShouldRetry} for rationale. Pre-v0.19.0 callers that
 * relied on the previous "retry everything" behaviour can opt back in
 * by passing `shouldRetry: () => true` explicitly.
 *
 * **Behaviour change in v0.19.0**: prior versions retried every error
 * type, including wrong-password and weak-password errors. The new
 * default skips those, which is a subtle behavioural change for
 * callers that relied on the old behaviour for retry-counting tests
 * or for absorbing transient password-validation failures (which
 * should not happen in practice — password validation is
 * deterministic given identical input).
 *
 * @param fn - Function to retry. Must return a promise.
 * @param config - Retry configuration. Defaults to
 *                 `{ maxRetries: 3, baseDelay: 1000 }`.
 * @returns Promise that resolves to the function's resolved value
 * @throws The last captured error if all retries fail or if
 *         `config.shouldRetry` returns `false`.
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  config: RetryConfig = { maxRetries: 3, baseDelay: 1000 }
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt === config.maxRetries) {
        throw lastError;
      }

      // Decide whether to retry. The custom predicate (if provided)
      // takes precedence; otherwise fall back to the built-in default
      // policy that excludes password-related crypto errors.
      const predicate = config.shouldRetry ?? defaultShouldRetry;
      const allow = predicate(lastError, attempt);
      if (!allow) {
        throw lastError;
      }

      const delay = config.baseDelay * Math.pow(2, attempt);
      await sleep(delay);
    }
  }

  throw lastError || new Error('Retry failed with unknown error');
}

/**
 * Get file information
 * @param filePath - Path to the file
 * @returns Promise that resolves to file information
 * @throws CryptoError if file access fails
 */
export async function getFileInfo(filePath: string): Promise<FileInfo> {
  try {
    const stats = await stat(filePath);
    const extension = getFileExtension(filePath);

    return {
      path: filePath,
      size: stats.size,
      extension,
      isTextFile: isTextFile(filePath),
    };
  } catch (error) {
    throw new CryptoError(
      `Failed to get file info: ${error instanceof Error ? error.message : 'Unknown error'}`,
      CryptoErrorType.FILE_ERROR,
      'FILE_INFO_FAILED'
    );
  }
}

/**
 * Validate password strength with detailed feedback.
 *
 * `isValid` is computed from the same two acceptance rules as
 * `isValidPassword` in `crypto-manager.ts` — a password is accepted if
 * EITHER:
 *
 *  1. **Passphrase rule (NIST SP 800-63B style):** length ≥ 20, regardless
 *     of character composition.
 *  2. **Composition rule:** length ≥ 8 AND contains at least one uppercase
 *     letter, one lowercase letter, one digit, and one non-alphanumeric
 *     character (`[^A-Za-z0-9]`).
 *
 * `score` (0–5) and `feedback` are **advisory** — they surface stylistic
 * weaknesses such as repeated-character patterns that `isValid` intentionally
 * ignores. A password may have `isValid: true` while still carrying a
 * `feedback` entry (e.g. "Avoid repeated characters") or a score below 5.
 * UI code should gate on `isValid` and use `score` / `feedback` for
 * guidance only.
 *
 * The "special character" check accepts any character outside the
 * alphanumeric class (`[^A-Za-z0-9]`), broader than the previous narrow
 * allow-list (`[!@#$%^&*(),.?":{}|<>]`) so that e.g. `_`, `-`, `+`, `[`,
 * `]`, and non-ASCII punctuation all count.
 *
 * @param password - Password to validate
 * @returns Object with `isValid` (mirrors `isValidPassword` exactly),
 *          `score` (advisory, 0–5), and `feedback` (advisory strings)
 */
export function validatePasswordStrength(password: string): {
  isValid: boolean;
  score: number;
  feedback: string[];
} {
  const feedback: string[] = [];
  let score = 0;

  if (!password || typeof password !== 'string') {
    return {
      isValid: false,
      score: 0,
      feedback: ['Password must be a non-empty string'],
    };
  }

  // NIST SP 800-63B style: a long passphrase is accepted on length alone.
  // Score 5 (the cap) and emit no negative feedback so callers can
  // confidently treat the result as valid.
  if (password.length >= 20) {
    return {
      isValid: true,
      score: 5,
      feedback: [],
    };
  }

  // Pre-compute category booleans — used both for isValid (below) and for
  // the advisory score/feedback checks, so each regex runs exactly once.
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  // Any non-alphanumeric character counts as "special" — broader than the
  // previous narrow allow-list and consistent with `isValidPassword`.
  const hasSpecialChar = /[^A-Za-z0-9]/.test(password);

  // Binary validity: mirrors the composition rule of `isValidPassword` exactly.
  // Repeat-character penalties below may add to `feedback` and reduce `score`
  // without affecting this verdict — they are advisory strength signals only.
  const isValid =
    password.length >= 8 &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumbers &&
    hasSpecialChar;

  // Length check (advisory)
  if (password.length < 8) {
    feedback.push('Password must be at least 8 characters long');
  } else if (password.length >= 12) {
    score += 2;
  } else {
    score += 1;
  }

  // Character variety checks (advisory score and feedback)
  if (hasUpperCase) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one uppercase letter');
  }

  if (hasLowerCase) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one lowercase letter');
  }

  if (hasNumbers) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one number');
  }

  if (hasSpecialChar) {
    score += 1;
  } else {
    feedback.push('Password must contain at least one special character');
  }

  // Additional strength checks (advisory)
  if (password.length >= 16) {
    score += 1;
  }

  if (/(.)\1{2,}/.test(password)) {
    score -= 1;
    feedback.push('Avoid repeated characters');
  }

  if (/^(.)\1+$/.test(password)) {
    score -= 2;
    feedback.push('Avoid using the same character repeatedly');
  }

  return {
    isValid,
    score: Math.max(0, Math.min(5, score)),
    feedback,
  };
}

/**
 * Generate a secure random UUID v4
 * @returns UUID string
 */
export function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Hash a string using SHA-256
 * @param input - String to hash
 * @returns SHA-256 hash as hex string
 * @throws CryptoError (`INVALID_INPUT` / `INVALID_INPUT`) if `input` is not a string
 */
export function sha256(input: string): string {
  if (typeof input !== 'string') {
    throw new CryptoError(
      'sha256 input must be a string',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_INPUT'
    );
  }
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Generate a secure random hex string
 * @param length - Length of hex string (default: 32)
 * @returns Hex string
 * @throws CryptoError if length is invalid
 */
export function generateRandomHex(length: number = 32): string {
  if (!Number.isInteger(length) || length <= 0 || length > 1024) {
    throw new CryptoError(
      'Invalid length for random hex generation. Must be between 1 and 1024.',
      CryptoErrorType.INVALID_INPUT,
      'INVALID_RANDOM_HEX_LENGTH'
    );
  }

  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}
