/**
 * Snapshot tests for the v1 ciphertext byte layout (Task 13).
 *
 * Goal: catch silent on-disk format breakage. A future refactor that
 * accidentally re-orders fields, changes endian, or shifts a byte (e.g.
 * "the reserved region is now 0xFF instead of 0x00") would round-trip
 * cleanly under the existing tests (because a buggy decrypt that
 * matches a buggy encrypt is round-trip-clean) but break wire
 * compatibility for every previously-encrypted ciphertext in the wild.
 * The example tests below pin known-good byte layouts produced under
 * deterministic salt + IV mocks, so any byte-level drift fails loud.
 *
 * Determinism strategy:
 *   - Spy on {@link CryptoManager.generateSecureRandom} with `jest.spyOn`
 *     so EVERY call returns a fixed-pattern Buffer of the requested
 *     length (salt = 32 bytes of 0xAA; IV = 12 bytes of 0xBB).
 *   - Mock the `argon2` native module via `jest.unstable_mockModule` so
 *     the async path's KDF returns a fixed 32-byte buffer regardless of
 *     password + salt input. This frees the snapshot from depending on
 *     the actual Argon2id derivation algorithm (which would be
 *     hardware-dependent if the library ever swapped backends).
 *   - The PBKDF2 sync path runs against Node's built-in `crypto.pbkdf2Sync`,
 *     which is platform-stable. We use a low iteration count + a fixed
 *     password and pin the resulting ciphertext exactly.
 *
 * Format-version pinning:
 *   - Both snapshots assert that buffer offset 4 (the version byte) ===
 *     0x01 BEFORE comparing the full hex dump. If a future change ships
 *     v2 ciphertexts, the version-byte assertion fires first with a
 *     clear "format version changed; either bump the snapshot or keep
 *     v1 backward compat" failure rather than a giant hex-dump diff.
 *
 * Snapshot mechanism: we use Jest's standard `toMatchSnapshot()` which
 * writes to `__snapshots__/format-snapshot.test.ts.snap`. (Inline
 * snapshots via `toMatchInlineSnapshot()` are incompatible with
 * `ts-jest`'s ESM mode in jest 30 — the AST transformation makes the
 * source-position lookup fail with "Couldn't locate all inline
 * snapshots".) The companion `.snap` file is checked into the repo so
 * a wire-format change shows up as a diff in code review just like an
 * inline snapshot would.
 */
import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  jest,
} from '@jest/globals';
import {
  HEADER_LENGTH,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  MAGIC_BYTES,
  FORMAT_VERSION,
} from '../format';

// ----------------------------------------------------------------------------
// Determinism plumbing.
// ----------------------------------------------------------------------------

/** Salt content: 32 bytes of 0xAA. Chosen to be visually distinguishable from IV. */
const FIXED_SALT_BYTE = 0xaa;

/** IV content: 12 bytes of 0xBB. */
const FIXED_IV_BYTE = 0xbb;

/** Argon2id mock output: 32 bytes of 0xCC. */
const FIXED_ARGON2_KEY_BYTE = 0xcc;

/**
 * Stable test parameters. These pin into the snapshots: changing any of
 * them requires regenerating the inline snapshot strings below.
 */
const TEST_PASSWORD = 'SnapshotTestP@ssw0rd123!';
const TEST_PLAINTEXT = 'snapshot-fixed-plaintext';

/** Argon2id parameters embedded in the v1 header (Argon2id snapshot). */
const TEST_ARGON2_OPTS = {
  memoryCost: 2 ** 14, // 16 MiB — the LOW tier; doesn't matter because we mock argon2
  timeCost: 1,
  parallelism: 1,
};

/** PBKDF2 iterations embedded in the v1 header (PBKDF2 snapshot). */
const TEST_PBKDF2_ITERATIONS = 1000;

/**
 * Install a `jest.spyOn` on `CryptoManager.prototype.generateSecureRandom`
 * that returns deterministic bytes for the documented salt + IV calls.
 * Buffer length determines whether the call is producing salt (32) or
 * IV (12); the spy fills the buffer with the matching constant byte.
 *
 * Returns a teardown function that restores the original method.
 */
function installFixedRandomSpy(
  CryptoManager: typeof import('../crypto-manager').CryptoManager
): () => void {
  const spy = jest.spyOn(CryptoManager.prototype, 'generateSecureRandom');
  spy.mockImplementation((length: number) => {
    // The library only ever asks for 32 bytes (salt) or 12 bytes (IV)
    // in the snapshot path. Any other length means a code change has
    // shifted what generateSecureRandom is used for, and we want to
    // know loudly rather than fill with mystery bytes.
    if (length === 32) {
      return Buffer.alloc(32, FIXED_SALT_BYTE);
    }
    if (length === 12) {
      return Buffer.alloc(12, FIXED_IV_BYTE);
    }
    throw new Error(
      `Unexpected generateSecureRandom length=${length} in snapshot test ` +
        `(only 32-byte salt and 12-byte IV are expected). If a code ` +
        `change introduces a new fixed-randomness source, update this ` +
        `mock; otherwise this is a real surprise worth investigating.`
    );
  });
  return () => spy.mockRestore();
}

// ============================================================================

describe('v1 ciphertext format snapshot tests (Task 13)', () => {
  // --------------------------------------------------------------------------
  // Format-version pinning. These run FIRST so a v2 bump produces a clear
  // "format version changed" diff rather than an opaque hex-dump diff.
  // The byte-layout snapshots below depend on these constants.
  // --------------------------------------------------------------------------
  describe('format version pinning', () => {
    it('FORMAT_VERSION is 0x01 (snapshots below are v1-only)', () => {
      expect(FORMAT_VERSION).toBe(0x01);
    });

    it('HEADER_LENGTH is 22 bytes (4 magic + 1 version + 1 kdfId + 16 params)', () => {
      expect(HEADER_LENGTH).toBe(22);
    });

    it('MAGIC_BYTES is exactly the ASCII string "HPCR"', () => {
      expect(MAGIC_BYTES.toString('ascii')).toBe('HPCR');
      expect(MAGIC_BYTES.length).toBe(4);
    });

    it('KDF identifiers are 0 (Argon2id) and 1 (PBKDF2-SHA256)', () => {
      expect(KDF_ID_ARGON2ID).toBe(0x00);
      expect(KDF_ID_PBKDF2_SHA256).toBe(0x01);
    });
  });

  // --------------------------------------------------------------------------
  // Argon2id (async) snapshot. The argon2 native module is mocked so
  // the derived key is fixed; this isolates the snapshot from the
  // actual Argon2id implementation (which we don't want to bake into
  // wire-format expectations).
  // --------------------------------------------------------------------------
  describe('Argon2id v1 ciphertext (async)', () => {
    beforeEach(() => {
      jest.resetModules();
    });

    afterEach(() => {
      jest.resetModules();
      jest.restoreAllMocks();
    });

    it('produces a stable v1 byte layout for fixed plaintext + password + salt + IV + KDF output', async () => {
      // Mock the argon2 native module to return a fixed key. We do this
      // via jest.unstable_mockModule so the lazy `await import('argon2')`
      // inside loadArgon2 resolves to our mock. The mock must
      // implement the same shape as the real module:
      //   - argon2id: numeric type id (2)
      //   - hash(password, options): Promise<Buffer>
      jest.unstable_mockModule('argon2', () => ({
        argon2id: 2,
        hash: jest.fn(async () => Buffer.alloc(32, FIXED_ARGON2_KEY_BYTE)),
      }));

      // Dynamic import AFTER the mock is installed, so loadArgon2 sees
      // the mocked module on first call.
      const { CryptoManager, __resetArgon2ModuleCacheForTesting } =
        await import('../crypto-manager');
      __resetArgon2ModuleCacheForTesting();

      const restoreRandom = installFixedRandomSpy(CryptoManager);
      try {
        const cm = new CryptoManager(TEST_ARGON2_OPTS);
        const ciphertextB64 = await cm.encryptText(
          TEST_PLAINTEXT,
          TEST_PASSWORD
        );
        const buf = Buffer.from(ciphertextB64, 'base64url');

        // ---- format-version + magic guard rails ----
        expect(buf.subarray(0, 4).equals(MAGIC_BYTES)).toBe(true);
        expect(buf.readUInt8(4)).toBe(FORMAT_VERSION); // 0x01
        expect(buf.readUInt8(5)).toBe(KDF_ID_ARGON2ID); // 0x00

        // ---- header length sanity ----
        expect(buf.length).toBeGreaterThan(HEADER_LENGTH); // 22

        // ---- file-based byte-layout snapshot ----
        // Hex dump of the entire ciphertext (not just the header). Any
        // future change that re-orders fields, shifts the tag, or
        // changes encoding will diff this string in
        // __snapshots__/format-snapshot.test.ts.snap and require an
        // explicit snapshot update.
        // Layout: header(22) + salt(32) + iv(12) + tag(16) + ciphertext(len)
        const hexDump = buf.toString('hex');
        expect(hexDump).toMatchSnapshot('argon2id full hex dump');

        // ---- structural decomposition ----
        // Split the hex dump into the documented field layout so the
        // test reads as a wire-format spec. Each `toMatchSnapshot()`
        // pin doubles as documentation.
        const headerHex = buf.subarray(0, HEADER_LENGTH).toString('hex');
        expect(headerHex).toMatchSnapshot('argon2id header (22 bytes)');
        const saltHex = buf
          .subarray(HEADER_LENGTH, HEADER_LENGTH + 32)
          .toString('hex');
        expect(saltHex).toMatchSnapshot('argon2id salt (32 bytes)');
        const ivHex = buf
          .subarray(HEADER_LENGTH + 32, HEADER_LENGTH + 32 + 12)
          .toString('hex');
        expect(ivHex).toMatchSnapshot('argon2id iv (12 bytes)');
        const tagHex = buf
          .subarray(HEADER_LENGTH + 32 + 12, HEADER_LENGTH + 32 + 12 + 16)
          .toString('hex');
        expect(tagHex).toMatchSnapshot('argon2id auth tag (16 bytes)');
        const ctHex = buf
          .subarray(HEADER_LENGTH + 32 + 12 + 16)
          .toString('hex');
        expect(ctHex).toMatchSnapshot('argon2id ciphertext body');

        // The AES-GCM ciphertext byte length equals the UTF-8 plaintext
        // byte length (AES-GCM is a streaming cipher).
        expect(ctHex.length / 2).toBe(
          Buffer.from(TEST_PLAINTEXT, 'utf8').length
        );
      } finally {
        restoreRandom();
      }
    });
  });

  // --------------------------------------------------------------------------
  // PBKDF2 (sync) snapshot. Unlike Argon2id, PBKDF2 runs through Node's
  // built-in `crypto.pbkdf2Sync` which is bit-stable across platforms
  // and Node versions. We do NOT mock the KDF here — fixing the salt +
  // password + iterations is enough to make the derived key
  // deterministic.
  // --------------------------------------------------------------------------
  describe('PBKDF2-SHA256 v1 ciphertext (sync)', () => {
    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('produces a stable v1 byte layout for fixed plaintext + password + salt + IV + iteration count', async () => {
      // Use dynamic import for consistency with the async test (Jest
      // ESM mode requires this for any module we want to fresh-import).
      const { CryptoManager } = await import('../crypto-manager');

      const restoreRandom = installFixedRandomSpy(CryptoManager);
      try {
        const cm = new CryptoManager({
          // The Argon2 fields are unused by the sync path but must
          // pass constructor validation.
          memoryCost: 2 ** 14,
          timeCost: 1,
          parallelism: 1,
          pbkdf2Iterations: TEST_PBKDF2_ITERATIONS,
        });
        const ciphertextB64 = cm.encryptTextSync(TEST_PLAINTEXT, TEST_PASSWORD);
        const buf = Buffer.from(ciphertextB64, 'base64url');

        // ---- format-version + magic guard rails ----
        expect(buf.subarray(0, 4).equals(MAGIC_BYTES)).toBe(true);
        expect(buf.readUInt8(4)).toBe(FORMAT_VERSION); // 0x01
        expect(buf.readUInt8(5)).toBe(KDF_ID_PBKDF2_SHA256); // 0x01

        // ---- header length sanity ----
        expect(buf.length).toBeGreaterThan(HEADER_LENGTH); // 22

        // Sanity-check the iteration count is encoded big-endian at
        // bytes 6..9. This pins one of the v1-vs-v2 risk vectors:
        // a future change that flipped this to little-endian would
        // round-trip but break old ciphertexts.
        expect(buf.readUInt32BE(6)).toBe(TEST_PBKDF2_ITERATIONS);

        // ---- file-based byte-layout snapshot ----
        const hexDump = buf.toString('hex');
        expect(hexDump).toMatchSnapshot('pbkdf2 full hex dump');

        // ---- structural decomposition ----
        const headerHex = buf.subarray(0, HEADER_LENGTH).toString('hex');
        expect(headerHex).toMatchSnapshot('pbkdf2 header (22 bytes)');
        const saltHex = buf
          .subarray(HEADER_LENGTH, HEADER_LENGTH + 32)
          .toString('hex');
        expect(saltHex).toMatchSnapshot('pbkdf2 salt (32 bytes)');
        const ivHex = buf
          .subarray(HEADER_LENGTH + 32, HEADER_LENGTH + 32 + 12)
          .toString('hex');
        expect(ivHex).toMatchSnapshot('pbkdf2 iv (12 bytes)');
        const tagHex = buf
          .subarray(HEADER_LENGTH + 32 + 12, HEADER_LENGTH + 32 + 12 + 16)
          .toString('hex');
        expect(tagHex).toMatchSnapshot('pbkdf2 auth tag (16 bytes)');
        const ctHex = buf
          .subarray(HEADER_LENGTH + 32 + 12 + 16)
          .toString('hex');
        expect(ctHex).toMatchSnapshot('pbkdf2 ciphertext body');

        // The PBKDF2 ciphertext byte length equals the UTF-8 plaintext
        // byte length (AES-GCM is a streaming cipher).
        expect(ctHex.length / 2).toBe(
          Buffer.from(TEST_PLAINTEXT, 'utf8').length
        );
      } finally {
        restoreRandom();
      }
    });

    /**
     * Round-trip sanity. The snapshot above pins the bytes; this
     * smoke test confirms those exact bytes still decrypt back to the
     * original plaintext under the same fixed mocks.
     */
    it('round-trips the snapshot-pinned ciphertext back to the original plaintext', async () => {
      const { CryptoManager } = await import('../crypto-manager');
      const restoreRandom = installFixedRandomSpy(CryptoManager);
      try {
        const cm = new CryptoManager({
          memoryCost: 2 ** 14,
          timeCost: 1,
          parallelism: 1,
          pbkdf2Iterations: TEST_PBKDF2_ITERATIONS,
        });
        const enc = cm.encryptTextSync(TEST_PLAINTEXT, TEST_PASSWORD);
        const dec = cm.decryptTextSync(enc, TEST_PASSWORD);
        expect(dec).toBe(TEST_PLAINTEXT);
      } finally {
        restoreRandom();
      }
    });
  });
});
