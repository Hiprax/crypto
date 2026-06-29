/**
 * Property-based tests (Task 19, extended in Task 7).
 *
 * Uses `fast-check` to assert encryption invariants over many random
 * (text, password) inputs rather than a handful of hand-curated examples.
 * The five invariants we lock in here:
 *
 *   1. Round-trip: `decrypt(encrypt(text, password), password) === text`
 *      for both async (Argon2id) and sync (PBKDF2) paths, and for both
 *      the text API and the file API.
 *   2. Distinct plaintexts produce distinct ciphertexts (no IV/salt
 *      collision under reasonable parameters).
 *   3. Encrypting the same text twice with the same password produces
 *      DIFFERENT ciphertexts (proves a fresh salt + IV per call).
 *   4. Decrypting with the wrong password throws `CryptoError` (does
 *      NOT silently return garbled plaintext — AES-GCM auth tag catches
 *      this).
 *   5. Single-bit tampering anywhere in the produced ciphertext (or the
 *      v1 header, post Task 1's AAD binding) causes `decrypt*` to throw
 *      `CryptoError`. Covers both base64url-encoded text ciphertexts and
 *      file ciphertexts.
 *
 * Why a low-cost CryptoManager instance: the default Argon2id
 * configuration was raised to `m=2^17 (128 MiB), t=3, p=1` in v0.15.0
 * (Task 18) to match OWASP 2026 first-choice. That default is wonderful
 * for production but punishing for property tests — at ~700ms per
 * derivation, even 50 random cases would take 35+ seconds per property.
 * Argon2 is *deliberately* expensive; the property tests only need
 * Argon2id to be *correct*, not slow. So we instantiate a `CryptoManager`
 * with the lowest reasonable parameters (`memoryCost: 2^14 = 16 MiB`,
 * `timeCost: 1`) and a low PBKDF2 iteration count for the sync path.
 * This is a TEST-ONLY configuration; consumers should never lower their
 * production parameters this far.
 *
 * `numRuns` is set deliberately conservatively (50 cases per property)
 * so the suite stays under ~30s wall-clock even on slow CI runners.
 * Increasing `numRuns` will improve coverage but inflate runtime
 * roughly linearly.
 */
import { describe, it, expect, beforeAll, afterAll, jest } from '@jest/globals';
import fc from 'fast-check';
import { writeFile, unlink, readFile } from 'node:fs/promises';
import {
  existsSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  unlinkSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { CryptoManager } from '../crypto-manager';
import { CryptoError } from '../types';

// Unique per-suite scratch directory so concurrent jest workers / repeated
// runs cannot collide on file paths (Task 21). Created once in beforeAll
// and torn down in afterAll. Sub-tests that need their own scratch dir
// nest under TEST_DIR rather than os.tmpdir() directly.
const TEST_DIR = path.join(
  os.tmpdir(),
  `hiprax-crypto-property-${crypto.randomBytes(8).toString('hex')}`
);

// ----------------------------------------------------------------------------
// Test-only low-cost crypto config.
// ----------------------------------------------------------------------------
//
// `memoryCost: 2^14` (16 MiB) and `timeCost: 1` are the LOW security tier
// per `SECURITY_THRESHOLDS` — emphatically NOT recommended for production.
// They are chosen here purely so that running 50+ Argon2id derivations in
// a single test does not balloon CI time to several minutes.
//
// Sync path: PBKDF2 iterations are passed via `pbkdf2Iterations` (still
// embedded in the v1 ciphertext header, so subsequent decryption with the
// same instance works correctly). 10 000 iterations is well below
// production guidance but keeps the property suite responsive.
function makeFastCrypto(opts?: {
  defaultPassphrase?: string;
}): CryptoManager {
  return new CryptoManager({
    memoryCost: 2 ** 14, // 16 MiB
    timeCost: 1,
    parallelism: 1,
    pbkdf2Iterations: 10_000,
    ...(opts?.defaultPassphrase
      ? { defaultPassphrase: opts.defaultPassphrase }
      : {}),
  });
}

// ----------------------------------------------------------------------------
// Per-property fast-check configuration.
// ----------------------------------------------------------------------------
//
// 50 cases is enough to catch nearly all classes of bugs that property
// tests are useful for (off-by-one boundaries, encoding mishaps,
// state-leak between calls). Argon2id at the low-cost config above runs
// at roughly 5-15 ms per derivation on commodity hardware, so each
// property runs in well under 30s.
//
// `endOnFailure: true` means fast-check stops shrinking immediately when
// it finds the first reproduction — we don't need exhaustive shrinking
// for these properties; the failing input is informative enough.
const FC_CONFIG_FAST: fc.Parameters = {
  numRuns: 50,
  endOnFailure: true,
};

// Sync path is a hair faster than async — we can afford slightly more
// runs for the sync round-trip without blowing the budget.
const FC_CONFIG_SYNC: fc.Parameters = {
  numRuns: 75,
  endOnFailure: true,
};

// Properties that don't even involve a KDF (e.g. comparing two raw
// ciphertexts) can run many more cases cheaply.
const FC_CONFIG_CHEAP: fc.Parameters = {
  numRuns: 200,
  endOnFailure: true,
};

// ----------------------------------------------------------------------------
// Arbitraries.
// ----------------------------------------------------------------------------
//
// Texts: include unicode, but keep length bounded — encryption itself is
// O(n) so very large texts mostly just slow the suite without revealing
// new bugs. The CryptoManager rejects empty strings, so set minLength=1.
//
// Passwords: hand-rolled arbitrary that constructs strings always
// satisfying the password-strength validator. Filtering with
// `validatePassword` over `fc.string()` is technically correct but
// rejects an astronomical fraction of random strings — it would burn the
// fast-check budget retrying. The hand-curated arbitrary is faster and
// gives uniform coverage of the password-rule space.

/**
 * Bounded UTF-8 text arbitrary. We exclude the empty string and cap at
 * 200 characters — long enough to span multiple AES blocks, short enough
 * not to dominate the suite's wall-clock.
 *
 * We use `oneof` to mix in BOTH ASCII (the default `fc.string()` unit) and
 * arbitrary unicode codepoints (`unit: 'binary'`). Without the unicode
 * branch the round-trip property would only be exercised against printable
 * ASCII (0x20-0x7E), masking bugs in NFC normalisation, surrogate-pair
 * handling, multi-byte UTF-8 encoding, and similar unicode-only failure
 * modes. The two arbitraries are weighted equally so unicode bugs surface
 * at the same rate as ASCII bugs.
 */
const arbText = fc
  .oneof(
    // ASCII branch — the previous default behaviour. Cheap and exercises
    // the common case.
    fc.string({ minLength: 1, maxLength: 200 }),
    // Unicode branch — includes arbitrary codepoints (incl. multibyte
    // UTF-8 sequences, combining marks, etc). `unit: 'binary'` produces
    // the broadest unicode space supported by fast-check 4.x.
    fc.string({ minLength: 1, maxLength: 200, unit: 'binary' })
  )
  // Filter out strings that would lose data through UTF-8 encoding (lone
  // surrogates, etc). `Buffer.from(text, 'utf8').toString('utf8') ===
  // text` is the canonical "round-trips through UTF-8" check — unpaired
  // surrogates fail this and would spuriously fail the round-trip
  // property even if encryption is correct.
  .filter(
    s =>
      s.length > 0 &&
      Buffer.from(s, 'utf8').toString('utf8') === s
  );

/**
 * Hand-curated strong-password arbitrary.
 *
 * Construction: take 4 mandatory category samples (uppercase, lowercase,
 * digit, special) and shuffle them in front of an arbitrary tail so the
 * resulting password always satisfies `validatePassword`'s composition
 * rule (8+ chars, all four categories present). This avoids the huge
 * filtering cost of `fc.string().filter(validatePassword)`.
 */
const arbStrongPassword = fc
  .tuple(
    fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
    fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'),
    fc.constantFrom(...'0123456789'),
    fc.constantFrom(...'!@#$%^&*()_+-=[]{}|;:,.<>?/~`'),
    // Tail of any printable ASCII chars — pads length, doesn't have to
    // satisfy any category rule.
    fc.string({ minLength: 4, maxLength: 16 })
  )
  .map(([upper, lower, digit, special, tail]) => {
    // Concatenate in a stable order; the four mandatory categories are
    // always present so the result always passes `validatePassword`.
    // (We don't need shuffling — the rule is set-membership, not
    // positional.)
    return `${upper}${lower}${digit}${special}${tail}`;
  });

/**
 * Two distinct strong passwords. fast-check's default tuple may produce
 * pairs that happen to be equal; we filter them out so "wrong password"
 * tests are well-defined.
 */
const arbTwoDistinctPasswords = fc
  .tuple(arbStrongPassword, arbStrongPassword)
  .filter(([a, b]) => a !== b);

/**
 * Two distinct non-empty texts. Similar to passwords, filter out the
 * (rare but possible) collision.
 */
const arbTwoDistinctTexts = fc
  .tuple(arbText, arbText)
  .filter(([a, b]) => a !== b);

// ============================================================================

describe('property-based tests (Task 19)', () => {
  // The default Jest timeout is 5s; our property tests run dozens of
  // KDF derivations per `it`, so bump generously. Argon2 at the
  // low-cost config takes ~5-15ms per call.
  jest.setTimeout(120_000);

  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  // --------------------------------------------------------------------------
  // Property 1: round-trip — decrypt(encrypt(text, password), password) === text
  // --------------------------------------------------------------------------

  describe('round-trip invariants', () => {
    it('async text path: decrypt(encrypt(t, p), p) === t', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(arbText, arbStrongPassword, async (text, pwd) => {
          const enc = await cm.encryptText(text, pwd);
          const dec = await cm.decryptText(enc, pwd);
          // We compare the round-trip output against the original
          // text. NFC normalisation of the password does NOT mutate the
          // text, so the plaintext must be byte-identical.
          expect(dec).toBe(text);
        }),
        FC_CONFIG_FAST
      );
    });

    it('sync text path: decryptSync(encryptSync(t, p), p) === t', async () => {
      const cm = makeFastCrypto();
      // Note: this property is synchronous in nature, but fast-check's
      // `fc.property` (sync) is also fine here. We use asyncProperty for
      // a uniform shape across the suite.
      await fc.assert(
        fc.asyncProperty(arbText, arbStrongPassword, async (text, pwd) => {
          const enc = cm.encryptTextSync(text, pwd);
          const dec = cm.decryptTextSync(enc, pwd);
          expect(dec).toBe(text);
        }),
        FC_CONFIG_SYNC
      );
    });

    it('async file path: decryptFile(encryptFile(f, p), p) reproduces input bytes', async () => {
      const cm = makeFastCrypto();
      // Per-test scratch dir nested under the suite-wide TEST_DIR so the
      // suite cleanup in afterAll catches any leftover entries even if
      // the inner finally block is skipped (e.g. test runner crash).
      const dir = path.join(
        TEST_DIR,
        `prop-${crypto.randomBytes(8).toString('hex')}`
      );
      const inputPath = path.join(dir, 'in.bin');
      const encryptedPath = path.join(dir, 'enc.bin');
      const decryptedPath = path.join(dir, 'dec.bin');
      const { mkdir } = await import('node:fs/promises');
      await mkdir(dir, { recursive: true });

      try {
        // Smaller numRuns for file I/O — disk roundtrips dominate.
        await fc.assert(
          fc.asyncProperty(arbText, arbStrongPassword, async (text, pwd) => {
            const inputBytes = Buffer.from(text, 'utf8');
            await writeFile(inputPath, inputBytes);
            await cm.encryptFile(inputPath, encryptedPath, pwd);
            await cm.decryptFile(encryptedPath, decryptedPath, pwd);
            const out = await readFile(decryptedPath);
            // Hash compare for fairness — large texts could be expensive
            // to compare structurally.
            const hashIn = crypto
              .createHash('sha256')
              .update(inputBytes)
              .digest('hex');
            const hashOut = crypto
              .createHash('sha256')
              .update(out)
              .digest('hex');
            expect(hashOut).toBe(hashIn);
            // Cleanup between runs so the next iteration starts fresh.
            for (const f of [inputPath, encryptedPath, decryptedPath]) {
              if (existsSync(f)) await unlink(f);
            }
          }),
          // 25 runs for the file path — each run does 2 disk encryptions.
          { numRuns: 25, endOnFailure: true }
        );
      } finally {
        // Best-effort cleanup of the per-test scratch dir.
        const { rm } = await import('node:fs/promises');
        await rm(dir, { recursive: true, force: true });
      }
    });

    it('sync file path: decryptFileSync(encryptFileSync(buf, p), p) reproduces input bytes', async () => {
      // Per-test scratch directory nested under TEST_DIR.
      const dir = path.join(
        TEST_DIR,
        `sync-file-rt-${crypto.randomBytes(8).toString('hex')}`
      );
      const inputPath = path.join(dir, 'in.bin');
      const encryptedPath = path.join(dir, 'enc.bin');
      const decryptedPath = path.join(dir, 'dec.bin');
      const { mkdir, rm } = await import('node:fs/promises');
      await mkdir(dir, { recursive: true });

      // 64 KiB matches SYNC_ENCRYPT_CHUNK_SIZE / SYNC_DECRYPT_CHUNK_SIZE.
      // Three size classes exercise the full chunking boundary space:
      //   - empty   (0 bytes)       — cipher produces header+salt+iv+final()+tag only
      //   - sub-chunk (1..CHUNK-1)  — single partial chunk
      //   - multi-chunk (CHUNK+1..2*CHUNK+1) — at least two full iterations of the loop
      const SYNC_CHUNK = 65536;
      const arbSyncPlaintext = fc.oneof(
        { weight: 1, arbitrary: fc.constant(new Uint8Array(0)) },
        {
          weight: 3,
          arbitrary: fc.uint8Array({ minLength: 1, maxLength: SYNC_CHUNK - 1 }),
        },
        {
          weight: 1,
          arbitrary: fc.uint8Array({
            minLength: SYNC_CHUNK + 1,
            maxLength: SYNC_CHUNK * 2 + 1,
          }),
        }
      );

      // Valid pbkdf2Iterations within bounds; kept low for suite speed.
      const arbPbkdf2Iters = fc.integer({ min: 1_000, max: 10_000 });

      try {
        await fc.assert(
          fc.asyncProperty(
            arbSyncPlaintext,
            arbStrongPassword,
            arbPbkdf2Iters,
            async (plaintext, pwd, pbkdf2Iterations) => {
              // Create a fresh CryptoManager with the given pbkdf2Iterations.
              // The iteration count is embedded in the v1 ciphertext header by
              // encryptFileSync and read back by decryptFileSync, so the same
              // instance correctly round-trips at any valid iteration count.
              const cm = new CryptoManager({
                memoryCost: 2 ** 14,
                timeCost: 1,
                parallelism: 1,
                pbkdf2Iterations,
              });
              const inputBuf = Buffer.from(plaintext);
              writeFileSync(inputPath, inputBuf);
              cm.encryptFileSync(inputPath, encryptedPath, pwd);
              cm.decryptFileSync(encryptedPath, decryptedPath, pwd);
              const out = readFileSync(decryptedPath);
              // Hash-compare for large multi-chunk buffers.
              const hashIn = crypto
                .createHash('sha256')
                .update(inputBuf)
                .digest('hex');
              const hashOut = crypto
                .createHash('sha256')
                .update(out)
                .digest('hex');
              expect(hashOut).toBe(hashIn);
              // Cleanup between runs so each iteration starts fresh.
              for (const f of [inputPath, encryptedPath, decryptedPath]) {
                if (existsSync(f)) unlinkSync(f);
              }
            }
          ),
          // 20 runs covers all three size classes (1:3:1 weighting gives
          // ~4 empty + 12 sub-chunk + 4 multi-chunk per 20 cases).
          { numRuns: 20, endOnFailure: true }
        );
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  });

  // --------------------------------------------------------------------------
  // Property 2: distinct plaintexts produce distinct ciphertexts.
  // --------------------------------------------------------------------------
  // Note: this is technically guaranteed by AES-GCM with a fresh IV,
  // even for the same plaintext — see Property 3 below. The "distinct
  // plaintexts" version of this property is a sanity check that
  // ciphertext encoding is deterministic in the inputs (no spurious
  // randomness *outside* salt+IV).

  describe('ciphertext distinguishability', () => {
    it('encrypt(t1, p) !== encrypt(t2, p) for t1 !== t2', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbTwoDistinctTexts,
          arbStrongPassword,
          async ([t1, t2], pwd) => {
            const c1 = await cm.encryptText(t1, pwd);
            const c2 = await cm.encryptText(t2, pwd);
            // Even with identical password but different plaintexts AND
            // a fresh salt+IV per call, the ciphertexts MUST differ.
            // (They'd differ even with the same plaintext — see prop 3.)
            expect(c1).not.toBe(c2);
          }
        ),
        FC_CONFIG_FAST
      );
    });

    it('sync: encryptSync(t1, p) !== encryptSync(t2, p) for t1 !== t2', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbTwoDistinctTexts,
          arbStrongPassword,
          async ([t1, t2], pwd) => {
            const c1 = cm.encryptTextSync(t1, pwd);
            const c2 = cm.encryptTextSync(t2, pwd);
            expect(c1).not.toBe(c2);
          }
        ),
        FC_CONFIG_SYNC
      );
    });
  });

  // --------------------------------------------------------------------------
  // Property 3: encrypt(text, password) !== encrypt(text, password) — fresh
  // IV/salt per call means ciphertext is non-deterministic across calls.
  // --------------------------------------------------------------------------

  describe('IV/salt freshness (non-deterministic ciphertext)', () => {
    it('async: encrypting same text twice yields different ciphertexts', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(arbText, arbStrongPassword, async (text, pwd) => {
          const c1 = await cm.encryptText(text, pwd);
          const c2 = await cm.encryptText(text, pwd);
          // Ciphertexts MUST differ — the salt is 32 random bytes, IV
          // 12 random bytes, so the probability of collision is
          // effectively zero. Failure here means the RNG was reused,
          // which is a critical security bug.
          expect(c1).not.toBe(c2);
        }),
        FC_CONFIG_FAST
      );
    });

    it('sync: encrypting same text twice yields different ciphertexts', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(arbText, arbStrongPassword, async (text, pwd) => {
          const c1 = cm.encryptTextSync(text, pwd);
          const c2 = cm.encryptTextSync(text, pwd);
          expect(c1).not.toBe(c2);
        }),
        FC_CONFIG_SYNC
      );
    });

    it('cheap: raw base64url ciphertext header bytes vary across calls', async () => {
      // Cheap property: doesn't even need to decrypt. Just verifies the
      // first ~50 bytes of the base64url payload (which encodes the
      // header + start of salt) differ across two encryptions of the
      // same text. Runs at 200 cases with no KDF cost.
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(arbText, arbStrongPassword, async (text, pwd) => {
          const c1 = cm.encryptTextSync(text, pwd);
          const c2 = cm.encryptTextSync(text, pwd);
          // The header bytes are deterministic for a given config, but
          // the salt that follows is 32 random bytes. Compare a slice
          // that starts AFTER the deterministic header and IS likely
          // to span random salt bytes.
          expect(c1.slice(20, 80)).not.toBe(c2.slice(20, 80));
        }),
        FC_CONFIG_CHEAP
      );
    });
  });

  // --------------------------------------------------------------------------
  // Property 4: wrong password throws CryptoError on decrypt.
  // --------------------------------------------------------------------------
  // AES-GCM is an authenticated cipher: the wrong key produces a
  // failed auth-tag verification, which the library wraps as a
  // `CryptoError`. The library MUST NOT silently return garbled
  // plaintext when the key is wrong.

  describe('wrong-password rejection', () => {
    it('async: decryptText with wrong password throws CryptoError', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbText,
          arbTwoDistinctPasswords,
          async (text, [right, wrong]) => {
            const enc = await cm.encryptText(text, right);
            await expect(cm.decryptText(enc, wrong)).rejects.toThrow(
              CryptoError
            );
          }
        ),
        FC_CONFIG_FAST
      );
    });

    it('sync: decryptTextSync with wrong password throws CryptoError', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbText,
          arbTwoDistinctPasswords,
          async (text, [right, wrong]) => {
            const enc = cm.encryptTextSync(text, right);
            // `expect(...).toThrow(CryptoError)` requires a function
            // value, not a thrown error. We wrap.
            expect(() => cm.decryptTextSync(enc, wrong)).toThrow(CryptoError);
          }
        ),
        FC_CONFIG_SYNC
      );
    });
  });

  // --------------------------------------------------------------------------
  // Property 5: ciphertext tampering — flipping a single bit anywhere in the
  // produced ciphertext (or its v1 header) MUST cause decryption to throw a
  // CryptoError. AES-GCM's auth tag and (post-Task 1) the AAD-bound v1 header
  // both contribute to this guarantee:
  //   - bytes 0-21 are the v1 header (now AAD-bound), so any flip there
  //     either changes the AAD passed to the cipher (tag mismatch) or
  //     changes a parsed parameter (key derivation produces a different
  //     key, again tag mismatch) or changes the magic / version / kdfId
  //     (parse-time CryptoError before the KDF runs).
  //   - bytes 22..end-1 are salt + iv + tag + ciphertext (text format) or
  //     salt + iv + ciphertext + tag (file format). Flipping any bit in
  //     this region must invalidate the auth tag.
  //
  // Pre-Task-1 the v1 reserved bytes (offsets 16-21 for Argon2id, 10-21 for
  // PBKDF2) escaped detection — this property locks in the post-Task-1
  // guarantee in addition to the always-present body-tampering check.
  // --------------------------------------------------------------------------

  describe('single-bit tampering (Task 7)', () => {
    /**
     * Flip a single bit at the chosen position in `buf` and return a NEW
     * Buffer with the modification. The original buffer is not mutated so
     * the same encrypted output can be reused across parameterised
     * properties.
     */
    function flipBit(buf: Buffer, byteIdx: number, bitIdx: number): Buffer {
      const out = Buffer.from(buf);
      // Force-cast through indexed access — `out[byteIdx]` is `number |
      // undefined` under `noUncheckedIndexedAccess`, but we already
      // bounds-checked the byteIdx in the caller.
      out[byteIdx] = (out[byteIdx] ?? 0) ^ (1 << bitIdx);
      return out;
    }

    /** Random bit position within a byte, 0..7. */
    const arbBitIdx = fc.integer({ min: 0, max: 7 });

    it('async text: flipping any single bit causes decryptText to throw CryptoError', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbText,
          arbStrongPassword,
          // Fraction in [0, 1); we map it to the actual ciphertext length
          // inside the property body (we don't know the length until we
          // encrypt). Using a fraction means we never generate an
          // out-of-range index and waste cases.
          fc.double({ min: 0, max: 1, noNaN: true, maxExcluded: true }),
          arbBitIdx,
          async (text, pwd, fraction, bitIdx) => {
            const enc = await cm.encryptText(text, pwd);
            const buf = Buffer.from(enc, 'base64url');
            const byteIdx = Math.floor(fraction * buf.length);
            // Defensive: skip the (vanishingly rare) edge case where
            // fraction maps to byteIdx === buf.length due to a 1.0
            // upper bound; using maxExcluded above prevents this, but
            // belt-and-braces.
            if (byteIdx >= buf.length) return;
            const tampered = flipBit(buf, byteIdx, bitIdx).toString(
              'base64url'
            );
            // The exact CryptoError code depends on which byte was hit:
            // bytes 0-3 -> INVALID_MAGIC (parse-time);
            // byte 4    -> UNSUPPORTED_VERSION;
            // byte 5    -> UNSUPPORTED_KDF;
            // bytes 6-21 (parsed params + reserved) -> DECRYPTION_FAILED
            //             (the AAD-bound bytes flipped, or the derived key
            //             changed, or both);
            // bytes 22+ -> DECRYPTION_FAILED (auth tag verification fails).
            // The invariant is "tamper -> CryptoError", not a specific
            // code, so we assert the broader property.
            await expect(cm.decryptText(tampered, pwd)).rejects.toThrow(
              CryptoError
            );
          }
        ),
        FC_CONFIG_FAST
      );
    });

    it('sync text: flipping any single bit causes decryptTextSync to throw CryptoError', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbText,
          arbStrongPassword,
          fc.double({ min: 0, max: 1, noNaN: true, maxExcluded: true }),
          arbBitIdx,
          async (text, pwd, fraction, bitIdx) => {
            const enc = cm.encryptTextSync(text, pwd);
            const buf = Buffer.from(enc, 'base64url');
            const byteIdx = Math.floor(fraction * buf.length);
            if (byteIdx >= buf.length) return;
            const tampered = flipBit(buf, byteIdx, bitIdx).toString(
              'base64url'
            );
            // Same invariant as the async case but routed through
            // PBKDF2; the v1 header for sync ciphertexts puts the
            // PBKDF2 reserved bytes at offsets 10-21 so all of those
            // are now AAD-bound.
            expect(() => cm.decryptTextSync(tampered, pwd)).toThrow(
              CryptoError
            );
          }
        ),
        FC_CONFIG_SYNC
      );
    });

    /**
     * Targeted v1-header property: pin the byte index to the 22-byte v1
     * header range so every generated case actually exercises the AAD
     * binding (rather than statistically hitting the body, which was
     * already detected pre-Task-1 via the auth tag).
     *
     * This is the "after Task 1 ships, ANY header tampering throws"
     * invariant called out in FIX.md Task 7. The body-only version above
     * occasionally lands here too, but a targeted property gives the
     * fast-check shrinker a denser space to find header-specific
     * regressions.
     */
    it('async text v1 header: flipping any byte in offsets 0..21 throws CryptoError', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbText,
          arbStrongPassword,
          // 22-byte v1 header.
          fc.integer({ min: 0, max: 21 }),
          arbBitIdx,
          async (text, pwd, byteIdx, bitIdx) => {
            const enc = await cm.encryptText(text, pwd);
            const buf = Buffer.from(enc, 'base64url');
            const tampered = flipBit(buf, byteIdx, bitIdx).toString(
              'base64url'
            );
            await expect(cm.decryptText(tampered, pwd)).rejects.toThrow(
              CryptoError
            );
          }
        ),
        FC_CONFIG_FAST
      );
    });

    it('sync text v1 header: flipping any byte in offsets 0..21 throws CryptoError', async () => {
      const cm = makeFastCrypto();
      await fc.assert(
        fc.asyncProperty(
          arbText,
          arbStrongPassword,
          fc.integer({ min: 0, max: 21 }),
          arbBitIdx,
          async (text, pwd, byteIdx, bitIdx) => {
            const enc = cm.encryptTextSync(text, pwd);
            const buf = Buffer.from(enc, 'base64url');
            const tampered = flipBit(buf, byteIdx, bitIdx).toString(
              'base64url'
            );
            expect(() => cm.decryptTextSync(tampered, pwd)).toThrow(
              CryptoError
            );
          }
        ),
        FC_CONFIG_SYNC
      );
    });

    /**
     * File-path tampering. Smaller numRuns because each case writes,
     * encrypts, tampers, and (must) fail-decrypts on disk.
     *
     * File format reminder: salt (32) + iv (12) + ciphertext (variable) +
     * tag (16). Plus the 22-byte v1 header at the front. So the entire
     * encrypted file (including header + ciphertext + trailing tag) must
     * be tamper-evident.
     */
    it('async file: flipping any single bit causes decryptFile to throw CryptoError', async () => {
      const cm = makeFastCrypto();
      const dir = path.join(
        TEST_DIR,
        `tamper-${crypto.randomBytes(8).toString('hex')}`
      );
      const inputPath = path.join(dir, 'in.bin');
      const encryptedPath = path.join(dir, 'enc.bin');
      const decryptedPath = path.join(dir, 'dec.bin');
      const { mkdir, writeFile: writeFileAsync, rm } = await import(
        'node:fs/promises'
      );
      await mkdir(dir, { recursive: true });

      try {
        await fc.assert(
          fc.asyncProperty(
            arbText,
            arbStrongPassword,
            fc.double({ min: 0, max: 1, noNaN: true, maxExcluded: true }),
            arbBitIdx,
            async (text, pwd, fraction, bitIdx) => {
              const inputBytes = Buffer.from(text, 'utf8');
              await writeFileAsync(inputPath, inputBytes);
              await cm.encryptFile(inputPath, encryptedPath, pwd);
              const buf = await readFile(encryptedPath);
              const byteIdx = Math.floor(fraction * buf.length);
              if (byteIdx >= buf.length) {
                // Cleanup before returning to keep the per-case state clean.
                for (const f of [inputPath, encryptedPath]) {
                  if (existsSync(f)) await unlink(f);
                }
                return;
              }
              const tamperedBuf = flipBit(buf, byteIdx, bitIdx);
              await writeFileAsync(encryptedPath, tamperedBuf);
              await expect(
                cm.decryptFile(encryptedPath, decryptedPath, pwd)
              ).rejects.toThrow(CryptoError);
              // Cleanup between iterations so subsequent runs start fresh.
              for (const f of [inputPath, encryptedPath, decryptedPath]) {
                if (existsSync(f)) await unlink(f);
              }
            }
          ),
          // File I/O dominates per-case wall-clock; cap runs to keep the
          // suite responsive on slow CI runners.
          { numRuns: 25, endOnFailure: true }
        );
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it('sync file: flipping any single bit causes decryptFileSync to throw CryptoError', async () => {
      const cm = makeFastCrypto();
      const dir = path.join(
        TEST_DIR,
        `tamper-sync-${crypto.randomBytes(8).toString('hex')}`
      );
      const inputPath = path.join(dir, 'in.bin');
      const encryptedPath = path.join(dir, 'enc.bin');
      const decryptedPath = path.join(dir, 'dec.bin');
      const { mkdir, rm } = await import('node:fs/promises');
      await mkdir(dir, { recursive: true });

      try {
        await fc.assert(
          fc.asyncProperty(
            arbText,
            arbStrongPassword,
            fc.double({ min: 0, max: 1, noNaN: true, maxExcluded: true }),
            arbBitIdx,
            async (text, pwd, fraction, bitIdx) => {
              const inputBytes = Buffer.from(text, 'utf8');
              await writeFile(inputPath, inputBytes);
              cm.encryptFileSync(inputPath, encryptedPath, pwd);
              const buf = await readFile(encryptedPath);
              const byteIdx = Math.floor(fraction * buf.length);
              if (byteIdx >= buf.length) {
                for (const f of [inputPath, encryptedPath]) {
                  if (existsSync(f)) await unlink(f);
                }
                return;
              }
              const tamperedBuf = flipBit(buf, byteIdx, bitIdx);
              await writeFile(encryptedPath, tamperedBuf);
              expect(() =>
                cm.decryptFileSync(encryptedPath, decryptedPath, pwd)
              ).toThrow(CryptoError);
              for (const f of [inputPath, encryptedPath, decryptedPath]) {
                if (existsSync(f)) await unlink(f);
              }
            }
          ),
          { numRuns: 25, endOnFailure: true }
        );
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  });
});
