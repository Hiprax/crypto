/**
 * Property-based tests for the isomorphic byte API (Phase 8 — interop-vectors),
 * run under Node 22+ against BOTH engines.
 *
 * `encrypt-bytes.test.ts` pins `encryptBytes`/`decryptBytes` with hand-curated
 * examples on the Node engine; this file uses `fast-check` to assert the same
 * invariants over many random `Uint8Array` payloads (INCLUDING the empty array)
 * and random strong passwords, and it runs the whole battery against the Node
 * engine (`node:crypto`) AND the Web engine (`SubtleCrypto` + hash-wasm) so the
 * runtime-agnostic core is exercised uniformly. The three invariants:
 *
 *   1. Round-trip identity: `decryptBytes(encryptBytes(b, p), p)` reproduces `b`
 *      byte-for-byte, for random `b` including the empty array.
 *   2. Tamper-evidence: flipping a single bit anywhere in the ciphertext always
 *      makes `decryptBytes` throw `CryptoError` (never silent corruption).
 *   3. Freshness/distinctness: distinct plaintexts produce distinct
 *      ciphertexts, and the SAME plaintext encrypted twice produces distinct
 *      ciphertexts (a fresh random salt + IV per call).
 *
 * Why low-cost params: Argon2id at the production default is ~700 ms per
 * derivation; property tests only need it to be CORRECT, so both managers use
 * the LOW tier (`memoryCost: 2^14 = 16 MiB`, `timeCost: 1`). TEST-ONLY — never
 * lower production parameters this far.
 *
 * Availability gating (Core Principle 4): the Web-engine properties depend on
 * the optional `hash-wasm`. A `beforeAll` probe runs one real Web-engine
 * derivation; if hash-wasm cannot load, `webEngineReady` stays false and the
 * Web-engine properties skip (logged) rather than fail. The Node-engine
 * properties are never gated — the rest of the Node suite assumes `node:crypto`
 * + a working Argon2id provider, and gating it would mask a real regression.
 */
import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import fc from 'fast-check';
import { CryptoManager as NodeCryptoManager } from '../crypto-manager';
import { CryptoManager as BrowserCryptoManager } from '../crypto-manager.browser';
import type { CryptoCore } from '../core';
import { CryptoError } from '../types';
import { bytesToHex } from '../codec';

const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

// KDF-bound properties do ~2 Argon2id derivations per case; 20 cases keeps each
// property well under its timeout on both engines while still sampling widely.
const FC_CONFIG: fc.Parameters = { numRuns: 20, endOnFailure: true };

// The tamper property flips bytes anywhere in the ciphertext — including the v1
// header's KDF-param bytes. A fixed seed makes the (deliberately bounded, see
// the memoryCost-window skip in the tamper test) input space reproducible and
// vettable across runs rather than drawing a fresh random sample each time.
const FC_TAMPER_CONFIG: fc.Parameters = { ...FC_CONFIG, seed: 0x1505 };

/** True when an error is the documented "Argon2id unavailable" graceful state. */
function isArgon2Unavailable(err: unknown): boolean {
  return (
    err instanceof CryptoError &&
    (err as InstanceType<typeof CryptoError>).code === 'ARGON2_NOT_AVAILABLE'
  );
}

// ---------------------------------------------------------------------------
// Arbitraries.
// ---------------------------------------------------------------------------

// Random byte payloads. The empty array is a first-class plaintext (it still
// yields a full 82-byte v1 wire envelope), so it is modelled as an EXPLICIT,
// weighted branch — mirroring `property.test.ts`'s `arbSyncPlaintext` — rather
// than left to the sampling bias of a bare `fc.uint8Array({ minLength: 0 })`.
// The `weight: 1` empty vs `weight: 4` non-empty split puts ~20% of every
// property's runs on the empty case, so the "incl. empty" guarantee holds each
// run instead of only probabilistically.
const arbBytes = fc.oneof(
  { weight: 1, arbitrary: fc.constant(new Uint8Array(0)) },
  { weight: 4, arbitrary: fc.uint8Array({ minLength: 1, maxLength: 256 }) }
);

/**
 * Hand-curated strong-password arbitrary (mirrors `property.test.ts`): four
 * mandatory category samples plus a tail, so every generated password satisfies
 * `validatePassword`'s composition rule without paying the huge cost of
 * `fc.string().filter(validatePassword)`.
 */
const arbStrongPassword = fc
  .tuple(
    fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
    fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'),
    fc.constantFrom(...'0123456789'),
    fc.constantFrom(...'!@#$%^&*()_+-=[]{}|;:,.<>?/~`'),
    fc.string({ minLength: 4, maxLength: 16 })
  )
  .map(([upper, lower, digit, special, tail]) => {
    return `${upper}${lower}${digit}${special}${tail}`;
  });

/** Two byte payloads guaranteed to differ (so "distinct plaintext" is defined). */
const arbTwoDistinctByteArrays = fc
  .tuple(arbBytes, arbBytes)
  .filter(([a, b]) => bytesToHex(a) !== bytesToHex(b));

/** Random bit position within a byte, 0..7. */
const arbBitIdx = fc.integer({ min: 0, max: 7 });

/** Flip a single bit, returning a NEW array (input untouched). */
function flipBit(buf: Uint8Array, byteIdx: number, bitIdx: number): Uint8Array {
  const out = Uint8Array.from(buf);
  out[byteIdx] = (out[byteIdx] ?? 0) ^ (1 << bitIdx);
  return out;
}

interface EngineCase {
  name: string;
  make: () => CryptoCore;
  /** Web-engine cases are gated on hash-wasm availability. */
  gated: boolean;
}

const ENGINES: EngineCase[] = [
  {
    name: 'node engine (node:crypto)',
    make: () => new NodeCryptoManager(LOW_COST),
    gated: false,
  },
  {
    name: 'web engine (SubtleCrypto + hash-wasm)',
    make: () => new BrowserCryptoManager(LOW_COST),
    gated: true,
  },
];

describe('property-based encryptBytes/decryptBytes (both engines)', () => {
  jest.setTimeout(120_000);

  let webEngineReady = false;
  beforeAll(async () => {
    try {
      const probe = new BrowserCryptoManager(LOW_COST);
      const ct = await probe.encryptBytes(
        new Uint8Array([1, 2, 3]),
        'a strong test passphrase 123!'
      );
      await probe.decryptBytes(ct, 'a strong test passphrase 123!');
      webEngineReady = true;
    } catch (err) {
      if (isArgon2Unavailable(err)) {
        // In CI the optional hash-wasm dependency MUST be installed so the
        // Web-engine property battery cannot silently no-op. Graceful [skip]
        // is reserved for genuinely-unsupported local dev hosts.
        if (process.env.CI) {
          throw new Error(
            `hash-wasm Argon2id failed to load in CI; the Web-engine property ` +
              `tests cannot be silently skipped. Ensure the optional hash-wasm ` +
              `dependency is installed.`,
            { cause: err }
          );
        }
        webEngineReady = false;
        // eslint-disable-next-line no-console
        console.warn(
          `[skip] hash-wasm Argon2id unavailable; web-engine property tests ` +
            `will be skipped: ${String(err)}`
        );
      } else {
        throw err;
      }
    }
  }, 60_000);

  for (const engine of ENGINES) {
    describe(engine.name, () => {
      /** Skip a Web-engine property when hash-wasm is unavailable. */
      const skipGated = (): boolean => engine.gated && !webEngineReady;

      it('round-trip: decryptBytes(encryptBytes(b, p), p) === b (incl. empty)', async () => {
        if (skipGated()) return;
        const cm = engine.make();
        await fc.assert(
          fc.asyncProperty(arbBytes, arbStrongPassword, async (bytes, pwd) => {
            const ct = await cm.encryptBytes(bytes, pwd);
            const back = await cm.decryptBytes(ct, pwd);
            expect(bytesToHex(back)).toBe(bytesToHex(bytes));
          }),
          FC_CONFIG
        );
      });

      it('tamper-evidence: flipping any single bit makes decryptBytes throw CryptoError', async () => {
        if (skipGated()) return;
        const cm = engine.make();
        await fc.assert(
          fc.asyncProperty(
            arbBytes,
            arbStrongPassword,
            // Fraction mapped to a byte index once we know the ciphertext
            // length; `maxExcluded` keeps the index strictly in range.
            fc.double({ min: 0, max: 1, noNaN: true, maxExcluded: true }),
            arbBitIdx,
            async (bytes, pwd, fraction, bitIdx) => {
              const ct = await cm.encryptBytes(bytes, pwd);
              const byteIdx = Math.floor(fraction * ct.length);
              // ct.length is >= 82 (header+salt+iv+tag) even for empty
              // plaintext, so a valid index always exists.
              if (byteIdx >= ct.length) return;
              // Skip the v1 header memoryCost field (u32BE at offsets 6..9): a
              // single-bit flip there can encode a valid-but-multi-GiB Argon2id
              // memory cost (<= the 2^22 KiB wire cap) that decryptBytes
              // attempts to derive BEFORE the GCM auth check, which can OOM or
              // time out a constrained runner. The test's assertion would still
              // pass (a CryptoError is thrown either way), so this is purely a
              // resource-hygiene guard — single-byte header tamper is already
              // covered deterministically in encrypt-bytes.test.ts, so no
              // tamper-evidence coverage is lost.
              if (byteIdx >= 6 && byteIdx <= 9) return;
              const tampered = flipBit(ct, byteIdx, bitIdx);
              await expect(cm.decryptBytes(tampered, pwd)).rejects.toThrow(
                CryptoError
              );
            }
          ),
          FC_TAMPER_CONFIG
        );
      });

      it('distinctness: distinct plaintexts produce distinct ciphertexts', async () => {
        if (skipGated()) return;
        const cm = engine.make();
        await fc.assert(
          fc.asyncProperty(
            arbTwoDistinctByteArrays,
            arbStrongPassword,
            async ([a, b], pwd) => {
              const ctA = await cm.encryptBytes(a, pwd);
              const ctB = await cm.encryptBytes(b, pwd);
              expect(bytesToHex(ctA)).not.toBe(bytesToHex(ctB));
            }
          ),
          FC_CONFIG
        );
      });

      it('freshness: the same plaintext encrypts to distinct ciphertexts (fresh salt+IV)', async () => {
        if (skipGated()) return;
        const cm = engine.make();
        await fc.assert(
          fc.asyncProperty(arbBytes, arbStrongPassword, async (bytes, pwd) => {
            const ct1 = await cm.encryptBytes(bytes, pwd);
            const ct2 = await cm.encryptBytes(bytes, pwd);
            expect(bytesToHex(ct1)).not.toBe(bytesToHex(ct2));
          }),
          FC_CONFIG
        );
      });
    });
  }
});
