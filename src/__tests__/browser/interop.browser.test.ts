/**
 * Real-browser interop suite (Phase 9 — browser-ci).
 *
 * Runs INSIDE a headless Chromium via Vitest Browser Mode (Playwright
 * provider), so every assertion here executes against a real browser engine:
 * SubtleCrypto for AES-256-GCM and hash-wasm's WASM Argon2id — NOT a Node
 * process emulating them. It is the live companion to the Node-run
 * `src/__tests__/interop.test.ts`; together they pin the crown-jewel guarantee
 * of the isomorphic release from both sides of the runtime boundary.
 *
 * What this proves in a real browser:
 *   1. The BUILT browser entry (`dist/index.browser.js` — the exact artifact a
 *      bundler ships) imports and works: its `node:`-free graph loads, and its
 *      Web engine derives keys and encrypts/decrypts.
 *   2. `encryptBytes`/`decryptBytes` and `encryptText`/`decryptText` round-trip
 *      across edge sizes (0/1/15/16/17/large), binary and multi-byte Unicode,
 *      and mixing the bytes and text APIs — one wire format, one codepath.
 *   3. Node→browser interop: every committed Node-produced golden vector
 *      (`fixtures/node-vectors.json`) decrypts here to its recorded plaintext,
 *      in a real browser. Decryption is header-driven (each vector embeds its
 *      own KDF params), so even a DEFAULT (32 MiB) browser manager recovers a
 *      vector encrypted at the low-cost test profile.
 *   4. Negatives survive: a wrong password and a single-bit tamper (auth tag or
 *      AAD-bound header byte) both reject via `CryptoError`.
 *   5. The Node-only surface (file/stream/sync/`Buffer`-typed low-level) is
 *      present but throws `CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER')`.
 *
 * Unlike the Node suite, this one does NOT gate on Argon2id availability: the
 * browser IS the target runtime, so if hash-wasm cannot derive here that is a
 * genuine failure, not a skip.
 *
 * Globals are OFF (Vitest default) — `describe`/`it`/`expect` are imported
 * explicitly, mirroring the Node suite's `@jest/globals` convention. The specs
 * touch NO Node global (`Buffer`/`process`) or `node:` builtin, since neither
 * exists in the browser.
 */
import { describe, it, expect } from 'vitest';
import {
  CryptoManager,
  SECURITY_THRESHOLDS,
  isValidPassword,
  SecurityLevel,
  CryptoError,
  CryptoErrorType,
  HEADER_LENGTH,
  utf8Encode,
  utf8Decode,
  bytesToBase64url,
  base64urlToBytes,
} from '../../../dist/index.browser.js';
// Committed Node-produced golden vectors. Bundled by Vite as a JSON module.
import nodeVectors from '../fixtures/node-vectors.json';

// Test-only low-cost Argon2id profile — shared with the Node suite and the
// fixture generator (`memoryCost = 2**14` KiB = 16 MiB, t=1, p=1) so browser
// derivations are fast. NEVER use in production.
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

// A 20+ character passphrase (NIST passphrase acceptance rule) plus a distinct
// one for the wrong-password negatives.
const PASSWORD = 'correct horse battery staple';
const WRONG_PASSWORD = 'incorrect zebra piano lantern';

// v1 TEXT wire layout `[header:22][salt:32][iv:12][tag:16][ciphertext]`.
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_OFFSET = HEADER_LENGTH + SALT_LENGTH + IV_LENGTH; // 66 — always present

interface NodeVector {
  description: string;
  password: string;
  plaintext: string;
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  ciphertext: string;
}

interface NodeVectorsFixture {
  generatedWith: { package: string; version: string; kdf: string };
  kdfParams: { memoryCost: number; timeCost: number; parallelism: number };
  vectors: NodeVector[];
}

// The JSON import is typed loosely by the bundler; assert the shape we rely on.
const fixture = nodeVectors as unknown as NodeVectorsFixture;

/** Pure byte-equality (no `Buffer` — this runs in the browser). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Deterministic-but-varied filler bytes for a given length. */
function fillerBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = (i * 31 + 7) & 0xff;
  }
  return out;
}

/** Flip a single bit at `offset`, returning a NEW array (input untouched). */
function flipBitAt(buf: Uint8Array, offset: number): Uint8Array {
  const out = Uint8Array.from(buf);
  out[offset] = (out[offset] ?? 0) ^ 0x01;
  return out;
}

/** Assert a synchronous Node-only stub threw the `UNSUPPORTED_IN_BROWSER` error. */
function expectUnsupportedSync(run: () => unknown): void {
  let caught: unknown;
  try {
    run();
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(CryptoError);
  expect((caught as InstanceType<typeof CryptoError>).code).toBe(
    'UNSUPPORTED_IN_BROWSER'
  );
  expect((caught as InstanceType<typeof CryptoError>).type).toBe(
    CryptoErrorType.INVALID_INPUT
  );
}

/** Assert an async Node-only stub REJECTED with the `UNSUPPORTED_IN_BROWSER` error. */
async function expectUnsupportedAsync(
  run: () => Promise<unknown>
): Promise<void> {
  let caught: unknown;
  try {
    await run();
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(CryptoError);
  expect((caught as InstanceType<typeof CryptoError>).code).toBe(
    'UNSUPPORTED_IN_BROWSER'
  );
  expect((caught as InstanceType<typeof CryptoError>).type).toBe(
    CryptoErrorType.INVALID_INPUT
  );
}

// Construction is cheap (no KDF, no default passphrase) — reuse across tests.
const cm = new CryptoManager(LOW_COST);
const defaultCm = new CryptoManager();

describe('@hiprax/crypto browser build — real headless Chromium (Vitest Browser Mode)', () => {
  describe('environment is a real browser with Web Crypto + WebAssembly', () => {
    it('exposes the browser DOM globals and SubtleCrypto (not a Node shim)', () => {
      // `window`/`document` exist only in a browser; SubtleCrypto powers the
      // Web engine's AES-GCM; WebAssembly powers hash-wasm Argon2id.
      expect(typeof window).toBe('object');
      expect(typeof document).toBe('object');
      expect(typeof globalThis.crypto?.subtle?.encrypt).toBe('function');
      expect(typeof WebAssembly).toBe('object');
    });
  });

  describe('in-memory round-trip inside the browser', () => {
    it('encryptBytes/decryptBytes round-trips across edge sizes and binary content', async () => {
      // 0/1/15/16/17 straddle the AES block boundary; 100_000 is multi-block.
      const sizes = [0, 1, 15, 16, 17, 100_000];
      for (const size of sizes) {
        const data = fillerBytes(size);
        const ct = await cm.encryptBytes(data, PASSWORD);
        const back = await cm.decryptBytes(ct, PASSWORD);
        expect(back.length).toBe(size);
        expect(bytesEqual(back, data)).toBe(true);
      }
    });

    it('encryptText/decryptText round-trips ascii, unicode, empty, and long text', async () => {
      const texts = [
        '',
        'hello world',
        'café — 世界 — 🔐 — Ω≈ç√∫ — Здравствуй',
        'x'.repeat(5000),
      ];
      for (const text of texts) {
        const ct = await cm.encryptText(text, PASSWORD);
        expect(await cm.decryptText(ct, PASSWORD)).toBe(text);
      }
    });

    it('mixes the bytes and text APIs over one wire format', async () => {
      const text = 'one wire format, two APIs — café 🔐';

      // encryptBytes -> base64url -> decryptText
      const bytesCt = await cm.encryptBytes(utf8Encode(text), PASSWORD);
      expect(await cm.decryptText(bytesToBase64url(bytesCt), PASSWORD)).toBe(
        text
      );

      // encryptText -> base64url bytes -> decryptBytes
      const textCt = await cm.encryptText(text, PASSWORD);
      const back = await cm.decryptBytes(base64urlToBytes(textCt), PASSWORD);
      expect(utf8Decode(back)).toBe(text);
    });
  });

  // ---------------------------------------------------------------------------
  // The crown jewel, in a real browser: Node-produced ciphertexts decrypt here.
  //
  // A DEFAULT (32 MiB) browser manager decrypts vectors that were encrypted at
  // the low-cost test profile — decryption reads the KDF params embedded in
  // each header, so it is independent of the manager's own configuration. This
  // is the frozen Node→browser proof, now executed inside actual Chromium.
  // ---------------------------------------------------------------------------
  describe('Node-produced golden vectors decrypt in the browser (fixtures/node-vectors.json)', () => {
    it('the fixture is present, non-empty, and Argon2id-tagged', () => {
      expect(Array.isArray(fixture.vectors)).toBe(true);
      expect(fixture.vectors.length).toBeGreaterThanOrEqual(4);
      expect(fixture.generatedWith.kdf).toBe('argon2id');
    });

    for (const vector of fixture.vectors) {
      it(`browser decrypts Node golden vector: ${vector.description}`, async () => {
        // Header inspection is a pure parse (no KDF): the embedded params must
        // match what the fixture documents.
        const header = defaultCm.inspectHeader(vector.ciphertext);
        expect(header).not.toBeNull();
        expect(header?.params.kind).toBe('argon2id');
        if (header?.params.kind === 'argon2id') {
          expect(header.params.memoryCost).toBe(vector.memoryCost);
          expect(header.params.timeCost).toBe(vector.timeCost);
          expect(header.params.parallelism).toBe(vector.parallelism);
        }

        // Real-browser Argon2id (hash-wasm) derivation + AES-GCM decrypt.
        const recovered = await defaultCm.decryptText(
          vector.ciphertext,
          vector.password
        );
        expect(recovered).toBe(vector.plaintext);
      });
    }
  });

  describe('negatives reject inside the browser', () => {
    it('a wrong password fails to decrypt', async () => {
      const ct = await cm.encryptBytes(fillerBytes(64), PASSWORD);
      await expect(cm.decryptBytes(ct, WRONG_PASSWORD)).rejects.toThrow(
        CryptoError
      );
    });

    it('a single-bit tamper of the auth tag or an AAD-bound header byte fails', async () => {
      const ct = await cm.encryptBytes(fillerBytes(48), PASSWORD);

      // GCM auth tag (offset 66, always present even for tiny plaintext).
      await expect(
        cm.decryptBytes(flipBitAt(ct, TAG_OFFSET), PASSWORD)
      ).rejects.toThrow(CryptoError);

      // A reserved header byte is bound into the GCM AAD, so flipping it must
      // also fail authentication.
      await expect(
        cm.decryptBytes(flipBitAt(ct, HEADER_LENGTH - 2), PASSWORD)
      ).rejects.toThrow(CryptoError);
    });
  });

  // ---------------------------------------------------------------------------
  // Node-only surface: present (so the class shape matches the Node build) but
  // unimplementable with one-shot, async Web Crypto — every such method throws
  // `CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER')`.
  // ---------------------------------------------------------------------------
  describe('Node-only methods throw UNSUPPORTED_IN_BROWSER', () => {
    it('synchronous / Buffer-typed / sync-file methods throw synchronously', () => {
      const salt = new Uint8Array(SALT_LENGTH);
      const key = new Uint8Array(32);
      const iv = new Uint8Array(IV_LENGTH);
      const tag = new Uint8Array(16);
      const data = new Uint8Array([1, 2, 3]);

      expectUnsupportedSync(() => cm.generateSecureRandom(16));
      expectUnsupportedSync(() => cm.deriveKeySync(PASSWORD, salt));
      expectUnsupportedSync(() => cm.encryptData(data, key, iv));
      expectUnsupportedSync(() => cm.decryptData(data, key, iv, tag));
      expectUnsupportedSync(() => cm.encryptTextSync('hello world', PASSWORD));
      expectUnsupportedSync(() => cm.decryptTextSync('x', PASSWORD));
      expectUnsupportedSync(() =>
        cm.encryptFileSync('in.txt', 'out.bin', PASSWORD)
      );
      expectUnsupportedSync(() =>
        cm.decryptFileSync('in.bin', 'out.txt', PASSWORD)
      );
    });

    it('asynchronous Node-only methods reject (not synchronously throw)', async () => {
      const salt = new Uint8Array(SALT_LENGTH);
      await expectUnsupportedAsync(() => cm.deriveKey(PASSWORD, salt));
      await expectUnsupportedAsync(() =>
        cm.encryptFile('in.txt', 'out.bin', PASSWORD)
      );
      await expectUnsupportedAsync(() =>
        cm.decryptFile('in.bin', 'out.txt', PASSWORD)
      );
    });
  });

  describe('isomorphic non-KDF surface works in the browser', () => {
    it('validatePassword / isValidPassword agree with the Node build', () => {
      expect(isValidPassword(PASSWORD)).toBe(true);
      expect(isValidPassword('weak')).toBe(false);
      expect(cm.validatePassword(PASSWORD)).toBe(true);
      expect(cm.validatePassword('weak')).toBe(false);
    });

    it('the default browser manager classifies as MEDIUM (32 MiB < HIGH threshold)', () => {
      // Browser default is a lighter 32 MiB Argon2id profile; the shared
      // threshold table classifies it MEDIUM (below the 128 MiB HIGH bar).
      expect(defaultCm.getSecurityLevel()).toBe(SecurityLevel.MEDIUM);
    });

    it('SECURITY_THRESHOLDS is the shared, frozen table', () => {
      expect(SECURITY_THRESHOLDS.HIGH.memoryCost).toBe(2 ** 17);
      expect(Object.isFrozen(SECURITY_THRESHOLDS)).toBe(true);
      expect(Object.isFrozen(SECURITY_THRESHOLDS.HIGH)).toBe(true);
    });

    it('inspectHeader returns the parsed v1 header or null for non-magic input', async () => {
      const ct = await cm.encryptText('inspect me', PASSWORD);
      const header = cm.inspectHeader(ct);
      expect(header).not.toBeNull();
      expect(header?.params.kind).toBe('argon2id');

      // A buffer with no HPCR magic is treated as a legacy (v0) ciphertext.
      expect(cm.inspectHeader(new Uint8Array(64))).toBeNull();
    });
  });
});
