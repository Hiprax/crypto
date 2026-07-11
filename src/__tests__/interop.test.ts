/**
 * Cross-runtime interop tests (Phase 8 — interop-vectors), run under Node 22+.
 *
 * This is the crown-jewel guarantee of the isomorphic release: there is exactly
 * ONE wire format, so a ciphertext produced by the **Node** build decrypts in
 * the **browser** build and vice-versa. Both builds share the same
 * {@link CryptoCore}; the only differences are the engine (Node `node:crypto`
 * vs Web `SubtleCrypto` + hash-wasm) and the default Argon2id cost. Here we
 * construct BOTH managers at MATCHING low-cost Argon2id parameters and prove:
 *
 *   1. Live round-trip BOTH directions (Node→browser and browser→Node) over
 *      `encryptBytes`/`decryptBytes` AND `encryptText`/`decryptText`, across
 *      edge sizes (0/1/15/16/17/large), binary and multi-byte Unicode content,
 *      and mixing the text and bytes APIs across runtimes.
 *   2. Negatives survive the crossing: a wrong password and a single-bit tamper
 *      of a cross-runtime ciphertext both throw `CryptoError` on either build.
 *   3. Committed Node-produced golden vectors (`fixtures/node-vectors.json`)
 *      decrypt in the browser build to their recorded plaintext — a frozen
 *      Node→browser proof that survives even if the live Node encryptor changes
 *      (the real-headless-Chromium companion arrives in Phase 9).
 *
 * The two engines derive bit-identical Argon2id keys (RFC 9106; proven at the
 * primitive layer in `engine-web.test.ts`) and byte-identical AES-256-GCM
 * output, which is what makes the crossing work.
 *
 * Availability gating (Core Principle 4): `hash-wasm` is an optional dependency
 * and powers the browser (Web engine) Argon2id path. A single probe in
 * `beforeAll` runs one real Web-engine derivation; if hash-wasm genuinely
 * cannot load it sets `webEngineReady = false` and every browser-dependent
 * assertion is skipped (logged) rather than failed. Pure, KDF-free checks
 * (header inspection, fixture shape) always run. The Node engine (native
 * `argon2` → hash-wasm fallback) is assumed available, exactly as the rest of
 * the Node suite assumes.
 */
import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import nodeCrypto from 'node:crypto';
import { CryptoManager as NodeCryptoManager } from '../crypto-manager';
import { CryptoManager as BrowserCryptoManager } from '../crypto-manager.browser';
import { CryptoError } from '../types';
import {
  utf8Encode,
  utf8Decode,
  bytesToHex,
  bytesToBase64url,
  base64urlToBytes,
} from '../codec';
import { HEADER_LENGTH } from '../format';

// Test-only low-cost Argon2id profile. Passed to BOTH managers so they encrypt
// at IDENTICAL parameters (the browser default would otherwise be 32 MiB vs the
// Node 128 MiB) — "matching Argon2id params". Never use in production.
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

// A 20+ character passphrase (NIST passphrase acceptance rule) plus a distinct
// one for the wrong-password negatives.
const PASSWORD = 'correct horse battery staple';
const WRONG_PASSWORD = 'incorrect zebra piano lantern';

// v1 TEXT wire layout `[header:22][salt:32][iv:12][tag:16][ciphertext]`.
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_OFFSET = HEADER_LENGTH + SALT_LENGTH + IV_LENGTH; // 66 — always present

/** Committed golden-vector fixture, resolved from the repo root (jest cwd). */
const FIXTURE_PATH = path.join(
  process.cwd(),
  'src',
  '__tests__',
  'fixtures',
  'node-vectors.json'
);

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

/** Read the committed fixture, failing with a regeneration hint if absent. */
function loadFixture(): NodeVectorsFixture {
  try {
    return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as NodeVectorsFixture;
  } catch (err) {
    throw new Error(
      `Could not read golden vectors at ${FIXTURE_PATH}. ` +
        'Regenerate with: `npm run build && node scripts/gen-node-vectors.mjs`.',
      { cause: err }
    );
  }
}

/** True when an error is the documented "Argon2id unavailable" graceful state. */
function isArgon2Unavailable(err: unknown): boolean {
  return (
    err instanceof CryptoError &&
    (err as InstanceType<typeof CryptoError>).code === 'ARGON2_NOT_AVAILABLE'
  );
}

/** Byte-equality helper (fast memcmp via Buffer — harness-side only). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a).equals(Buffer.from(b));
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

describe('cross-runtime interop — one wire format round-trips Node <-> browser', () => {
  jest.setTimeout(120_000);

  const node = new NodeCryptoManager(LOW_COST);
  const browser = new BrowserCryptoManager(LOW_COST);

  // Probe IS the call: one real Web-engine round-trip. If hash-wasm cannot load
  // this flips to false and browser-dependent assertions skip rather than fail.
  let webEngineReady = false;
  beforeAll(async () => {
    try {
      const probe = new BrowserCryptoManager(LOW_COST);
      const ct = await probe.encryptBytes(new Uint8Array([1, 2, 3]), PASSWORD);
      await probe.decryptBytes(ct, PASSWORD);
      webEngineReady = true;
    } catch (err) {
      if (isArgon2Unavailable(err)) {
        webEngineReady = false;
        // eslint-disable-next-line no-console
        console.warn(
          `[skip] hash-wasm Argon2id unavailable; browser-side interop ` +
            `assertions will be skipped: ${String(err)}`
        );
      } else {
        throw err;
      }
    }
  }, 60_000);

  describe('live round-trip (both directions)', () => {
    it('bytes: Node-encrypted decrypts in the browser AND browser-encrypted decrypts in Node (edge sizes, binary)', async () => {
      if (!webEngineReady) return;
      // 0/1/15/16/17 straddle the AES block boundary; the last is a multi-block
      // "large" buffer. Data size is negligible next to the KDF cost.
      const sizes = [0, 1, 15, 16, 17, 100_000];
      for (const size of sizes) {
        const data = new Uint8Array(nodeCrypto.randomBytes(size));

        // Node -> browser
        const nodeCt = await node.encryptBytes(data, PASSWORD);
        const nodeToBrowser = await browser.decryptBytes(nodeCt, PASSWORD);
        expect(bytesEqual(nodeToBrowser, data)).toBe(true);
        expect(nodeToBrowser.length).toBe(size);

        // browser -> Node
        const browserCt = await browser.encryptBytes(data, PASSWORD);
        const browserToNode = await node.decryptBytes(browserCt, PASSWORD);
        expect(bytesEqual(browserToNode, data)).toBe(true);
        expect(browserToNode.length).toBe(size);

        // Same matching params ⇒ byte-identical 22-byte header on both builds
        // (only the random salt/iv/tag/ciphertext differ). Proof of ONE format.
        expect(bytesToHex(nodeCt.subarray(0, HEADER_LENGTH))).toBe(
          bytesToHex(browserCt.subarray(0, HEADER_LENGTH))
        );
      }
    });

    it('text: Node-encrypted decrypts in the browser AND browser-encrypted decrypts in Node (ascii, unicode, empty, long)', async () => {
      if (!webEngineReady) return;
      const texts = [
        '',
        'hello world',
        'café — 世界 — 🔐 — Ω≈ç√∫ — Здравствуй',
        'x'.repeat(5000),
      ];
      for (const text of texts) {
        const nodeCt = await node.encryptText(text, PASSWORD);
        expect(await browser.decryptText(nodeCt, PASSWORD)).toBe(text);

        const browserCt = await browser.encryptText(text, PASSWORD);
        expect(await node.decryptText(browserCt, PASSWORD)).toBe(text);
      }
    });

    it('mixes the text and bytes APIs across runtimes (one wire format, both ways)', async () => {
      if (!webEngineReady) return;
      const text = 'shared wire format across runtime AND api — café 🔐';

      // Node bytes -> base64url -> browser text
      const nodeBytesCt = await node.encryptBytes(utf8Encode(text), PASSWORD);
      expect(
        await browser.decryptText(bytesToBase64url(nodeBytesCt), PASSWORD)
      ).toBe(text);

      // browser text -> base64url bytes -> Node bytes
      const browserTextCt = await browser.encryptText(text, PASSWORD);
      const back = await node.decryptBytes(
        base64urlToBytes(browserTextCt),
        PASSWORD
      );
      expect(utf8Decode(back)).toBe(text);
    });
  });

  describe('negatives survive the crossing', () => {
    it('a wrong password fails to decrypt a cross-runtime ciphertext (both directions)', async () => {
      if (!webEngineReady) return;

      const nodeCt = await node.encryptBytes(fillerBytes(64), PASSWORD);
      await expect(
        browser.decryptBytes(nodeCt, WRONG_PASSWORD)
      ).rejects.toThrow(CryptoError);

      const browserCt = await browser.encryptBytes(fillerBytes(64), PASSWORD);
      await expect(
        node.decryptBytes(browserCt, WRONG_PASSWORD)
      ).rejects.toThrow(CryptoError);
    });

    it('a single-bit tamper of a cross-runtime ciphertext fails on the other build (both directions)', async () => {
      if (!webEngineReady) return;

      // Tamper the auth tag (offset 66, always present even for empty
      // plaintext): GCM authentication must fail on the decrypting build.
      const nodeCt = await node.encryptBytes(fillerBytes(48), PASSWORD);
      await expect(
        browser.decryptBytes(flipBitAt(nodeCt, TAG_OFFSET), PASSWORD)
      ).rejects.toThrow(CryptoError);

      const browserCt = await browser.encryptBytes(fillerBytes(48), PASSWORD);
      await expect(
        node.decryptBytes(flipBitAt(browserCt, TAG_OFFSET), PASSWORD)
      ).rejects.toThrow(CryptoError);

      // Also tamper an AAD-bound header reserved byte: the header is bound into
      // the GCM AAD, so flipping it must fail on the other build too.
      await expect(
        browser.decryptBytes(flipBitAt(nodeCt, HEADER_LENGTH - 2), PASSWORD)
      ).rejects.toThrow(CryptoError);
      await expect(
        node.decryptBytes(flipBitAt(browserCt, HEADER_LENGTH - 2), PASSWORD)
      ).rejects.toThrow(CryptoError);
    });
  });

  // ---------------------------------------------------------------------------
  // Task 8.2 — committed Node-produced golden vectors decrypt in the browser.
  //
  // A DEFAULT browser manager (32 MiB profile) decrypts each vector: decryption
  // reads the KDF params embedded in the header, so it is independent of the
  // manager's own configuration. This is the frozen Node→browser proof; the
  // live encryptor above could drift and this would still pin the format. The
  // same fixture is re-decrypted inside a REAL headless Chromium in Phase 9.
  // ---------------------------------------------------------------------------
  describe('Node-produced golden vectors decrypt in the browser build (fixtures/node-vectors.json)', () => {
    const fixture = loadFixture();
    const defaultBrowser = new BrowserCryptoManager();

    it('the fixture is present, non-empty, and Argon2id-tagged', () => {
      expect(Array.isArray(fixture.vectors)).toBe(true);
      expect(fixture.vectors.length).toBeGreaterThanOrEqual(4);
      expect(fixture.generatedWith.kdf).toBe('argon2id');
    });

    for (const vector of fixture.vectors) {
      it(`browser decrypts golden vector: ${vector.description}`, async () => {
        // Header inspection is a pure parse (no KDF) — always assert the
        // embedded params match what the fixture documents.
        const header = defaultBrowser.inspectHeader(vector.ciphertext);
        expect(header).not.toBeNull();
        expect(header?.params.kind).toBe('argon2id');
        if (header?.params.kind === 'argon2id') {
          expect(header.params.memoryCost).toBe(vector.memoryCost);
          expect(header.params.timeCost).toBe(vector.timeCost);
          expect(header.params.parallelism).toBe(vector.parallelism);
        }

        // Decryption needs Argon2id (hash-wasm) — gate on availability.
        if (!webEngineReady) return;
        const recovered = await defaultBrowser.decryptText(
          vector.ciphertext,
          vector.password
        );
        expect(recovered).toBe(vector.plaintext);
      });
    }
  });
});
