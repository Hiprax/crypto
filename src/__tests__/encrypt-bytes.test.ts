/**
 * Isomorphic in-memory byte API tests (Phase 3 — core-bytes).
 *
 * Exercises `CryptoManager.encryptBytes` / `decryptBytes` — the runtime-agnostic
 * async API implemented on `CryptoCore`. In Node these run against `nodeEngine`
 * (native `argon2` → `hash-wasm` fallback + `node:crypto` AES-256-GCM). The same
 * code and the same wire bytes will later run in the browser against the Web
 * engine, so these tests pin the round-trip identity, the negative paths
 * (wrong password, single-bit tampering of every wire segment), and the
 * v1 header shape.
 *
 * A byte-format cross-check also proves that `encryptBytes` produces exactly the
 * bytes the existing `encryptText` produces (modulo base64url) — i.e. there is
 * ONE wire format shared by the text API and the bytes API. This is the
 * foundation for the Phase 4 text re-expression and the cross-runtime interop
 * guarantee.
 *
 * Why a low-cost CryptoManager: Argon2id at the production 128 MiB default is
 * ~700ms per derivation. These tests only need Argon2id to be CORRECT, so we
 * use the LOW tier (`memoryCost: 2^14 = 16 MiB`, `timeCost: 1`). This is a
 * TEST-ONLY configuration — consumers must never lower production parameters
 * this far.
 */
import { describe, it, expect } from '@jest/globals';
import nodeCrypto from 'node:crypto';
import { CryptoManager } from '../crypto-manager';
import { CryptoError } from '../types';
import { FORMAT_VERSION, KDF_ID_ARGON2ID, HEADER_LENGTH } from '../format';
import { utf8Encode, bytesToBase64url, base64urlToBytes } from '../codec';

// Test-only low-cost Argon2id profile. `timeCost: 1` keeps many derivations
// cheap while still exercising the real KDF path.
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

// A 20+ character passphrase (passes the NIST passphrase acceptance rule) plus
// a distinct one for the wrong-password negatives.
const PASSWORD = 'correct horse battery staple';
const WRONG_PASSWORD = 'incorrect zebra piano lantern';

// Fixed byte offsets of each v1 wire segment in the TEXT layout
// `[header:22][salt:32][iv:12][tag:16][ciphertext]`.
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_OFFSET = HEADER_LENGTH; // 22
const IV_OFFSET = SALT_OFFSET + SALT_LENGTH; // 54
const TAG_OFFSET = IV_OFFSET + IV_LENGTH; // 66
const CT_OFFSET = TAG_OFFSET + TAG_LENGTH; // 82

/** Byte-equality helper (fast memcmp via Buffer). */
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

describe('encryptBytes / decryptBytes (isomorphic in-memory API)', () => {
  const cm = new CryptoManager(LOW_COST);

  describe('round-trip identity', () => {
    // Edge sizes around the AES block boundary (16) plus larger buffers.
    const sizes = [0, 1, 15, 16, 17, 1024, 1024 * 1024];

    it.each(sizes)('round-trips a %d-byte random buffer', async size => {
      const data = new Uint8Array(nodeCrypto.randomBytes(size));
      const ciphertext = await cm.encryptBytes(data, PASSWORD);
      const back = await cm.decryptBytes(ciphertext, PASSWORD);
      expect(bytesEqual(back, data)).toBe(true);
      expect(back.length).toBe(size);
    });

    it('round-trips deterministic filler bytes (binary content)', async () => {
      const data = fillerBytes(257);
      const back = await cm.decryptBytes(
        await cm.encryptBytes(data, PASSWORD),
        PASSWORD
      );
      expect(bytesEqual(back, data)).toBe(true);
    });

    it('round-trips multi-byte UTF-8 (unicode) bytes', async () => {
      const text = 'café — 世界 — 🔐 — Ω≈ç√∫ — Здравствуй';
      const data = utf8Encode(text);
      const back = await cm.decryptBytes(
        await cm.encryptBytes(data, PASSWORD),
        PASSWORD
      );
      expect(bytesEqual(back, data)).toBe(true);
      expect(Buffer.from(back).toString('utf8')).toBe(text);
    });

    it('produces distinct ciphertexts for the same plaintext (fresh salt+IV)', async () => {
      const data = utf8Encode('same plaintext, twice');
      const a = await cm.encryptBytes(data, PASSWORD);
      const b = await cm.encryptBytes(data, PASSWORD);
      expect(bytesEqual(a, b)).toBe(false);
    });

    it('does NOT mutate the caller-supplied plaintext buffer', async () => {
      const data = fillerBytes(64);
      const snapshot = Uint8Array.from(data);
      await cm.encryptBytes(data, PASSWORD);
      expect(bytesEqual(data, snapshot)).toBe(true);
    });
  });

  describe('v1 header shape', () => {
    it('emits the HPCR magic and inspectHeader agrees on the embedded params', async () => {
      const ciphertext = await cm.encryptBytes(fillerBytes(48), PASSWORD);

      // First four bytes spell the v1 magic "HPCR".
      expect(Buffer.from(ciphertext.subarray(0, 4)).toString('ascii')).toBe(
        'HPCR'
      );

      // inspectHeader accepts the raw Uint8Array (isomorphic guard) and reports
      // the exact Argon2id parameters this instance encrypts with.
      const header = cm.inspectHeader(ciphertext);
      expect(header).not.toBeNull();
      expect(header?.version).toBe(FORMAT_VERSION);
      expect(header?.kdfId).toBe(KDF_ID_ARGON2ID);
      expect(header?.params.kind).toBe('argon2id');
      if (header?.params.kind === 'argon2id') {
        expect(header.params.memoryCost).toBe(LOW_COST.memoryCost);
        expect(header.params.timeCost).toBe(LOW_COST.timeCost);
        expect(header.params.parallelism).toBe(LOW_COST.parallelism);
      }
    });

    it('has the exact TEXT wire layout length [hdr][salt][iv][tag][ct]', async () => {
      const plaintextLen = 100;
      const ciphertext = await cm.encryptBytes(
        fillerBytes(plaintextLen),
        PASSWORD
      );
      expect(ciphertext.length).toBe(
        HEADER_LENGTH + SALT_LENGTH + IV_LENGTH + TAG_LENGTH + plaintextLen
      );
    });
  });

  describe('negative paths', () => {
    it('rejects a wrong password with CryptoError', async () => {
      const ciphertext = await cm.encryptBytes(fillerBytes(80), PASSWORD);
      await expect(cm.decryptBytes(ciphertext, WRONG_PASSWORD)).rejects.toThrow(
        CryptoError
      );
    });

    it('rejects non-Uint8Array plaintext with INVALID_DATA', async () => {
      await expect(
        cm.encryptBytes('not bytes' as unknown as Uint8Array, PASSWORD)
      ).rejects.toThrow(CryptoError);
      try {
        await cm.encryptBytes('not bytes' as unknown as Uint8Array, PASSWORD);
      } catch (err) {
        expect((err as CryptoError).code).toBe('INVALID_DATA');
      }
    });

    it('rejects non-Uint8Array ciphertext with INVALID_ENCRYPTED_DATA', async () => {
      try {
        await cm.decryptBytes('not bytes' as unknown as Uint8Array, PASSWORD);
        throw new Error('expected decryptBytes to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_ENCRYPTED_DATA');
      }
    });

    it('rejects a weak password on encrypt with WEAK_PASSWORD', async () => {
      try {
        await cm.encryptBytes(fillerBytes(8), 'weak');
        throw new Error('expected encryptBytes to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('WEAK_PASSWORD');
      }
    });

    // A single-bit flip anywhere in the wire format must break decryption:
    // salt/iv changes flip the derived key or GCM nonce, header changes flip
    // the AAD-bound tag (including the reserved bytes), and tag/ciphertext
    // changes fail GCM authentication. Every case surfaces as a CryptoError.
    const segments: Array<{ name: string; offset: number }> = [
      { name: 'header (reserved byte, AAD-bound)', offset: HEADER_LENGTH - 2 },
      { name: 'salt', offset: SALT_OFFSET },
      { name: 'iv', offset: IV_OFFSET },
      { name: 'tag', offset: TAG_OFFSET },
      { name: 'ciphertext', offset: CT_OFFSET },
    ];

    it.each(segments)(
      'rejects a single-bit tamper in the $name segment',
      async ({ offset }) => {
        const ciphertext = await cm.encryptBytes(fillerBytes(64), PASSWORD);
        const tampered = Uint8Array.from(ciphertext);
        // Flipping the low bit guarantees the byte value changes.
        tampered[offset] ^= 0x01;
        await expect(cm.decryptBytes(tampered, PASSWORD)).rejects.toThrow(
          CryptoError
        );
      }
    );
  });

  describe('one wire format — bytes API and text API interoperate', () => {
    it('decryptText decodes the base64url of encryptBytes output', async () => {
      const text = 'shared wire format proof';
      const ciphertextBytes = await cm.encryptBytes(utf8Encode(text), PASSWORD);
      const asText = bytesToBase64url(ciphertextBytes);
      expect(await cm.decryptText(asText, PASSWORD)).toBe(text);
    });

    it('decryptBytes decodes the base64url ciphertext of encryptText output', async () => {
      const text = 'shared wire format proof (reverse)';
      const encryptedText = await cm.encryptText(text, PASSWORD);
      const back = await cm.decryptBytes(
        base64urlToBytes(encryptedText),
        PASSWORD
      );
      expect(bytesEqual(back, utf8Encode(text))).toBe(true);
      expect(Buffer.from(back).toString('utf8')).toBe(text);
    });
  });

  // ---------------------------------------------------------------------------
  // Phase 4 — encryptText/decryptText re-expressed as base64url⇄bytes wrappers
  // over encryptBytes/decryptBytes. The single-input interop checks above are
  // widened here into a matrix (empty string, block-boundary, multi-byte UTF-8,
  // long buffer) in BOTH directions so the text API and the bytes API can never
  // drift, plus the text-specific input rules now owned by the isomorphic core
  // (INVALID_TEXT, INVALID_ENCRYPTED_TEXT, empty-string acceptance).
  // ---------------------------------------------------------------------------
  describe('text API re-expressed on the bytes API (Phase 4)', () => {
    // '' is a first-class plaintext; the rest cover ascii, a length straddling
    // the AES block boundary, multi-byte UTF-8, and a long buffer.
    const texts = [
      '',
      'a',
      'exactly-sixteen!',
      'café — 世界 — 🔐 — Ω≈ç√∫ — Здравствуй',
      'x'.repeat(5000),
    ];

    it.each(texts)(
      'decryptText(bytesToBase64url(encryptBytes(utf8(t)))) === t  [case %#]',
      async text => {
        const ciphertextBytes = await cm.encryptBytes(
          utf8Encode(text),
          PASSWORD
        );
        const asText = bytesToBase64url(ciphertextBytes);
        expect(await cm.decryptText(asText, PASSWORD)).toBe(text);
      }
    );

    it.each(texts)(
      'decryptBytes(base64urlToBytes(encryptText(t))) === utf8(t)  [case %#]',
      async text => {
        const encryptedText = await cm.encryptText(text, PASSWORD);
        const back = await cm.decryptBytes(
          base64urlToBytes(encryptedText),
          PASSWORD
        );
        expect(bytesEqual(back, utf8Encode(text))).toBe(true);
      }
    );

    it.each(texts)(
      'encryptText → decryptText round-trips t  [case %#]',
      async text => {
        const enc = await cm.encryptText(text, PASSWORD);
        expect(await cm.decryptText(enc, PASSWORD)).toBe(text);
      }
    );

    it('encryptText accepts the empty string and emits a v1 (HPCR) ciphertext', async () => {
      const enc = await cm.encryptText('', PASSWORD);
      expect(cm.inspectHeader(enc)).not.toBeNull();
      expect(await cm.decryptText(enc, PASSWORD)).toBe('');
    });

    it.each([null, undefined, 123, {}])(
      'encryptText rejects non-string (%p) with INVALID_TEXT',
      async bad => {
        try {
          await cm.encryptText(bad as unknown as string, PASSWORD);
          throw new Error('expected encryptText to throw');
        } catch (err) {
          expect(err).toBeInstanceOf(CryptoError);
          expect((err as CryptoError).code).toBe('INVALID_TEXT');
        }
      }
    );

    it('decryptText rejects the empty string with INVALID_ENCRYPTED_TEXT', async () => {
      try {
        await cm.decryptText('', PASSWORD);
        throw new Error('expected decryptText to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_ENCRYPTED_TEXT');
      }
    });
  });

  describe('default passphrase', () => {
    it('uses the configured defaultPassphrase when no password is passed', async () => {
      const withDefault = new CryptoManager({
        ...LOW_COST,
        defaultPassphrase: PASSWORD,
      });
      const data = fillerBytes(40);
      const ciphertext = await withDefault.encryptBytes(data);
      const back = await withDefault.decryptBytes(ciphertext);
      expect(bytesEqual(back, data)).toBe(true);
    });

    it('requires a password when none is available', async () => {
      try {
        await cm.encryptBytes(fillerBytes(8));
        throw new Error('expected encryptBytes to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(CryptoError);
        expect((err as CryptoError).code).toBe('INVALID_PASSWORD');
      }
    });
  });
});
