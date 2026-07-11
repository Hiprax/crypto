/**
 * Unit tests for the Web {@link CryptoEngine} implementation
 * (`src/engine.web.ts`, Phase 5), run under Node 22+.
 *
 * The Web engine is written for the browser (SubtleCrypto + hash-wasm, ZERO
 * `node:` imports), but Node 22+ also exposes `globalThis.crypto` and can load
 * the same pure-WASM `hash-wasm`, so the engine is fully exercisable here
 * WITHOUT a real browser. The real-browser suite (Phase 9) imports the built
 * browser entry and re-runs the interop fixtures.
 *
 * These tests verify the engine's observable contracts AND — the crown jewel —
 * that it is byte-for-byte interoperable with the Node engine, which is what
 * makes ONE wire format round-trip across Node and the browser:
 *
 *   1. `deriveArgon2id` reproduces the pinned RFC 9106 Argon2id KAT (the same
 *      vector the Node engine and the cross-provider parity test pin), and
 *      AGREES byte-for-byte with `nodeEngine.deriveArgon2id` — including when
 *      the salt is a subarray VIEW (as the core passes on decrypt).
 *   2. `aeadEncrypt` → `aeadDecrypt` round-trips, the 16-byte tag is returned
 *      SEPARATELY, and AAD/tag/ciphertext/key tampering all surface as a
 *      generic `DECRYPTION_FAILED` (no oracle).
 *   3. CROSS-ENGINE AEAD interop: `nodeEngine` and `webEngine` produce
 *      byte-identical ciphertext+tag for the same inputs, and each engine
 *      decrypts the other's output in both directions.
 *   4. `sha256` matches the NIST FIPS 180-4 vectors and equals `nodeEngine`.
 *   5. `randomBytes` returns the requested length (incl. requests larger than
 *      Web Crypto's 65536-byte per-call cap, via chunking).
 *
 * Availability gating (Core Principle 4): `hash-wasm` is an optional dependency.
 * On a host where it genuinely cannot load, `deriveArgon2id` throws
 * `ARGON2_NOT_AVAILABLE` — the documented graceful state — so the Argon2id
 * tests use the "probe IS the call" pattern and SKIP (logged) rather than fail.
 * The `subtle` AES-GCM / SHA-256 / CSPRNG paths need no gating (Node 22+ always
 * has `globalThis.crypto`). This file registers NO module mocks (real
 * providers); the `ARGON2_NOT_AVAILABLE` failure path is covered separately in
 * `engine-web-unavailable.test.ts`.
 */
import { describe, it, expect } from '@jest/globals';
import { webEngine } from '../engine.web';
import { nodeEngine } from '../engine.node';
import { CryptoError, CryptoErrorType } from '../types';
import { bytesToHex, utf8Encode } from '../codec';

// ----------------------------------------------------------------------------
// Argon2id known-answer vector — identical to engine-node.test.ts and
// argon2-provider-parity.test.ts. Computed live at implementation time from the
// REAL installed providers; never authored from memory.
//
//   password    = 'parity-vector-password'  (ASCII; NFC is a no-op)
//   salt        = 32 bytes, values 0x00..0x1f
//   memoryCost  = 4096 KiB (4 MiB), timeCost = 2, parallelism = 1, len = 32
// ----------------------------------------------------------------------------
const KAT_HEX =
  '79fce5dc8932db4e5d85f8d32c1d8f2206188c3c1bcbe5ef555bab13c595567b';
const KAT_PASSWORD = 'parity-vector-password';
const KAT_SALT = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
const KAT_PARAMS = {
  memoryCost: 4096,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
} as const;

/** True when an error is the documented "Argon2id unavailable" graceful state. */
function isArgon2Unavailable(err: unknown): boolean {
  return (
    err instanceof CryptoError &&
    (err as InstanceType<typeof CryptoError>).code === 'ARGON2_NOT_AVAILABLE'
  );
}

describe('webEngine.deriveArgon2id (real hash-wasm)', () => {
  it('reproduces the pinned RFC 9106 Argon2id KAT vector', async () => {
    // Probe IS the call: run the real derivation. If hash-wasm cannot load,
    // this throws ARGON2_NOT_AVAILABLE and we skip rather than fail.
    let derivedHex: string;
    try {
      const key = await webEngine.deriveArgon2id(
        KAT_PASSWORD,
        KAT_SALT,
        KAT_PARAMS
      );
      expect(key.length).toBe(32);
      derivedHex = bytesToHex(key);
    } catch (err) {
      if (isArgon2Unavailable(err)) {
        // eslint-disable-next-line no-console
        console.warn(
          `[skip] Argon2id unavailable, skipping web engine KAT: ${String(err)}`
        );
        return;
      }
      throw err;
    }
    expect(derivedHex).toBe(KAT_HEX);
  });

  it('agrees byte-for-byte with nodeEngine.deriveArgon2id (cross-engine KDF parity)', async () => {
    // Both engines implement RFC 9106 Argon2id (web via hash-wasm; node via
    // native argon2 OR hash-wasm) and MUST produce bit-identical output — this
    // is exactly what lets a ciphertext derived under one engine decrypt under
    // the other.
    let nodeHex: string;
    let webHex: string;
    try {
      const [nodeKey, webKey] = await Promise.all([
        nodeEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, KAT_PARAMS),
        webEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, KAT_PARAMS),
      ]);
      nodeHex = bytesToHex(nodeKey);
      webHex = bytesToHex(webKey);
    } catch (err) {
      if (isArgon2Unavailable(err)) {
        // eslint-disable-next-line no-console
        console.warn(
          `[skip] Argon2id unavailable, skipping cross-engine KDF parity: ${String(err)}`
        );
        return;
      }
      throw err;
    }
    expect(webHex).toBe(KAT_HEX);
    expect(nodeHex).toBe(KAT_HEX);
    expect(webHex).toBe(nodeHex);
  });

  it('derives with a subarray-view salt identically to a compacted salt', async () => {
    // The core passes the salt on decrypt as a subarray VIEW over the combined
    // ciphertext (non-zero byteOffset). hash-wasm must read the viewed region,
    // not the buffer start, or cross-engine decrypt would derive a wrong key.
    let viewHex: string;
    let copyHex: string;
    try {
      const backing = new Uint8Array(64);
      backing.set(KAT_SALT, 22); // 0x00..0x1f living at byteOffset 22
      const viewSalt = backing.subarray(22, 54);
      expect(viewSalt.byteOffset).toBe(22);
      const [viewKey, copyKey] = await Promise.all([
        webEngine.deriveArgon2id(KAT_PASSWORD, viewSalt, KAT_PARAMS),
        webEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, KAT_PARAMS),
      ]);
      viewHex = bytesToHex(viewKey);
      copyHex = bytesToHex(copyKey);
    } catch (err) {
      if (isArgon2Unavailable(err)) {
        // eslint-disable-next-line no-console
        console.warn(
          `[skip] Argon2id unavailable, skipping view-salt parity: ${String(err)}`
        );
        return;
      }
      throw err;
    }
    expect(viewHex).toBe(copyHex);
    expect(viewHex).toBe(KAT_HEX);
  });
});

describe('webEngine.aeadEncrypt / aeadDecrypt (AES-256-GCM)', () => {
  const KEY = webEngine.randomBytes(32);
  const IV = webEngine.randomBytes(12);
  const AAD = utf8Encode('engine-web-aad-context');

  it('round-trips plaintext of various sizes and keeps the tag separate', async () => {
    for (const size of [0, 1, 15, 16, 17, 100, 1024]) {
      const plaintext = webEngine
        .randomBytes(Math.max(size, 1))
        .subarray(0, size);

      const { ciphertext, tag } = await webEngine.aeadEncrypt(
        KEY,
        IV,
        plaintext,
        AAD
      );

      // GCM is a stream cipher: ciphertext length == plaintext length, and the
      // 16-byte tag is returned SEPARATELY (Web Crypto's appended tag is split
      // off inside the engine).
      expect(ciphertext.length).toBe(size);
      expect(tag.length).toBe(16);

      const recovered = await webEngine.aeadDecrypt(
        KEY,
        IV,
        ciphertext,
        tag,
        AAD
      );
      expect(recovered.length).toBe(size);
      expect(bytesToHex(recovered)).toBe(bytesToHex(plaintext));
    }
  });

  it('does not mutate the caller-provided key buffer (drop-in parity with nodeEngine)', async () => {
    // The engine scrubs only its OWN transient key copy after importKey; the
    // caller's buffer is untouched (the core owns and scrubs it), so a single
    // key buffer can be reused across encrypt + decrypt exactly like nodeEngine.
    const key = webEngine.randomBytes(32);
    const keySnapshot = bytesToHex(key);
    const iv = webEngine.randomBytes(12);
    const aad = utf8Encode('key-not-mutated');
    const plaintext = utf8Encode('reuse the same key buffer across calls');

    const { ciphertext, tag } = await webEngine.aeadEncrypt(
      key,
      iv,
      plaintext,
      aad
    );
    expect(bytesToHex(key)).toBe(keySnapshot);

    const recovered = await webEngine.aeadDecrypt(
      key,
      iv,
      ciphertext,
      tag,
      aad
    );
    expect(bytesToHex(key)).toBe(keySnapshot);
    expect(bytesToHex(recovered)).toBe(bytesToHex(plaintext));
  });

  it('rejects with DECRYPTION_FAILED when the AAD does not match', async () => {
    const plaintext = utf8Encode('bind me to my context');
    const { ciphertext, tag } = await webEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const wrongAad = utf8Encode('a-different-aad-context');
    await expect(
      webEngine.aeadDecrypt(KEY, IV, ciphertext, tag, wrongAad)
    ).rejects.toThrow(CryptoError);

    try {
      await webEngine.aeadDecrypt(KEY, IV, ciphertext, tag, wrongAad);
      throw new Error('Expected aeadDecrypt to throw on AAD mismatch');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
      expect(e.code).toBe('DECRYPTION_FAILED');
    }
  });

  it('rejects with DECRYPTION_FAILED when the tag is corrupted', async () => {
    const plaintext = utf8Encode('integrity matters');
    const { ciphertext, tag } = await webEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const badTag = Uint8Array.from(tag);
    badTag[0] ^= 0x01; // flip a single bit

    await expect(
      webEngine.aeadDecrypt(KEY, IV, ciphertext, badTag, AAD)
    ).rejects.toThrow(CryptoError);

    try {
      await webEngine.aeadDecrypt(KEY, IV, ciphertext, badTag, AAD);
      throw new Error('Expected aeadDecrypt to throw on tag corruption');
    } catch (err) {
      expect((err as InstanceType<typeof CryptoError>).code).toBe(
        'DECRYPTION_FAILED'
      );
    }
  });

  it('rejects with DECRYPTION_FAILED when the ciphertext is tampered', async () => {
    const plaintext = utf8Encode('do not touch my bytes');
    const { ciphertext, tag } = await webEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const badCt = Uint8Array.from(ciphertext);
    badCt[0] ^= 0x80;

    await expect(
      webEngine.aeadDecrypt(KEY, IV, badCt, tag, AAD)
    ).rejects.toThrow(CryptoError);
  });

  it('rejects with DECRYPTION_FAILED under a different key', async () => {
    const plaintext = utf8Encode('wrong key, wrong result');
    const { ciphertext, tag } = await webEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const otherKey = webEngine.randomBytes(32);
    await expect(
      webEngine.aeadDecrypt(otherKey, IV, ciphertext, tag, AAD)
    ).rejects.toThrow(CryptoError);
  });
});

describe('cross-engine AES-256-GCM interop (node <-> web)', () => {
  it('byte-identical ciphertext+tag and both-direction round-trip across sizes', async () => {
    // For the SAME (key, iv, aad, plaintext), the two engines must produce the
    // exact same ciphertext AND the exact same tag, and each must decrypt the
    // other's output. A fresh key+iv per size avoids modelling nonce reuse.
    for (const size of [0, 1, 15, 16, 17, 100, 1024, 4096]) {
      const key = webEngine.randomBytes(32);
      const iv = webEngine.randomBytes(12);
      const aad = utf8Encode(`cross-engine-ctx-${size}`);
      const plaintext = webEngine
        .randomBytes(Math.max(size, 1))
        .subarray(0, size);

      const nodeOut = await nodeEngine.aeadEncrypt(key, iv, plaintext, aad);
      const webOut = await webEngine.aeadEncrypt(key, iv, plaintext, aad);

      // Byte-identical output — the heart of the one-wire-format guarantee.
      expect(bytesToHex(webOut.ciphertext)).toBe(
        bytesToHex(nodeOut.ciphertext)
      );
      expect(bytesToHex(webOut.tag)).toBe(bytesToHex(nodeOut.tag));
      expect(webOut.ciphertext.length).toBe(size);
      expect(webOut.tag.length).toBe(16);

      // node encrypt -> web decrypt, and web encrypt -> node decrypt.
      const webFromNode = await webEngine.aeadDecrypt(
        key,
        iv,
        nodeOut.ciphertext,
        nodeOut.tag,
        aad
      );
      const nodeFromWeb = await nodeEngine.aeadDecrypt(
        key,
        iv,
        webOut.ciphertext,
        webOut.tag,
        aad
      );
      expect(bytesToHex(webFromNode)).toBe(bytesToHex(plaintext));
      expect(bytesToHex(nodeFromWeb)).toBe(bytesToHex(plaintext));
    }
  });

  it('web-decrypting a node ciphertext under the wrong AAD fails (and vice-versa)', async () => {
    const key = webEngine.randomBytes(32);
    const iv = webEngine.randomBytes(12);
    const plaintext = utf8Encode('cross-engine AAD binding');
    const aad = utf8Encode('right-context');
    const wrongAad = utf8Encode('wrong-context');

    const nodeOut = await nodeEngine.aeadEncrypt(key, iv, plaintext, aad);
    await expect(
      webEngine.aeadDecrypt(key, iv, nodeOut.ciphertext, nodeOut.tag, wrongAad)
    ).rejects.toThrow(CryptoError);

    const webOut = await webEngine.aeadEncrypt(key, iv, plaintext, aad);
    await expect(
      nodeEngine.aeadDecrypt(key, iv, webOut.ciphertext, webOut.tag, wrongAad)
    ).rejects.toThrow(CryptoError);
  });
});

describe('webEngine.randomBytes', () => {
  it('returns the requested number of bytes as a Uint8Array', () => {
    const bytes = webEngine.randomBytes(48);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(48);
  });

  it('returns an empty array for length 0', () => {
    const bytes = webEngine.randomBytes(0);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(0);
  });

  it('produces distinct output across calls (overwhelmingly likely)', () => {
    const a = webEngine.randomBytes(32);
    const b = webEngine.randomBytes(32);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it('fills requests larger than the 65536-byte Web Crypto per-call cap (chunked)', () => {
    const length = 70000; // > 65536, spans two getRandomValues chunks
    const bytes = webEngine.randomBytes(length);
    expect(bytes.length).toBe(length);
    // The bytes past the 65536 boundary must actually be filled (not left as
    // zeros): with overwhelming probability at least one is non-zero.
    const tail = bytes.subarray(65536);
    expect(tail.length).toBe(length - 65536);
    expect(tail.some(byte => byte !== 0)).toBe(true);
  });
});

describe('webEngine.sha256', () => {
  it('matches the NIST FIPS 180-4 vector for "abc" and equals nodeEngine', async () => {
    const digest = await webEngine.sha256(utf8Encode('abc'));
    expect(digest.length).toBe(32);
    expect(bytesToHex(digest)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    const nodeDigest = await nodeEngine.sha256(utf8Encode('abc'));
    expect(bytesToHex(digest)).toBe(bytesToHex(nodeDigest));
  });

  it('matches the SHA-256 vector for the empty input', async () => {
    const digest = await webEngine.sha256(new Uint8Array(0));
    expect(bytesToHex(digest)).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });
});
