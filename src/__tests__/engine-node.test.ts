/**
 * Unit tests for the Node {@link CryptoEngine} implementation
 * (`src/engine.node.ts`, Phase 2).
 *
 * These tests exercise `nodeEngine` directly — the small runtime seam that the
 * shared isomorphic core will call in later phases. They verify the four
 * observable contracts of the engine:
 *
 *   1. `deriveArgon2id` reproduces the pinned RFC 9106 Argon2id known-answer
 *      vector (the same KAT the cross-provider parity test pins), proving the
 *      engine's parameter mapping and output handling are correct.
 *   2. `aeadEncrypt` → `aeadDecrypt` round-trips, and the 16-byte GCM tag is
 *      returned SEPARATELY from the ciphertext (engine contract).
 *   3. AAD tampering and a corrupted tag both surface as
 *      `CryptoError(DECRYPTION_FAILED)` — no decryption oracle.
 *   4. `sha256` matches the canonical NIST FIPS 180-4 vectors.
 *
 * Availability gating (Core Principle 4): `argon2` is a native optional
 * dependency and `hash-wasm` is its pure-WASM fallback. On a host where BOTH
 * are genuinely unavailable, the library's documented behaviour is a graceful
 * `ARGON2_NOT_AVAILABLE` throw — so the Argon2id KAT uses the "probe IS the
 * call" pattern and SKIPs (logged) rather than failing when neither provider
 * can load. The KAT value is bit-identical across both providers (RFC 9106),
 * so any successful derivation must equal it regardless of which one ran.
 *
 * This file registers NO module mocks, so it does not perturb (and is not
 * perturbed by) the `jest.unstable_mockModule` registrations in the argon2
 * lazy-load suite.
 */
import { describe, it, expect } from '@jest/globals';
import { nodeEngine } from '../engine.node';
import { CryptoError, CryptoErrorType } from '../types';
import { bytesToHex, utf8Encode } from '../codec';

// ----------------------------------------------------------------------------
// Argon2id known-answer vector (identical to argon2-provider-parity.test.ts).
// Computed live at implementation time from the REAL installed providers —
// argon2 (native) AND hash-wasm (pure WASM) — which produced the same 32-byte
// output. Never authored from memory.
//
//   password    = 'parity-vector-password'  (ASCII; NFC is a no-op)
//   salt        = 32 bytes, values 0x00..0x1f
//   memoryCost  = 4096 KiB (4 MiB)
//   timeCost    = 2
//   parallelism = 1
//   hashLength  = 32
// ----------------------------------------------------------------------------
const KAT_HEX =
  '79fce5dc8932db4e5d85f8d32c1d8f2206188c3c1bcbe5ef555bab13c595567b';
const KAT_PASSWORD = 'parity-vector-password';
const KAT_SALT = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));

describe('nodeEngine.deriveArgon2id', () => {
  it('reproduces the pinned RFC 9106 Argon2id KAT vector', async () => {
    // Probe IS the call: run the real derivation. On a host where neither
    // provider can load, this throws ARGON2_NOT_AVAILABLE — the documented
    // graceful-fallback state — and we skip rather than fail.
    let derivedHex: string;
    try {
      const key = await nodeEngine.deriveArgon2id(KAT_PASSWORD, KAT_SALT, {
        memoryCost: 4096,
        timeCost: 2,
        parallelism: 1,
        hashLength: 32,
      });
      // The engine returns exactly `hashLength` bytes; both providers agree.
      expect(key.length).toBe(32);
      derivedHex = bytesToHex(key);
    } catch (err) {
      if (
        err instanceof CryptoError &&
        (err as InstanceType<typeof CryptoError>).code ===
          'ARGON2_NOT_AVAILABLE'
      ) {
        // eslint-disable-next-line no-console
        console.warn(
          `[skip] Argon2id unavailable, skipping engine KAT: ${String(err)}`
        );
        return;
      }
      throw err;
    }

    // Any successful derivation — native or WASM — must equal the pinned KAT.
    expect(derivedHex).toBe(KAT_HEX);
  });
});

describe('nodeEngine.aeadEncrypt / aeadDecrypt (AES-256-GCM)', () => {
  const KEY = nodeEngine.randomBytes(32);
  const IV = nodeEngine.randomBytes(12);
  const AAD = utf8Encode('engine-node-aad-context');

  it('round-trips plaintext of various sizes and keeps the tag separate', async () => {
    for (const size of [0, 1, 15, 16, 17, 100, 1024]) {
      const plaintext = nodeEngine
        .randomBytes(Math.max(size, 1))
        .subarray(0, size);

      const { ciphertext, tag } = await nodeEngine.aeadEncrypt(
        KEY,
        IV,
        plaintext,
        AAD
      );

      // GCM is a stream cipher: ciphertext length == plaintext length, and the
      // 16-byte tag is returned SEPARATELY (not appended to the ciphertext).
      expect(ciphertext.length).toBe(size);
      expect(tag.length).toBe(16);

      const recovered = await nodeEngine.aeadDecrypt(
        KEY,
        IV,
        ciphertext,
        tag,
        AAD
      );
      expect(recovered.length).toBe(size);
      expect(Buffer.from(recovered).equals(Buffer.from(plaintext))).toBe(true);
    }
  });

  it('rejects with DECRYPTION_FAILED when the AAD does not match', async () => {
    const plaintext = utf8Encode('bind me to my context');
    const { ciphertext, tag } = await nodeEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const wrongAad = utf8Encode('a-different-aad-context');
    await expect(
      nodeEngine.aeadDecrypt(KEY, IV, ciphertext, tag, wrongAad)
    ).rejects.toThrow(CryptoError);

    try {
      await nodeEngine.aeadDecrypt(KEY, IV, ciphertext, tag, wrongAad);
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
    const { ciphertext, tag } = await nodeEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const badTag = Uint8Array.from(tag);
    badTag[0] ^= 0x01; // flip a single bit

    await expect(
      nodeEngine.aeadDecrypt(KEY, IV, ciphertext, badTag, AAD)
    ).rejects.toThrow(CryptoError);

    try {
      await nodeEngine.aeadDecrypt(KEY, IV, ciphertext, badTag, AAD);
      throw new Error('Expected aeadDecrypt to throw on tag corruption');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      expect((err as InstanceType<typeof CryptoError>).code).toBe(
        'DECRYPTION_FAILED'
      );
    }
  });

  it('rejects with DECRYPTION_FAILED when the ciphertext is tampered', async () => {
    const plaintext = utf8Encode('do not touch my bytes');
    const { ciphertext, tag } = await nodeEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const badCt = Uint8Array.from(ciphertext);
    badCt[0] ^= 0x80;

    await expect(
      nodeEngine.aeadDecrypt(KEY, IV, badCt, tag, AAD)
    ).rejects.toThrow(CryptoError);
  });

  it('rejects with DECRYPTION_FAILED under a different key', async () => {
    const plaintext = utf8Encode('wrong key, wrong result');
    const { ciphertext, tag } = await nodeEngine.aeadEncrypt(
      KEY,
      IV,
      plaintext,
      AAD
    );

    const otherKey = nodeEngine.randomBytes(32);
    await expect(
      nodeEngine.aeadDecrypt(otherKey, IV, ciphertext, tag, AAD)
    ).rejects.toThrow(CryptoError);
  });
});

describe('nodeEngine.randomBytes', () => {
  it('returns the requested number of bytes as a Uint8Array', () => {
    const bytes = nodeEngine.randomBytes(48);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(48);
  });

  it('produces distinct output across calls (overwhelmingly likely)', () => {
    const a = nodeEngine.randomBytes(32);
    const b = nodeEngine.randomBytes(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe('nodeEngine.sha256', () => {
  it('matches the NIST FIPS 180-4 vector for "abc"', async () => {
    const digest = await nodeEngine.sha256(utf8Encode('abc'));
    expect(digest.length).toBe(32);
    expect(bytesToHex(digest)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('matches the SHA-256 vector for the empty input', async () => {
    const digest = await nodeEngine.sha256(new Uint8Array(0));
    expect(bytesToHex(digest)).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });
});
