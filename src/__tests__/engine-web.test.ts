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
import { describe, it, expect, afterEach, jest } from '@jest/globals';
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

/**
 * Handle an Argon2id-unavailable error at a test's catch site. Any OTHER error
 * propagates. In CI the optional `hash-wasm` dependency MUST be installed — the
 * cross-engine parity in this file is the primitive-level crown jewel of the
 * isomorphic release and may never be silently skipped — so we hard-fail;
 * on a genuinely-unsupported local dev host we log a graceful skip and the
 * caller `return`s. Mirrors the CI guard in interop/property-bytes/container.
 */
function skipOrThrowArgon2Unavailable(err: unknown, context: string): void {
  if (!isArgon2Unavailable(err)) throw err;
  if (process.env.CI) {
    throw new Error(
      `hash-wasm Argon2id failed to load in CI; ${context} cannot be silently ` +
        `skipped. Ensure the optional hash-wasm dependency is installed.`,
      { cause: err }
    );
  }
  // eslint-disable-next-line no-console
  console.warn(
    `[skip] hash-wasm Argon2id unavailable; ${context} skipped: ${String(err)}`
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
      skipOrThrowArgon2Unavailable(err, 'web engine KAT');
      return;
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
      skipOrThrowArgon2Unavailable(err, 'cross-engine KDF parity');
      return;
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
      skipOrThrowArgon2Unavailable(err, 'view-salt parity');
      return;
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

/**
 * Phase 7 — the Web Crypto per-call entropy cap, pinned deterministically.
 *
 * `getRandomValues` rejects a single request larger than 65 536 bytes with a
 * `QuotaExceededError`, while Node's `crypto.randomBytes` has no such limit.
 * `webRandomBytes` hides that difference by filling the output in <= 65 536-byte
 * chunks, and the two engines are only drop-in interchangeable while it does.
 *
 * Two complementary checks, because neither alone is enough:
 *
 *   - A SPY-based test that replaces `getRandomValues` with a marker filler.
 *     Each call stamps the region it was handed with its own call index, so the
 *     resulting array *encodes* the split and the assertions are exact and
 *     fully deterministic — no probability anywhere. This is what pins the
 *     boundary arithmetic at 0 / 65 536 / 65 537 / 200 000.
 *   - A REAL, unmocked test that the delivered bytes are genuine entropy, so a
 *     regression that "chunks" correctly while leaving the tail zeroed is
 *     caught too. Its probabilistic assertions are scoped to FULL 4096-byte
 *     windows (an all-zero window has probability 2^-32768), never to a single
 *     byte, so it cannot flake.
 */
describe('webEngine.randomBytes chunking at the Web Crypto per-call cap', () => {
  /** Web Crypto's documented per-call quota; the engine must never exceed it. */
  const CAP = 65536;

  afterEach(() => {
    jest.restoreAllMocks();
  });

  /**
   * Replace `getRandomValues` with a deterministic marker filler: the Nth call
   * fills the view it is given with the byte value N. The returned `chunks`
   * array records the exact (offset, length) of every call.
   */
  function spyOnGetRandomValues(): Array<{ offset: number; length: number }> {
    const chunks: Array<{ offset: number; length: number }> = [];
    jest
      .spyOn(globalThis.crypto, 'getRandomValues')
      .mockImplementation(<T extends ArrayBufferView | null>(view: T): T => {
        if (view !== null && ArrayBuffer.isView(view)) {
          chunks.push({ offset: view.byteOffset, length: view.byteLength });
          const bytes = new Uint8Array(
            view.buffer,
            view.byteOffset,
            view.byteLength
          );
          bytes.fill(chunks.length & 0xff);
        }
        return view;
      });
    return chunks;
  }

  it('makes NO entropy call at all for length 0 and returns an empty array', () => {
    const chunks = spyOnGetRandomValues();
    const bytes = webEngine.randomBytes(0);

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(0);
    // NEGATIVE: a `<=` loop bound would ask Web Crypto for a zero-length view;
    // harmless in Node, but it is not the contract and it is free to assert.
    expect(chunks).toEqual([]);
  });

  it('fills exactly ONE chunk for a request of exactly 65536 bytes', () => {
    const chunks = spyOnGetRandomValues();
    const bytes = webEngine.randomBytes(CAP);

    expect(bytes.length).toBe(CAP);
    // Boundary n: still a single call — an off-by-one that splits here would
    // work, but it would also mean the loop bound is wrong in the other
    // direction, so pin it.
    expect(chunks).toEqual([{ offset: 0, length: CAP }]);
    // Every byte carries call #1's marker: the whole buffer really was filled.
    expect(bytes[0]).toBe(1);
    expect(bytes[CAP - 1]).toBe(1);
    expect(bytes.every(byte => byte === 1)).toBe(true);
  });

  it('splits a 65537-byte request into 65536 + 1, with the last byte from the SECOND call', () => {
    const chunks = spyOnGetRandomValues();
    const bytes = webEngine.randomBytes(CAP + 1);

    expect(bytes.length).toBe(CAP + 1);
    // Boundary n+1: the single byte past the cap must come from its own call,
    // because one call for 65537 bytes would throw QuotaExceededError.
    expect(chunks).toEqual([
      { offset: 0, length: CAP },
      { offset: CAP, length: 1 },
    ]);
    expect(bytes[CAP - 1]).toBe(1);
    expect(bytes[CAP]).toBe(2);
    // NEGATIVE: the tail byte must NOT be left at its zero-initialised value,
    // which is exactly what a `length` (rather than `end`) slice bug produces.
    expect(bytes[CAP]).not.toBe(0);
  });

  it('splits a 200000-byte request into three full chunks plus a remainder', () => {
    const chunks = spyOnGetRandomValues();
    const length = 200000;
    const bytes = webEngine.randomBytes(length);

    expect(bytes.length).toBe(length);
    expect(chunks).toEqual([
      { offset: 0, length: CAP },
      { offset: CAP, length: CAP },
      { offset: 2 * CAP, length: CAP },
      { offset: 3 * CAP, length: length - 3 * CAP },
    ]);
    // NEGATIVE: no single request may exceed the Web Crypto quota.
    expect(chunks.every(chunk => chunk.length <= CAP)).toBe(true);
    // Each region carries its own call's marker, so no region was filled twice
    // and none was skipped.
    expect(bytes[0]).toBe(1);
    expect(bytes[CAP]).toBe(2);
    expect(bytes[2 * CAP]).toBe(3);
    expect(bytes[3 * CAP]).toBe(4);
    expect(bytes[length - 1]).toBe(4);
  });

  it('delivers real entropy across the chunk boundary (unmocked)', () => {
    // The marker tests above prove the SPLIT; this proves the BYTES. Assertions
    // are over full 4096-byte windows, never a single byte, so they are
    // deterministic in practice (p(all-zero window) = 2^-32768).
    for (const length of [CAP, CAP + 1, 200000]) {
      const bytes = webEngine.randomBytes(length);
      expect(bytes.length).toBe(length);

      // Only FULL windows are scanned, so the trailing partial chunk (1 byte at
      // 65537, 3392 bytes at 200000) is not entropy-checked here. That tail is
      // covered by the marker tests above, which assert `bytes[CAP]` and
      // `bytes[length - 1]` carry the LAST call's marker and therefore that the
      // final view really aliases `out`. Do not delete those on the assumption
      // that this loop subsumes them.
      const windowSize = 4096;
      for (
        let offset = 0;
        offset + windowSize <= length;
        offset += windowSize
      ) {
        const window = bytes.subarray(offset, offset + windowSize);
        expect(window.some(byte => byte !== 0)).toBe(true);
      }
    }

    // NEGATIVE: the chunked path must not repeat a block — a fill that reused
    // one 65536-byte chunk of entropy for the whole buffer would be
    // catastrophic (repeated salts/IVs) yet would pass every length check.
    const big = webEngine.randomBytes(200000);
    const firstChunk = bytesToHex(big.subarray(0, CAP));
    const secondChunk = bytesToHex(big.subarray(CAP, 2 * CAP));
    const thirdChunk = bytesToHex(big.subarray(2 * CAP, 3 * CAP));
    expect(secondChunk).not.toBe(firstChunk);
    expect(thirdChunk).not.toBe(firstChunk);
    expect(thirdChunk).not.toBe(secondChunk);
  });
});

/**
 * Phase 7 — the empty-plaintext case of Web Crypto's appended-tag convention.
 *
 * `subtle.encrypt` returns `C‖T`; the {@link CryptoEngine} contract returns the
 * tag separately, so `webAeadEncrypt` slices the trailing 16 bytes off. With an
 * empty plaintext the whole result IS the tag, which makes this the degenerate
 * case where a wrong split boundary is invisible in every length check that
 * only looks at `combined.length`. The v2 container's `encMeta`/`encData`
 * segments can legitimately be empty, so this is a reachable wire-format case,
 * not a curiosity.
 */
describe('webEngine.aeadEncrypt — empty-plaintext tag split parity with nodeEngine', () => {
  it('returns an empty ciphertext plus a 16-byte tag byte-identical to nodeEngine', async () => {
    const key = webEngine.randomBytes(32);
    const iv = webEngine.randomBytes(12);
    const aad = utf8Encode('empty-plaintext-split-parity');
    const empty = new Uint8Array(0);

    const webOut = await webEngine.aeadEncrypt(key, iv, empty, aad);
    const nodeOut = await nodeEngine.aeadEncrypt(key, iv, empty, aad);

    // The split lands exactly at 0: everything Web Crypto returned is tag.
    expect(webOut.ciphertext.length).toBe(0);
    expect(webOut.tag.length).toBe(16);
    // Byte-identical to Node's GMAC-over-AAD tag — one wire format, both
    // runtimes, even with nothing to encrypt.
    expect(bytesToHex(webOut.tag)).toBe(bytesToHex(nodeOut.tag));
    expect(nodeOut.ciphertext.length).toBe(0);

    // NEGATIVE: the tag must NOT have been left inside the ciphertext. A split
    // at `combined.length` (rather than `combined.length - 16`) yields a
    // 16-byte "ciphertext" and an empty tag, and every round-trip below would
    // still be reversible within a single engine — only these two assertions
    // and the cross-engine comparison catch it.
    expect(webOut.ciphertext.length).not.toBe(16);
    expect(webOut.tag.length).not.toBe(0);

    // Both engines accept each other's empty-plaintext output.
    const webFromWeb = await webEngine.aeadDecrypt(
      key,
      iv,
      webOut.ciphertext,
      webOut.tag,
      aad
    );
    const nodeFromWeb = await nodeEngine.aeadDecrypt(
      key,
      iv,
      webOut.ciphertext,
      webOut.tag,
      aad
    );
    const webFromNode = await webEngine.aeadDecrypt(
      key,
      iv,
      nodeOut.ciphertext,
      nodeOut.tag,
      aad
    );
    expect(webFromWeb.length).toBe(0);
    expect(nodeFromWeb.length).toBe(0);
    expect(webFromNode.length).toBe(0);
  });

  it('still binds the AAD when there is no plaintext to authenticate', async () => {
    // With an empty plaintext the tag is a pure GMAC over the AAD, so this is
    // the case where a dropped `additionalData` would go completely unnoticed
    // by a round-trip test.
    const key = webEngine.randomBytes(32);
    const iv = webEngine.randomBytes(12);
    const empty = new Uint8Array(0);

    const boundToA = await webEngine.aeadEncrypt(
      key,
      iv,
      empty,
      utf8Encode('context-a')
    );
    const boundToB = await webEngine.aeadEncrypt(
      key,
      iv,
      empty,
      utf8Encode('context-b')
    );

    // Different AAD, same key+iv, empty plaintext => different tags.
    expect(bytesToHex(boundToA.tag)).not.toBe(bytesToHex(boundToB.tag));

    await expect(
      webEngine.aeadDecrypt(
        key,
        iv,
        boundToA.ciphertext,
        boundToA.tag,
        utf8Encode('context-b')
      )
    ).rejects.toThrow(CryptoError);

    try {
      await webEngine.aeadDecrypt(
        key,
        iv,
        boundToA.ciphertext,
        boundToA.tag,
        utf8Encode('context-b')
      );
      throw new Error('Expected aeadDecrypt to reject on AAD mismatch');
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      const e = err as InstanceType<typeof CryptoError>;
      expect(e.type).toBe(CryptoErrorType.DECRYPTION_FAILED);
      expect(e.code).toBe('DECRYPTION_FAILED');
    }
  });
});
