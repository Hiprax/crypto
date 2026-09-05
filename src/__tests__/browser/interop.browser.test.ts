/**
 * Real-browser interop suite.
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
 *   6. The **v2 container** works here too — SubtleCrypto AES-256-GCM over a
 *      two-layer key hierarchy plus WASM Argon2id — round-tripping across the
 *      edge-size table, opening every Node-produced golden container with its
 *      confidential `filename` / `mime` / `size` intact, and rejecting a wrong
 *      password, a bit flipped in any of the three GCM ciphertext segments, a
 *      structurally invalid header, and a foreign `aad`. This is the only place
 *      the container's portability is proven outside a Node process.
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

/**
 * One committed v2 container golden. `plaintextBase64url` is the base64url of
 * the payload that was sealed (`plaintextLength` its byte count — the value
 * `decryptContainer` must report back as `meta.size`), and `meta` is the
 * confidential metadata the container carries.
 */
interface NodeContainerVector {
  description: string;
  password: string;
  plaintextBase64url: string;
  plaintextLength: number;
  meta: { filename?: string; mime?: string };
  container: string;
}

interface NodeVectorsFixture {
  generatedWith: { package: string; version: string; kdf: string };
  kdfParams: { memoryCost: number; timeCost: number; parallelism: number };
  vectors: NodeVector[];
  containers: NodeContainerVector[];
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

/**
 * Index of `needle` inside `haystack`, or -1 (a pure substring search — there
 * is no `Buffer.indexOf` in the browser). Used to prove that confidential
 * container metadata never appears in cleartext on the wire.
 */
function bytesIndexOf(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0 || needle.length > haystack.length) return -1;
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/** Flip a single bit at `offset`, returning a NEW array (input untouched). */
function flipBitAt(buf: Uint8Array, offset: number): Uint8Array {
  const out = Uint8Array.from(buf);
  out[offset] = (out[offset] ?? 0) ^ 0x01;
  return out;
}

/**
 * Flip the HIGH bit at `offset`, returning a NEW array. Used where a low-bit
 * flip would leave a header field inside its accepted range: driving the high
 * bit of `memoryCost` or of `metaLen` puts the field far out of bounds, which
 * is what the pre-authentication structural parse must reject.
 */
function flipHighBitAt(buf: Uint8Array, offset: number): Uint8Array {
  const out = Uint8Array.from(buf);
  out[offset] = (out[offset] ?? 0) ^ 0x80;
  return out;
}

// ---------------------------------------------------------------------------
// v2 CONTAINER byte layout. Every offset below is fixed except `encMeta`
// (length = the `metaLen` field) and `encData` (whatever is left before the
// trailing tag):
//
//   header 0(22) | salt 22(32) | kekIv 54(12) | wrappedDek 66(32) | kekTag 98(16)
//   metaIv 114(12) | metaLen 126(u32BE,4) | encMeta 130(metaLen)
//   metaTag 130+metaLen(16) | dataIv 146+metaLen(12) | encData 158+metaLen
//   dataTag len-16(16)
//
// so `container.length === 174 + metaLen + payload.length` always holds. Only
// THREE of those segments are GCM ciphertext — `wrappedDek`, `encMeta` and
// `encData` — and those are the only ones whose tamper surfaces as an
// authentication failure. The offsets are spelled out here rather than read
// from a parser export because `parseV2Container` deliberately does not reach
// the browser entry point: this spec must pin the WIRE layout independently of
// the code that slices it.
// ---------------------------------------------------------------------------
const CONTAINER_IV_LENGTH = 12;
const CONTAINER_TAG_LENGTH = 16;
/** Every container segment except `encMeta` and `encData` (22+32+12+32+16+12+4+16+12+16). */
const CONTAINER_FIXED_OVERHEAD = 174;
const CONTAINER_VERSION_OFFSET = 4;
const CONTAINER_MEMORY_COST_OFFSET = 6;
const CONTAINER_TIME_COST_OFFSET = 10;
const CONTAINER_PARALLELISM_OFFSET = 14;
/** First of the six reserved header bytes — parsed by nobody, bound into every AAD. */
const CONTAINER_RESERVED_HEADER_OFFSET = 16;
const CONTAINER_WRAPPED_DEK_OFFSET = 66;
const CONTAINER_META_LEN_OFFSET = 126;
const CONTAINER_ENC_META_OFFSET = 130;

/** Read a container's `metaLen` field (u32BE at offset 126). */
function containerMetaLen(container: Uint8Array): number {
  return new DataView(
    container.buffer,
    container.byteOffset,
    container.byteLength
  ).getUint32(CONTAINER_META_LEN_OFFSET, false);
}

/** Absolute offset of a container's `encData` segment (158 + `metaLen`). */
function containerEncDataOffset(container: Uint8Array): number {
  return (
    CONTAINER_ENC_META_OFFSET +
    containerMetaLen(container) +
    CONTAINER_TAG_LENGTH +
    CONTAINER_IV_LENGTH
  );
}

/**
 * Assert that `run()` REJECTED with exactly `{ type, code }` — and, as the
 * negative, that it did not resolve (no payload was ever handed back).
 */
async function expectContainerRejection(
  run: () => Promise<unknown>,
  expected: { type: CryptoErrorType; code: string }
): Promise<void> {
  let caught: unknown;
  let resolved = false;
  try {
    await run();
    resolved = true;
  } catch (err) {
    caught = err;
  }
  // The thing that must NOT have happened: a decrypted payload came back.
  expect(resolved).toBe(false);
  expect(caught).toBeInstanceOf(CryptoError);
  const error = caught as InstanceType<typeof CryptoError>;
  expect(error.code).toBe(expected.code);
  expect(error.type).toBe(expected.type);
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

      // Anti-vacuity: the golden-CONTAINER specs below are generated by a
      // `for` loop over `fixture.containers`. An empty array would silently
      // produce zero of them and the suite would still go green.
      expect(Array.isArray(fixture.containers)).toBe(true);
      expect(fixture.containers.length).toBeGreaterThanOrEqual(4);
      for (const vector of fixture.containers) {
        const container = base64urlToBytes(vector.container);
        expect(container[CONTAINER_VERSION_OFFSET]).toBe(0x02);
        expect(container.length).toBe(
          CONTAINER_FIXED_OVERHEAD +
            containerMetaLen(container) +
            vector.plaintextLength
        );
        // The goldens must stay on the low-cost TEST profile the fixture
        // documents; a regeneration at the 128 MiB production default would
        // otherwise be accepted silently (and crawl in a browser).
        const headerView = new DataView(
          container.buffer,
          container.byteOffset,
          container.byteLength
        );
        expect(headerView.getUint32(CONTAINER_MEMORY_COST_OFFSET, false)).toBe(
          fixture.kdfParams.memoryCost
        );
        expect(headerView.getUint32(CONTAINER_TIME_COST_OFFSET, false)).toBe(
          fixture.kdfParams.timeCost
        );
        expect(headerView.getUint16(CONTAINER_PARALLELISM_OFFSET, false)).toBe(
          fixture.kdfParams.parallelism
        );
      }
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

  // ---------------------------------------------------------------------------
  // The v2 container, inside a real browser.
  //
  // Everything above proves the v1 text/bytes format crosses runtimes. The
  // container is a different, additive envelope: an Argon2id KEK wraps a random
  // DEK, and THREE independent AES-GCM segments (`wrappedDek`, `encMeta`,
  // `encData`) are each bound to `aad ‖ header`. Node-side tests can only
  // exercise the Web engine through a Node process; here it runs on the real
  // SubtleCrypto with a real WASM Argon2id, which is the only way to know the
  // envelope is genuinely portable.
  //
  // Negative scoping matters and is deliberate: only the three GCM ciphertext
  // segments turn a bit flip into an authentication failure. A bit in the
  // header parameters or in the `metaLen` field is refused EARLIER, by the pure
  // pre-authentication structural parse, with its own code — so a blanket
  // "any bit anywhere -> DECRYPTION_FAILED" expectation would simply be false.
  // ---------------------------------------------------------------------------
  describe('v2 container inside the browser (SubtleCrypto + WASM Argon2id)', () => {
    /** Metadata `decryptContainer` must report for a golden (size is authenticated too). */
    const expectedMetaOf = (
      vector: NodeContainerVector
    ): { filename?: string; mime?: string; size: number } => ({
      ...vector.meta,
      size: vector.plaintextLength,
    });

    it('round-trips across edge sizes with confidential metadata intact', async () => {
      // 0/1/15/16/17 straddle the AES block boundary; 4096 is multi-block.
      for (const size of [0, 1, 15, 16, 17, 4096]) {
        const data = fillerBytes(size);
        const container = await cm.encryptContainer(data, PASSWORD, {
          filename: 'in-browser.dat',
          mime: 'application/x-browser',
        });

        // It is a v2 container, and it obeys the documented byte layout.
        expect(container[CONTAINER_VERSION_OFFSET]).toBe(0x02);
        expect(container.length).toBe(
          CONTAINER_FIXED_OVERHEAD + containerMetaLen(container) + size
        );
        // Confidentiality: the filename must not sit in the clear on the wire.
        expect(bytesIndexOf(container, utf8Encode('in-browser.dat'))).toBe(-1);

        const { data: back, meta } = await cm.decryptContainer(
          container,
          PASSWORD
        );
        expect(back.length).toBe(size);
        expect(bytesEqual(back, data)).toBe(true);
        expect(meta).toEqual({
          filename: 'in-browser.dat',
          mime: 'application/x-browser',
          size,
        });
      }
    });

    // The crown jewel for the container format: Node-sealed envelopes opened by
    // a real browser. A DEFAULT (32 MiB) manager is used deliberately —
    // decryption reads the Argon2id params from the container header, so it is
    // independent of this manager's own configuration.
    for (const vector of fixture.containers) {
      it(`opens Node-produced golden container: ${vector.description}`, async () => {
        const container = base64urlToBytes(vector.container);
        const expectedPayload = base64urlToBytes(vector.plaintextBase64url);
        expect(expectedPayload.length).toBe(vector.plaintextLength);

        const { data, meta } = await defaultCm.decryptContainer(
          container,
          vector.password
        );
        expect(data.length).toBe(vector.plaintextLength);
        expect(bytesEqual(data, expectedPayload)).toBe(true);
        // Exact metadata shape: a golden with no `mime` must come back without
        // one, not with an extra field.
        expect(meta).toEqual(expectedMetaOf(vector));
      });
    }

    it('rejects a wrong password', async () => {
      const container = await cm.encryptContainer(fillerBytes(64), PASSWORD, {
        filename: 'secret.dat',
      });
      await expectContainerRejection(
        () => cm.decryptContainer(container, WRONG_PASSWORD),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );
      // ...and still opens with the right one, so the rejection is the password.
      const { data } = await cm.decryptContainer(container, PASSWORD);
      expect(data.length).toBe(64);
    });

    // Tamper, part 1: the three GCM ciphertext segments. `DECRYPTION_FAILED` is
    // the only acceptable outcome — `CONTAINER_INTEGRITY_FAILED` would mean a
    // GCM tag was ACCEPTED on modified bytes and the damage was only noticed
    // afterwards by the SHA-256 re-check.
    const gcmSegments: Array<{
      label: string;
      offsetOf: (container: Uint8Array) => number;
    }> = [
      {
        label: 'wrappedDek (offset 66)',
        offsetOf: () => CONTAINER_WRAPPED_DEK_OFFSET,
      },
      {
        label: 'encMeta (offset 130)',
        offsetOf: () => CONTAINER_ENC_META_OFFSET,
      },
      {
        label: 'encData (offset 158 + metaLen)',
        offsetOf: containerEncDataOffset,
      },
    ];

    for (const segment of gcmSegments) {
      it(`rejects a single-bit tamper in ${segment.label} with DECRYPTION_FAILED`, async () => {
        // A non-empty payload is required for `encData` to exist at all.
        const container = await cm.encryptContainer(fillerBytes(96), PASSWORD, {
          filename: 'tamper-me.bin',
          mime: 'application/octet-stream',
        });
        const offset = segment.offsetOf(container);
        // Pin the offset to the SEGMENT, not merely to somewhere in range: a
        // mis-derived `encData` offset would land in the adjacent `dataIv` and
        // still throw, quietly testing nonce binding instead of ciphertext
        // authentication. These two identities make that impossible.
        expect(container.length).toBe(
          CONTAINER_FIXED_OVERHEAD + containerMetaLen(container) + 96
        );
        expect(
          containerEncDataOffset(container) + 96 + CONTAINER_TAG_LENGTH
        ).toBe(container.length);
        // `encMeta` at offset 130 is only INSIDE that segment while the
        // container actually carries metadata; with `metaLen` 0 it would
        // land in `metaTag` and still throw, testing the wrong segment.
        expect(containerMetaLen(container)).toBeGreaterThan(0);
        expect(offset).toBeLessThan(container.length - CONTAINER_TAG_LENGTH);

        await expectContainerRejection(
          () => cm.decryptContainer(flipBitAt(container, offset), PASSWORD),
          { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
        );
        // The untampered container still opens — the rejection above is the
        // flipped bit, not a broken fixture.
        const { data } = await cm.decryptContainer(container, PASSWORD);
        expect(data.length).toBe(96);
      });
    }

    it('rejects a flipped RESERVED header byte via the AAD binding (not the structural parse)', async () => {
      // Header offsets 16-21 are reserved: the structural parse never reads
      // them, so this can only be caught by the header being bound verbatim
      // into every segment's AAD.
      const container = await cm.encryptContainer(fillerBytes(48), PASSWORD);
      await expectContainerRejection(
        () =>
          cm.decryptContainer(
            flipBitAt(container, CONTAINER_RESERVED_HEADER_OFFSET),
            PASSWORD
          ),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );
    });

    // Tamper, part 2: bytes the PRE-AUTHENTICATION structural parse rejects.
    // These never reach a GCM tag, and never reach the KDF — each carries its
    // OWN code, so asserting `DECRYPTION_FAILED` here would be wrong.
    const preAuthCases: Array<{
      label: string;
      mutate: (container: Uint8Array) => Uint8Array;
      type: CryptoErrorType;
      code: string;
    }> = [
      {
        label: 'a flipped magic byte (offset 0)',
        mutate: c => flipBitAt(c, 0),
        type: CryptoErrorType.DECRYPTION_FAILED,
        code: 'CONTAINER_INVALID_MAGIC',
      },
      {
        label: 'a flipped version byte (offset 4: 0x02 -> 0x03)',
        mutate: c => flipBitAt(c, CONTAINER_VERSION_OFFSET),
        type: CryptoErrorType.DECRYPTION_FAILED,
        code: 'CONTAINER_UNSUPPORTED_VERSION',
      },
      {
        label: 'the memoryCost high bit (offset 6), over the DoS cap',
        mutate: c => flipHighBitAt(c, CONTAINER_MEMORY_COST_OFFSET),
        type: CryptoErrorType.INVALID_INPUT,
        code: 'CONTAINER_KDF_PARAMS_OUT_OF_BOUNDS',
      },
      {
        label: 'the metaLen high bit (offset 126), overrunning the buffer',
        mutate: c => flipHighBitAt(c, CONTAINER_META_LEN_OFFSET),
        type: CryptoErrorType.INVALID_INPUT,
        code: 'TRUNCATED_CONTAINER',
      },
    ];

    for (const preAuth of preAuthCases) {
      it(`rejects ${preAuth.label} with ${preAuth.code}, not DECRYPTION_FAILED`, async () => {
        const container = base64urlToBytes(
          fixture.containers[0]?.container ?? ''
        );
        expect(container.length).toBeGreaterThanOrEqual(
          CONTAINER_FIXED_OVERHEAD
        );
        await expectContainerRejection(
          () => cm.decryptContainer(preAuth.mutate(container), PASSWORD),
          { type: preAuth.type, code: preAuth.code }
        );
      });
    }

    it('does not open a container sealed under a different `aad`', async () => {
      const appA = new CryptoManager({ ...LOW_COST, aad: 'application-A' });
      const appB = new CryptoManager({ ...LOW_COST, aad: 'application-B' });
      const container = await appA.encryptContainer(fillerBytes(48), PASSWORD, {
        filename: 'domain-separated.dat',
      });

      // Same password AND identical Argon2id params (⇒ byte-identical header),
      // so the ONLY separator is the bound `aad` context string.
      await expectContainerRejection(
        () => appB.decryptContainer(container, PASSWORD),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );
      // The default-`aad` manager is equally locked out.
      await expectContainerRejection(
        () => cm.decryptContainer(container, PASSWORD),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );

      // Sanity: the originating application still opens its own container.
      const { data, meta } = await appA.decryptContainer(container, PASSWORD);
      expect(data.length).toBe(48);
      expect(meta).toEqual({ filename: 'domain-separated.dat', size: 48 });
    });
  });
});
