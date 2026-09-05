/**
 * Cross-runtime interop tests, run under Node 22+.
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
 *      (the real-headless-Chromium companion is
 *      `src/__tests__/browser/interop.browser.test.ts`).
 *   4. The same three claims for the **v2 container**: the fixture's committed
 *      `containers` goldens open under the Web engine with byte-identical
 *      payload and identical confidential metadata, a live container round-trips
 *      both directions across the edge-size table, and the negatives are pinned
 *      to the layer that actually rejects them — a bit flipped in one of the
 *      three GCM ciphertext segments authenticates-fails with
 *      `DECRYPTION_FAILED`, while a bit in the header parameters or the
 *      `metaLen` field is refused by the pre-authentication structural parse,
 *      with its own code and before any Argon2id work happens at all.
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
import {
  describe,
  it,
  expect,
  beforeAll,
  afterEach,
  jest,
} from '@jest/globals';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import nodeCrypto from 'node:crypto';
import { CryptoManager as NodeCryptoManager } from '../crypto-manager';
import { CryptoManager as BrowserCryptoManager } from '../crypto-manager.browser';
import { CryptoError, CryptoErrorType } from '../types';
import type { ContainerMetadata } from '../types';
import {
  utf8Encode,
  utf8Decode,
  bytesToHex,
  bytesToBase64url,
  base64urlToBytes,
} from '../codec';
import { HEADER_LENGTH } from '../format';
import { parseV2Container } from '../core';

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
// authentication failure. `scripts/gen-node-vectors.mjs` re-derives and
// re-asserts this layout before writing each golden, so a layout change fails
// regeneration rather than silently sliding these offsets onto other segments.
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
        // In CI the optional hash-wasm dependency MUST be installed: the
        // cross-runtime interop guarantee is the crown jewel of this release
        // and may never be silently skipped on a release/CI leg. A graceful
        // [skip] is reserved for genuinely-unsupported local dev hosts.
        if (process.env.CI) {
          throw new Error(
            `hash-wasm Argon2id failed to load in CI; the Node<->browser ` +
              `interop crown-jewel cannot be silently skipped. Ensure the ` +
              `optional hash-wasm dependency is installed.`,
            { cause: err }
          );
        }
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
  // Committed Node-produced golden vectors decrypt in the browser.
  //
  // A DEFAULT browser manager (32 MiB profile) decrypts each vector: decryption
  // reads the KDF params embedded in the header, so it is independent of the
  // manager's own configuration. This is the frozen Node→browser proof; the
  // live encryptor above could drift and this would still pin the format. The
  // same fixture is re-decrypted inside a REAL headless Chromium by
  // `src/__tests__/browser/interop.browser.test.ts`.
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

  // ---------------------------------------------------------------------------
  // The v2 CONTAINER crosses runtimes for real.
  //
  // The container is defined ONCE on `CryptoCore`, so both managers inherit it;
  // that makes it easy to believe it is portable and hard to know. These specs
  // pin it from both sides: frozen Node-sealed goldens opened by the Web
  // engine, a live both-directions round-trip, and negatives scoped to the
  // layer that actually rejects them.
  //
  // The scoping matters. Only THREE segments are GCM ciphertext — `wrappedDek`,
  // `encMeta`, `encData` — and only those turn a bit flip into an
  // authentication failure. Bits in the header parameters or in the `metaLen`
  // field are rejected EARLIER, by the pure pre-authentication structural parse,
  // with their own codes and before a single Argon2id byte is computed. A
  // blanket "any bit anywhere -> DECRYPTION_FAILED" property is simply false.
  // ---------------------------------------------------------------------------
  describe('v2 container: one wire format across runtimes', () => {
    const containerFixture = loadFixture();
    const defaultBrowserForContainers = new BrowserCryptoManager();

    afterEach(() => jest.restoreAllMocks());

    /** Metadata `decryptContainer` must report for a golden (size is authenticated too). */
    const expectedMetaOf = (
      vector: NodeContainerVector
    ): ContainerMetadata => ({
      ...vector.meta,
      size: vector.plaintextLength,
    });

    it('the fixture carries self-describing v2 container goldens', () => {
      expect(Array.isArray(containerFixture.containers)).toBe(true);
      expect(containerFixture.containers.length).toBeGreaterThanOrEqual(4);

      for (const vector of containerFixture.containers) {
        const container = base64urlToBytes(vector.container);
        const payload = base64urlToBytes(vector.plaintextBase64url);
        // The recorded payload length is the value that must come back as
        // `meta.size`, so it has to agree with the recorded payload bytes.
        expect(payload.length).toBe(vector.plaintextLength);
        // Magic + v2 version byte: these are containers, not v1 ciphertexts.
        expect(bytesToHex(container.subarray(0, 4))).toBe('48504352'); // "HPCR"
        expect(container[CONTAINER_VERSION_OFFSET]).toBe(0x02);
        // The documented layout, re-derived here: the tamper offsets below are
        // only meaningful while this identity holds.
        expect(container.length).toBe(
          CONTAINER_FIXED_OVERHEAD +
            containerMetaLen(container) +
            vector.plaintextLength
        );
        // The goldens must stay on the low-cost TEST profile the fixture
        // documents. Without this, a regeneration at the 128 MiB production
        // default would be accepted silently (and crawl).
        const headerView = new DataView(
          container.buffer,
          container.byteOffset,
          container.byteLength
        );
        expect(headerView.getUint32(CONTAINER_MEMORY_COST_OFFSET, false)).toBe(
          containerFixture.kdfParams.memoryCost
        );
        expect(headerView.getUint32(CONTAINER_TIME_COST_OFFSET, false)).toBe(
          containerFixture.kdfParams.timeCost
        );
        expect(headerView.getUint16(CONTAINER_PARALLELISM_OFFSET, false)).toBe(
          containerFixture.kdfParams.parallelism
        );

        // Cross-check the hand-copied offsets above against the parser's OWN
        // segment views (their `byteOffset` is absolute). Three places now
        // spell this layout out — the generator, this file and the browser
        // spec — so drift must fail loudly here rather than quietly sliding a
        // tamper offset onto a neighbouring segment.
        const parsed = parseV2Container(container);
        expect(parsed.wrappedDek.byteOffset).toBe(CONTAINER_WRAPPED_DEK_OFFSET);
        expect(parsed.wrappedDek.length).toBe(32);
        expect(parsed.encMeta.byteOffset).toBe(CONTAINER_ENC_META_OFFSET);
        expect(parsed.encMeta.length).toBe(containerMetaLen(container));
        expect(parsed.encData.byteOffset).toBe(
          containerEncDataOffset(container)
        );
        expect(parsed.encData.length).toBe(vector.plaintextLength);

        // A v2 container is NOT a v1 ciphertext: the v1 header parser must
        // refuse it rather than quietly reporting a parsed v1 header.
        expect(() =>
          defaultBrowserForContainers.inspectHeader(container)
        ).toThrow(CryptoError);
      }

      // At least one golden must carry a non-empty payload and one must carry
      // metadata, otherwise the tamper/metadata assertions below are vacuous.
      expect(containerFixture.containers.some(v => v.plaintextLength > 0)).toBe(
        true
      );
      expect(
        containerFixture.containers.some(v => v.meta.filename !== undefined)
      ).toBe(true);
    });

    // Frozen Node->browser proof: each golden was sealed by the Node build and
    // must open under the Web engine with byte-identical payload and identical
    // metadata. A DEFAULT (32 MiB) browser manager is used deliberately —
    // decryption reads the Argon2id params from the container header, so it is
    // independent of the manager's own configuration.
    for (const vector of containerFixture.containers) {
      it(`the browser build opens Node golden container: ${vector.description}`, async () => {
        const container = base64urlToBytes(vector.container);
        const expectedPayload = base64urlToBytes(vector.plaintextBase64url);

        // The golden must open on the runtime that PRODUCED it, so a browser
        // failure below is unambiguously a CROSSING failure and not a stale
        // fixture. This half needs only native argon2, so it runs UNGATED.
        const onNode = await node.decryptContainer(container, vector.password);
        expect(bytesEqual(onNode.data, expectedPayload)).toBe(true);
        expect(onNode.meta).toEqual(expectedMetaOf(vector));

        // The crossing itself needs the Web engine's hash-wasm Argon2id.
        if (!webEngineReady) return;
        const opened = await defaultBrowserForContainers.decryptContainer(
          container,
          vector.password
        );
        expect(bytesEqual(opened.data, expectedPayload)).toBe(true);
        expect(opened.data.length).toBe(vector.plaintextLength);
        // Exact metadata shape: a golden with no filename must come back with
        // no filename, not with an extra field.
        expect(opened.meta).toEqual(expectedMetaOf(vector));
      });
    }

    it('live round-trip both directions: Node-sealed opens in the browser AND browser-sealed opens in Node (edge sizes, metadata preserved)', async () => {
      if (!webEngineReady) return;
      // 0/1/15/16/17 straddle the AES block boundary; 4096 is multi-block —
      // the same size table `container.test.ts` drives.
      for (const size of [0, 1, 15, 16, 17, 4096]) {
        const data = new Uint8Array(nodeCrypto.randomBytes(size));

        // Node -> browser
        const sealedInNode = await node.encryptContainer(data, PASSWORD, {
          filename: 'from-node.dat',
          mime: 'application/x-node',
        });
        const openedInBrowser = await browser.decryptContainer(
          sealedInNode,
          PASSWORD
        );
        expect(bytesEqual(openedInBrowser.data, data)).toBe(true);
        expect(openedInBrowser.meta).toEqual({
          filename: 'from-node.dat',
          mime: 'application/x-node',
          size,
        });

        // browser -> Node
        const sealedInBrowser = await browser.encryptContainer(data, PASSWORD, {
          filename: 'from-browser.dat',
        });
        const openedInNode = await node.decryptContainer(
          sealedInBrowser,
          PASSWORD
        );
        expect(bytesEqual(openedInNode.data, data)).toBe(true);
        // `mime` was never sealed, so it must NOT reappear on the other side.
        expect(openedInNode.meta).toEqual({
          filename: 'from-browser.dat',
          size,
        });

        // Matching Argon2id params ⇒ byte-identical 22-byte v2 header on both
        // builds (only the random salt/nonces/ciphertext differ). One format.
        expect(bytesToHex(sealedInNode.subarray(0, HEADER_LENGTH))).toBe(
          bytesToHex(sealedInBrowser.subarray(0, HEADER_LENGTH))
        );
      }
    });

    it('a wrong password fails to open a cross-runtime container (both directions)', async () => {
      if (!webEngineReady) return;

      const sealedInNode = await node.encryptContainer(
        fillerBytes(64),
        PASSWORD,
        { filename: 'secret.dat' }
      );
      await expectContainerRejection(
        () => browser.decryptContainer(sealedInNode, WRONG_PASSWORD),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );

      const sealedInBrowser = await browser.encryptContainer(
        fillerBytes(64),
        PASSWORD
      );
      await expectContainerRejection(
        () => node.decryptContainer(sealedInBrowser, WRONG_PASSWORD),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );
    });

    // -------------------------------------------------------------------------
    // Tamper, part 1: the THREE GCM ciphertext segments. These — and only these
    // — surface as an authentication failure. Never CONTAINER_INTEGRITY_FAILED:
    // that code would mean a GCM tag was ACCEPTED on modified bytes and the
    // mismatch was only caught afterwards by the SHA-256 re-check.
    // -------------------------------------------------------------------------
    describe('a single-bit tamper of a GCM ciphertext segment fails authentication on the other build', () => {
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
        it(`rejects a flipped bit in ${segment.label} with DECRYPTION_FAILED`, async () => {
          if (!webEngineReady) return;
          // A non-empty payload is required for `encData` to exist at all.
          const container = await node.encryptContainer(
            fillerBytes(96),
            PASSWORD,
            { filename: 'tamper-me.bin', mime: 'application/octet-stream' }
          );
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
            () =>
              browser.decryptContainer(flipBitAt(container, offset), PASSWORD),
            {
              type: CryptoErrorType.DECRYPTION_FAILED,
              code: 'DECRYPTION_FAILED',
            }
          );
          // The untampered container still opens — the rejection above is the
          // flipped bit, not a broken fixture.
          const { data } = await browser.decryptContainer(container, PASSWORD);
          expect(data.length).toBe(96);
        });
      }

      it('a flipped RESERVED header byte is caught by the AAD binding, not by the structural parse', async () => {
        if (!webEngineReady) return;
        // Offsets 16-21 are reserved: `parseV2Container` never reads them, so
        // this survives the structural parse and can only be caught by the
        // header being bound verbatim into every segment's AAD.
        const container = await node.encryptContainer(
          fillerBytes(48),
          PASSWORD
        );
        await expectContainerRejection(
          () =>
            browser.decryptContainer(
              flipBitAt(container, CONTAINER_RESERVED_HEADER_OFFSET),
              PASSWORD
            ),
          { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
        );
      });
    });

    // -------------------------------------------------------------------------
    // Tamper, part 2: bytes the PRE-AUTHENTICATION structural parse rejects.
    // These never reach a GCM tag and — critically — never reach the KDF, so
    // an attacker cannot use a malformed container to force Argon2id work.
    // Each carries its OWN code; asserting DECRYPTION_FAILED here would be wrong.
    // -------------------------------------------------------------------------
    describe('structurally invalid bytes are rejected before any Argon2id work', () => {
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
        it(`rejects ${preAuth.label} with ${preAuth.code}, without deriving a key`, async () => {
          // Argon2id is the expensive step; spying on the engine primitive the
          // Node manager actually calls proves the rejection is pre-KDF.
          const { nodeEngine } = await import('../engine.node');
          const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

          const container = base64urlToBytes(
            containerFixture.containers[0]?.container ?? ''
          );
          expect(container.length).toBeGreaterThan(
            CONTAINER_FIXED_OVERHEAD - 1
          );

          await expectContainerRejection(
            () => node.decryptContainer(preAuth.mutate(container), PASSWORD),
            { type: preAuth.type, code: preAuth.code }
          );
          // The thing that must NOT have happened: attacker-controlled bytes
          // triggering a key derivation.
          expect(deriveSpy).not.toHaveBeenCalled();
        });
      }
    });

    it('a container sealed under a custom `aad` does NOT open under a manager with the default `aad` (either runtime)', async () => {
      if (!webEngineReady) return;
      const appA = new NodeCryptoManager({ ...LOW_COST, aad: 'application-A' });
      const appABrowser = new BrowserCryptoManager({
        ...LOW_COST,
        aad: 'application-A',
      });
      const container = await appA.encryptContainer(fillerBytes(48), PASSWORD, {
        filename: 'domain-separated.dat',
      });

      // Same password AND identical Argon2id params (⇒ byte-identical header),
      // so the ONLY separator is the bound `aad` context string.
      await expectContainerRejection(
        () => browser.decryptContainer(container, PASSWORD),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );
      await expectContainerRejection(
        () => node.decryptContainer(container, PASSWORD),
        { type: CryptoErrorType.DECRYPTION_FAILED, code: 'DECRYPTION_FAILED' }
      );

      // ...but the SAME `aad` opens it on the OTHER runtime: `aad` separates
      // applications, never runtimes.
      const opened = await appABrowser.decryptContainer(container, PASSWORD);
      expect(opened.data.length).toBe(48);
      expect(opened.meta).toEqual({
        filename: 'domain-separated.dat',
        size: 48,
      });
    });
  });
});
