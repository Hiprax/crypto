#!/usr/bin/env node
/**
 * Golden interop-vector generator for @hiprax/crypto.
 *
 * Produces `src/__tests__/fixtures/node-vectors.json` — a committed set of
 * ciphertexts encrypted by the **Node** build. It carries TWO frozen golden
 * arrays, both proving that there is exactly ONE wire format per format
 * version and that a Node-produced blob round-trips into the browser:
 *
 *   - `vectors`    — v1 text ciphertexts from `encryptText()`. The browser
 *                    build must decrypt each `ciphertext` (with its
 *                    `password`) back to the recorded `plaintext`.
 *   - `containers` — v2 envelopes from `encryptContainer()`. The browser build
 *                    must decrypt each `container` back to the recorded
 *                    `plaintextBase64url` bytes AND recover the recorded
 *                    `meta` (filename / mime) plus the payload's byte length.
 *
 * The Node-run companion test lives in `src/__tests__/interop.test.ts`; the
 * real-headless-Chromium companion is `src/__tests__/browser/interop.browser.test.ts`.
 *
 * ---------------------------------------------------------------------------
 * REGENERATION
 * ---------------------------------------------------------------------------
 *   npm run build && node scripts/gen-node-vectors.mjs
 *
 * The script imports the COMPILED Node entry (`dist/index.js`), so `dist/` must
 * exist first (run `npm run build`). Each ciphertext and container embeds fresh
 * random salt/IV bytes (and, for a container, a fresh random DEK), so every run
 * rewrites every `ciphertext` and `container` string — decryption stays correct
 * because the KDF salt and every GCM nonce are carried on the wire. The inputs
 * (passwords, plaintexts, metadata, KDF parameters) are fixed here, so the
 * fixture's SHAPE — and every `plaintext` / `plaintextBase64url` / `meta`
 * field — is stable across regenerations; only the opaque ciphertext bytes
 * change.
 *
 * The KDF parameters are intentionally the repo's TEST-ONLY low-cost profile
 * (`memoryCost = 2**14` KiB = 16 MiB, `timeCost = 1`, `parallelism = 1`) so the
 * Node and browser suites derive quickly. NEVER use these parameters in
 * production; the browser production default is 32 MiB (see
 * `crypto-manager.browser.ts`) and the Node default is 128 MiB.
 *
 * Before writing, the script SELF-VERIFIES every vector by decrypting it with
 * the same Node manager (and checking the embedded header parameters), so a
 * regeneration can never commit a vector that does not round-trip. Containers
 * get the same treatment: each one is decrypted back, its payload bytes are
 * compared byte-for-byte, its recovered `filename` / `mime` / `size` are
 * re-checked against the inputs, and its v2 header (magic, version 0x02, kdfId,
 * Argon2id parameters) plus its total length are validated against the
 * documented layout.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);
const distEntry = path.join(repoRoot, 'dist', 'index.js');
const fixtureDir = path.join(repoRoot, 'src', '__tests__', 'fixtures');
const fixturePath = path.join(fixtureDir, 'node-vectors.json');

if (!existsSync(distEntry)) {
  console.error(
    `[gen-node-vectors] Compiled Node entry not found at ${distEntry}.\n` +
      'Run `npm run build` before regenerating the interop vectors.'
  );
  process.exit(1);
}

// `pathToFileURL` yields a spec import() accepts on every OS (it encodes the
// Windows drive-letter path as file:///D:/... correctly).
const { CryptoManager, bytesToBase64url } = await import(
  pathToFileURL(distEntry).href
);

// TEST-ONLY low-cost Argon2id profile — shared by every vector. `memoryCost` is
// in KiB, so `2**14` = 16384 KiB = 16 MiB. Never use in production.
const KDF_PARAMS = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 };

/**
 * Fixed generation inputs. Each entry becomes one committed vector once its
 * `encryptText(plaintext, password)` ciphertext is filled in below. Passwords
 * all satisfy `validatePassword` (either the 20+ char passphrase rule or the
 * 8+ char four-category composition rule). Plaintexts cover the empty string,
 * short ASCII, the exact 16-byte AES block boundary, multi-byte Unicode, a
 * multi-block long buffer, and mixed line endings / control-ish characters.
 */
const INPUTS = [
  {
    description: 'empty string',
    password: 'correct horse battery staple',
    plaintext: '',
  },
  {
    description: 'short ascii',
    password: 'correct horse battery staple',
    plaintext: 'hello world',
  },
  {
    description: 'exactly 16 bytes (AES block boundary)',
    password: 'Tr0ub4dour&3xample!',
    plaintext: 'exactly-sixteen!',
  },
  {
    description: 'multi-byte unicode (accents, CJK, emoji, math, cyrillic)',
    password: 'correct horse battery staple',
    plaintext: 'café — 世界 — 🔐 — Ω≈ç√∫ — Здравствуй',
  },
  {
    description: 'long ascii (multi-block)',
    password: 'correct horse battery staple',
    plaintext: 'The quick brown fox jumps over the lazy dog. '.repeat(40),
  },
  {
    description: 'mixed line endings and control-ish text',
    password: 'S3cure-Passphrase#2026',
    plaintext: 'line1\nline2\ttabbed\r\nwindows-eol\n',
  },
];

// ---------------------------------------------------------------------------
// v2 CONTAINER goldens.
// ---------------------------------------------------------------------------

/**
 * Byte offsets of the fixed-position v2 container segments, used only to
 * SELF-VERIFY the generated goldens against the documented wire layout:
 *
 *   header 0(22) | salt 22(32) | kekIv 54(12) | wrappedDek 66(32) | kekTag 98(16)
 *   metaIv 114(12) | metaLen 126(u32BE 4) | encMeta 130(metaLen)
 *   metaTag 130+metaLen(16) | dataIv 146+metaLen(12) | encData 158+metaLen | dataTag len-16(16)
 *
 * `CONTAINER_FIXED_OVERHEAD` is everything except `encMeta` and `encData`, so
 * `container.length === 174 + metaLen + payload.length` always holds. Checking
 * that here means a future layout change cannot silently produce goldens whose
 * documented offsets (the ones the interop tamper tests flip bits at) drifted.
 */
const CONTAINER_MAGIC = 'HPCR';
const CONTAINER_VERSION_BYTE = 0x02;
const CONTAINER_KDF_ID_ARGON2ID = 0x00;
const CONTAINER_META_LEN_OFFSET = 126;
const CONTAINER_FIXED_OVERHEAD = 174;

/** Deterministic-but-varied filler bytes, so `plaintextBase64url` never drifts. */
function fillerBytes(length) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = (i * 31 + 7) & 0xff;
  }
  return out;
}

const utf8 = new TextEncoder();

/**
 * Fixed container-generation inputs. Payload bytes are deterministic so only
 * the opaque `container` string changes between regenerations. Coverage:
 * an empty payload with NO metadata (the 174 + 37 = 211-byte minimum container),
 * a small binary payload carrying both `filename` and `mime`, a non-ASCII
 * `filename` (UTF-8 in the confidential metadata block), and a payload well
 * past the 16-byte AES block boundary.
 */
const CONTAINER_INPUTS = [
  {
    description: 'empty payload, no metadata',
    password: 'correct horse battery staple',
    payload: new Uint8Array(0),
    meta: undefined,
  },
  {
    description: 'small binary payload with filename + mime',
    password: 'correct horse battery staple',
    payload: Uint8Array.from([
      0x00, 0xff, 0x01, 0xfe, 0x7f, 0x80, 0x0a, 0x0d, 0x09, 0x20, 0x2e, 0x2f,
      0x5c, 0x00, 0xff, 0x00, 0x42,
    ]),
    meta: { filename: 'report.bin', mime: 'application/octet-stream' },
  },
  {
    description: 'unicode filename (multi-byte UTF-8 metadata)',
    password: 'Tr0ub4dour&3xample!',
    payload: utf8.encode('café — 世界 — 🔐 — Ω≈ç√∫ — Здравствуй'),
    meta: { filename: 'résumé — 履歴書 — 🔐.txt', mime: 'text/plain; charset=utf-8' },
  },
  {
    description: 'multi-block payload (573 bytes, filename only)',
    password: 'S3cure-Passphrase#2026',
    payload: fillerBytes(573),
    meta: { filename: 'multi-block.dat' },
  },
];

const containers = [];
for (const input of CONTAINER_INPUTS) {
  const cm = new CryptoManager({ ...KDF_PARAMS });
  const container = await cm.encryptContainer(
    input.payload,
    input.password,
    input.meta
  );

  // SELF-VERIFY 1: the container must round-trip under the same Node manager,
  // byte-for-byte, with its metadata and size intact.
  const { data: recovered, meta: recoveredMeta } = await cm.decryptContainer(
    container,
    input.password
  );
  const payloadMatches =
    recovered.length === input.payload.length &&
    Buffer.from(recovered).equals(Buffer.from(input.payload));
  if (!payloadMatches) {
    console.error(
      `[gen-node-vectors] Container self-check FAILED for "${input.description}": ` +
        'decrypted payload did not match the input bytes.'
    );
    process.exit(1);
  }
  const expectedMeta = { size: input.payload.length };
  if (input.meta?.filename !== undefined) {
    expectedMeta.filename = input.meta.filename;
  }
  if (input.meta?.mime !== undefined) {
    expectedMeta.mime = input.meta.mime;
  }
  if (
    recoveredMeta.size !== expectedMeta.size ||
    recoveredMeta.filename !== expectedMeta.filename ||
    recoveredMeta.mime !== expectedMeta.mime
  ) {
    console.error(
      `[gen-node-vectors] Container metadata self-check FAILED for ` +
        `"${input.description}": got ${JSON.stringify(recoveredMeta)}, ` +
        `expected ${JSON.stringify(expectedMeta)}.`
    );
    process.exit(1);
  }

  // SELF-VERIFY 2: the v2 header and the documented byte layout. The interop
  // tamper tests flip bits at fixed offsets derived from exactly this layout,
  // so a drift here must fail the regeneration rather than the test suite.
  const view = new DataView(
    container.buffer,
    container.byteOffset,
    container.byteLength
  );
  const metaLen = view.getUint32(CONTAINER_META_LEN_OFFSET, false);
  const layoutOk =
    Buffer.from(container.subarray(0, 4)).toString('ascii') ===
      CONTAINER_MAGIC &&
    container[4] === CONTAINER_VERSION_BYTE &&
    container[5] === CONTAINER_KDF_ID_ARGON2ID &&
    view.getUint32(6, false) === KDF_PARAMS.memoryCost &&
    view.getUint32(10, false) === KDF_PARAMS.timeCost &&
    view.getUint16(14, false) === KDF_PARAMS.parallelism &&
    container.length === CONTAINER_FIXED_OVERHEAD + metaLen + recovered.length;
  if (!layoutOk) {
    console.error(
      `[gen-node-vectors] Container layout/header self-check FAILED for ` +
        `"${input.description}" (length ${container.length}, metaLen ${metaLen}).`
    );
    process.exit(1);
  }

  const entry = {
    description: input.description,
    password: input.password,
    plaintextBase64url: bytesToBase64url(input.payload),
    plaintextLength: input.payload.length,
    meta: {},
    container: bytesToBase64url(container),
  };
  if (input.meta?.filename !== undefined) {
    entry.meta.filename = input.meta.filename;
  }
  if (input.meta?.mime !== undefined) {
    entry.meta.mime = input.meta.mime;
  }
  containers.push(entry);
}

const pkg = JSON.parse(
  readFileSync(path.join(repoRoot, 'package.json'), 'utf8')
);

const vectors = [];
for (const input of INPUTS) {
  const cm = new CryptoManager({ ...KDF_PARAMS });
  const ciphertext = await cm.encryptText(input.plaintext, input.password);

  // SELF-VERIFY: the freshly produced ciphertext must round-trip under the same
  // Node manager, and its embedded header must carry the documented params.
  const roundTrip = await cm.decryptText(ciphertext, input.password);
  if (roundTrip !== input.plaintext) {
    console.error(
      `[gen-node-vectors] Self-check FAILED for "${input.description}": ` +
        'decrypted plaintext did not match the input.'
    );
    process.exit(1);
  }
  const header = cm.inspectHeader(ciphertext);
  if (
    !header ||
    header.params.kind !== 'argon2id' ||
    header.params.memoryCost !== KDF_PARAMS.memoryCost ||
    header.params.timeCost !== KDF_PARAMS.timeCost ||
    header.params.parallelism !== KDF_PARAMS.parallelism
  ) {
    console.error(
      `[gen-node-vectors] Header self-check FAILED for "${input.description}".`
    );
    process.exit(1);
  }

  vectors.push({
    description: input.description,
    password: input.password,
    plaintext: input.plaintext,
    memoryCost: KDF_PARAMS.memoryCost,
    timeCost: KDF_PARAMS.timeCost,
    parallelism: KDF_PARAMS.parallelism,
    ciphertext,
  });
}

const fixture = {
  _comment:
    'Golden cross-runtime interop vectors. Each `vectors[].ciphertext` was ' +
    "produced by the Node build's encryptText(plaintext, password), and each " +
    "`containers[].container` by the Node build's encryptContainer(payload, " +
    'password, meta) (v2 envelope). The browser build MUST decrypt each one ' +
    'back to its recorded `plaintext` / `plaintextBase64url` + `meta` — proof ' +
    'that Node and the browser share ONE wire format per version. Consumed by ' +
    'src/__tests__/interop.test.ts (Node) and, in a real browser, by ' +
    'src/__tests__/browser/interop.browser.test.ts.',
  _generator: 'scripts/gen-node-vectors.mjs',
  _regenerate: 'npm run build && node scripts/gen-node-vectors.mjs',
  _note:
    'Ciphertexts embed a fresh random salt + IV (containers additionally a ' +
    'fresh random DEK and three GCM nonces), so regeneration changes every ' +
    '`ciphertext` and `container` string while every input field stays fixed ' +
    '(decryption stays correct). The KDF parameters are the repo\'s TEST-ONLY ' +
    'low-cost profile — never use them in production.',
  _containersNote:
    'v2 container goldens. `plaintextBase64url` is the base64url of the sealed ' +
    'payload bytes (`plaintextLength` is their count, and the value ' +
    'decryptContainer must report as `meta.size`); `meta` is the confidential ' +
    'metadata the container carries. Fixed byte layout used by the tamper ' +
    'tests: header 0(22) salt 22(32) kekIv 54(12) wrappedDek 66(32) ' +
    'kekTag 98(16) metaIv 114(12) metaLen 126(u32BE,4) encMeta 130(metaLen) ' +
    'metaTag 130+metaLen(16) dataIv 146+metaLen(12) encData 158+metaLen ' +
    'dataTag len-16(16); container.length === 174 + metaLen + plaintextLength.',
  generatedWith: {
    package: pkg.name,
    version: pkg.version,
    kdf: 'argon2id',
    engine: 'node build (native argon2 or hash-wasm fallback)',
  },
  kdfParams: { ...KDF_PARAMS },
  vectors,
  containers,
};

mkdirSync(fixtureDir, { recursive: true });
writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

console.log(
  `[gen-node-vectors] Wrote ${vectors.length} self-verified v1 vectors and ` +
    `${containers.length} self-verified v2 containers to ` +
    `${path.relative(repoRoot, fixturePath)}.`
);
