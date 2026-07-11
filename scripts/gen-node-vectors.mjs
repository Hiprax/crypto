#!/usr/bin/env node
/**
 * Golden interop-vector generator for @hiprax/crypto.
 *
 * Produces `src/__tests__/fixtures/node-vectors.json` — a committed set of
 * ciphertexts encrypted by the **Node** build's `encryptText()`. The browser
 * build must decrypt each `ciphertext` (with its `password`) back to the
 * recorded `plaintext`; that is the frozen, cross-runtime proof that there is
 * exactly ONE wire format and that a Node-produced ciphertext round-trips into
 * the browser. The Node-run companion test lives in
 * `src/__tests__/interop.test.ts`; the real-headless-Chromium companion is
 * added in Phase 9 (`src/__tests__/browser/interop.browser.test.ts`).
 *
 * ---------------------------------------------------------------------------
 * REGENERATION
 * ---------------------------------------------------------------------------
 *   npm run build && node scripts/gen-node-vectors.mjs
 *
 * The script imports the COMPILED Node entry (`dist/index.js`), so `dist/` must
 * exist first (run `npm run build`). Each ciphertext embeds a fresh random salt
 * and IV, so every run rewrites every `ciphertext` string — decryption stays
 * correct because the KDF salt and the GCM IV are carried on the wire. The
 * inputs (passwords, plaintexts, KDF parameters) are fixed here, so the
 * fixture's SHAPE is stable across regenerations; only the opaque ciphertext
 * bytes change.
 *
 * The KDF parameters are intentionally the repo's TEST-ONLY low-cost profile
 * (`memoryCost = 2**14` KiB = 16 MiB, `timeCost = 1`, `parallelism = 1`) so the
 * Node and browser suites derive quickly. NEVER use these parameters in
 * production; the browser production default is 32 MiB (see
 * `crypto-manager.browser.ts`) and the Node default is 128 MiB.
 *
 * Before writing, the script SELF-VERIFIES every vector by decrypting it with
 * the same Node manager (and checking the embedded header parameters), so a
 * regeneration can never commit a vector that does not round-trip.
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
const { CryptoManager } = await import(pathToFileURL(distEntry).href);

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
    'Golden cross-runtime interop vectors. Each `ciphertext` was produced by ' +
    "the Node build's encryptText(plaintext, password). The browser build MUST " +
    'decrypt each one back to `plaintext` — proof that Node and the browser ' +
    'share ONE wire format. Consumed by src/__tests__/interop.test.ts (Node) ' +
    'and, in a real browser, by src/__tests__/browser/interop.browser.test.ts.',
  _generator: 'scripts/gen-node-vectors.mjs',
  _regenerate: 'npm run build && node scripts/gen-node-vectors.mjs',
  _note:
    'Ciphertexts embed a fresh random salt + IV, so regeneration changes every ' +
    '`ciphertext` string (decryption stays correct). The KDF parameters are the ' +
    "repo's TEST-ONLY low-cost profile — never use them in production.",
  generatedWith: {
    package: pkg.name,
    version: pkg.version,
    kdf: 'argon2id',
    engine: 'node build (native argon2 or hash-wasm fallback)',
  },
  kdfParams: { ...KDF_PARAMS },
  vectors,
};

mkdirSync(fixtureDir, { recursive: true });
writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

console.log(
  `[gen-node-vectors] Wrote ${vectors.length} self-verified vectors to ` +
    `${path.relative(repoRoot, fixturePath)}.`
);
