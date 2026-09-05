// Benchmark: base64url codec + inspectHeader (no key derivation at all)
//
// Why this file exists
// --------------------
// Every other bench in this directory is gated by Argon2id at the default
// 128 MiB / t=3 / p=1 profile, which costs ~150-300 ms per derivation. That
// single number dwarfs everything else in `encrypt-text.mjs`: even at the two
// orders of magnitude the pure codec once trailed the platform's own encoder
// by, a 1 MiB `encryptText` total moved by only a few percent, which is inside
// Argon2id's own run-to-run spread. The cost was therefore invisible — the
// text bench stayed flat while the codec regressed underneath it. (The pure
// codec trailed `Buffer` by 71-137x before it was rewritten and by roughly
// 15-60x after, the spread depending on payload size and on whether you
// compare average or median latency — read the real ratio off the pair of
// rows below rather than off any single number quoted in a comment.)
//
// So this file removes the KDF from the measurement entirely. Nothing here
// derives a key, and the only work on the clock is the codec (or, for the
// last two rows, header inspection). A regression in these paths shows up
// here as a directly readable multiple, not as noise in a KDF-bound total.
//
// What is measured
// ----------------
//   - `bytesToBase64url` and `base64urlToBytes` (the pure, isomorphic codec
//     from `./codec.js`, which is what the BROWSER build runs) at 1 KiB,
//     1 MiB and 8 MiB.
//   - A `Buffer` reference row beside each of those six, spelled exactly the
//     way the Node `CryptoManager` spells it in its `encodeBase64url` /
//     `decodeBase64url` seam overrides (`src/crypto-manager.ts`). The encode
//     reference wraps the input as a VIEW — `Buffer.from(ab, byteOffset,
//     byteLength)` — rather than `Buffer.from(bytes)`, which would copy and
//     make the native side look artificially slow. These rows are the floor
//     the pure codec is measured against, and the ratio between a pair is
//     the number worth tracking across releases.
//   - `inspectHeader` on a ciphertext produced from 1 MiB of plaintext,
//     given as a string, plus a `Uint8Array` reference row for the same
//     record. `inspectHeader` decodes only the first 32 base64url characters
//     (see `HEADER_B64URL_PREFIX_CHARS` in `src/core.ts`), so the string row
//     is dominated by the O(n) canonical-form scan over the WHOLE string
//     that has to run first; the `Uint8Array` row skips that scan and shows
//     what is left once it is gone. The gap between the two rows IS the scan.
//
// Runs against the compiled `dist/` output, like every other bench here, so
// `npm run build` is a prerequisite.
//
// Expected runtime: ~30 s. There is no KDF in any measured case.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { Bench } from 'tinybench';

import {
  CryptoManager,
  bytesToBase64url,
  base64urlToBytes,
} from '../dist/index.js';

const KiB = 1024;
const MiB = 1024 * 1024;

// Fixed fixture sizes. 8 MiB is the largest because the base64url encoding of
// it is ~11.2 M characters, comfortably under V8's ~512 MiB string cap while
// still being large enough that per-call overhead is irrelevant.
const SIZES = [
  ['1 KiB', 1 * KiB],
  ['1 MiB', 1 * MiB],
  ['8 MiB', 8 * MiB],
];

// A plain `Uint8Array`, deliberately NOT a `Buffer`: that is what
// `CryptoCore.encryptBytes` hands to the encode seam via `concatBytes`, and
// it is the branch the Node override has to wrap as a view.
const asPlainBytes = n => new Uint8Array(randomBytes(n));

// Fixtures: one random byte array per size, and its canonical base64url form
// produced by `Buffer` (the trusted oracle the codec's own tests use), so the
// pure decoder and the native decoder are fed byte-identical input.
const fixtures = SIZES.map(([label, size]) => {
  const bytes = asPlainBytes(size);
  const encoded = Buffer.from(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength
  ).toString('base64url');
  return { label, size, bytes, encoded };
});

// Self-check before measuring anything. A bench that silently measures a
// broken build is worse than no bench: it would report a "speedup" that is
// really a wrong answer. This asserts the two implementations agree on every
// fixture, in both directions, before a single sample is taken.
for (const { label, bytes, encoded } of fixtures) {
  assert.equal(
    bytesToBase64url(bytes),
    encoded,
    `pure encoder disagrees with Buffer at ${label}`
  );
  assert.deepStrictEqual(
    base64urlToBytes(encoded),
    bytes,
    `pure decoder disagrees with Buffer at ${label}`
  );
}

// The `inspectHeader` fixture needs a real v1 record, and producing one needs
// one key derivation. That derivation happens HERE, once, outside every
// measured case — and at a deliberately cheap Argon2id profile, because
// `inspectHeader`'s cost does not depend on the KDF parameters stamped into
// the header it reads. The manager that does the inspecting is the default
// one, so the measured rows use production settings.
const fixtureCm = new CryptoManager({ memoryCost: 2 ** 14, timeCost: 1 });
const cm = new CryptoManager();
const password = 'MyBenchmarkP@ssw0rd123!';

const ciphertext = await fixtureCm.encryptText('c'.repeat(1 * MiB), password);
const ciphertextBytes = base64urlToBytes(ciphertext);

// Same self-check discipline: prove the fixture is actually a v1 record and
// that both input forms parse to the same header, so the two rows below are
// measuring the same work minus the scan rather than two different things.
const inspected = cm.inspectHeader(ciphertext);
assert.notEqual(inspected, null, 'inspectHeader fixture is not a v1 record');
assert.deepStrictEqual(
  cm.inspectHeader(ciphertextBytes),
  inspected,
  'inspectHeader disagrees between its string and Uint8Array input forms'
);

// Blackhole. Every measured call's result is written here so V8 cannot decide
// the work is dead and elide it; `sink` is read once at the end of the file.
let sink = 0;

// tinybench v6 defaults are time: 1000 ms, iterations: 64, warmupIterations:
// 16. 64 + 16 runs of an 8 MiB encode would spend ~8 s on one row for no
// extra precision, so the iteration floors are lowered and the 1000 ms time
// budget is left to govern the small cases (where it is what binds).
// `throws: true` because a task that throws must fail this file loudly rather
// than print a row of zeros.
const bench = new Bench({
  name: 'codec',
  time: 1_000,
  iterations: 20,
  warmupIterations: 5,
  throws: true,
});

for (const { label, bytes, encoded } of fixtures) {
  bench
    .add(`bytesToBase64url (${label}, pure codec)`, () => {
      sink = bytesToBase64url(bytes).length;
    })
    .add(`Buffer.toString('base64url') (${label}, reference)`, () => {
      sink = Buffer.from(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength
      ).toString('base64url').length;
    })
    .add(`base64urlToBytes (${label}, pure codec)`, () => {
      sink = base64urlToBytes(encoded).byteLength;
    })
    .add(`Buffer.from(s, 'base64url') (${label}, reference)`, () => {
      sink = Buffer.from(encoded, 'base64url').byteLength;
    });
}

bench
  .add('inspectHeader (1 MiB ciphertext, base64url string)', () => {
    sink = cm.inspectHeader(ciphertext).params.memoryCost;
  })
  .add('inspectHeader (1 MiB ciphertext, Uint8Array, reference)', () => {
    sink = cm.inspectHeader(ciphertextBytes).params.memoryCost;
  });

console.log(`Running ${bench.name} benchmarks (no key derivation)...`);
console.log(`  - payload sizes: ${SIZES.map(([l]) => l).join(', ')}`);
console.log(
  `  - inspectHeader fixture: ${ciphertext.length} base64url characters`
);
console.log(
  `  - reference rows use Buffer exactly as the Node seam does\n`
);

await bench.run();

console.log(`\n=== ${bench.name} results ===`);
console.table(bench.table());

// Read the blackhole so it cannot be optimised away. In a healthy run it holds
// the last case's `params.memoryCost`, which is `fixtureCm`'s 2**14 — note the
// KDF parameters live on `ParsedHeader.params`, not on the header object
// itself (`src/format-core.ts`), so reading `.memoryCost` directly would
// silently store `undefined` here and make this guard vacuous.
if (sink !== 2 ** 14) {
  throw new Error(
    `codec bench sink is ${sink}, expected ${2 ** 14} — the last case did not ` +
      'run as intended and the results are not meaningful. (A case that THREW ' +
      'would have failed earlier, at bench.run(), because throws: true is set.)'
  );
}
