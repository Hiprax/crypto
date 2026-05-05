// Benchmark: streaming file encrypt + decrypt round-trip on a 10 MiB file
//
// Measures the end-to-end cost of the public file-streaming API:
//
//   - encryptFile  (async, Argon2id default, atomic temp-file write)
//   - decryptFile  (async, streaming decipher, GCM tag check)
//
// Both cases are dominated by Argon2id key derivation at the default
// 128 MiB / t=3 / p=1 profile (one derivation per call); the AES-GCM
// streaming body is a small fraction of the wall time at 10 MiB.
//
// Output paths use a fresh suffix per iteration so we never hit the existing
// atomic-rename code path's "destination exists" branch (which would skew
// timings — that's a workload property of the *caller*, not the encrypt
// path). Inputs are written once at startup and re-read each iteration.

import { Bench } from 'tinybench';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { CryptoManager } from '../dist/index.js';

const cm = new CryptoManager();
const password = 'MyBenchmarkP@ssw0rd123!';

const workDir = mkdtempSync(path.join(tmpdir(), 'hiprax-crypto-bench-'));
const plaintextPath = path.join(workDir, 'input.bin');
const ciphertextPath = path.join(workDir, 'input.enc');

// 10 MiB of pseudo-random bytes (deterministic for reproducibility — same
// shape across runs, but distinct from all-zeros so we exercise realistic
// AES-GCM body work, not a trivial keystream-XOR-with-zero special case).
const PAYLOAD_SIZE = 10 * 1024 * 1024;
const buf = Buffer.allocUnsafe(PAYLOAD_SIZE);
for (let i = 0; i < PAYLOAD_SIZE; i++) {
  buf[i] = (i * 31 + 7) & 0xff;
}
writeFileSync(plaintextPath, buf);

// Pre-generate a ciphertext for the decrypt bench. Both benches share the
// same plaintext+password, so the decrypt bench is a true round-trip of the
// encrypt bench's output.
console.log(`Pre-generating 10 MiB ciphertext for decrypt bench...`);
await cm.encryptFile(plaintextPath, ciphertextPath, password);

// Each encrypt iteration writes to a fresh path so we don't accidentally
// fall into "destination already exists" handling.
let encryptOutCounter = 0;
let decryptOutCounter = 0;
const encryptOutPath = () =>
  path.join(workDir, `encrypt-out-${encryptOutCounter++}.enc`);
const decryptOutPath = () =>
  path.join(workDir, `decrypt-out-${decryptOutCounter++}.bin`);

const bench = new Bench({
  name: 'encrypt-file',
  time: 30_000,
  iterations: 3,
});

bench
  .add(
    'encryptFile (10 MiB plaintext, async streaming, Argon2id default)',
    async () => {
      await cm.encryptFile(plaintextPath, encryptOutPath(), password);
    }
  )
  .add(
    'decryptFile (10 MiB ciphertext, async streaming, Argon2id default)',
    async () => {
      await cm.decryptFile(ciphertextPath, decryptOutPath(), password);
    }
  );

console.log(
  `Running ${bench.name} benchmarks (10 MiB payload, Argon2id default)...\n`
);

try {
  await bench.run();
  console.log(`\n=== ${bench.name} results ===`);
  console.table(bench.table());
} finally {
  // Clean up the temp directory regardless of whether the bench succeeded.
  // recursive: true so the per-iteration encrypt/decrypt output files go
  // with it.
  rmSync(workDir, { recursive: true, force: true });
}
