// Benchmark: text encryption at two payload sizes
//
//   - encryptText 1 KiB (small JSON-blob / config-row workload)
//   - encryptText 1 MiB (medium document workload)
//
// Both cases are gated by Argon2id key derivation at the default 128 MiB /
// t=3 / p=1 profile, so the bench measures end-to-end async encrypt latency
// (KDF + AES-GCM body + base64url encode + secureClear scrubbing).
//
// We deliberately use the public `encryptText` API rather than reaching for
// an internal "skip KDF" hook: production callers always pay the KDF cost,
// so that's what we measure. To isolate AES-GCM throughput, run kdf.mjs
// separately and subtract.

import { Bench } from 'tinybench';
import { CryptoManager } from '../dist/index.js';

const cm = new CryptoManager();
const password = 'MyBenchmarkP@ssw0rd123!';

// Generate the plaintext payloads once. tinybench will run the encrypt call
// many times against these fixed inputs.
const text1KiB = 'a'.repeat(1024);
const text1MiB = 'b'.repeat(1024 * 1024);

const bench = new Bench({
  name: 'encrypt-text',
  time: 30_000,
  iterations: 5,
});

bench
  .add('encryptText (1 KiB plaintext, async, Argon2id default)', async () => {
    await cm.encryptText(text1KiB, password);
  })
  .add('encryptText (1 MiB plaintext, async, Argon2id default)', async () => {
    await cm.encryptText(text1MiB, password);
  });

console.log(
  `Running ${bench.name} benchmarks (Argon2id default: ~150-300 ms per call)...\n`
);

await bench.run();

console.log(`\n=== ${bench.name} results ===`);
console.table(bench.table());
