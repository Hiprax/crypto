// Benchmark runner — runs every bench file in this directory in sequence.
//
// Each child bench file is a standalone ESM module that runs its own
// tinybench `Bench` instance and prints a results table. We dynamically
// import them in fixed order so the output is grouped predictably.
//
// Why dynamic-import instead of a single shared `Bench` instance: each
// bench file already prints its own table when imported (the `await
// bench.run()` is at module top level), and grouping them under a single
// table would mix Argon2id-bound and AES-GCM-bound cases that aren't
// directly comparable. Separate tables keep the output readable.
//
// Expected total runtime: ~2-5 minutes on a modern laptop. Argon2id at the
// default 128 MiB profile dominates every group.

const start = Date.now();
console.log('=== @hiprax/crypto benchmarks ===');
console.log(
  `Started at ${new Date().toISOString()} — total runtime is typically 2-5 minutes.\n`
);

await import('./kdf.mjs');
await import('./encrypt-text.mjs');
await import('./encrypt-file.mjs');

const elapsedSec = ((Date.now() - start) / 1000).toFixed(1);
console.log(`\nAll benchmarks finished in ${elapsedSec}s.`);
