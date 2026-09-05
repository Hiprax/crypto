// Benchmark runner — runs every bench file in this directory in sequence.
//
// Each child bench file is a standalone ESM module that runs its own
// tinybench `Bench` instance and prints a results table. We dynamically
// import them in fixed order so the output is grouped predictably.
//
// Why dynamic-import instead of a single shared `Bench` instance: each
// bench file already prints its own table when imported (the `await
// bench.run()` is at module top level), and grouping them under a single
// table would mix KDF-free, Argon2id-bound and AES-GCM-bound cases that
// aren't directly comparable. Separate tables keep the output readable.
//
// Order matters in one place: `codec.mjs` runs FIRST because it is the only
// group with no key derivation in it. It is also the cheapest (~30 s), so a
// codec change gets its answer immediately instead of after several minutes
// of Argon2id. Everything after it is KDF-bound.
//
// Expected total runtime: ~2.5-5.5 minutes on a modern laptop. Argon2id at
// the default 128 MiB profile dominates every group except the first.

const start = Date.now();
console.log('=== @hiprax/crypto benchmarks ===');
console.log(
  `Started at ${new Date().toISOString()} — total runtime is typically 2.5-5.5 minutes.\n`
);

await import('./codec.mjs');
await import('./kdf.mjs');
await import('./encrypt-text.mjs');
await import('./encrypt-file.mjs');

const elapsedSec = ((Date.now() - start) / 1000).toFixed(1);
console.log(`\nAll benchmarks finished in ${elapsedSec}s.`);
