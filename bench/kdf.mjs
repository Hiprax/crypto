// Benchmark: key derivation (Argon2id default + PBKDF2 default)
//
// Runs the public KDF entry points exposed by CryptoManager:
//
//   - deriveKey       (Argon2id, async, default 128 MiB / t=3 / p=1)
//   - deriveKeySync   (PBKDF2-HMAC-SHA256, default 600,000 iterations)
//
// Both calls use a fresh 32-byte salt per invocation (matching real-world
// usage — each encrypt call generates a fresh random salt) so we measure
// steady-state KDF cost rather than a degenerate cached-input case.
//
// Expected runtime: ~2-3 minutes total. Argon2id dominates.

import { Bench } from 'tinybench';
import { CryptoManager } from '../dist/index.js';

const cm = new CryptoManager();
const password = 'MyBenchmarkP@ssw0rd123!';

// Pre-generate a salt pool so the benchmark is not measuring randomBytes()
// throughput. Each iteration picks the next salt out of the pool.
const SALT_POOL = 64;
const salts = [];
for (let i = 0; i < SALT_POOL; i++) {
  salts.push(cm.generateSecureRandom(32));
}
let saltIdx = 0;
const nextSalt = () => salts[saltIdx++ % SALT_POOL];

// tinybench v6: pass options as second argument to constructor.
//   - time: total time budget per case in ms (default 500)
//   - iterations: minimum iteration count (default 10)
// Argon2id at 128 MiB takes ~150-300 ms per call, so we widen the budget so
// tinybench has enough samples to compute a stable mean. PBKDF2 inherits
// the same budget for symmetry; it's faster so it samples more.
const bench = new Bench({
  name: 'kdf',
  time: 30_000, // 30 s per case
  iterations: 5,
});

bench
  .add('Argon2id (default: 128 MiB, t=3, p=1, 32-byte key)', async () => {
    await cm.deriveKey(password, nextSalt());
  })
  .add('PBKDF2-SHA256 (default: 600,000 iterations, 32-byte key)', () => {
    cm.deriveKeySync(password, nextSalt());
  });

console.log(`Running ${bench.name} benchmarks (this can take 2-5 minutes)...`);
console.log(`  - Argon2id default profile: 128 MiB, 3 passes, 1 lane`);
console.log(`  - PBKDF2-SHA256 default: 600,000 iterations\n`);

await bench.run();

console.log(`\n=== ${bench.name} results ===`);
console.table(bench.table());
