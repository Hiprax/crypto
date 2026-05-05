# Benchmarks

Performance benchmarks for `@hiprax/crypto`, driven by
[tinybench](https://github.com/tinylibs/tinybench).

## Running

The benchmark suite runs against the compiled `dist/` output, so build first:

```bash
npm run build
npm run bench
```

The default `npm run bench` runs every benchmark below in sequence and prints a
single tinybench results table per group. Individual benchmark files can be
run on their own:

```bash
node bench/kdf.mjs            # Argon2id + PBKDF2 only
node bench/encrypt-text.mjs   # 1 KB and 1 MB text encrypt
node bench/encrypt-file.mjs   # 10 MiB file encrypt + decrypt streaming
```

## What's measured

| Group         | Cases                                                     |
| ------------- | --------------------------------------------------------- |
| KDF           | Argon2id (default 128 MiB / t=3 / p=1), PBKDF2-SHA256 (default 600,000 iterations) |
| Text encrypt  | `encryptText` 1 KiB plaintext, `encryptText` 1 MiB plaintext |
| File streaming | `encryptFile` 10 MiB, `decryptFile` 10 MiB                |

Each case reports throughput (ops/sec), mean latency, p99, and standard
deviation. Tinybench's defaults are used (warmup, iteration count auto-tuned
per case until results stabilise).

## Expected runtime

The full suite takes roughly **2-5 minutes** on a modern laptop:

- **Argon2id key derivation** dominates the wall time. The default profile
  allocates 128 MiB and runs 3 passes per derivation — each call takes
  ~100-300 ms depending on the host. Tinybench will sample roughly 30-50
  iterations to converge, so this single bench typically takes 60-90 s.
- **PBKDF2** at 600,000 iterations takes ~150-300 ms per call on modern
  CPUs and similarly takes 30-60 s to converge.
- **`encryptText` 1 KiB** is gated by Argon2id (one derivation per call),
  so it inherits Argon2id's runtime characteristics — typically the same
  order of magnitude as the raw KDF bench.
- **`encryptText` 1 MiB** and the **10 MiB file streaming benches** are
  similarly Argon2id-bound — the AES-GCM body work is a small fraction of
  the total time at the default KDF parameters.

If you want a fast sanity check, lower `memoryCost` and `timeCost` at the top
of `bench/kdf.mjs` and `bench/encrypt-text.mjs` (e.g. `memoryCost: 2 ** 12,
timeCost: 1`) — the relative shape of the numbers stays informative even
though the absolute values are no longer production-representative.

## CI integration

The benchmark suite is **not** wired into CI. Argon2id at 128 MiB is too slow
for hosted runners and the numbers vary too much between runner generations
to be useful as a regression check. Run benchmarks locally on a known machine
when you want comparable numbers across releases.

## Output format

Each bench file calls `bench.table()` at the end, which prints a table like:

```text
┌─────────┬───────────────────────────────┬─────────────┬──────────────────┬─────────────┬─────────┐
│ (index) │ Task name                     │ ops/sec     │ Average Time (ns)│ Margin      │ Samples │
├─────────┼───────────────────────────────┼─────────────┼──────────────────┼─────────────┼─────────┤
│    0    │ 'Argon2id (128 MiB, t=3)'    │ '4 ± 2.50%' │   220314000      │ ' ± 5.50%'  │    20   │
│    1    │ 'PBKDF2-SHA256 (600k iters)' │ '5 ± 1.10%' │   180120000      │ ' ± 2.40%'  │    25   │
└─────────┴───────────────────────────────┴─────────────┴──────────────────┴─────────────┴─────────┘
```

Numbers are illustrative only — your hardware will produce different values.
