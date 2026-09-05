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
node bench/codec.mjs          # base64url codec + inspectHeader (no KDF)
node bench/kdf.mjs            # Argon2id + PBKDF2 only
node bench/encrypt-text.mjs   # 1 KB and 1 MB text encrypt
node bench/encrypt-file.mjs   # 10 MiB file encrypt + decrypt streaming
```

`bench/codec.mjs` is the one group with no key derivation in it, and it runs
first for that reason — see [Why the codec group exists](#why-the-codec-group-exists).

## What's measured

| Group         | Cases                                                     |
| ------------- | --------------------------------------------------------- |
| Codec (no KDF) | `bytesToBase64url` and `base64urlToBytes` at 1 KiB / 1 MiB / 8 MiB, each with a `Buffer` reference row; `inspectHeader` on a ciphertext built from 1 MiB of plaintext, as a base64url string and as a `Uint8Array` |
| KDF           | Argon2id (default 128 MiB / t=3 / p=1), PBKDF2-SHA256 (default 600,000 iterations) |
| Text encrypt  | `encryptText` 1 KiB plaintext, `encryptText` 1 MiB plaintext |
| File streaming | `encryptFile` 10 MiB, `decryptFile` 10 MiB                |

Each case reports average and median latency, average and median throughput,
and the sample count it converged on (see [Output format](#output-format)).
Every bench file sets its own tinybench time and iteration budget rather than
taking the library defaults, because the groups differ by four to five orders
of magnitude: one Argon2id derivation at 128 MiB costs about as much as twenty
thousand 1 KiB pure-codec calls, or a third of a million native ones.

## Why the codec group exists

`bench/codec.mjs` measures the base64url codec on its own, with **no key
derivation anywhere in a measured case**.

It exists because the codec's cost was invisible everywhere else. Every other
group in this directory pays Argon2id at the default 128 MiB / t=3 / p=1
profile, which is ~100-400 ms per derivation depending on the host. Against that, even an encoder
trailing the platform's own by two orders of magnitude moves a 1 MiB
`encryptText` total by only a few percent — inside Argon2id's own run-to-run
spread. `bench/encrypt-text.mjs` therefore stayed flat while the codec
regressed underneath it, which is exactly the failure mode this group removes.
(The pure codec trailed `Buffer` by 71-137x before it was rewritten. It still
trails, by roughly 15-60x — the spread depends on the payload size and on
whether you compare average or median latency, since a GC pause inside a
handful of samples inflates the native rows' averages and so makes the
average-based ratio the conservative one. Read the real ratio off a pair of
rows rather than off a single number quoted in prose.)

Two conventions make the numbers readable:

- **Every pure-codec row is paired with a `Buffer` reference row**, spelled
  the same way the Node `CryptoManager` spells it in its `encodeBase64url` /
  `decodeBase64url` seam overrides — including `Buffer.from(ab, byteOffset,
  byteLength)` for the encode input, which wraps rather than copies. The ratio
  within a pair is the number worth tracking across releases; the absolute
  values are hardware-specific. The browser build has no `Buffer`, so it runs
  the pure row's implementation and the pure row is what browser consumers
  actually pay.
- **`inspectHeader` is measured in both of its input forms.** It decodes only
  the first 32 base64url characters, so the string row is dominated by the
  O(n) canonical-form scan over the whole string that has to run before the
  slice is known to be safe; the `Uint8Array` row skips that scan entirely.
  The gap between the two rows is the scan.

The file self-checks before it measures: it asserts the pure codec and
`Buffer` agree in both directions on every fixture, and that `inspectHeader`
returns the same header for both input forms. A bench that silently measures a
broken build would report a wrong answer as a speedup.

## Expected runtime

The full suite takes roughly **2.5-5.5 minutes** on a modern laptop:

- **The codec group** takes ~30 s and is the only one that is not KDF-bound.
  It runs first so a codec change gets an answer without waiting out
  Argon2id. Its 8 MiB rows are the slowest in the group at tens of
  milliseconds per call; the 1 KiB rows are microseconds and are bound by the
  1 s per-case time budget rather than by the iteration floor. One Argon2id
  derivation happens during its setup, at a deliberately cheap
  `memoryCost: 2 ** 14, timeCost: 1` profile, purely to mint the
  `inspectHeader` fixture — no measured case pays for it.
- **Argon2id key derivation** dominates the rest of the wall time. The default
  profile allocates 128 MiB and runs 3 passes per derivation — each call takes
  ~100-400 ms depending on the host (395 ms on the machine these figures were
  taken on). `bench/kdf.mjs` gives each of its two cases a 30 s budget, so that
  group takes ~70 s including warmup.
- **PBKDF2** at 600,000 iterations takes ~150-300 ms per call on modern CPUs
  and is the second of those two cases.
- **`encryptText` 1 KiB** is gated by Argon2id (one derivation per call),
  so it inherits Argon2id's runtime characteristics — typically the same
  order of magnitude as the raw KDF bench.
- **`encryptText` 1 MiB** and the **10 MiB file streaming benches** are
  similarly Argon2id-bound — the AES-GCM body work is a small fraction of
  the total time at the default KDF parameters.

If you want a fast sanity check, run `node bench/codec.mjs` on its own — it is
KDF-free and finishes in ~30 s. For the KDF-bound groups, lower `memoryCost`
and `timeCost` at the top of `bench/kdf.mjs` and `bench/encrypt-text.mjs`
(e.g. `memoryCost: 2 ** 12, timeCost: 1`) — the relative shape of the numbers
stays informative even though the absolute values are no longer
production-representative.

## CI integration

The benchmark suite is **not** wired into CI. Argon2id at 128 MiB is too slow
for hosted runners and the numbers vary too much between runner generations
to be useful as a regression check. Run benchmarks locally on a known machine
when you want comparable numbers across releases.

## Output format

Each bench file calls `bench.table()` at the end, which prints a table like:

```text
┌─────────┬───────────────────────────────────────────────────┬────────────────────┬────────────────────┬────────────────────────┬─────────┐
│ (index) │ Task name                                         │ Latency avg (ns)   │ Latency med (ns)   │ Throughput avg (ops/s) │ Samples │
├─────────┼───────────────────────────────────────────────────┼────────────────────┼────────────────────┼────────────────────────┼─────────┤
│    4    │ 'bytesToBase64url (1 MiB, pure codec)'            │ '10794741 ± 6.82%' │ '9371101 ± 360388' │ '98 ± 3.82%'           │   93    │
│    5    │ "Buffer.toString('base64url') (1 MiB, reference)" │ '323161 ± 11.44%'  │ '151729 ± 11905'   │ '6149 ± 0.93%'         │  3108   │
└─────────┴───────────────────────────────────────────────────┴────────────────────┴────────────────────┴────────────────────────┴─────────┘
```

Those two rows are real output from the codec group, with the
`Throughput med (ops/s)` column dropped to fit the page. Numbers are
illustrative only — your hardware will produce
different values. On the large native rows the average and the median can
diverge by 2x because a GC pause lands inside a handful of samples; the median
column is the more stable one to compare across runs.
