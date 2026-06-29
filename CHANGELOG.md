# Changelog

## [Unreleased]

### Fixed

- **Constructor now rejects KDF parameters above the wire-format DoS caps** (`src/crypto-manager.ts`). Previously, a `CryptoManager` constructed with `memoryCost > 2^22`, `timeCost > 100`, `parallelism > 64`, `pbkdf2Iterations > 10,000,000`, or `legacyPbkdf2Iterations > 10,000,000` would encrypt successfully but produce ciphertext that could never be decrypted (`KDF_PARAMS_OUT_OF_BOUNDS` at parse time). The fix imports the exact cap constants from `src/format.ts` (single source of truth) and throws `CryptoError(INVALID_INPUT)` with an actionable message immediately at construction, converting silent data loss into a fail-fast error. The caps are generous: the library's default (`HIGH` tier, `memoryCost = 2^17`, `timeCost = 3`) and the documented `ULTRA` tier (`memoryCost = 2^19`, `timeCost = 4`) both clear the bounds by a large margin. All previously-working configurations are unaffected. New error codes: `MEMORY_COST_TOO_LARGE`, `TIME_COST_TOO_LARGE`, `PARALLELISM_TOO_LARGE`, `PBKDF2_ITERATIONS_TOO_LARGE`, `LEGACY_PBKDF2_ITERATIONS_TOO_LARGE`.
- New tests covering over-cap construction (all five parameters), at-cap boundary construction (must not throw), and sync/async round-trips confirming that every constructable configuration produces decryptable ciphertext (`src/__tests__/crypto-manager.test.ts`).
- **`encryptFile` async write path hardened against stream errors** (`src/crypto-manager.ts`). The previous `writeChunk` helper had three confirmed bugs affecting the upfront `[header][salt][iv]` prefix write and the trailing GCM auth-tag write (the body goes through `pipeline()` which manages its own errors). (1) On the `ok===true` (immediate) path, `resolve()` was called synchronously before the write callback fired; a subsequent write-callback error was silently dropped and the stream `'error'` event went unhandled, crashing the process with `ERR_UNHANDLED_ERROR`. (2) On the `ok===false` (backpressured) path, a stream `'error'` event before `'drain'` caused the `writeChunk` promise to hang forever AND crashed the process. (3) The `'drain'` listener was never removed if the stream errored while backpressured (listener leak). The fix attaches a single persistent `'error'` listener (`onStreamError`) to `outputStream` for the lifetime of the operation; it records the error and rejects any in-flight `writeChunk` promise. The `writeChunk` promise now uses an idempotent `settleOnce` guard and always cleans up transient `'drain'` listeners on error. The persistent listener is removed after `outputStream.end()` completes in the `finally` block. The `ok===true` path no longer resolves synchronously — it waits for the write callback. `pipeline()`'s own error listeners are unaffected (Node streams support multiple `'error'` listeners). Four new failure-path tests cover: prefix-write error (immediate), prefix-write error (backpressured / `ok===false`), tag-write error (immediate), tag-write error (backpressured) — each asserting rejection with `CryptoError`, no orphan `.tmp` file, and any pre-existing output path left untouched.
- New tests (`src/__tests__/streaming-cleanup.test.ts`): 4 new tests in the "outputStream write error injection" describe block (Phase 2 / Task 2.2).
- **Derived key is now scrubbed via `secureClear` on error paths in all eight high-level methods** (`src/crypto-manager.ts`). Previously, when a method threw after successfully deriving the 32-byte AES-256 key (e.g. wrong password causing a GCM tag mismatch in `decryptData`, a disk error mid-stream in `encryptFile`, or a throwing progress callback in `encryptFileSync`), the key `Buffer` was left unscrubbed until GC — a defense-in-depth gap. The fix hoists `key` to `let key: Buffer | null = null` before each method's `try` block and adds `if (key !== null) { this.secureClear(key); }` at the top of each `catch` block. The scope is strictly limited to `key` (a standalone `Buffer` returned directly from `deriveKey`/`deriveKeySync`); other Buffers that are subarray views (`salt`, `iv`, `tag`, `combined`, `front`) are not touched on error paths. Success-path scrubs are unchanged.
- New tests (`src/__tests__/crypto-manager.test.ts`): 8 tests in `describe('key scrub on error paths (Phase 3 — Tasks 3.1/3.2)')` — one per method — each forcing a post-derivation failure (via `encryptData` spy for encrypt methods, wrong-password GCM mismatch for decrypt methods, and progress-callback throws for file methods) and asserting `secureClear` was called with a 32-byte `Buffer`.

- **`validatePasswordStrength.isValid` now mirrors `isValidPassword` exactly** (`src/utils.ts`). Previously, `isValid` was computed as `score >= 4 && feedback.length === 0`. Repeat-character advisory penalties (e.g. `/(.)\1{2,}/` → "Avoid repeated characters") added to `feedback`, causing `isValid: false` for passwords that `isValidPassword` (and therefore `encryptText`) correctly accepts — for example `'Aaaa1234_'` and `'Passw0rd!!!'`. This violated the JSDoc claim that the two validators agree. The fix computes `isValid` directly from the two acceptance rules (`length >= 20` passphrase shortcut OR `length >= 8` with all four character categories), independent of `score`/`feedback`, which remain unchanged as advisory strength signals. The JSDoc was updated to accurately describe the contract. New parity tests assert `validatePasswordStrength(p).isValid === isValidPassword(p)` across a battery of eight inputs, including both regression cases and edge cases (too-short, missing categories, passphrase rule, non-string) (`src/__tests__/utils.test.ts`).

- **async `decryptFile` now verifies the front-matter `bytesRead`** (`src/crypto-manager.ts`). The async path called `fileHandle.read(front, 0, frontReadLen, 0)` and discarded the returned `{ bytesRead }`, unlike the sync path (`decryptFileSync`) and the async tag-read in the same method — both of which already check for a short read. On a normally-functioning local filesystem the gap is benign (GCM authentication safely rejects corrupted data), but on truncated or network-backed files the async path would surface a misleading error code. The fix captures `frontBytesRead` and throws `CryptoError(INVALID_INPUT, 'INVALID_ENCRYPTED_FILE_SIZE', 'Failed to read full file header region')` when `frontBytesRead !== frontReadLen`, mirroring both the sync path and the tag-read check exactly.
- **File-method path arguments now reject non-string truthy values** (`src/crypto-manager.ts`). `encryptFile`, `decryptFile`, `encryptFileSync`, and `decryptFileSync` previously guarded with `if (!inputPath || !outputPath)`, which passes non-string truthy arguments (e.g. a `number` or `object`) through to filesystem calls and surfaces an opaque wrapped error. The fix adds `typeof inputPath !== 'string' || typeof outputPath !== 'string'` to each guard, throwing `CryptoError(INVALID_INPUT, 'MISSING_REQUIRED_PARAMS')` immediately — consistent with the text methods' guard pattern.
- New tests: one "non-string path arguments" test per file method in `src/__tests__/crypto-manager.test.ts`; one mock-based "short front-matter read" test in `src/__tests__/streaming-cleanup.test.ts` asserting the `INVALID_ENCRYPTED_FILE_SIZE` code and `INVALID_INPUT` type.

- **`encryptFileSync` now streams the plaintext in fixed 64 KiB chunks** (`src/crypto-manager.ts`). Previously `encryptFileSync` read the entire input into memory with `readFileSync`, produced the full ciphertext buffer in memory, and wrote it in a single `writeFileSync` call — peak memory ≈ 2× file size, which could OOM or stall the event loop for large files. The rewrite mirrors `decryptFileSync`'s proven chunked pattern (reversed): open the temp file with `openSync(..., 'w')`; write `[v1 header][salt][iv]` first; then loop `readSync` over the input in 64 KiB blocks → `cipher.update(chunk)` → `writeFileSync(fd, outSlice)` → repeat; then `writeFileSync(fd, cipher.final())` and `writeFileSync(fd, cipher.getAuthTag())`; `closeSync`; atomic rename. The on-disk layout `[v1 header][salt][iv][ciphertext body][auth tag]` is byte-identical to the previous implementation — existing ciphertexts and callers are unaffected. Peak memory is now bounded by the 64 KiB chunk size regardless of input file size. The `SYNC_ENCRYPT_CHUNK_SIZE` private constant (64 KiB) mirrors `SYNC_DECRYPT_CHUNK_SIZE`. Progress contract is unchanged (two bracketing events: `(0, total)` before work, `(total, total)` after rename). Error cleanup now closes both `inputFd` and `outputFd` before unlinking the temp file.
- New tests (`src/__tests__/crypto-manager.test.ts`): 5 new tests in `describe('encryptFileSync - chunked streaming round-trips (Phase 6)')` — multi-chunk sync round-trip (> 128 KiB, 4 loop iterations), cross-path round-trip (`encryptFileSync` → async `decryptFile`), empty-file round-trip, sub-chunk round-trip (100 bytes), and v1 byte-layout field-size sanity check confirming the format is unchanged.

### Files changed

- `src/crypto-manager.ts` — import `MAX_ARGON2_MEMORY_COST`, `MAX_ARGON2_TIME_COST`, `MAX_ARGON2_PARALLELISM`, `MAX_PBKDF2_ITERATIONS` from `./format.js`; add upper-bound checks in constructor; harden `encryptFile` `writeChunk` helper and add persistent `onStreamError` guard; hoist `key` before each method's `try` block and add catch-path `secureClear(key)` in all eight high-level encrypt/decrypt methods; capture `frontBytesRead` in `decryptFile` front-matter read; add `typeof` string guards to all four file method path args; rewrite `encryptFileSync` to stream in fixed 64 KiB chunks (remove `readFileSync` dependency); add `SYNC_ENCRYPT_CHUNK_SIZE` private constant.
- `src/__tests__/crypto-manager.test.ts` — 8 new tests in the `Constructor` describe block; 8 new key-scrub error-path tests in the `key scrub on error paths (Phase 3)` describe block; 4 new non-string path argument tests (one per file method); 5 new Phase 6 streaming round-trip tests.
- `src/__tests__/streaming-cleanup.test.ts` — 4 new failure-path tests for `outputStream` error injection during prefix and tag writes; 1 new short front-matter read test for `decryptFile`.
- `src/utils.ts` — decouple `validatePasswordStrength.isValid` from advisory score/feedback; update JSDoc.
- `src/__tests__/utils.test.ts` — parity test battery for `validatePasswordStrength` vs `isValidPassword`.
- `CLAUDE.md` — updated Constructor Options table to document the upper bounds; updated design decision §9 and `encryptFileSync` method bullet to reflect chunked streaming.

---

## 2026-05-12 (v1.3.5 — CodeQL alert triage, drop Dependencies badge)

Hygiene-only patch release. No source changes, no public API changes, no wire-format changes, no devDependency changes. The published tarball is bit-identical to v1.3.4 (the changes are README + GitHub-side alert state only).

### What changed

CodeQL alerts on `main` (all 98 open warnings) triaged and dismissed:

- **91 × `js/insecure-temporary-file`** — dismissed as `used in tests` (87) or `false positive` (4).
  - The 87 test alerts flag the documented per-suite scratch-directory pattern: `path.join(os.tmpdir(), 'hiprax-crypto-${randomBytes(8).hex}')`. 64 bits of entropy in the suffix make CWE-377-style pre-existing-file collision infeasible; the pattern is the project's standard testing convention (see CLAUDE.md).
  - The 4 source-tree alerts flag `tempPath = this.buildTempOutputPath(outputPath)` in `src/crypto-manager.ts`. `buildTempOutputPath` returns `${outputPath}.<8 hex bytes>.tmp` — a sibling of the user-supplied output path, **not** a file in `os.tmpdir()`. CodeQL misclassified on the `randomBytes + .tmp` signature.
- **5 × `js/file-system-race`** — dismissed as `won't fix`. Atomic rename with a random temp suffix is the canonical defense for this TOCTOU class; `validateFile` is documented as syntactic-only and not symlink-aware (callers needing strict containment use `validatePath` with the `allowedRoot` option). Two of the five are in a test-only `filesEqualSync` helper.
- **2 × `js/missing-await`** — dismissed as `false positive`. Both flag `src/crypto-manager.ts:592`, which is the intentional compare-and-swap on the in-flight Argon2 module cache slot (`argon2ModuleCache === inFlight`). The comparison is on promise identity, not resolved value; awaiting would defeat the CAS pattern.

README:

- Dropped the libraries.io "Dependencies" badge. Signal isn't worth the row in the badge strip for a single-runtime-dep package.

### Files changed

- `README.md` — removed the `librariesio/release/npm/@hiprax/crypto` badge from the header.
- `package.json` — version `1.3.4` → `1.3.5`.
- `CHANGELOG.md` — this entry.

### Verification

`build`, `lint`, `type-check`, and the full test suite pass identically to v1.3.4. No source files were touched.

## 2026-05-12 (v1.3.4 — Codecov integration, repo-side hardening, README badge sweep)

Hygiene-only patch release. No source changes, no public API changes, no wire-format changes, no devDependency changes. The published tarball is bit-identical to v1.3.3 (the changes are CI-config and repo-settings only).

### What changed

CI / repo automation:

- `ci.yml` — Ubuntu / Node 22 leg now runs `npm test -- --coverage` and uploads `coverage/lcov.info` to Codecov via `codecov/codecov-action@v6`. Other matrix legs stay on plain `npm test`. The upload step is gated to non-fork PRs so secret-less fork runs don't emit warnings.
- `codecov.yml` (new) — Codecov configured as a visualization-only layer: project + patch targets at 80% with `if_ci_failed: success` and `if_not_found: success`, so Codecov can never block a merge by itself. The local Jest `coverageThreshold` (80% across branches/functions/lines/statements) remains the actual gate. Ignore patterns cover `dist/`, `bench/`, tests, `.d.ts`, and `node_modules`.

GitHub repo hardening (applied via `gh api`, not file-based — listed here so future maintainers know what's configured server-side):

- Branch ruleset for `main` — block force-push and deletion; require status checks `Test (ubuntu-latest, Node 22)`, `Test (ubuntu-latest, Node 24)`, `Test (windows-latest, Node 22)`, `Test (windows-latest, Node 24)`, and `Analyze (javascript-typescript)` to pass before merge; require a pull request before merging (0 required approvals — solo maintainers can self-merge). Repository admin role has `bypass_mode: always` so the maintainer can still push directly to `main` for releases.
- Tag ruleset for `v*` — block deletion, update, and force-push of release tags so tagged release history cannot be rewritten.
- Discussions enabled (the issue-template `config.yml` already routes "question / discussion" links there).
- Dependabot security alerts enabled (security-advisory alerts only — automatic version-bump PRs are intentionally NOT enabled per project policy).
- `delete_branch_on_merge: true` — auto-cleanup of merged feature branches.
- `allow_auto_merge: true`, `allow_update_branch: true` — convenience options for the eventual flow once contributors land.
- Secret scanning + secret-push-protection were already enabled and are confirmed retained.

README badges:

- Codecov, CodeQL — backfilled (Codecov was new this release; CodeQL should have shipped with v1.3.2 but the badge was missed).
- Dependencies — `librariesio/release` badge linking to libraries.io; will stay green as long as no direct dep has an outdated release.
- npm provenance — static badge linking to the npm package page (every release since v1.3.2 ships with `--provenance` attestation via OIDC; the badge advertises the guarantee).

### Files changed

- `.github/workflows/ci.yml` — Codecov upload step (shipped in 9115a17, between v1.3.3 and v1.3.4).
- `codecov.yml` (new) — Codecov config.
- `README.md` — five badge additions: Codecov, CodeQL, Dependencies, npm provenance, plus the existing CI / license / npm / TypeScript / Node.js row.
- `package.json` — version `1.3.3` → `1.3.4`.
- `CHANGELOG.md` — this entry.

### Verification

`build`, `lint`, `type-check`, and the full 598-test suite pass identically to v1.3.3. Coverage upload to Codecov on the v1.3.4-precursor commit (9115a17) reported 96.18% statements / 90.01% branches / 97.61% functions / 96.15% lines — well above the 80% floor. The release-workflow run for this tag is the end-to-end verification that the rulesets-enabled `main` branch still accepts the maintainer-direct release push (admin bypass on the PR-required rule).

## 2026-05-12 (v1.3.3 — Clear Node-20-action deprecation warnings on workflow runs)

Hygiene-only patch release shipped within minutes of v1.3.2. No source changes, no public API changes, no wire-format changes, no devDependency changes. The published tarball is bit-identical to v1.3.2.

### What changed

The v1.3.2 release run surfaced a GitHub-side deprecation warning that the project's pinned action majors still ran on Node.js 20, which GitHub is removing from runners on 2026-09-16 (forced to Node 24 from 2026-06-02). The action authors all have stable Node-24-native majors available; this release moves to them.

| Action | v1.3.2 | v1.3.3 | Latest at pin time |
| --- | --- | --- | --- |
| `actions/checkout` | `@v4` | `@v6` | v6.0.2 |
| `actions/setup-node` | `@v4` | `@v6` | v6.4.0 |
| `softprops/action-gh-release` | `@v2` | `@v3` | v3.0.0 |
| `github/codeql-action/init` | `@v3` | `@v4` | v4.35.4 |
| `github/codeql-action/analyze` | `@v3` | `@v4` | v4.35.4 |

No breaking surface in any of the upgrades — all are major versions whose release notes explicitly list the runtime move (Node 20 → Node 24) as the primary motivation, with the action's own inputs/outputs unchanged.

### Files changed

- `.github/workflows/ci.yml` — `checkout @v4 → @v6`, `setup-node @v4 → @v6`.
- `.github/workflows/release.yml` — `checkout @v4 → @v6`, `setup-node @v4 → @v6`, `action-gh-release @v2 → @v3`.
- `.github/workflows/codeql.yml` — `checkout @v4 → @v6`, `codeql-action/init @v3 → @v4`, `codeql-action/analyze @v3 → @v4`.
- `package.json` — version `1.3.2` → `1.3.3`.
- `CHANGELOG.md` — this entry.

### Verification

`build`, `lint`, `type-check`, and the full 598-test suite pass identically to v1.3.2 (the changes are workflow-file-only and the published tarball is unchanged). The release.yml run for this tag is the actual verification that the upgraded actions still chain correctly end-to-end.

## 2026-05-12 (v1.3.2 — Routine devDependency refresh + CI/release pipeline modernization)

Patch release. No source changes, no public API changes, no wire-format changes; v1 ciphertexts produced by v1.3.1 round-trip unchanged under v1.3.2 and vice versa. Runtime `optionalDependencies` (`argon2`, `hash-wasm`) are unchanged at `^0.44.0` and `^4.12.0` respectively — both already at the npm `latest` dist-tag. The published tarball is bit-identical to what v1.3.2 would have produced under the previous workflow.

### What changed

Audit pass (npm `latest` dist-tag for every direct dep against `package.json` ranges and `node_modules` reality):

- `npm outdated` reported six devDep patch/minor bumps since v1.3.1. All within the existing caret ranges, but the `package.json` floors were lifted to match the actually-installed/tested versions so a fresh checkout against a wiped lockfile resolves to the tested-against minor.
- `npm audit` reports zero advisories across 419 deps (9 prod, 406 dev, 33 optional) — `node_modules` shrank by 24 transitive packages versus v1.3.1 as a side effect of the bumps.
- No major-version migrations were required; every direct dep is already at the latest stable major.

CI/release pipeline modernization (this release):

- `.github/workflows/release.yml` (new) replaces the old `publish.yml`. Now triggered directly by `v*.*.*` tag push (instead of "GitHub Release published" event), so a single `git push origin vX.Y.Z` drives the whole pipeline: gates → tag-matches-`package.json`-version guard → `npm pack --dry-run` tarball check → `npm publish --provenance --access public` → GitHub Release creation with notes extracted from this CHANGELOG. A `workflow_dispatch` fallback re-runs a specified tag manually (e.g. after fixing a stale NPM_TOKEN).
- `.github/workflows/ci.yml` — added least-privilege `permissions: contents: read`, a 20-minute per-leg `timeout-minutes` cap (guards against hung native builds — `argon2`'s node-gyp fallback is the historical Windows offender), and `persist-credentials: false` on the checkout step.
- `.github/workflows/codeql.yml` (new) — static analysis on push to `main`, on PRs, and weekly (Mon 06:00 UTC) using the `security-and-quality` query suite over the unified `javascript-typescript` language.
- `.github/PULL_REQUEST_TEMPLATE.md` (new) — security-impact callout and pre-completion checklist mirroring the CLAUDE.md gates.
- `.github/ISSUE_TEMPLATE/bug_report.yml`, `feature_request.yml`, `config.yml` (new) — structured issue forms; bug template forces "this is not a security vulnerability" confirmation (security reports route to the private advisory channel via `config.yml`).

The six devDep floor moves shipped here:

| Package | Before | After | Type | Notes |
| --- | --- | --- | --- | --- |
| `@types/node` | `^25.6.0` | `^25.7.0` | patch | Node 25 type definitions kept in lockstep with the Node minor running in CI. |
| `@typescript-eslint/eslint-plugin` | `^8.59.2` | `^8.59.3` | patch | Bug-fix-only release. |
| `@typescript-eslint/parser` | `^8.59.2` | `^8.59.3` | patch | Bug-fix-only release. |
| `fast-check` | `^4.7.0` | `^4.8.0` | minor | Adds `chainUntil` arbitrary; restored ability to drop `skipLibCheck`. No breaking changes — verified against release notes. None of the existing property/fuzz tests touch the new surface. |
| `jest` | `^30.3.0` | `^30.4.2` | minor | 30.4.0 ships a runtime rewrite preparing for ESM stabilisation; 30.4.1 aligned CJS-from-ESM default-export behaviour with Node; 30.4.2 fixed named imports from CJS modules whose `module.exports` is a function. Relevant to us because `argon2-lazy-load.test.ts` uses `jest.unstable_mockModule('argon2', factory)` BEFORE dynamically `import()`-ing CryptoManager — the mock-then-dynamic-import pattern is exactly the path the new runtime exercises. Verified by running the full 598-test suite green (including `argon2-lazy-load.test.ts`); no test code changes were required. |
| `jiti` | `^2.6.1` | `^2.7.0` | minor | New: `using`/`await using` support, opt-in `tsconfigPaths`, virtual modules, `jiti/static` export. ~2× `interopDefault` perf via proxy-cache. We use jiti only via `eslint.config.ts` (flat-config TypeScript loader); no behavioural change observed. |

### Files changed

- `package.json` — six devDep caret floors tightened (see table above); version `1.3.1` → `1.3.2`.
- `package-lock.json` — regenerated; 60 transitive packages changed, 3 added, 3 removed (net `-24` from the dedup that follows the bumps).
- `.github/workflows/release.yml` — new; replaces `.github/workflows/publish.yml` (removed).
- `.github/workflows/ci.yml` — hardened (permissions, timeout, no persisted credentials).
- `.github/workflows/codeql.yml` — new.
- `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/*.yml` — new.
- `CHANGELOG.md` — this entry.

### Verification

All four pre-completion checks pass:

- `npm run build` — clean.
- `npm run lint` — clean (zero warnings, zero errors).
- `npm run type-check` — clean.
- `npm test` — 598 / 598 tests pass, 12 / 12 snapshots pass, 8 test suites, ~116 s. The runtime time grew slightly versus v1.3.1's ~82 s — likely the Jest 30.4 runtime rewrite warming up; well within normal noise and not actionable.

Test count: 598 → 598 (no new tests; the changes are below the test-suite layer — devDep range floors are not test-observable beyond "the suite still passes").

### Caveats / things to know

- The `ts-jest` `node10` `ignoreDeprecations: "6.0"` workaround documented in v1.3.0 is unchanged — `ts-jest@29.4.9` is still the latest and still hard-codes `Node10` resolution before merging the project tsconfig. When a TS-6-aware ts-jest releases, the escape hatch in `jest.config.js` can be removed in a follow-up patch.
- A consumer with an existing `package-lock.json` for v1.3.1 will see resolved-version movement on the six bumped packages plus their transitive deps when running `npm install` against v1.3.2's `package.json`. Production consumers (who only see `optionalDependencies`) are unaffected — none of the bumped packages ship in the published tarball.

## 2026-05-05 (v1.3.1 — Tighten devDependency floors + fix stale Node version in publish workflow)

Hygiene-only patch release. No source changes, no public API changes, no wire-format changes; v1 ciphertexts produced by v1.3.0 round-trip unchanged under v1.3.1 and vice versa. Runtime `optionalDependencies` (`argon2`, `hash-wasm`) are unchanged at `^0.44.0` and `^4.12.0` respectively — both already at the npm `latest` dist-tag.

### What changed

Audit pass (npm `latest` dist-tag for every direct dep against `package.json` ranges and `node_modules` reality):

- Every installed dependency is already at the latest stable version; `npm outdated` reports an empty set, `npm audit` reports zero advisories across 443 deps (9 prod, 430 dev, 33 optional).
- No major-version migrations were required because no dep has a newer major than what is already installed (`@typescript-eslint/*` 8.59.2, `ts-jest` 29.4.9, `argon2` 0.44.0, `hash-wasm` 4.12.0, `eslint` 10.3.0, `typescript` 6.0.3, `jest` 30.3.0, `@types/node` 25.6.0, `prettier` 3.8.3, etc.).

The two changes shipped here are:

1. **devDependency caret floors tightened to match the actually-installed/tested versions.** The `package.json` floors were lagging behind what `npm install` resolved to — e.g. `"jest": "^30.0.3"` while 30.3.0 was installed and tested in the v1.3.0 release. Tightening the floors documents the tested-against versions and prevents a fresh checkout against a wiped lockfile from resolving to an older minor than the maintainer ever ran the test suite under. Specifically: `@typescript-eslint/eslint-plugin` `^8.35.0` → `^8.59.2`, `@typescript-eslint/parser` `^8.35.0` → `^8.59.2`, `eslint-config-prettier` `^10.1.5` → `^10.1.8`, `eslint-plugin-prettier` `^5.5.1` → `^5.5.5`, `jest` `^30.0.3` → `^30.3.0`, `prettier` `^3.6.2` → `^3.8.3`, `rimraf` `^6.0.1` → `^6.1.3`, `ts-jest` `^29.4.0` → `^29.4.9`. This is a devDep-only change; consumers of the published library see no diff (devDeps don't propagate).

2. **`publish.yml` — Node 22 (was Node 20).** v1.3.0's "drop EOL'd Node 18/20" sweep updated `engines.node`, `ci.yml`, the README badge, and the ESM smoke test, but missed the publish workflow at `.github/workflows/publish.yml:32` which still pinned `node-version: 20`. Node 20 reached EOL on 2026-04-30 (5 days before this release). The publish runner now uses Node 22, matching the `engines.node` floor (`>=22.0.0`) so the publish job runs on a Node version the package is actually declared to support. Pinned to 22 (not the 22/24 matrix from CI) per the existing comment: there is no value in matrix-publishing the same artefact from multiple Node versions.

### Files changed

- `package.json` — eight devDep caret floors tightened (see list above); version `1.3.0` → `1.3.1`.
- `package-lock.json` — regenerated for the version bump (no resolved versions changed; the pre-bump lockfile already pinned every dep at the new floor).
- `.github/workflows/publish.yml` — `node-version: 20` → `node-version: 22` with an updated comment citing the EOL date and engines-floor cross-reference.
- `CHANGELOG.md` — this entry.

### Verification

All four pre-completion checks pass against the tightened ranges (no resolved-version movement was actually required, since the lockfile already pinned the latest patches):

- `npm run build` — clean.
- `npm run lint` — clean (zero warnings, zero errors).
- `npm run type-check` — clean.
- `npm test` — 598 / 598 tests pass, 12 / 12 snapshots pass, 8 test suites, ~82 s.

Test count: 598 → 598 (no new tests; the changes are below the test-suite layer — devDep range floors and a CI workflow Node version are not test-observable).

### Caveats / things to know

- A consumer with an existing `package-lock.json` for v1.3.0 will see no changes when bumping to v1.3.1; the resolved tree is byte-identical. The change is only visible to anyone running a fresh `npm install` against this repo's `package.json` without a lockfile.
- The `ts-jest` `node10` `ignoreDeprecations: "6.0"` workaround documented in v1.3.0 is unchanged — `ts-jest@29.4.9` is still the latest and still hard-codes `Node10` resolution before merging the project tsconfig. When a TS-6-aware ts-jest releases, the escape hatch in `jest.config.js` can be removed in a follow-up patch.

## 2026-05-04 (v1.3.0 — Iteration 3 Closeout: Drop EOL'd Node 18/20 + TypeScript 6 + README Anchor Fix)

This release closes the three hygiene tasks from FIX.md Iteration 3. All three are non-functional / toolchain changes — there are no public API changes, no wire-format changes, and no behavioural changes at runtime. v1 ciphertexts produced by v1.2.x round-trip unchanged under v1.3.0 and vice versa.

The minor (not patch) version bump is to signal the **breaking infrastructure change** for consumers still on Node 18 or Node 20: the `engines.node` field is now `>=22.0.0` and `npm install @hiprax/crypto` will refuse to install on out-of-LTS Nodes. If you are on Node 18 (EOL April 30, 2025) or Node 20 (EOL April 30, 2026), upgrade to Node 22 (maintenance LTS through April 2027) or Node 24 (active LTS through April 2028) before bumping this dependency. The runtime code itself does not use any Node-22+-only APIs, but a security-focused library should not advertise support for Node lines that no longer receive security patches.

### Task 1 — Fix README broken anchor link (`README.md`)

The threat-model bullet on "Authenticity and integrity of ciphertext (including the v1 header)" at line 1048 ended with a Markdown link `[Migration: v1.0.0 → v1.1.0](#migration-v100--v101)`. The actual heading at line 783 is `#### Migration: v1.0.0 → v1.1.0`, which GitHub-flavored-Markdown's slug generator renders as `migration-v100--v110` (last digits of the target version: `1.1.0`, not `1.0.1`). The link 404'd when clicked from the rendered README on GitHub or npm.

Fixed by changing `#migration-v100--v101` → `#migration-v100--v110`. No other occurrences of the broken anchor exist in the repo (FIX.md retains it in the bug-description prose, which is the intended use).

### Task 2 — Drop EOL'd Node 18/20 from engines, CI matrix, and README badge (`package.json`, `.github/workflows/ci.yml`, `README.md`, `src/__tests__/esm-smoke.test.ts`)

Node 18 reached EOL on April 30, 2025 (~12 months ago at the time of this release). Node 20 reached EOL on April 30, 2026 (4 days before this release). Continuing to advertise support for either is factually wrong for a security-focused library — Node lines past EOL receive no security patches, and any CVE in Node's `crypto` module since their respective EOL dates is unpatched on those installs.

State of the world (May 4, 2026):

- Node 22 — maintenance LTS through April 2027.
- Node 24 — active LTS through April 2028.
- Node 26 — current (unstable) line.

Changes:

- **`package.json`** — `engines.node` `">=18.0.0"` → `">=22.0.0"`. `engines.npm` bumped from `>=8.0.0` to `>=10.0.0` to track the npm baseline shipped with Node 22 (Node 22 ships with npm 10.x; the prior `>=8.0.0` constraint allowed some pre-Node-22 npm installs through).
- **`.github/workflows/ci.yml`** — matrix `node: [18, 20, 22]` → `node: [22, 24]`. Two LTS lines covered, both currently supported by upstream. The matrix shrinks from 6 jobs (3 nodes × 2 OSes) to 4 jobs, freeing ~30% of CI runner-time per push.
- **`README.md`** — Node.js version badge `Node.js-18+` → `Node.js-22+` so the badge matches the engines field.
- **`src/__tests__/esm-smoke.test.ts`** — the `package.json` shape assertion at line 82 previously required `engines.node` to match `/>=18\.0\.0/`. Updated to `/>=22\.0\.0/` to track the new floor; the test continues to lock in the engines-field contract, just at the new value.

Decision rationale for the version bump: dropping Node 18/20 from `engines` is a breaking infrastructure change (those consumers will get an `EBADENGINE` install warning or refusal depending on their npm config). Traditionally that's a major-version bump. For a 1.x library that's only weeks old and where the failure mode is a clean install error (not a silent runtime break), v2.0.0 over an engines-only change is excessive — v1.3.0 (minor) signals "new requirements" while keeping the v1.x line and the existing wire format. This CHANGELOG entry documents the breaking aspect loudly so consumers grepping for "breaking" find it.

### Task 3 — TypeScript 6 upgrade (`package.json`, `package-lock.json`, `tsconfig.json`, `jest.config.js`)

TypeScript 6.0 shipped on March 23, 2026 — the final JavaScript-based TypeScript before the Go-native 7.0 line. Two behaviour differences relevant to this project:

1. **TS 6 stops auto-discovering `@types/*` packages.** Projects that relied on implicit `@types/node` discovery (this project does, via the `@types/node` devDep) need an explicit `compilerOptions.types: ["node"]` entry in `tsconfig.json`. Without it, `Buffer` / `process` / `Crypto` etc. surface as "Cannot find name" type errors. Added `"types": ["node"]` to `tsconfig.json`'s `compilerOptions` block.
2. **`target: es5` and `--outFile` are deprecated.** We target `ES2022`, so this doesn't affect us.

`npm install --save-dev typescript@^6.0.3` updated the dependency and regenerated `package-lock.json`. All four pre-completion checks (`build`, `lint`, `type-check`, `test`) passed without source-code changes after adding the explicit `types` entry — the source uses no deprecated TS features and `module: NodeNext` is still supported.

**One TS-6-specific surfacing error required a non-source workaround in `jest.config.js`.** `ts-jest@29.4.9`'s legacy compiler (`node_modules/ts-jest/dist/legacy/compiler/ts-compiler.js:111`) internally hard-codes `moduleResolution: this._ts.ModuleResolutionKind.Node10 ?? ...` BEFORE merging the project-supplied tsconfig override. TS 6 errors on `node10` as deprecated:

> `error TS5107: Option 'moduleResolution=node10' is deprecated and will stop functioning in TypeScript 7.0. Specify compilerOption '"ignoreDeprecations": "6.0"' to silence this error.`

Until ts-jest releases a TS-6-aware version (the deprecation has been a 5.0+ warning for over a year; the 6.0 hard-error finally forces the issue), the documented escape hatch is to opt into `ignoreDeprecations: "6.0"` in the test-compile tsconfig. Added that single line to the existing `tsconfig` block in `jest.config.js`'s `transform` rule, with a comment explaining the upstream cause and that the production `tsconfig.json` is unaffected. This is test-compile-only — the published library tarball never runs through ts-jest, so consumers see no impact.

### Files changed

- `package.json` — `typescript: ^5.9.3` → `^6.0.3` (devDep); `engines.node` `>=18.0.0` → `>=22.0.0`; `engines.npm` `>=8.0.0` → `>=10.0.0`; version `1.2.2` → `1.3.0`.
- `package-lock.json` — regenerated for the TypeScript bump + version bump.
- `tsconfig.json` — added `"types": ["node"]` to `compilerOptions`.
- `jest.config.js` — added `ignoreDeprecations: "6.0"` to the ts-jest tsconfig override (with explanatory comment).
- `.github/workflows/ci.yml` — matrix `node: [18, 20, 22]` → `[22, 24]`.
- `README.md` — Node.js badge `Node.js-18+` → `Node.js-22+`; threat-model anchor `#migration-v100--v101` → `#migration-v100--v110`.
- `src/__tests__/esm-smoke.test.ts` — engines-shape assertion updated from `/>=18\.0\.0/` to `/>=22\.0\.0/`.
- `FIX.md` — Tasks 1, 2, 3 marked `[x]`; Task 4 (4-check verification) and Task 5 (CHANGELOG/bump) marked `[x]` with the executed values inlined.
- `CHANGELOG.md` — this entry.

Test count: 598 → 598 (no new tests; the toolchain changes are below the test-suite layer). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass on Node 24 (the development host). The CI matrix will exercise Node 22 and Node 24 on the next push.

Caveats / things to know:

- Consumers on Node 18 or 20 will see `EBADENGINE` install warnings (or refusals, depending on their `engine-strict` setting). The recommended fix is to upgrade Node to 22+. There is no v1.2.x → v1.3.0 code-level migration required beyond that.
- `ts-jest`'s `node10` hard-coding is an upstream issue. When ts-jest releases a TS-6-aware version, the `ignoreDeprecations: "6.0"` line in `jest.config.js` can be removed. Until then it's a one-line known workaround.

## 2026-05-04 (v1.2.2 — Iteration 2 Closeout: Benchmark Suite + Coverage-Glob Hygiene + Threat-Model Verification)

This release closes the final three items from FIX.md Iteration 2 — Tasks 24, 25, and 28. The headline addition is a `tinybench`-driven benchmark suite under `bench/` covering the four end-to-end paths most representative of real workloads. The other two are non-functional cleanups (one Jest config tweak, one verified-still-accurate threat-model claim). All changes are backward-compatible: no public API changes, no wire-format changes; v1 ciphertexts produced by v1.2.1 round-trip unchanged under v1.2.2 and vice versa.

### Task 24 — Benchmark suite (`bench/`, `package.json`, `.npmignore`, `README.md`)

Iteration 2's final loose end was the lack of a reproducible "how slow are we?" measurement story. The library has well-documented expected runtimes in the README ("Argon2id at 128 MiB takes ~150-300 ms per derivation"), but no in-tree way to verify those numbers on a contributor's machine, and no regression-detection story for performance changes that slip in alongside security fixes.

`tinybench@^6.0.1` is now a `devDependency`. A new `bench/` directory contains four ESM scripts and a per-directory `README.md`:

- **`bench/index.mjs`** — top-level runner. `await import`s the three child bench files in fixed order so output is grouped predictably (KDF first, then text, then file streaming). Wired into `package.json` as `npm run bench`.
- **`bench/kdf.mjs`** — Argon2id (default 128 MiB / `t=3` / `p=1`) and PBKDF2-SHA256 (default 600,000 iterations) head-to-head. Pre-generates a 64-entry salt pool so the bench measures KDF cost rather than `crypto.randomBytes` throughput. Tinybench `time: 30_000, iterations: 5` per case (Argon2id at 128 MiB takes ~150-300 ms per call, so the 30 s budget gives tinybench enough samples to compute a stable mean with margin-of-error around 1-3%).
- **`bench/encrypt-text.mjs`** — `encryptText` at 1 KiB and 1 MiB plaintexts, both async, both gated by Argon2id's default profile. Uses the public API rather than reaching for an internal "skip KDF" hook because production callers always pay the KDF cost — this is what we want to measure end-to-end.
- **`bench/encrypt-file.mjs`** — round-trip on a 10 MiB file. Pre-generates one ciphertext at startup so the decrypt bench has a stable input. Each iteration writes to a fresh output path (`encrypt-out-N.enc` / `decrypt-out-N.bin`) so we never accidentally fall into the "destination exists" branch in `atomicRename`. The temp work directory is `mkdtempSync`'d at startup and unconditionally `rmSync`'d in a `finally` block.

Sample timings on a development laptop (Argon2id at the smaller 64 MiB profile for the smoke run; the production 128 MiB profile is ~2x slower):

```text
Argon2id (64 MiB, t=3, p=1)   mean=170.74 ms, p99=187.49 ms, samples=24, ops/s=5.9
PBKDF2-SHA256 (600k iter)     mean=312.50 ms, p99=339.05 ms, samples=13, ops/s=3.2
encryptText 1 KiB             mean=169.66 ms, p99=178.90 ms, samples=24, ops/s=5.9
encryptText 1 MiB             mean=176.97 ms, p99=186.40 ms, samples=23, ops/s=5.7
encryptFile 10 MiB            mean=213.85 ms, p99=233.80 ms, samples=15, ops/s=4.7
decryptFile 10 MiB            mean=213.04 ms, p99=228.01 ms, samples=15, ops/s=4.7
```

Two observations from the smoke run that surprised nobody but are now provable:

1. **Argon2id dominates every encrypt path.** The 1 KiB, 1 MiB, and 10 MiB encrypt cases all land within ~25% of the raw KDF cost — the AES-GCM body work is a small fraction of the wall time at the default KDF parameters. This is exactly what the README has always claimed.
2. **PBKDF2 at 600k iterations is meaningfully slower than Argon2id at 64 MiB on this hardware** (~310 ms vs ~170 ms). This confirms the security-vs-performance trade-off documented in the README's "Asynchronous vs Synchronous Operations" section is fair: PBKDF2 isn't faster, it's just synchronous.

Documentation:

- New "## Benchmarks" section in the main `README.md`, between "## Testing" and "## Error Handling", with the headline `npm run bench` invocation, expected total runtime (~2-5 minutes at the production 128 MiB profile), per-bench-file invocation pattern, and an explicit note that benchmarks are NOT in CI.
- New `bench/README.md` with the full per-case methodology, expected runtime breakdown, suggested parameter overrides for fast sanity checks, and a sample tinybench output table.

Tarball hygiene: `bench/` is excluded from the published npm tarball via a new entry in `.npmignore` (`bench/`). `npm pack --dry-run` still produces the same 15-file output as v1.2.1 (no benchmark files leak into the published package).

CI integration: deliberately none. Argon2id at 128 MiB takes ~30-90 s per case to converge on hosted runners, and the absolute numbers vary by 2-3x between runner generations (GitHub-hosted Linux, ARM64, Windows) which makes them useless as a regression check. Run benchmarks locally on a known machine when you want comparable numbers across releases.

### Task 25 — Verify README threat-model wording (`README.md`, no change)

Task 25 was bundled into Task 1 (the v1.1.0 AAD-binding fix). The README threat-model bullet at line 1029 reads:

> **Authenticity and integrity of ciphertext (including the v1 header).** [...] As of v1.1.0 the AAD bound to v1 ciphertexts includes the configured AAD context string [...] **concatenated with the verbatim 22 bytes of the v1 header** — so any single-bit modification to the ciphertext, salt, IV, header (including the reserved-byte regions inside the KDF parameter block), or AAD context causes `decrypt*` to fail with `DECRYPTION_FAILED` rather than return wrong plaintext.

This claim was made true at the time of writing by the v1.1.0 AAD-binding fix and remains true under v1.2.x — none of the patch releases between v1.1.0 and v1.2.2 have touched the AAD-binding code path (`aadForV1` in `src/crypto-manager.ts`), and the property test added under Task 7 (`src/__tests__/property.test.ts`) continues to pass on every release, which is the running guarantee that the claim still holds. No README change needed.

### Task 28 — Tighten Jest coverage exclusion (`jest.config.js`)

`jest.config.js` `collectCoverageFrom` previously excluded `*.test.ts` and `*.spec.ts` files but did not exclude the `__tests__` directory as a whole. The current state happens to be safe (the directory contains only `*.test.ts` files plus a `__snapshots__/` subdirectory whose `.snap` contents fall outside the `*.ts` glob), so the coverage delta is essentially zero today:

- v1.2.1: 96.28% statements / 90.74% branches / 97.61% functions / 96.25% lines
- v1.2.2: 96.28% statements / 90.74% branches / 97.61% functions / 96.25% lines (unchanged)

The fix is defensive hygiene: a future contributor adding a test-helper file under `__tests__` without a `.test.ts` suffix (e.g. `src/__tests__/helpers.ts`) would have it counted as production code under the previous patterns, distorting the coverage % up or down depending on the helper's coverage characteristics. Adding `'!src/__tests__/**'` makes the exclusion intent explicit at the directory level, matching the test-runner's mental model that everything under `__tests__/` is test scaffolding.

### Files changed

- `package.json` — `tinybench: ^6.0.1` added to `devDependencies`; new `bench` script (`node bench/index.mjs`); version `1.2.1` → `1.2.2`.
- `package-lock.json` — regenerated for `tinybench` install + version bump.
- `bench/index.mjs`, `bench/kdf.mjs`, `bench/encrypt-text.mjs`, `bench/encrypt-file.mjs`, `bench/README.md` — new (Task 24).
- `.npmignore` — `bench/` added to the source-code exclusion block (Task 24).
- `README.md` — new "## Benchmarks" section between Testing and Error Handling (Task 24).
- `jest.config.js` — `'!src/__tests__/**'` added to `collectCoverageFrom` (Task 28).
- `CLAUDE.md` — build-system / NPM scripts table gains a `bench` row.
- `FIX.md` — Tasks 24, 25, 28 marked `[x]`.

Test count: 598 → 598 (no new tests; benchmarks are run-on-demand, not under Jest). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.2.1 — Low-Priority Cleanups: ESLint Security Plugin + Backup-Path Cap + Symlink Doc + Prepare Decision)

This release closes the remaining tractable low-priority items from FIX.md Iteration 2 — Tasks 19, 20, 22, and 23. All four are non-functional cleanups (one new lint plugin, one defensive bound in a utility function, two doc-only fixes), so the patch version bump captures the lint-plugin addition (which is the only externally-observable surface change). All changes are backward-compatible: no public API changes, no wire-format changes; v1 ciphertexts produced by v1.2.0 round-trip unchanged under v1.2.1 and vice versa.

### Task 19 — `prepare` vs `prepack` decision is final (`CLAUDE.md`, `FIX.md`)

The audit asked whether `prepare` should be replaced with a `prepack` + `postinstall` pair to avoid the duplicate compile in `npm publish` (where `prepublishOnly` already builds, then `prepare` builds again). Decision: keep `prepare` as-is. Rationale documented as final in `CLAUDE.md`'s prepare-script section and in the FIX.md task entry — replacing with `prepack`+`postinstall` would silently break the git-install workflow (`npm install github:Hiprax/crypto`), and the duplicate compile cost is dominated by `tsc` (~2-3s on this codebase) and is invisible to users. Future contributors are explicitly asked not to re-open this design unless npm lifecycle semantics change upstream.

No code change.

### Task 20 — Enable `eslint-plugin-security` recommended rules (`eslint.config.ts`, `package.json`, `src/__tests__/utils.test.ts`)

Added `eslint-plugin-security@4.0.0` to `devDependencies` and wired `security.configs.recommended` into the flat ESLint config. The plugin runs the standard Node-security checks (unsafe regex / catastrophic backtracking, non-literal `require` / `fs.*` paths, eval-with-expression, pseudo-random bytes, child-process calls, bidi characters, etc.) on every `npm run lint` invocation.

Findings, classified:

- **One real false positive in tests** — `security/detect-unsafe-regex` flagged `/\d+(\.\d+)?\s+TB$/` in `utils.test.ts:292`. The `safe-regex` scanner is conservative about consecutive `\d+` quantifiers; the actual pattern cannot catastrophically backtrack because the `\s+TB$` suffix forces commit and the input under test is the bounded output of `formatFileSize`. Suppressed with an inline `eslint-disable-next-line security/detect-unsafe-regex` comment and a justifying paragraph.
- **Two systemic false positives — disabled globally**:
  - `security/detect-object-injection` flags every computed-key access where the key isn't a literal. This is endemic in a crypto library (every byte-buffer index, every constant-time-style comparison loop, every `Buffer[i]` / `randomBytes(n)[i]`). The genuine concern (user-controlled keys being injected into prototype-chain properties) doesn't apply — this library only indexes Node `Buffer`s and primitive arrays, neither of which carry prototype-injection risk.
  - `security/detect-non-literal-fs-filename` flags every fs call whose path argument isn't a string literal. This library is a *file encryption library* — by definition every fs call takes a user-supplied path. The defence (path validation, allowedRoot containment) lives in `validatePath`, which has its own dedicated tests. Disabling the lint rule shifts the check from compile-time to code-review-time, which is appropriate given the impossibility of a literal-only fs API in this domain.
- **Tests get an additional disable** — `security/detect-non-literal-regexp` is turned off in `src/__tests__/**` because fuzz / property tests legitimately construct regex patterns from string inputs.

Net result: `npm run lint` runs with zero warnings and zero errors after the plugin is in place. The plugin will catch any *new* security smell introduced in future PRs (e.g. a stray `eval(userInput)` or a regex with nested quantifiers); the false-positive surface is contained and documented.

### Task 22 — `createBackupPath` enforces 255-char basename cap (`src/utils.ts`, `src/__tests__/utils.test.ts`)

`createBackupPath` previously concatenated the user-supplied filename directly into the result, so a 300-character input name produced a backup path with a 320+ character basename — exceeding the 255-char filesystem maximum on most platforms (NTFS, ext4, APFS).

Fix: pre-shorten the user-supplied `name` portion so the meaningful tail (`_${timestamp}_${rand}${suffix}${ext}`) fits within 255 characters, then route the assembled basename through `sanitizeFilename` as a final safety net. Pre-shortening is required because `sanitizeFilename`'s built-in head-keep / tail-drop truncation (which preserves extension at the right edge) would otherwise eat the timestamp + random discriminator on a long input name and break uniqueness across rapid successive backup calls. The directory portion of the path is unaffected — only the constructed basename is sanitised.

Four new tests in `utils.test.ts`:

1. 300-char `name` + `.txt` → result basename is `<= 255` chars, ends in `.txt`.
2. 500-char `name` + `.json` → result still matches the full timestamp + 6-hex + `.backup.json` regex (proves the tail wasn't truncated).
3. 8 rapid successive calls on a 400-char `name` → all 8 results unique (proves the random discriminator is intact even after pre-shortening).
4. 300-char `name` under `/some/nested/dir` → `path.dirname` of the result equals `path.dirname` of the input (proves the directory portion wasn't affected by sanitisation).

### Task 23 — Document `validateFile` symlink-following behaviour (`src/utils.ts`)

`validateFile` calls `fs.promises.access(filePath, R_OK)` which follows symlinks — the function reports `isValid: true` for any symlink whose resolved target is readable. The previous JSDoc was silent on this behaviour, leaving a contract gap analogous to the one closed for `validatePath` in iteration 1.

Updated JSDoc to mirror `validatePath`'s symlink note: explicitly warns that `validateFile` does NOT detect symlink-based privilege-escalation attacks (e.g. a `filePath` argument supplied by an untrusted source that resolves to `/etc/shadow` or `C:\Windows\System32\config\SAM`), and points callers needing symlink-aware containment to `fs.lstat` / `fs.realpath` + re-verify against an allowed root.

No code change — purely a documentation fix.

### Files changed

- `package.json` — `eslint-plugin-security: ^4.0.0` added to `devDependencies`; version `1.2.0` → `1.2.1`.
- `package-lock.json` — regenerated.
- `eslint.config.ts` — `security.configs.recommended` wired in; two systemic false-positive rules disabled globally; `security/detect-non-literal-regexp` disabled in tests (Task 20).
- `src/utils.ts` — `createBackupPath` pre-shortens `name` and routes through `sanitizeFilename` (Task 22); `validateFile` JSDoc rewritten to document symlink behaviour (Task 23).
- `src/__tests__/utils.test.ts` — 4 new `createBackupPath` tests for the 255-char cap; one inline `eslint-disable-next-line security/detect-unsafe-regex` suppression with justifying comment (Tasks 22 + 20).
- `CLAUDE.md` — `prepare` decision documented as final (Task 19); `validateFile` and `createBackupPath` entries updated; build-system section notes the new lint plugin and disables.
- `FIX.md` — Tasks 19, 20, 22, 23 marked `[x]`.

Test count: 594 → 598 (4 new `createBackupPath` tests). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.2.0 — Pure-WASM Argon2id Fallback + Streaming-Cleanup Coverage)

This release closes the last two unblocked items in FIX.md Iteration 2 — Task 17 (WASM Argon2 fallback) ships as a new optional dependency, and Task 18 fills in coverage for streaming-cleanup branches that were uncovered by iteration 1's example tests. The minor version bump is for Task 17, which adds a new (optional) dependency and a new behaviour (transparent WASM fallback when native `argon2` is missing). All changes are backward-compatible: v1 ciphertexts produced by v1.1.x round-trip unchanged under v1.2.0 and vice versa, and v1 ciphertexts produced by either provider (native or WASM) round-trip across both — RFC 9106 Argon2id is bit-identical between the two implementations, and we pin a known test vector to lock the parity in.

### Task 17 — WASM Argon2id fallback via `hash-wasm` (`src/crypto-manager.ts`, `src/__tests__/argon2-lazy-load.test.ts`, `package.json`, `README.md`)

Iteration 1 made `argon2` an `optionalDependency` so installs in environments without a C++ toolchain don't fail. The recovery story was "use `*Sync` (PBKDF2) methods", which silently downgrades the security profile from Argon2id (memory-hard, GPU-resistant) to PBKDF2 (only CPU-hard). A caller skimming the README might keep using `encryptTextSync` not realising the security level changed.

`hash-wasm` (4.12.0, MIT) ships a pure-WebAssembly Argon2id implementation with zero native dependencies and zero runtime npm dependencies. Pre-implementation parity check (against native `argon2` 0.44.0, salt = 32 bytes of `0x42`, password = `'MySecureP@ssw0rd123!'`, memoryCost = 65536, timeCost = 3, parallelism = 1, hashLength = 32) returned bit-identical 32-byte raw output:

```text
e368bb157114953b17017a398bcf20d9a8800227cfdbc5d38eb6564111e8a188
```

The same vector is now pinned as a regression test in `argon2-lazy-load.test.ts` (`'native and WASM produce identical raw key bytes for the same input (RFC 9106 parity)'`). Two further parity vectors (default 128 MiB / parallelism=4 / NFC-normalised unicode password) also matched at investigation time.

Implementation:

- New `Argon2Hasher` interface unifies the native and WASM provider signatures behind `(password, options) => Promise<Buffer>`, normalising parameter naming differences (`memoryCost` ↔ `memorySize`, `timeCost` ↔ `iterations`).
- `loadArgon2()` now tries `import('argon2')` FIRST (native preferred for performance — WASM is roughly 2-3x slower at the default 128 MiB profile), falls back to `import('hash-wasm')` if native is unavailable, and only after BOTH fail throws the friendly `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` with an updated message that mentions all three fix paths (build tools / install hash-wasm / use *Sync PBKDF2).
- The in-flight-promise pattern from Task 4 (iteration 2) is preserved: concurrent first-callers share a single load attempt regardless of which provider ends up winning the cascade. Failure clears the cache so transient errors recover.
- New internal hook `__peekArgon2ProviderForTesting()` exposes which provider was loaded (`'native' | 'wasm' | null`) for test assertions. Marked `@internal`; not part of the public API.
- `package.json` adds `hash-wasm: ^4.12.0` to `optionalDependencies` alongside `argon2`. Both are optional — installing neither still works for callers using only the sync (PBKDF2) methods.

Seven new tests cover the cascade:

- Both providers available → uses native (provider tag asserted).
- Native fails, WASM available → falls through to WASM (parameter mapping verified).
- WASM module shape variants (`.default`-wrapped vs direct namespace) — both load.
- Both fail → `ARGON2_NOT_AVAILABLE` with the updated three-path message.
- RFC 9106 parity test against the pinned vector (mocked providers returning the fixed output).
- Cross-runtime round trip: encrypt under native-mocked, decrypt under WASM-mocked, plaintext matches.

The original 11 lazy-load tests are also updated to mock BOTH providers when simulating "argon2 unavailable" — without this, the tests would silently fall through to a real `hash-wasm` install and pass for the wrong reason.

### Task 18 — Coverage for streaming-cleanup branches (`src/__tests__/streaming-cleanup.test.ts`)

Iteration 1 left coverage at 88% on `crypto-manager.ts` because several streaming failure paths only fire under conditions that don't naturally arise on a fast development filesystem with normal-sized inputs. Task 18 fills those in via targeted tests with ESM module mocks (`jest.unstable_mockModule` against `node:fs` and `node:fs/promises`).

Four cleanup branches now have explicit tests:

1. **`atomicRename` copy-fallback path** — when `fs.rename` fails (modeling Windows `MoveFileExW` failures when the target file is locked but the destination directory is writeable), the encrypt path falls through to `fs.copyFile + fs.unlink`. We mock `rename` to throw EBUSY, verify the canonical output appears (via the fallback path), and check the temp file is unlinked. Covered for both async (`encryptFile`) and sync (`encryptFileSync`) paths. A third test covers the "rename AND copyFile both fail" path (the inner catch re-throws the original rename error).

2. **Drain backpressure handling** — the encrypt path's `writeChunk` helper handles `outputStream.write()` returning `false` (write queue full) by awaiting the `'drain'` event. The default 64 KiB highWaterMark means small test inputs rarely fill the queue. We mock `createWriteStream` to use a 16-byte highWaterMark, encrypt 64 KiB, then round-trip via decrypt — if drain handling drops or reorders bytes, byte-equality fails.

3. **`progressError` tagging in encrypt vs decrypt** — both file streaming paths have their own `data` event listener that captures user throws via `tagProgressThrow`. Iteration 1 covered this generally; Task 18 adds explicit per-direction tests that throw a custom error class from a chunk-level callback (skipping the bracket events) and assert the user's class identity is preserved (`instanceof EncryptBoom` / `instanceof DecryptBoom`) rather than wrapped in `CryptoError(FILE_*_FAILED)`.

4. **`decryptFile` zero-body path** — when the plaintext was an empty buffer, the ciphertext layout is `[header][salt][iv][body=empty][tag]`. The async decrypt path detects `bodyLen === 0` and skips `createReadStream` entirely, calling `decipher.final()` directly to authenticate. Three tests: (a) async round-trip of an empty plaintext (uses `encryptData` directly to construct the zero-body ciphertext), (b) sync round-trip ditto via PBKDF2, (c) tampered zero-body ciphertext fails authentication and leaves no orphan output.

Mocking pattern note: `jest.unstable_mockModule` registrations persist across tests (resetting the module registry doesn't unregister mocks), so every test that uses fs mocks ALSO installs explicit identity-passthrough mocks for the OTHER fs module. This isolates the per-test mock state and prevents bleed-through (e.g. a `rename: throw 'rename boom'` mock from the double-fail test was previously leaking into the drain-backpressure test).

Coverage delta after Task 18: lines 95.81%, branches 88.93%, functions 97.61%, statements 96.22% on `crypto-manager.ts` (up from approximately 88% branches in iteration 1).

### Files changed

- `src/crypto-manager.ts` — new `Argon2Hasher` / `HashWasmModule` types, new `importNativeArgon2` / `importHashWasmArgon2` / `importArgon2Hasher` functions, `loadArgon2` rewritten to cascade, `deriveKey` updated to use the unified hasher, new `__peekArgon2ProviderForTesting` test hook (Task 17).
- `src/__tests__/argon2-lazy-load.test.ts` — 11 existing tests updated to mock BOTH providers; 7 new tests for the cascade + parity (Task 17).
- `src/__tests__/streaming-cleanup.test.ts` — new file, 9 tests covering the four uncovered branches (Task 18).
- `package.json` — `hash-wasm: ^4.12.0` added to `optionalDependencies`; version `1.1.4` → `1.2.0`.
- `package-lock.json` — regenerated.
- `README.md` — installation section updated to document the WASM fallback (Task 17).
- `FIX.md` — Tasks 17, 18 marked `[x]`.

Test count: 578 → 594 (16 new tests; 7 for Task 17, 9 for Task 18). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.1.4 — Memory-Hygiene Polish + Default-Passphrase Retention Disclosure)

This release ships two medium-priority defence-in-depth items from FIX.md Iteration 2 (Tasks 14 and 15) and formally defers Task 11 (streaming text encrypt/decrypt) to iteration 3 with a documented rationale. All changes are backward-compatible — no public API changes, no wire-format changes; v1 ciphertexts produced by v1.1.3 round-trip unchanged under v1.1.4 and vice versa.

### Task 14 — `secureClear` ciphertext-side buffers in encrypt paths (`src/crypto-manager.ts`)

`encryptText` and `encryptTextSync` previously cleared `key` and `textBuffer` after encryption but left the ciphertext-side buffers (`encrypted`, `tag`, `combined`) alive in memory until V8 garbage-collected them. `encryptFileSync` had the same gap with `encrypted`, `tag`, and `fullPayload`. The decrypt path already cleared its analogous buffers (post-iteration-1), so the encrypt path was the asymmetric outlier.

These buffers are not "secrets" per se — they are the public ciphertext components — but they hold the cipher's internal state and the auth tag immediately after encryption. Clearing them keeps the encrypt path symmetric with the decrypt path and aligns with the threat-model claim of "Memory hygiene for buffer-resident secrets". Defence-in-depth, not a correctness fix.

The encode-then-clear order is deliberate: `combined.toString('base64url')` runs FIRST, then the buffers are zero-filled. Clearing before encoding would leave `encoded` as a base64url string of zero-bytes ("AAAA..."), which is not what the API contract returns.

Six new `secureClear` calls total (3 in `encryptText`, 3 in `encryptTextSync`, 3 in `encryptFileSync`). All in the success path — no point clearing buffers that are already going out of scope on a thrown error.

### Task 15 — Document `defaultPassphrase` retention as a known memory-hygiene gap (`src/types.ts`, `src/crypto-manager.ts`, `README.md`, `SECURITY.md`)

The `defaultPassphrase` constructor option stores the password on the manager instance as a regular V8 string. V8 strings are immutable and GC-managed; the library cannot scrub them with `secureClear` (which only zero-fills `Buffer`-backed allocations). A `CryptoManager` configured with `defaultPassphrase` therefore keeps a copy of the password resident for the full instance lifetime, plus an unbounded GC tail for any internal V8 string copies the engine made along the way. This is a deliberate convenience-vs-scrubability trade-off, but it conflicts with the threat-model narrative around memory hygiene.

We chose the conservative documentation fix (per FIX.md Task 15's recommendation) over the aggressive `Buffer`-stored-passphrase refactor — the aggressive variant has subtle issues with NFC normalisation timing and would have been weaker than callers might assume. The documentation now appears in four places:

- `src/types.ts` — `defaultPassphrase` JSDoc on `CryptoManagerOptions` now spells out the V8 string retention caveat and the "prefer passing the password per call" recommendation.
- `src/crypto-manager.ts` — the private `defaultPassphrase` field has matching JSDoc covering the lifetime + GC-tail semantics.
- `README.md` — the "Using Default Passphrase" usage section now ends with a memory-retention callout, and the "Password Requirements" section has a dedicated paragraph on memory hygiene of `defaultPassphrase`. The Threat Model bullet on V8 string-copy leaks now cross-references `defaultPassphrase` as the deliberate-retention case.
- `SECURITY.md` — new "Memory-retention caveats" section documents the two known retention paths (V8 internal copies and `defaultPassphrase`) so they're explicit in the formal security policy, not just in usage docs.

### Task 11 — DEFERRED to iteration 3

Streaming text encrypt/decrypt (`encryptStream` / `decryptStream` taking `Readable` / `Writable`) requires a NEW wire format. The existing v1 file layout puts the GCM auth tag at the end of the stream, which means streaming decrypt either has to buffer the entire body (defeats the purpose), require the consumer to declare body length up front (defeats opaque pipelines), or introduce a length-prefixed / chunked format alongside v1. The third option is correct but is substantially more work than iteration 2 has room for and interacts with the iteration-3 backlog (Task 17 — WASM Argon2 fallback may want streaming awareness). Deferred to iteration 3 for proper format design rather than rushed alongside the iteration-2 hardening work. See FIX.md Task 11 for the full rationale and the documented workaround for callers hitting the in-memory ceiling today (chunk plaintext into N base64url-encoded segments yourself, concat, reverse on decrypt).

### Files changed

- `src/crypto-manager.ts` — 9 new `secureClear` calls across `encryptText`, `encryptTextSync`, `encryptFileSync` (Task 14); JSDoc on the private `defaultPassphrase` field (Task 15).
- `src/types.ts` — JSDoc on `CryptoManagerOptions.defaultPassphrase` (Task 15).
- `README.md` — "Using Default Passphrase" usage callout, Password Requirements memory-hygiene paragraph, Threat Model cross-reference (Task 15).
- `SECURITY.md` — new "Memory-retention caveats" section (Task 15).
- `FIX.md` — Task 11 marked deferred with rationale; Tasks 14 / 15 marked `[x]` (Task 11/14/15).
- `package.json` — version `1.1.3` → `1.1.4`.
- `package-lock.json` — version sync.

Test count: 578 → 578 (no new tests; Task 14 is a memory-hygiene polish that doesn't require behavioural test coverage — the existing round-trip suite still passes, and a `secureClear` of a buffer that is about to go out of scope is impossible to assert externally without process-memory introspection. Task 15 is documentation-only). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.1.3 — Parser-Robustness Fix, Edge-Case Bound, Dependency Refresh)

This release ships three medium-priority fixes from FIX.md Iteration 2 (Tasks 8, 9, 10). All changes are backward-compatible — no public API or wire-format changes; v1 ciphertexts produced by v1.1.2 round-trip cleanly under v1.1.3.

### Task 8 — `inspectHeader` validates base64url encoding upstream of `Buffer.from` (`src/crypto-manager.ts`, `src/__tests__/crypto-manager.test.ts`, `src/__tests__/format-fuzz.test.ts`)

`Buffer.from(input, 'base64url')` silently coerces invalid characters to an empty buffer (e.g. `'!!!!'` decodes to a 0-byte buffer rather than throwing). Pre-fix, calling `inspectHeader` with a malformed string would not see the v1 magic in the decoded buffer and would silently return `null` — the same return value used for genuine v0 ciphertexts. A caller using `inspectHeader` to classify ciphertexts could not distinguish "this string is malformed" from "this is a v0 ciphertext".

`inspectHeader` now precondition-checks string inputs with `isValidBase64Url(input)` BEFORE the decode. Malformed inputs throw `CryptoError(INVALID_INPUT, 'INVALID_BASE64URL')`. Buffer inputs are unaffected (raw bytes, no encoding to validate). The contract is now "well-formed base64url that doesn't carry the magic returns `null`; malformed encoding throws".

Six new tests cover disallowed characters, mixed valid/invalid characters, base64-padding rejection (`'YWJj=='` is valid base64 but NOT base64url since base64url is unpadded), standard-base64 `+`/`/` rejection (base64url uses `-`/`_`), valid-base64url-without-magic still returning `null`, and Buffer inputs being read as-is. The fast-check fuzz test on `inspectHeader(string)` also adds `INVALID_BASE64URL` to its allowed-codes set.

### Task 9 — Dependency refresh: minor/patch bumps via `npm update`, triaged majors (`package.json`, `package-lock.json`, `src/__tests__/crypto-manager.test.ts`)

`npm update` brought all minor/patch lines to latest. Major bumps were triaged one at a time, with all 4 pre-completion checks rerun after each:

- `@eslint/js` 9.34.0 → 9.39.4 → **10.0.1** (major) — accepted. ESLint 10's new `no-useless-assignment` rule flagged 3 test-file declarations of the form `let caught: unknown = undefined;` where `caught` is reassigned in a subsequent `catch`. Trivially fixed by dropping the `= undefined` initializer (the variable is initialized in the catch block's `caught = err;`).
- `eslint` 9.34.0 → 9.39.4 → **10.3.0** (major) — accepted (no further changes beyond the `no-useless-assignment` fix).
- `@types/node` 24.3.0 → 24.12.2 → **25.6.0** (major) — accepted, no source changes.
- `cross-env` 7.0.3 → **10.1.0** (major) — accepted, CLI-compatible. The test scripts use `cross-env NODE_OPTIONS=--experimental-vm-modules jest` which has identical behaviour in 10.x.
- `@typescript-eslint/eslint-plugin` 8.41.0 → **8.59.2** (minor)
- `@typescript-eslint/parser` 8.41.0 → **8.59.2** (minor)
- `eslint-plugin-prettier` 5.5.4 → **5.5.5** (patch)
- `jest` 30.1.1 → **30.3.0** (minor)
- `prettier` 3.6.2 → **3.8.3** (minor)
- `rimraf` 6.0.1 → **6.1.3** (minor)
- `ts-jest` 29.4.1 → **29.4.9** (patch)

**Deferred:** `typescript` 5.9.2 → 6.0.3 (major). TypeScript 6 changes the auto-include semantics for `@types/node` globals — `Buffer`, `process`, `node:crypto` and other Node-only types are no longer surfaced into the global scope by default, requiring an explicit `types: ['node']` (or similar) entry in `compilerOptions` and likely other knock-on changes. The cost/benefit didn't justify breaking up the iteration to chase this; left for a future iteration to investigate properly. We stay on TypeScript 5.9.3 for now.

`argon2` stays at 0.44.0 (in `optionalDependencies`). Iteration 1 already moved it to 0.44.0; bumping to 0.45+ requires a separate native-build-compatibility check that is out of scope here.

### Task 10 — `formatFileSize` upper-bound guard (`src/utils.ts`, `src/__tests__/utils.test.ts`)

`formatFileSize` previously validated `Number.isFinite(bytes)` and `bytes >= 0` but had no upper bound. A caller passing `Number.MAX_VALUE` (1.79e+308) got back the answer `1.7976931348623157e+308 TB` because the unit ladder caps at TB but the coefficient grows unbounded. The output was a mathematical artefact, not a useful display.

`formatFileSize` now throws `CryptoError(INVALID_INPUT, 'FILE_SIZE_TOO_LARGE')` for any input strictly greater than `Number.MAX_SAFE_INTEGER` (`2 ** 53 - 1`, ≈ 9 PB). JavaScript numbers above this threshold cannot represent integer byte counts exactly, so the resulting human-readable string would not be meaningful. The existing 1 PB (`1024 ** 5` ≈ 1.126e15) test still passes — that's well below the 9 PB safety boundary. The boundary value `Number.MAX_SAFE_INTEGER` itself is accepted (the threshold is strict `>`).

Three new tests cover `MAX_SAFE_INTEGER * 2` rejection, `Number.MAX_VALUE` rejection, and exact `MAX_SAFE_INTEGER` boundary acceptance.

### Files changed

- `src/crypto-manager.ts` — `inspectHeader` now validates base64url before decoding (Task 8); added `isValidBase64Url` import from `./utils.js`.
- `src/utils.ts` — `formatFileSize` upper-bound guard (Task 10).
- `src/__tests__/crypto-manager.test.ts` — 6 new tests for base64url validation in `inspectHeader` (Task 8); 3 `let caught: unknown = undefined;` → `let caught: unknown;` cleanups (ESLint 10 `no-useless-assignment` from Task 9).
- `src/__tests__/utils.test.ts` — 3 new tests for `formatFileSize` upper bound (Task 10).
- `src/__tests__/format-fuzz.test.ts` — `inspectHeader(string)` fuzz test allowed-codes set extended with `INVALID_BASE64URL` (Task 8).
- `package.json` — devDependency major/minor/patch bumps (Task 9); version `1.1.2` → `1.1.3`.
- `package-lock.json` — regenerated.

Test count: 569 → 578 (9 new tests; 6 base64url + 3 upper-bound). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.1.2 — Test Hardening: Property-Based Tampering, Format Fuzzing, Wire-Format Snapshots)

This release ships three medium-priority test-hardening tasks from FIX.md Iteration 2 (Tasks 7, 12, 13). All changes are test-only — no source code, no public API, no wire-format changes. v1 ciphertexts produced by v1.1.1 round-trip unchanged under v1.1.2 and vice versa.

### Task 7 — fast-check property tests for single-bit ciphertext tampering (`src/__tests__/property.test.ts`)

The existing `crypto-manager.test.ts` had example-based tampering tests (flip a specific reserved byte, flip the magic byte, etc.) that nailed down the post-Task-1 AAD-binding contract on a handful of pre-chosen offsets. Property-based coverage was missing: the example tests can't enumerate every byte position in a randomised plaintext + password + salt + IV configuration.

Six new property tests now lock in the invariant "flipping any single bit anywhere in a freshly produced ciphertext (or specifically inside the 22-byte v1 header) MUST cause `decrypt*` to throw `CryptoError`":

- `async text: flipping any single bit causes decryptText to throw CryptoError` — 50 cases over (plaintext, password, byteIdx fraction, bit index 0..7).
- `sync text: flipping any single bit causes decryptTextSync to throw CryptoError` — 75 cases.
- `async text v1 header: flipping any byte in offsets 0..21 throws CryptoError` — 50 cases targeted at the AAD-bound v1 header. After Task 1 shipped this is the first property-test that locks in the "header tampering throws" guarantee for randomised offsets / bit positions / plaintexts.
- `sync text v1 header: flipping any byte in offsets 0..21 throws CryptoError` — 75 cases for the PBKDF2 sync path.
- `async file: flipping any single bit causes decryptFile to throw CryptoError` — 25 cases (file I/O dominates per-case wall-clock).
- `sync file: flipping any single bit causes decryptFileSync to throw CryptoError` — 25 cases.

The properties use the same low-cost `makeFastCrypto` instance as the existing property tests (Argon2id at `memoryCost=2^14`, `timeCost=1`, PBKDF2 at 10 000 iterations), so wall-clock overhead is small (~14 s additional in the property suite). Random byte indices use a `[0, 1)` fraction multiplied by buffer length, which avoids out-of-range generations.

### Task 12 — fast-check fuzzing harness for `parseHeader` and `inspectHeader` (`src/__tests__/format-fuzz.test.ts`)

`parseHeader` is the only entry point that consumes attacker-controlled bytes BEFORE password authentication runs. The example-based tests cover specific malformed inputs (truncated header, unknown KDF id, unknown version, etc.) but the search space is too large to cover by hand. The new fuzz harness asserts the strict contract: for every input buffer, `parseHeader` either returns a well-formed `ParsedHeader` matching the published shape, or throws `CryptoError` with a code from the documented set (`TRUNCATED_HEADER`, `INVALID_MAGIC`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_KDF`, `INVALID_HEADER_PARAM`, `INVALID_HEADER_INPUT`, `KDF_PARAMS_OUT_OF_BOUNDS`). Never crashes, never returns garbage.

Six new fuzz tests:

- `parseHeader on random bytes: returns valid ParsedHeader OR throws known CryptoError` — 1000 cases over `Uint8Array` of length 0..1024.
- `parseHeader on magic-prefixed random bytes: deeper branches still safe` — 1000 cases with the first 4 bytes forced to `HPCR` so the fuzzer pushes past the magic-byte short-circuit and into version / kdfId / params validation.
- `parseHeader on tiny buffers (<HEADER_LENGTH): always throws TRUNCATED_HEADER` — 500 cases over 0..21 byte inputs; pins the truncation branch invariant exactly.
- `inspectHeader(Buffer)`, `inspectHeader(Buffer with magic prefix)`, `inspectHeader(string)` — 1000 cases each, asserting the public tooling-facing wrapper around `parseHeader` honours the same invariants and additionally returns `null` on missing-magic input.

`fc.assert` runs use a pinned seed (`0xc0ffee`, `0xfeedface`) so a regression always reproduces with the same failing input. Each case runs in microseconds (no KDF, no I/O), so the full fuzz file completes in ~1.3 s.

### Task 13 — Wire-format snapshot tests for v1 ciphertexts (`src/__tests__/format-snapshot.test.ts`, `src/__tests__/__snapshots__/format-snapshot.test.ts.snap`)

A round-trip test cannot detect format breakage where a buggy decrypt matches a buggy encrypt (the test passes, but every previously-encrypted ciphertext in the wild now fails to decrypt). Snapshot tests pin the on-disk byte layout exactly so that any silent reorder, endian flip, or off-by-one byte shift in the ciphertext format fails loud.

Determinism plumbing:

- `jest.spyOn(CryptoManager.prototype, 'generateSecureRandom')` returns 32 bytes of `0xAA` for salt, 12 bytes of `0xBB` for IV. Any unexpected length throws so a future code change that introduces a new fixed-randomness source surfaces visibly.
- `jest.unstable_mockModule('argon2', ...)` returns a fixed 32-byte `0xCC` key from `argon2.hash`. This isolates the snapshot from the actual Argon2id implementation (which we don't want to bake into wire-format expectations).
- The PBKDF2 sync path uses the platform-stable Node built-in `crypto.pbkdf2Sync` — fixed salt + password + iterations is enough to make the derived key bit-stable across runs.

Snapshot mechanism: standard Jest `toMatchSnapshot()` writing to `__snapshots__/format-snapshot.test.ts.snap`. (Inline `toMatchInlineSnapshot()` proved incompatible with `ts-jest`'s ESM mode in jest 30 — the AST transformation makes the source-position lookup fail.) The companion `.snap` file is checked into the repo, so a wire-format change shows up as a diff in code review just like an inline snapshot would.

Each ciphertext is broken into structural slices — full hex dump, header (22 bytes), salt (32 bytes), IV (12 bytes), auth tag (16 bytes), ciphertext body — so the snapshot file reads like a wire-format spec. Format version pinning (`FORMAT_VERSION === 0x01`, `HEADER_LENGTH === 22`, `MAGIC_BYTES === 'HPCR'`, KDF id constants) runs FIRST so a future v2 bump fails loud rather than silently overwriting v1 snapshots in `-u` mode.

### Files changed

- `src/__tests__/property.test.ts` — six new tampering property tests appended; module-level header comment updated to mention Task 7. No existing tests modified.
- `src/__tests__/format-fuzz.test.ts` — new file; six fuzz tests covering `parseHeader` and `inspectHeader` against random `Uint8Array` and base64url-shaped inputs.
- `src/__tests__/format-snapshot.test.ts` — new file; seven tests covering format-version pinning + Argon2id wire-format snapshot + PBKDF2 wire-format snapshot + round-trip sanity.
- `src/__tests__/__snapshots__/format-snapshot.test.ts.snap` — new file; 12 snapshot strings (hex-encoded byte slices for each KDF path).
- `package.json` — version `1.1.1` → `1.1.2`.

Test count: 550 → 569 (19 new tests). Property suite wall-clock: ~30 s (was ~14 s pre-Task-7). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.1.1 — Documentation, Argon2 Lazy-Load Robustness, Tarball Hygiene)

This release ships four high-priority correctness/hygiene fixes from FIX.md Iteration 2 (Tasks 3, 4, 5, 6). All changes are backward-compatible — no public API or wire-format changes; v1 ciphertexts produced by v1.1.0 round-trip cleanly under v1.1.1.

### Task 3 — `decryptFileSync` JSDoc rewritten to match the actual progress contract (`src/crypto-manager.ts`)

The previous JSDoc claimed the first progress event fired as `(bytesAlreadyRead, totalBytes)` (where `bytesAlreadyRead` represented the front-matter + trailing-tag bytes already consumed during metadata parsing). The implementation actually fires `(0, totalBytes)` as a literal start sentinel — matching the async `decryptFile` contract — followed by per-chunk events and a final `(totalBytes, totalBytes)`. The JSDoc and the inline implementation comment were both corrected to describe what the code actually does. No behaviour change; documentation-only fix.

### Task 4 — `loadArgon2` switched to an in-flight-promise pattern (`src/crypto-manager.ts`, `src/__tests__/argon2-lazy-load.test.ts`)

The previous implementation used a 3-state cache (`null` / loaded module / `ARGON2_LOAD_FAILED` sentinel). On any caught import error, the failure sentinel got written to the cache and stayed there for the lifetime of the process — meaning a transient failure (e.g. an ephemeral FS permission glitch on Windows during a parallel build-tool install) permanently disabled async crypto until the process restarted.

The new implementation stores either `null` (load not yet attempted, or previous attempt rejected) or a `Promise<Argon2Module>` (in-flight or already-settled successful load). Concurrent first-callers share the same in-flight promise (no duplicate dynamic imports under load). On rejection the cache slot is cleared via a compare-and-swap check, so the NEXT call after a failure starts a fresh import — transient failures recover. On success the resolved promise stays cached forever, so subsequent callers pay only an `await` of an already-settled promise.

Three new tests cover the new behaviour:

- `concurrent first-callers share a single import (Task 4 — coalescing)` — fires 20 parallel `deriveKey` calls and asserts exactly ONE module factory call.
- `concurrent first-callers all see the same rejection (Task 4 — failure coalescing)` — fires 20 parallel calls under a failing import and asserts all 20 reject with `CryptoError(MEMORY_ERROR, ARGON2_NOT_AVAILABLE)`, exactly one factory call for the burst, and a SUBSEQUENT call retries.
- `first call fails, second call succeeds — transient recovery (Task 4)` — first import rejects, second import resolves cleanly. The cache must NOT poison; the second call observes a fresh import that succeeds.

The pre-existing `caches the failure sentinel: a second call does NOT re-attempt the import` test (which pinned down the OLD stale-cache-forever behaviour) was rewritten as `on failure the cache clears so the next call can retry (Task 4 — transient recovery)` — it now asserts the opposite: every failed call retries, with one factory call per attempt.

### Task 5 — `SECURITY.md` Supported Versions table updated for post-1.0 (`SECURITY.md`)

The Supported Versions section still claimed "the package is pre-1.0 and is currently under active development" and listed `0.17.x` as the only supported line. Reality: the package shipped 1.0.0 in this codebase and is at 1.1.0+ with active 1.x maintenance. The section was rewritten to declare `1.x` as the sole supported line; pre-1.0 (`0.x`) is end-of-life and will not be patched. The next major bump (whenever 2.0.0 ships) will establish whether the previous major continues to receive security fixes.

### Task 6 — Source map / declaration map emission disabled to slim the published tarball (`tsconfig.json`, `CHANGELOG.md`)

`npm pack --dry-run` previously included 10 map files (`crypto-manager.js.map` 47 KB, `crypto-manager.d.ts.map` 3.5 KB, plus eight smaller maps) in the published tarball, despite `.npmignore` listing `*.d.ts.map` and `*.js.map` — the `package.json:files: dist/**/*` glob takes precedence over `.npmignore` for files matching the glob. The CHANGELOG entry for v1.0.0 (line 105 in the previous revision) inaccurately claimed source maps were "correctly excluded".

Fix: `tsconfig.json` now sets `sourceMap: false` and `declarationMap: false`, so no map files are emitted to `dist/` in the first place. `npm pack --dry-run` post-fix shows 15 files (was 25). The unpacked size drops by ~75 KB.

The previously-misleading v1.0.0 CHANGELOG sentence ("the published tarball includes `dist/**/*` ... source maps are correctly excluded") was true post-fix in v1.1.1 but was inaccurate when written for v1.0.0. We're not retconning the v1.0.0 entry; this v1.1.1 entry documents the actual fix.

### Files changed

- `src/crypto-manager.ts` — `decryptFileSync` JSDoc + implementation comment corrected (Task 3); `loadArgon2` rewritten to use the in-flight-promise pattern, removed `ARGON2_LOAD_FAILED` sentinel (Task 4).
- `src/__tests__/argon2-lazy-load.test.ts` — replaced the failure-sentinel-caching test with a transient-recovery test; added three new tests covering concurrent coalescing, failure coalescing, and first-fail-then-succeed transient recovery (Task 4).
- `SECURITY.md` — Supported Versions table updated to declare `1.x` as the sole supported line (Task 5).
- `tsconfig.json` — `sourceMap` and `declarationMap` flipped from `true` to `false` (Task 6).
- `package.json` — version `1.1.0` → `1.1.1`.

Test count: 547 → 550 (3 new tests for Task 4; 1 existing test rewritten in place to reflect the new behaviour). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.1.0 — Security Fixes: Header AAD Binding + KDF Parameter Caps)

This release ships **two critical security fixes** identified in FIX.md Iteration 2 (Tasks 1, 2, and 16). Both fixes change observable behaviour for v1 ciphertexts; v0 (legacy unversioned) ciphertexts are unaffected.

### Why a minor bump (1.0.0 → 1.1.0) for security fixes that change the wire format

Both changes are correctness fixes for documented properties of the library that v1.0.0 silently violated:

- The README's threat model promised "any single-bit modification to the ciphertext, salt, IV, header, or AAD context causes `decrypt*` to fail". v1.0.0 violated this for the 6 reserved bytes in the Argon2id header and the 12 reserved bytes in the PBKDF2 header.
- The library's input-handling promise was "malformed input surfaces as a `CryptoError` rather than a crash, infinite loop, or out-of-bounds read". v1.0.0 violated this for KDF-parameter-driven DoS (a 100-byte ciphertext could pin gigabytes of RAM or block the event loop for minutes).

A patch bump (`1.0.1`) would mask that the wire format for v1 ciphertexts changed. A major bump (`2.0.0`) would over-state the disruption — the public API surface is unchanged, only the AAD computation differs. We chose the minor bump (`1.1.0`) as the honest middle: the new feature is the `legacyHeaderAad` opt-in shim that lets callers decrypt pre-v1.1.0 ciphertexts without re-encrypting them. **Callers with v1 ciphertexts produced by v1.0.0 should set `legacyHeaderAad: true` to decrypt them, then re-encrypt under v1.1.0's default to gain the integrity-bound headers.**

### Critical security fixes

#### Task 1 — v1 header bytes are now bound to the AES-GCM auth tag (`src/crypto-manager.ts`, `src/format.ts`, `src/types.ts`)

**The vulnerability:** v1.0.0 called `setAAD(this.aad)` at all six encrypt/decrypt sites. The v1 header bytes (magic + version + kdfId + KDF parameter block) were NOT included in the AAD. The Argon2id parameter block has 6 reserved bytes (offsets 16–21), and the PBKDF2 parameter block has 12 reserved bytes (offsets 10–21). An attacker who flipped bits ONLY in those reserved regions changed the on-disk ciphertext bytes but left the parsed header parameters unchanged, so decryption proceeded and the auth tag still verified. End-to-end reproducer (FIX.md "Headline findings"):

```js
const cm = new CryptoManager();
const ct = await cm.encryptText('secret message', 'MySecureP@ssw0rd123!');
const buf = Buffer.from(ct, 'base64url');
buf[16] = 0xFF; buf[17] = 0xFF; // reserved bytes
const tampered = buf.toString('base64url');
console.log(await cm.decryptText(tampered, 'MySecureP@ssw0rd123!'));
// pre-fix: 'secret message' (vulnerability)
// post-fix: throws CryptoError(DECRYPTION_FAILED)
```

**The fix:** every v1 encrypt/decrypt path now passes `Buffer.concat([this.aad, headerBytes])` to `setAAD`. Critically, the decrypt path AAD-binds the **on-disk header bytes verbatim** (not a re-serialised copy via `packHeader`, which would zero-fill reserved regions and defeat the purpose). v0 paths still use `this.aad`-only — no header to bind. Code-level changes:

- `src/crypto-manager.ts:790-829` (`encryptData`) and `:879-933` (`decryptData`) gained an optional `aadOverride` parameter (default behaviour unchanged for direct callers).
- `src/crypto-manager.ts` six original `setAAD` call sites are now header-bound for v1; the encrypt path builds the header BEFORE the cipher so it can be passed in (v1 file paths previously built the header AFTER), and the decrypt path captures `headerForAad` at parse time so the bytes used in AAD are exactly what was on disk.
- `src/crypto-manager.ts` adds private `aadForV1(headerBytes: Buffer): Buffer` helper that toggles between header-bound and v1.0.0-compat formats based on `legacyHeaderAad`.
- New constructor option `legacyHeaderAad: boolean` (default `false`) opts back in to the v1.0.0 unbound-AAD format. Use only as a temporary migration aid for decrypting pre-v1.1.0 ciphertexts.

**Tests added** (`src/__tests__/crypto-manager.test.ts`):

- `'rejects tampering with reserved bytes 16..21'` — flips each Argon2id reserved byte individually and asserts `CryptoError`. Pre-fix this would silently succeed.
- `'rejects tampering with reserved bytes 10..21'` (PBKDF2 sync path) — same treatment for sync ciphertexts.
- `'rejects tampering with magic / version / kdfId bytes'` and `'rejects tampering with KDF param bytes 6..15'` — regression guards so the binding doesn't accidentally weaken existing detection.
- File-paths variant flips reserved bytes in encrypted files (sync + async) and asserts decrypt rejects.
- `'still decrypts a v0 ciphertext (AAD change must not affect v0 paths)'` — locks in v0 backward compatibility.
- `'lets a 1.0.0-format v1 ciphertext (header NOT bound) decrypt under legacyHeaderAad: true'` — pins down the migration shim contract.

#### Task 2 + Task 16 — `parseHeader` now rejects out-of-bounds KDF parameters fast (`src/format.ts`)

**The vulnerability:** v1.0.0's `parseHeader` only validated `memoryCost / timeCost / parallelism / iterations > 0`; it did NOT cap them. A malicious 100-byte ciphertext could request `memoryCost = 4 GiB` (the u32 max in KB) or `iterations = 100M`, and the library would dutifully invoke `argon2.hash` / `crypto.pbkdf2Sync` with those values. Validator's reproducers blocked for >5s (Argon2id at 1 GiB memoryCost) and indefinitely (PBKDF2 at 100M iterations).

**The fix:** `parseHeader` now enforces conservative upper bounds before returning, throwing `CryptoError(INVALID_INPUT, 'KDF_PARAMS_OUT_OF_BOUNDS')` on out-of-range parameters:

| KDF | Field | Cap | Rationale |
| --- | --- | --- | --- |
| Argon2id | `memoryCost` | `2^22` (4 GiB in KB) | 8× the documented `ULTRA` tier (512 MiB) — well above any legitimate need. |
| Argon2id | `timeCost` | 100 | OWASP HIGH recommends 3 — 100 is a 33× safety factor. |
| Argon2id | `parallelism` | 64 | Most deployments use 1–4 lanes. |
| PBKDF2-SHA256 | `iterations` | 10 000 000 | OWASP 2023+ recommends 600 000 — 16× safety factor. |

Caps live INSIDE `parseHeader` (not at the call site of `parseHeader` from `decryptText`). This is Task 16's "validator amendment" — it means `inspectHeader` (which calls `parseHeader`) returns bounded values too, so tooling cannot be tricked into displaying absurd parameters while the decrypt path catches a different limit. Caps fire BEFORE `argon2.hash` / `crypto.pbkdf2Sync` is invoked, so the rejection is sub-millisecond regardless of how malicious the input is. The caps are exported as `MAX_ARGON2_MEMORY_COST`, `MAX_ARGON2_TIME_COST`, `MAX_ARGON2_PARALLELISM`, `MAX_PBKDF2_ITERATIONS` for downstream introspection.

**Tests added** (`src/__tests__/crypto-manager.test.ts`):

- One test per Argon2id parameter and one for PBKDF2 iterations, each crafting a malicious header via the public `packHeader` helper, decrypting via the public API, and asserting `KDF_PARAMS_OUT_OF_BOUNDS` plus a wall-clock bound (`< 100ms` / `< 1000ms` / `< 2000ms` depending on path).
- Boundary tests confirming exact-cap values still parse successfully.
- Two `inspectHeader` tests (Task 16) confirming the caps apply to the tooling surface.

### Wire-format compatibility

| Ciphertext source | v1.1.0 default decrypt | v1.1.0 with `legacyHeaderAad: true` |
| --- | --- | --- |
| v0 (legacy, no header) | works | works |
| v1 from v1.1.0+ (header-bound AAD) | works | fails (`DECRYPTION_FAILED`) |
| v1 from v1.0.0 (unbound AAD) | fails (`DECRYPTION_FAILED`) | works |

### Files changed

- `src/format.ts` — added KDF parameter caps + `KDF_PARAMS_OUT_OF_BOUNDS` rejection inside `parseHeader`. Exported `MAX_ARGON2_MEMORY_COST`, `MAX_ARGON2_TIME_COST`, `MAX_ARGON2_PARALLELISM`, `MAX_PBKDF2_ITERATIONS`.
- `src/types.ts` — new `legacyHeaderAad?: boolean` option on `CryptoManagerOptions`.
- `src/crypto-manager.ts` — new private `aadForV1` helper; new `legacyHeaderAad` field; all 6 setAAD sites now use header-bound AAD for v1 ciphertexts (with the on-disk header bytes captured verbatim on decrypt). Reordered the encrypt paths to build the v1 header BEFORE the cipher so it can be passed into `setAAD`. `encryptData` / `decryptData` gained an optional `aadOverride` parameter for internal use.
- `src/__tests__/crypto-manager.test.ts` — 23 new tests covering header tampering, DoS bounds, `inspectHeader` cap enforcement, v0 backward compat, and the `legacyHeaderAad` migration shim.
- `README.md` — Threat Model section updated to reflect the new integrity guarantee + parser DoS protection. New "Migration: v1.0.0 → v1.1.0" subsection describing the wire-format change and migration paths.
- `package.json` — version `1.0.0` → `1.1.0`.

Test count: 524 → 547 (23 new). All four pre-completion checks (`build`, `test`, `lint`, `type-check`) pass.

## 2026-05-04 (v1.0.0 — First Stable Release: FIX.md Iteration 1 Consolidated)

This is the first **stable** release of `@hiprax/crypto`. It marks the point where the library leaves its pre-1.0 development line and adopts strict semver going forward. The 1.0.0 milestone consolidates a 33-task security and correctness audit ("FIX.md Iteration 1"), pulling together every change made in v0.13.0 through v0.19.0-Unreleased into a single coherent line that downstream consumers can pin to.

The release also rolls up the two undated "Unreleased" CHANGELOG sections that previously sat at the head of this file (Tasks 26+27 — Distribution Hygiene + Threat Model; Tasks 23+24+25 — Symbol Cleanup + Utility Hardening) so that everything from v0.13.0 forward ships under the single 1.0.0 label.

### Why 1.0.0 (semver rationale)

Three pieces of work in this iteration are unambiguously **breaking** under semver and force the major bump:

1. **Task 1 — PBKDF2 iterations bumped from 100 000 to 600 000** (`src/crypto-manager.ts`). New sync ciphertexts are derived with the higher iteration count. v0 sync ciphertexts produced before this change carry no embedded iteration count; the new `legacyPbkdf2Iterations` constructor option (default `100000`) controls what the decoder assumes for them.
2. **Task 2 — Versioned ciphertext format ("HPCR" v1 header)** (`src/format.ts`, `src/crypto-manager.ts`). Every ciphertext produced by 1.0.0 begins with a 22-byte header. Legacy v0 layouts are still decryptable under the default `legacyMode: 'auto'`, but the byte format on the wire is different and any code that hand-parsed v0 layouts is affected.
3. **Task 18 — Default Argon2id `memoryCost` raised from `2^16` (64 MiB) to `2^17` (128 MiB)** (`src/crypto-manager.ts`, `SECURITY_THRESHOLDS`). The `getSecurityLevel()` thresholds also moved up: HIGH from `2^16` → `2^17`, ULTRA from `2^18` → `2^19`. This is a roughly 2× CPU/memory regression for callers using defaults.

Two additional changes are TypeScript-breaking or subtly behavioural:

4. **Task 23 — `EncryptionAlgorithm.AES_256_CBC` removed** from the enum (`src/types.ts`). Any TypeScript consumer that referenced this identifier (e.g. in a switch statement, type guard, or fixture) will fail to type-check.
5. **Task 24 — `formatFileSize(negative)` now throws** `CryptoError(INVALID_INPUT, 'NEGATIVE_FILE_SIZE')` instead of silently returning `'0 Bytes'` (`src/utils.ts`). Inputs that are NaN / ±Infinity / non-number similarly throw with code `'INVALID_FILE_SIZE'`. **Task 25 — `retryWithBackoff` default policy** no longer retries `CryptoError`s of type `INVALID_PASSWORD` (or with code `WEAK_PASSWORD` / `INVALID_PASSWORD`). Pass `shouldRetry: () => true` to restore the previous behaviour.

A separate fix that is also breaking-by-honesty:

6. **Task 31 — CJS `require` keys removed from the `exports` map**. The package was advertising `"require": "./dist/index.js"` for a file that is emitted as ESM; CJS consumers were therefore broken in practice on Node 18-21 and got a footgun synthetic namespace on Node 22+. The 1.0.0 `exports` map honestly declares the package as ESM-only.

### Migration path for breaking changes

The following migration table is the canonical reference for upgrading from any v0.x release to 1.0.0. Each row says what changed, who is affected, and exactly how to recover:

| Change | Affected consumer | Recovery |
| --- | --- | --- |
| **Versioned ciphertext format (v1)** (Task 2) | Anyone holding ciphertexts produced by < v0.11.0 (no `HPCR` header) | Default `legacyMode: 'auto'` continues to decrypt them. To reject legacy data instead, pass `legacyMode: 'strict'` or `legacyMode: 'reject'` to the constructor. To inspect the format of a ciphertext without decrypting it, call `cm.inspectHeader(ciphertext)`. |
| **PBKDF2 iterations 100k → 600k** (Task 1) | Sync ciphertexts produced by < v0.11.0 (no embedded iteration count in the header) | Default `legacyPbkdf2Iterations: 100000` makes the decoder assume the historical 100k for v0 sync data, so existing legacy ciphertexts continue to decrypt with no caller change. Override `legacyPbkdf2Iterations` if you have v0 sync data produced under a non-default iteration count. v1 ciphertexts carry the iteration count in their header and are always decoded correctly. |
| **Argon2id memoryCost 64 MiB → 128 MiB** (Task 18) | Any caller using the default `memoryCost` whose runtime cannot afford the doubled memory + ~2× latency | Pass `memoryCost: 2 ** 16` to the constructor to opt back into the previous 64 MiB profile. Note that this configuration will report `getSecurityLevel() === 'medium'` rather than `'high'` under the new thresholds. v1 ciphertexts produced under either default round-trip across configurations because the parameters are embedded in each ciphertext's header. |
| **Security-level thresholds raised** (Task 18) | Any caller that asserted `getSecurityLevel() === 'ultra'` or `'high'` against a fixed configuration | Replace string-equality assertions with numeric comparisons against the exported `SECURITY_THRESHOLDS` constant: `params.argon2Options.memoryCost >= SECURITY_THRESHOLDS.HIGH.memoryCost`. The `SECURITY_THRESHOLDS` object is `Object.freeze`d so it cannot be mutated to weaken the bar. |
| **`EncryptionAlgorithm.AES_256_CBC` removed** (Task 23) | TypeScript consumers that reference this identifier (switch statements, type guards, test fixtures) | Delete the dead branch — the library never had a CBC implementation behind the identifier, so any code reading from this name was already non-functional. The remaining enum has the single member `AES_256_GCM = 'aes-256-gcm'`. |
| **`formatFileSize(negative)` throws** (Task 24 part 1) | Callers passing negative or non-finite input that previously got `'0 Bytes'` | Either validate inputs upstream (`if (size < 0) ...`) or catch the new `CryptoError` at the call site and convert. The `formatFileSize(0) === '0 Bytes'` contract is preserved — zero is still a legitimate size. |
| **`retryWithBackoff` no longer retries password errors by default** (Task 25) | Callers that wrapped an `encryptText` / `decryptText` call in `retryWithBackoff` and depended on retries firing for `WEAK_PASSWORD` / `INVALID_PASSWORD` | Pass `shouldRetry: () => true` to restore the pre-1.0 retry-everything behaviour, or supply a custom predicate that returns `true` for the specific cases you want retried. The new default policy still retries generic `Error`s and non-password `CryptoError`s. |
| **CJS `require()` no longer works** (Task 31) | CJS consumers of `require('@hiprax/crypto')` (always broken in practice — see release rationale above) | Switch to dynamic `import()` from inside an `async` function: `const { CryptoManager } = await import('@hiprax/crypto')`. ESM consumers (`import { CryptoManager } from '@hiprax/crypto'`) are unaffected. |
| **`createBackupPath` filename format gained `_HHHHHH` discriminator** (Task 24 part 2) | Callers that regex-parse the result of `createBackupPath` | Adjust the regex to accept an optional `_[0-9a-f]{6}` segment between the timestamp and the suffix. |

### Summary of all changes in 1.0.0

The full log of changes per FIX.md task is preserved in the `v0.13.0` through `v0.18.2` entries below — they are kept verbatim as the historical narrative of how 1.0.0 came together. The high-level rollup:

#### Critical (correctness / security, blocking)

- **C1 / Task 1** — PBKDF2 iteration count default raised from 100 000 to 600 000 (OWASP 2023+ minimum). New constructor options `pbkdf2Iterations` (active iterations) and `legacyPbkdf2Iterations` (assumption for v0 ciphertexts).
- **C2 / Task 2** — Versioned ciphertext format with 22-byte `HPCR` header carrying KDF id and parameters. New `legacyMode` option (`'auto'` / `'strict'` / `'reject'`) gates v0 decryption. New `inspectHeader()` method exposes the header without decrypting.
- **C3 / Task 5** — `secureClear` JSDoc tightened to spell out V8 / GC / compiler limitations honestly. Decrypt paths now also call `secureClear` on the `combined` buffer.
- **C5 / Task 4** — Atomic file output: all four file methods write to a sibling temp file (`${outputPath}.<random16hex>.tmp`) and `rename` to the canonical path only on full success. Pre-existing files at `outputPath` are preserved on error.
- **C6 / Task 3** — `decryptFile` and `decryptFileSync` now stream the ciphertext through the cipher rather than reading the whole file into memory. Peak memory is bounded by the stream high-water mark (default 64 KiB) regardless of input size.
- **C7 / Task 17** — JSDoc on `encryptData` and `decryptData` carries explicit `@security` warnings about (key, IV) reuse and the ~2^32-invocations-per-key birthday bound on random 96-bit IVs. New `README` section documents the same boundary. New documenting test (`encryptData with reused (key, iv) is deterministic`) locks in the security boundary.
- **C8 / Task 11 + Task 32** — `validatePath` rejects null bytes and ASCII control characters (codepoints `< 0x20` or `0x7F`). New optional `{ allowedRoot }` option performs segment-aware resolved-prefix containment so within-drive cross-traversal is caught even when `path.normalize` collapses `..` cancel-outs. `sanitizeFilename` neutralises literal `..` sequences and preserves the file extension when truncating to 255 chars.

#### High (production-readiness)

- **H1 / Task 6** — `npm audit fix` resolved 10 transitive dev-dep CVEs (1 critical, 5 high, 3 moderate, 1 low). `argon2` bumped to `^0.44.0`.
- **H2 / Task 7** — `.github/workflows/ci.yml` (matrix: Ubuntu + Windows × Node 18/20/22) and `.github/workflows/publish.yml` (release-published trigger, `--access public --provenance`).
- **H3 / Task 8** — `SECURITY.md` with disclosure policy, supported-versions table, scope rules, response-time SLA, and security-relevant defaults reference.
- **H4 / Task 9** — `argon2` moved to `optionalDependencies` and lazy-loaded on first async call. Failure surfaces as `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` with the actionable message: *"argon2 native module unavailable. Install build tools (Python + node-gyp) or use *Sync methods (PBKDF2)."*
- **H5 / Task 17** — Decryption-failure ambiguity (wrong password vs. tampered ciphertext vs. wrong AAD vs. KDF mismatch) now documented loudly in the README. The KDF-mismatch case becomes self-evident with the v1 header (Task 2) — `KDF_MISMATCH` is the explicit error code.
- **H6 / Task 10** — Optional `progress?: ProgressCallback` parameter added to all four file methods. Callback fires on stream `data` events for async paths and per 64 KiB chunk for `decryptFileSync`. Universal invariants: at least one event fires, `processed` is monotonically non-decreasing, the final event has `processed === total`. A throwing callback aborts the operation and preserves the caller's error identity.
- **H7 / Task 15** — `package.json` lint scripts dropped the legacy `--ext .ts` flag (ESLint 9 flat config infers from `eslint.config.ts`'s `files` block).
- **H8 / Task 15** — `@eslint/js` declared as a direct devDependency (was previously transitive via `eslint`).
- **H9 / Task 16** — `prepublishOnly` strengthened to `"npm run lint && npm run type-check && npm run build && npm test"` so a lint-failing or type-broken release cannot ship via `npm publish`.
- **H11 / Task 31** — CJS `require` keys dropped from the `exports` map. Package now declares ESM-only honestly. README documents `await import()` as the supported CJS interop pattern.

#### Medium (quality / best-practices)

- **M1 / Task 18** — Default `memoryCost` bumped to `2^17` (128 MiB), matching OWASP 2026 first-choice tier for Argon2id. `getSecurityLevel()` thresholds moved up correspondingly. `SECURITY_THRESHOLDS` now exported as a deeply-frozen `as const` record.
- **M3 / Task 11** — `sanitizeFilename` preserves the file extension when truncating long names (was: dropped the extension by truncating the tail).
- **M4 + M5 / Task 13** — `validatePassword` now accepts EITHER ≥20-char passphrases (NIST SP 800-63B style, no character-class requirements) OR the existing 8-char composition rule. The composition rule's "special character" check broadened from `[!@#$%^&*(),.?":{}|<>]` to `[^A-Za-z0-9]`.
- **M6 / Task 14** — Constructor validates `defaultPassphrase` strength immediately rather than deferring to first encrypt. New `skipPasswordValidation: boolean` option bypasses the check for legacy-data decryption.
- **M7 / Task 12** — Passwords are NFC-normalised (`String.prototype.normalize('NFC')`) before key derivation in both Argon2id and PBKDF2 paths. Visually identical inputs (precomposed `é` vs. `e + U+0301`) now derive the same key.
- **M11 / Task 25** — `RetryConfig.shouldRetry?: (error, attempt) => boolean` added. Default policy excludes password-class crypto errors.
- **M12 / Task 3 follow-up** — `decryptFile` / `decryptFileSync` JSDoc updated to describe the new streaming behaviour (was: "reads entire file into memory").
- **M13 / Task 23** — `EncryptionAlgorithm.AES_256_CBC` removed from the enum (the implementation never existed).
- **M14 / Task 10** — `ProgressCallback` type wired through the public file-method API (was: defined but unused).
- **M15 / Task 22** — Tests now use `jest.spyOn(nodeCrypto, ...).mockImplementation(...)` followed by `jest.restoreAllMocks()` instead of mutating `nodeCrypto` properties directly. Safe under parallel jest execution.
- **M16 / Task 21** — Per-suite unique tempdirs under `os.tmpdir()` (`hiprax-crypto-<hex>` etc.) eliminate cross-worker file-path collisions.
- **M17 / Task 17** — Documenting test added asserting that `encryptData` with a reused `(key, iv)` is deterministic (and demonstrating the two-time-pad keystream-cancellation leak).
- **M18 / Task 20** — Hash-verified large-file streaming round-trip tests (`SKIP_LARGE_TESTS=1` to skip; `LARGE_FILE_TEST_MB=N` to override default 10 MiB).
- **M19 / Task 19** — `fast-check`-based property tests in `src/__tests__/property.test.ts`: round-trip, distinguishability, IV freshness, wrong-password rejection. Async + sync coverage. 200+ random cases per property.

#### Low (nice-to-have)

- **L1 + L10 / Task 26** — README gained a `## 📜 Changelog` section linking to `CHANGELOG.md` and a `## 🛡️ Threat Model` section explicitly listing in-scope and out-of-scope attacks.
- **L6 / Task 24** — `createBackupPath` adds a 6-char hex random discriminator before the suffix to prevent intra-second collisions.
- **L8 / Task 26** — `package.json:repository.url` updated to the npm-canonical `git+https://github.com/Hiprax/crypto.git` form.
- **L11 / Task 29** — CHANGELOG dates audited; ISO `YYYY-MM-DD` format is now consistent throughout. Two `Unreleased` blocks consolidated into this 1.0.0 entry.
- **L12 / Task 26** — `CHANGELOG.md` added to `package.json:files` and `.npmignore` so it ships in the published tarball.
- **L13 / Task 27** — `.editorconfig` added at the repo root.
- **L14 / Task 27** — `engines.npm: ">=8.0.0"` added (npm 8 introduced reliable `optionalDependencies` install semantics).
- **L15 / Task 26** — `keywords` extended with `argon2id`, `aes-gcm`, `pbkdf2`, `authenticated-encryption`, `esm`.

#### Validator amendments (added during the audit, not in the original FIX.md)

- **Task 31** — CJS/ESM `exports` mismatch fix (rolled into H11 above).
- **Task 32** — `validatePath` allowedRoot containment + null-byte / control-char rejection (rolled into C8 above).
- **Task 33** — Triage update on the `prepare` script (kept it; supports the `npm install github:Hiprax/crypto` path).

### Tarball verification (1.0.0)

- `npm pack --dry-run` confirms the published tarball includes `dist/**/*` (compiled JS + `.d.ts`), `README.md`, `LICENSE`, `SECURITY.md`, and `CHANGELOG.md`. The `.editorconfig` is correctly excluded. **Correction (added in v1.1.1):** the line originally claimed source maps were also excluded — that was wrong for v1.0.0 and v1.1.0 (the `dist/**/*` glob took precedence over `.npmignore`'s `*.js.map` / `*.d.ts.map` rules, so 10 map files shipped). Source maps stopped being emitted entirely in v1.1.1 (see the v1.1.1 entry above). Publishing ESM-only — the `exports` map declares only `types` + `import` for each entry path.

### Backward compatibility — at a glance

- **Source-level breaking changes**: `EncryptionAlgorithm.AES_256_CBC` removed (Task 23). Any TypeScript code referencing this identifier needs the dead branch deleted.
- **Behavioural breaking changes**: `formatFileSize(negative)` throws (Task 24); `retryWithBackoff` skips password-class errors by default (Task 25). Both have documented opt-out paths.
- **Wire-format breaking changes**: New ciphertexts use the v1 `HPCR` header (Task 2). Legacy v0 ciphertexts are still decryptable under default `legacyMode: 'auto'`.
- **Performance regression**: Default Argon2id `memoryCost` doubled to 128 MiB (Task 18). Opt back into 64 MiB via `memoryCost: 2 ** 16` if needed.
- **Module-system breaking change**: CJS `require()` no longer works (Task 31; was always broken in practice). Use dynamic `import()`.
- **Non-breaking**: every other change in this iteration is additive (new options, new methods, new error codes, new tests, new documentation).

### Validation

All 4 pre-completion checks pass on the 1.0.0 release commit:

- `npm run build` — clean.
- `npm run type-check` — clean.
- `npm run lint` — 0 errors, 0 warnings.
- `npm test` — full suite passes (524 tests across 5 test files: `crypto-manager.test.ts`, `utils.test.ts`, `argon2-lazy-load.test.ts`, `esm-smoke.test.ts`, `property.test.ts`).

### Documentation

- **`FIX.md`**: All 33 tasks marked `[x]`. Tasks 29 (CHANGELOG dates) and 30 (1.0.0 version bump) are the final entries closing out FIX.md Iteration 1.
- **`CLAUDE.md`**: Package version reference updated from `v0.18.2` to `v1.0.0`. Internal `v0.19.0` reference for the AES_256_CBC removal updated to `v1.0.0`. The architectural sections (Source Files, Argon2 lazy-load, Ciphertext Formats, etc.) are the canonical post-iteration reference.
- **`README.md`**: Internal `v0.15.0` references for the threshold movement updated to `v1.0.0` where they describe the wire-format-current behaviour; historical narrative pointers ("prior to v0.11.0", "v0.14.x → v0.15.0") are preserved as historical context for users tracking pre-1.0 development.
- **`package.json`**: `version` bumped from `0.18.2` to `1.0.0`.

---

## 2026-05-04 (v0.18.2 — Test Isolation Hardening: Per-Suite Tempdirs + jest.spyOn)

### Changed

- **`src/__tests__/crypto-manager.test.ts`** (Task 21): Replaced the bare `os.tmpdir()` shared scratch dir with a unique-per-suite directory under `os.tmpdir()`. The new `TEST_DIR` constant is computed at module load as `path.join(os.tmpdir(), \`hiprax-crypto-${nodeCrypto.randomBytes(8).toString('hex')}\`)` and is created in `beforeAll` and torn down in `afterAll` via `mkdirSync`/`rmSync` with `recursive: true`. The `tempDir` alias inside the top-level describe block was repointed to `TEST_DIR` so the ~70 file-path constants nested across the suite (`testFilePath`, `encryptedFilePath`, etc.) automatically pick up the unique root with no per-test edits. This eliminates collisions between concurrent jest workers and between repeated runs whose `afterEach` cleanup was skipped due to a thrown assertion.
- **`src/__tests__/utils.test.ts`** (Task 21): Same TEST_DIR pattern applied with the suite-discriminator `hiprax-crypto-utils-` so the two suites' scratch dirs cannot alias each other when both run in parallel under jest.
- **`src/__tests__/property.test.ts`** (Task 21): The async file-path property test, which previously created its own `path.join(os.tmpdir(), \`hiprax-prop-${...}\`)` directory, now nests under a suite-wide `TEST_DIR` (`hiprax-crypto-property-${...}`). The per-test scratch dir is still randomised so each property iteration starts from an empty directory, but the suite-wide afterAll catches any leftover entries even if a property test crashes before its inner finally block runs.
- **`src/__tests__/esm-smoke.test.ts`** (Task 21): The four spawned-subprocess probes that each created their own `os.tmpdir()` sub-directory now nest those directories under a single suite-wide `TEST_DIR` (`hiprax-crypto-esm-smoke-${...}`). Each test still gets its own scratch dir for probe scripts (`probe.mjs`/`probe.cjs`) so subprocess invocations remain self-contained, but the parent dir is created once and torn down once.
- **`src/__tests__/crypto-manager.test.ts`** (Task 22): The two tests that mutated `node:crypto` directly (`(nodeCrypto as Record<string, unknown>).pbkdf2Sync = ...` and the matching `createCipheriv` block) now use `jest.spyOn(nodeCrypto, 'pbkdf2Sync').mockImplementation(...)` and `jest.spyOn(nodeCrypto, 'createCipheriv').mockImplementation(...)` respectively. Each enclosing describe block gained an `afterEach(() => jest.restoreAllMocks())` so the mock is automatically rolled back even if an assertion throws mid-test. The mocked-impl signatures are typed via `as unknown as typeof nodeCrypto.pbkdf2Sync` (resp. `createCipheriv`) to satisfy `jest.SpiedFunction` overload resolution under ts-jest's strict ESM mode without weakening the cast at the call site.

### Why This Matters

Both refactors target a class of test-state-leak bug that is invisible during single-threaded local runs but becomes a flaky-CI failure mode under parallel test execution:

- **Tempdir collision (Task 21)**: When two jest workers run `crypto-manager.test.ts` simultaneously (CI matrix, watch mode with multiple modified files, etc.), they would both write to the same `os.tmpdir()/test-encrypt.txt` path. One worker's `afterEach` `unlink` could race with the other's `writeFile`, producing ENOENT or partial-write artefacts that cause spurious failures. The unique-per-suite TEST_DIR contract makes file-path collisions structurally impossible.
- **Direct module mutation (Task 22)**: `(nodeCrypto as Record<string, unknown>).pbkdf2Sync = stub` mutates a property on the shared module namespace. Other tests in the same worker that happen to call `crypto.pbkdf2Sync` (e.g. through `deriveKeySync` from a sibling describe block) would see the stub if scheduled before the manual restore line ran. `jest.spyOn` + `restoreAllMocks` is jest's blessed pattern for the same intent: it tracks the spy in jest's mock registry, so even an unhandled exception that bypasses the manual restore is cleaned up by the next `afterEach` regardless.

### Backward Compatibility

- Test-only change. No source files modified, no public API change. Consumers are unaffected.
- The published runtime artefact (`dist/`) is byte-identical to v0.18.1.

### Caveats Around `jest.spyOn` Under ESM

- The `import nodeCrypto from 'node:crypto'` form resolves to the same CJS namespace object that production code (`src/crypto-manager.ts`) imports via `import crypto from 'node:crypto'`. Both imports reference the cached module record, so a spy installed on the test's binding observes calls made through the production binding. This is the standard ts-jest + `default-esm` preset behaviour and was verified against the live test suite (511/511 tests pass; the two refactored tests still trigger their `KEY_DERIVATION_FAILED`/`ENCRYPTION_FAILED` branches as before).
- `jest.spyOn` requires the target property be `configurable: true`. Node's `node:crypto` exports are configurable in current Node 18-22 lines, so the spy install succeeds. If a future Node major freezes the namespace (it has not signalled this), the test would fail loud rather than silently — `jest.spyOn` would throw `TypeError: Cannot redefine property` at the call site.

### Validation

- All 4 pre-completion checks pass (`npm run build`, `npm test`, `npm run lint`, `npm run type-check`).
- Test count unchanged at 511; runtime unchanged.

### Documentation

- **`FIX.md`**: Tasks 21 and 22 marked `[x]`.
- **`CLAUDE.md`**: No structural changes — the test-infrastructure conventions section already documented `os.tmpdir()` usage, which is still accurate (suites still root in `os.tmpdir()` — they just create a unique sub-directory now).

## 2026-05-04 (v0.18.1 — Property Tests Now Cover Unicode Inputs)

### Changed

- **`src/__tests__/property.test.ts`**: The `arbText` arbitrary used in every property now produces BOTH ASCII and arbitrary-unicode strings (via `fc.oneof` between `fc.string({ minLength: 1, maxLength: 200 })` and `fc.string({ minLength: 1, maxLength: 200, unit: 'binary' })`). Previously the suite only generated printable ASCII (0x20-0x7E), so the round-trip, distinguishability, IV-freshness, and wrong-password properties were never exercised against multibyte UTF-8 sequences, combining marks, or astral-plane codepoints. The existing UTF-8 round-trip filter (`Buffer.from(s, 'utf8').toString('utf8') === s`) drops any unpaired surrogates that fast-check produces under `unit: 'binary'`, so the property still has a clean precondition. All 10 property tests pass with the broader arbitrary; suite runtime is unchanged at ~22-30s.

### Backward Compatibility

- Test-only change. No source files modified, no public API change. Consumers are unaffected.

## 2026-05-04 (v0.18.0 — Property-Based Tests + Hash-Verified Large-File Streaming)

### Added

- **`src/__tests__/property.test.ts`** (Task 19, new file): Property-based test suite using `fast-check`. Locks in four high-level invariants of the encryption API across many random `(text, password)` inputs rather than a handful of hand-curated examples:
  1. **Round-trip** — `decrypt(encrypt(text, password), password) === text` for both async (Argon2id) and sync (PBKDF2) text APIs and for the file API. The file-API property writes random plaintext to disk, runs `encryptFile` + `decryptFile`, and asserts SHA-256 hash equality on the round-tripped bytes.
  2. **Distinct ciphertexts for distinct plaintexts** — `encrypt(t1, p) !== encrypt(t2, p)` whenever `t1 !== t2`. Async and sync paths covered.
  3. **Fresh IV/salt per call** — `encrypt(t, p) !== encrypt(t, p)` when called twice with identical inputs. Failure here would indicate RNG reuse, a critical security regression. A cheap variant of this property runs at 200 cases (no KDF involved) and only inspects the high-entropy slice of the base64url payload.
  4. **Wrong password rejection** — `decryptText(encrypt(t, p1), p2)` throws `CryptoError` whenever `p1 !== p2`. Locks in AES-GCM auth-tag enforcement: a wrong key MUST NOT produce silent garbled plaintext. Async and sync paths covered.
  - Uses a hand-curated `arbStrongPassword` arbitrary that constructs passwords always satisfying `validatePassword`'s composition rule (4 mandatory category samples + arbitrary tail), avoiding the huge filter-rejection cost of `fc.string().filter(validatePassword)`.
  - Uses a TEST-ONLY low-cost `CryptoManager` config (`memoryCost: 2 ** 14` = 16 MiB, `timeCost: 1`, `pbkdf2Iterations: 10_000`) so each property runs ~50-200 cases in well under a minute. The file is documented loudly that this configuration is NOT for production use; production callers should keep the v0.15.0 OWASP-aligned defaults (`memoryCost: 2 ** 17`, `timeCost: 3`, PBKDF2 `600_000`).
  - Per-property `numRuns` is set conservatively (50 for KDF-heavy properties, 75 for sync, 200 for KDF-free cheap properties, 25 for the disk-I/O file property) so the total suite runs in 20-50 seconds end-to-end on commodity hardware (varies with system load and parallel-test scheduler interference).
- **`src/__tests__/crypto-manager.test.ts`** (Task 20): New `'large file streaming (Task 20)'` describe block complementing the existing `'large-file streaming round-trip (Task 3)'` block. Adds two end-to-end tests (async + sync) that exercise the streaming pipeline through a stream-API-driven file generator and a sha256 integrity check rather than the chunk-by-chunk byte compare used in Task 3:
  - File generation uses `fs.createWriteStream` with chunked async writes and respects backpressure via the `drain` event — matches the Task 20 spec exactly and stresses the read side of the encryption pipeline against a stream that was itself produced by the canonical async stream API.
  - Round-trip integrity is verified by streaming the original and decrypted files through `crypto.createHash('sha256')` and comparing the digests. The hash is computed via `fs.createReadStream` so the test harness itself does NOT load the multi-MiB blob into memory (otherwise the test would not actually validate streaming).
  - Default size is 10 MiB, overridable via `process.env.LARGE_FILE_TEST_MB` (matches Task 3).
  - Block is skipped via `it.skip(...)` when `process.env.SKIP_LARGE_TESTS === '1'` so CI can opt out of the disk + CPU cost without recompiling.
  - Per-test timeout is 120000 ms (2 min) to absorb worst-case I/O on slow runners.
  - Deliberately does NOT duplicate the v0/v1 + sync/async corner matrix from Task 3 — those four corners are already covered there. The two new tests use the v1 default path and the hash compare; together with Task 3's byte compare across legacy/current and sync/async, the cumulative large-file surface is meaningfully broader than the sum of either block alone.
- **`package.json`**: `"fast-check": "^4.7.0"` added as a `devDependency`. The `4.x` line is the current major as of 2026-05-04 and ships ESM-first (matches this repo's `"type": "module"` setup). `fast-check` has zero runtime dependencies of its own (only `pure-rand` for the seeded RNG), so the install is small and audit-clean.

### Changed

- **Test count**: `npm test` now runs **511 tests** across 5 test files (was **499** across 4 files) — Task 19 adds 10 property tests in `property.test.ts`, Task 20 adds 2 large-file streaming tests in `crypto-manager.test.ts`. All 4 pre-completion checks (`build`, `test`, `lint`, `type-check`) pass with the new suite. Coverage threshold (80% across branches/functions/lines/statements) remains met.

### Documentation

- **`FIX.md`**: Tasks 19 and 20 marked `[x]`.
- **`CLAUDE.md`** + **`README.md`**: No structural changes — the new tests are additive and follow existing conventions (`os.tmpdir()` for scratch dirs, async/sync split, `expect(...).rejects.toThrow(CryptoError)` for async rejection).

### Backward Compatibility

- This release is purely additive: a new test file, a new describe block, and one new devDependency. The published runtime artefact (`dist/`) is byte-identical to v0.17.1 — no source files were changed. Consumers running `npm install @hiprax/crypto` are unaffected.
- `fast-check` is a `devDependency` only; it is not pulled in by consumer installs.
- Both new test blocks honour the existing `SKIP_LARGE_TESTS=1` and `LARGE_FILE_TEST_MB=N` environment-variable contracts, so existing CI configurations continue to work without changes.

## 2026-05-04 (v0.17.1 — npm Script Cleanup: ESLint Flat Config + Stronger prepublishOnly)

### Changed

- **`package.json`** (Task 15): The `lint` and `lint:fix` scripts dropped the legacy `--ext .ts` flag (`"eslint src --ext .ts"` → `"eslint src"`, and `"eslint src --ext .ts --fix"` → `"eslint src --fix"`). ESLint 9's flat config (`eslint.config.ts`) infers file patterns from its `files: ['src/**/*.ts']` block, so `--ext` is silently ignored under flat config and may be promoted to a hard error in a future ESLint major. The post-change behaviour was verified two ways: (1) `npx eslint src --debug` confirms all 9 `.ts` files in `src/` (5 source files + 4 test files: `crypto-manager.ts`, `format.ts`, `index.ts`, `types.ts`, `utils.ts`, `__tests__/argon2-lazy-load.test.ts`, `__tests__/crypto-manager.test.ts`, `__tests__/esm-smoke.test.ts`, `__tests__/utils.test.ts`) are picked up by the linter; (2) a deliberate `const __lintProbe: number = 1;` injected into `src/index.ts` produced an `'@typescript-eslint/no-unused-vars'` error from `npx eslint src` and exit code `1`, proving the script still catches real errors (rolled back immediately).
- **`package.json`** (Task 16): The `prepublishOnly` script was strengthened from `"npm run build && npm run test"` to `"npm run lint && npm run type-check && npm run build && npm test"`. The new gauntlet runs the full pre-completion checklist (lint → type-check → build → test) so a typed-but-broken or lint-failing release cannot ship via `npm publish`. Order is intentional: `lint` and `type-check` run before `build` so a syntactically-broken `src/` is rejected before `tsc` rather than after, and `npm test` runs last so a build that compiles but fails tests does not leave a dist/ tarball in a publishable-looking state.

### Added

- **`package.json`** (Task 15): `"@eslint/js": "^9.34.0"` added as a direct `devDependency`. Previously `@eslint/js` was only available transitively through the `eslint` package; the `eslint.config.ts`'s `import js from '@eslint/js'` worked at runtime but the import contract was implicit and could be silently broken by a future eslint major dropping `@eslint/js` from its own dependency tree. The pinned `^9.34.0` matches the version that `npm ls @eslint/js` reports for the current install (the same version eslint pulls transitively today, so the `package-lock.json` did not need to deduplicate).

### Documentation

- **`CLAUDE.md`** (Task 33): The npm-scripts reference table was updated to reflect the new `lint`, `lint:fix`, and `prepublishOnly` commands, and three new explanatory paragraphs were added below the table. The first documents the ESLint flat config rationale (why `--ext .ts` was removed, why `@eslint/js` is now a direct devDep). The second documents the `prepublishOnly` ordering rationale (lint/type-check before build). The third documents the **decision to keep the `prepare` script** despite the duplicate-build observation in Task 33's verifier note: `prepare` is required for the `npm install github:Hiprax/crypto` consumer workflow (where the consumer pulls from a git URL and needs a built `dist/` after install), and the duplicate-build cost in the publish path is ~2-3s of idempotent `tsc` work — invisible to the user and matched by the convention of every major TypeScript library on npm. The full table of three contexts where `prepare` runs (dev `npm install` in a git checkout, `npm install <git-url>`, and pre-publish) is included for future reference.
- **`FIX.md`**: Tasks 15, 16, 33 marked `[x]`. Task 33's text now records the explicit "Kept `prepare`" decision and rationale.

### Backward Compatibility

- The script signature changes are repository-internal only. Consumers running `npm install @hiprax/crypto` are unaffected — none of the modified scripts ship in the published tarball or run on the consumer side.
- The `npm run lint` / `npm run lint:fix` UX is unchanged: the same files are linted with the same rules and the same output format. The only invisible difference is which mechanism resolves the file list (flat config's `files` pattern vs the deprecated `--ext` flag).
- The strengthened `prepublishOnly` only runs during `npm publish` / `npm pack` flows on the maintainer's machine. CI's `.github/workflows/publish.yml` already runs the same lint + type-check + build + test sequence inline before invoking `npm publish`, so the workflow's behaviour is unchanged — `prepublishOnly` simply provides a defence-in-depth check for direct-from-localhost publishes.
- `@eslint/js` was already on disk as a transitive install; declaring it directly in `devDependencies` does not change the resolved on-disk version (`9.34.0`) and `package-lock.json` did not need to add a new tree.

## 2026-05-04 (v0.17.0 — Dependency Hygiene + CI/CD + Disclosure Policy)

### Fixed

- **`package.json`** (Task 6): Bumped `argon2` (optional dependency) from `^0.43.0` to `^0.44.0`. The 0.44.0 release is a maintenance update — build-system tweaks for reproducible builds, no breaking API changes (`argon2.hash()` and the `argon2id`/`argon2i`/`argon2d` constants are unchanged) — so the existing lazy-load path in `src/crypto-manager.ts` continues to work without code changes. The full 499-test suite was re-run after the bump to confirm no regressions.
- **`package-lock.json`** (Task 6): `npm audit fix` resolved all 10 reported vulnerabilities in transitive **dev** dependencies — 1 critical (`handlebars` JS injection via AST type confusion + prototype-method-access gap + multiple other CVEs through the jest dependency chain), 5 high (`@isaacs/brace-expansion` ReDoS, `flatted` unbounded-recursion DoS + prototype pollution, `glob` CLI command injection, `minimatch` ReDoS via repeated wildcards + GLOBSTAR backtracking + nested extglobs, `picomatch` POSIX-class method injection + ReDoS via extglob quantifiers), 3 moderate (`ajv` ReDoS via `$data`, `brace-expansion` zero-step memory exhaustion, `js-yaml` prototype pollution in merge), and 1 low (`diff` parsePatch / applyPatch DoS). Post-fix `npm audit` reports 0 vulnerabilities. None of the affected packages ship in `dist/`, so no published-artifact code path was vulnerable; this is a development-toolchain hygiene fix.

### Added

- **`.github/workflows/ci.yml`** (Task 7, new file): GitHub Actions CI workflow running on `push` and `pull_request` against `main`/`master`. Uses a 6-cell matrix (`os: [ubuntu-latest, windows-latest]` × `node: [18, 20, 22]`) with `fail-fast: false` so all combinations run to completion regardless of which fails first. Each cell runs the full pre-completion gauntlet — `npm ci`, `npm run lint`, `npm run type-check`, `npm run build`, `npm test`, `npm audit --audit-level=high` — in that order so a build/test failure does not get masked by an audit failure (or vice-versa). The workflow uses `setup-node` with `cache: npm` for fast incremental runs, and a workflow-level `concurrency` group cancels in-progress runs when a newer commit lands on the same ref. The `--audit-level=high` policy makes high+critical fail the build while letting moderate+low through (those are tracked but non-blocking, matching the `SECURITY.md` Out-of-Scope clause for transitive dev deps).
- **`.github/workflows/publish.yml`** (Task 7, new file): Release workflow triggered by `release: published` events. Pinned to `node: 20` (recent LTS — there is no value in matrix-publishing the same artefact across multiple Node versions) and the public npm registry (`registry-url: https://registry.npmjs.org/`). Re-runs the full lint + type-check + build + test gauntlet before invoking `npm publish --access public --provenance`. The `--access public` flag is required for scoped packages because npm defaults scoped publishes to private; the `--provenance` flag opts into npm's package-provenance attestations so consumers can verify the build originated from this exact GitHub Actions run. Authentication uses the `NPM_TOKEN` repository secret (passed as `NODE_AUTH_TOKEN` per `setup-node`'s contract) and the workflow declares `permissions: id-token: write` so the OIDC handshake required for provenance can succeed.
- **`SECURITY.md`** (Task 8, new file): Vulnerability disclosure policy at the repository root. Documents (1) the supported-versions table — currently only `0.16.x` (now `0.17.x`) receives patches, with the policy revising at 1.0.0 to support current major + previous minor; (2) two private reporting channels — GitHub Security Advisories (preferred — free, structured, supports CVE issuance) and `security@hiprax.dev` as an email fallback, both with a clear "do not file public issues" warning; (3) a response-time SLA — 72-hour acknowledgement, 7-day triage, coordinated public disclosure once a fix ships; (4) a coordinated-disclosure flow with up-to-90-day embargo and reporter credit unless anonymity is requested; (5) explicit **scope** covering crypto correctness, key handling, side channels (timing oracles + error-message disambiguation), authenticity bypass, format/parser bugs, path traversal in file APIs, and dep-driven weakening; (6) explicit **out-of-scope** for DoS via huge inputs, transitive dev-dep CVEs (those route to GitHub Issues + `npm audit`), brute force against weak passwords, theoretical primitive breaks, and missing best-practice hardening with no documented impact; (7) a security-relevant defaults reference (Argon2id `2 ** 17` / 3 / 1, PBKDF2 600 000 iterations, ciphertext format v1 with `legacyMode: 'auto'`, default AAD) so reporters can call out which defaults their PoC depends on.
- **`README.md`**: New CI badge in the badge row at the top of the file linking to `https://github.com/Hiprax/crypto/actions/workflows/ci.yml` so the live status of the matrix is visible from the package homepage. New "Reporting a Vulnerability" subsection under "Security Notice" pointing readers at `SECURITY.md` and explicitly forbidding public issue filings for security problems, with both private channels (GitHub Security Advisories + `security@hiprax.dev`) and the 72-hour acknowledgement SLA called out inline.

### Changed

- **`package.json`** (Task 8): Added `"SECURITY.md"` to the `files` array so the vulnerability disclosure policy ships with the published npm tarball. Consumers who installed the package previously had no in-tarball pointer to the disclosure flow.
- **`.npmignore`** (Task 8): Added `!SECURITY.md` to the markdown exclusion block so the `*.md` rule does not strip `SECURITY.md` from the published tarball. Mirrors the existing `!README.md` exception. (Both `*.md` excludes and `!`-style allowlists are needed because `package.json:files` is the authoritative inclusion list, but the redundant `.npmignore` allowlist is kept for defence-in-depth in case the include list is ever simplified.)

### Backward Compatibility

- The `argon2` bump from `^0.43.0` to `^0.44.0` is **not** a breaking change. The semver-major release of `argon2` happens at `0.x.0`, but per the upstream release notes the only differences between 0.43.x and 0.44.0 are build-system tweaks for reproducible builds — the `argon2.hash()` signature, the `argon2id` constant, and every other API surface this library uses are unchanged. Consumers do not need to take any action; `npm install` (or `npm ci`) will pick up 0.44.0 automatically on the next install. Consumers stuck on a runtime that has a prebuilt `argon2@0.43.x` binary but not `0.44.x` can still install — the dependency is `optional`, so `argon2` install failure no longer blocks `@hiprax/crypto` install (this was already true since v0.13.0).
- The CI/CD workflows are repository-internal — they have no effect on consumers. They run only when the repository is built on GitHub Actions, and the `publish.yml` workflow is gated on `release: published` events so it cannot fire on regular push/PR traffic.
- `SECURITY.md` is additive documentation and is now included in the published tarball. It does not change any runtime behaviour.

## 2026-05-04 (v0.16.0 — Progress Callbacks for File Ops)

### Fixed

- **`src/crypto-manager.ts`** (`encryptFile`): The initial `(0, totalBytes)` progress event is now invoked BEFORE the temp output file's `WriteStream` is created. Previously the stream was opened first, so a callback that threw on the bracket event left the underlying file descriptor open. On Windows that blocks the catch block's `safeUnlink(tempPath)` call (the OS refuses to unlink a file held open by another handle) and an orphan `${outputPath}.<rand>.tmp` would linger in the output directory across the abort. The other three file methods (`decryptFile`, `encryptFileSync`, `decryptFileSync`) already invoked the initial event before allocating any file resources, so they were not affected. A regression test (`does not leave an orphan .tmp file when the initial 0/total callback throws`) scans the output directory for sibling `.tmp` files after the abort and asserts the array is empty, locking the ordering in.

### Added

- **`src/crypto-manager.ts`** (Task 10): All four file methods (`encryptFile`, `decryptFile`, `encryptFileSync`, `decryptFileSync`) now accept an optional fourth `progress?: ProgressCallback` parameter. When supplied, the callback receives `(bytesProcessed: number, totalBytes: number)` events that satisfy the universal invariants: at least one event fires, every event reports the same `total`, `processed` is monotonically non-decreasing, and the FINAL event has `processed === total`. The async streaming methods attach a `data` listener to the readable BEFORE `pipeline()` starts (so the very first chunk cannot slip past), and accumulate `chunk.length` to report cumulative byte progress. The sync streaming decrypt fires per 64 KiB chunk inside the existing `readSync` loop. The sync encrypt path (which reads the full input via a single `readFileSync`) fires only the two bracket events (start + after rename) — per-chunk events would be misleading there. Argument is fully optional, every pre-Task-10 call shape continues to work unchanged.
- **`src/crypto-manager.ts`** (Task 10): New module-level helpers `tagProgressThrow` / `isProgressThrow` and a private `unique symbol` `PROGRESS_THROW`. The catch blocks of all four file methods detect the marker and re-throw progress-callback errors with their original identity intact (preserving `instanceof MyError`) instead of wrapping them in `CryptoError(FILE_ENCRYPTION_FAILED)` / `CryptoError(FILE_DECRYPTION_FAILED)`. The wrapping path is reserved for opaque internal failures.
- **`src/__tests__/crypto-manager.test.ts`** (Task 10): New `file progress callbacks (Task 10)` describe block with 18 tests across five sub-blocks: `encryptFile (async)` (4 tests), `decryptFile (async)` (3 tests), `encryptFileSync` (3 tests), `decryptFileSync` (3 tests), `round-trip with progress on both sides` (1 test), and `omitting the progress argument is backward compatible` (4 tests). Each method has at least one test asserting the universal progress invariants (monotonicity, total-stability, final 100% event), plus method-specific tests pinning down the exact event count for paths with a fixed contract (sync encrypt = 2 events, sync decrypt > 2). The throw-aborts behaviour is verified for all four methods using a custom `ProgressBoom extends Error` subclass and an `instanceof` assertion to confirm the caller's identity is preserved through the catch block.
- **`src/__tests__/crypto-manager.test.ts`** (Task 10): New shared `assertProgressInvariants` helper inside the describe block that captures the four universal invariants in one reusable function. Used by every "primary contract" test so a future regression that breaks any invariant fails the same assertion message regardless of which method introduced it.

### Changed

- **`src/crypto-manager.ts`** (Task 10): `encryptFile`, `decryptFile`, `encryptFileSync`, `decryptFileSync` JSDoc rewritten to describe the progress callback contract explicitly, including: the exact bracket events emitted (initial 0/total, final total/total), per-chunk vs once-only behaviour per method, what `totalBytes` denominates (input file size in bytes — for decrypt this is ciphertext bytes including overhead, not plaintext bytes), and the throw-aborts policy. Each method gained an `@example` block showing the callback in use.
- **`src/crypto-manager.ts`** (Task 10): `ProgressCallback` is now imported from `./types.js` via `import type` (per `verbatimModuleSyntax`) and referenced by all four file method signatures. The previously-dead type — flagged in FIX.md item M14 as "defined but unused" — is now wired through the public API.
- **`src/crypto-manager.ts`**: New imports `statSync` from `node:fs` (used by `encryptFile` and `encryptFileSync` to capture `totalBytes` once at the start so the progress callback receives a stable value across all events).
- **`src/crypto-manager.ts`**: New private helper `invokeProgress(progress, processed, total)` centralises the "fire one progress event" logic. Wraps the user callback in a try/catch and re-throws with the `PROGRESS_THROW` marker so the outer catch block can preserve the caller's error identity.
- **`README.md`**: New `Progress callbacks for file ops` subsection under `🔧 Configuration` documenting the contract table (per-method initial / per-chunk / final event behaviour, total denomination), the throw-aborts policy with rationale, the best-effort-progress workaround pattern (caller-side try/catch), and worked examples for all four methods.
- **`README.md`**: API reference signatures updated for `encryptFile`, `decryptFile`, `encryptFileSync`, `decryptFileSync` to include the new `progress?: ProgressCallback` argument, with example snippets in each method's documentation that show the callback in use.

### Backward Compatibility

- The `progress` argument is **strictly optional** on every method. All pre-Task-10 call shapes (`encryptFile(in, out, password)`, `encryptFileSync(in, out)`, etc.) continue to work unchanged with identical behaviour and identical output bytes — the four "omitting the progress argument is backward compatible" tests in the new test block lock this in explicitly.
- No method, type, or error code was removed or renamed. The only new visible-behaviour change is that callers who **opt in** to progress reporting now receive events; callers who do not pass a `progress` argument see exactly the same behaviour as before.
- The throw-propagation policy chosen for progress-callback errors is **Option A (honest abort)**: a throwing callback aborts the operation and the temp file is cleaned up so `outputPath` is never partially written. This preserves the caller's error identity (e.g. `instanceof MyError`) so debug tooling continues to recognise their own error subclasses. Callers who want best-effort progress (no abort on throw) can wrap their callback in a try/catch — the README documents this pattern.

## 2026-05-04 (v0.15.0 — Argon2id Memory Bump + Threshold Refactor + AES-GCM Caveat)

### ⚠️ Performance regression — read first

The default Argon2id `memoryCost` has been bumped from `2 ** 16` (64 MiB) up to `2 ** 17` (128 MiB) so the library's out-of-the-box configuration matches the OWASP 2026 first-choice tier for Argon2id (Task 18 in FIX.md). This **doubles the per-call memory footprint and roughly doubles the latency** of every async key-derivation call (`deriveKey`, `encryptText`, `decryptText`, `encryptFile`, `decryptFile`). The trade-off buys roughly 2× the GPU brute-force resistance.

If your environment is memory-constrained (mobile, embedded, low-memory containers, free-tier hosts) and the perf hit is unacceptable, **opt back into the previous 64 MiB profile** by passing `memoryCost: 2 ** 16` to the `CryptoManager` constructor. A `CryptoManager` configured this way will report `getSecurityLevel() === 'medium'` (per the new threshold table — see below) but will produce ciphertexts that are byte-for-byte indistinguishable from the previous default's output and will round-trip with the new default's instances unchanged.

**Existing v1 ciphertexts continue to decrypt unchanged.** Each ciphertext header embeds the exact `memoryCost` / `timeCost` / `parallelism` that were used to derive its key, so the decoder applies the embedded values rather than the constructor default. Data encrypted under the old 64 MiB default round-trips under the new default with no migration step — only the CPU/memory cost of NEW encryptions changes. Legacy v0 ciphertexts are also unaffected because they use the constructor's currently-configured Argon2id parameters at decrypt time, which the constructor option lets you control.

The security-level threshold table also moved up: the **HIGH** tier now requires `memoryCost >= 2 ** 17` (was `2 ** 16`) and the **ULTRA** tier now requires `memoryCost >= 2 ** 19` (was `2 ** 18`). A configuration of `(memoryCost: 2 ** 18, timeCost: 4)` that previously reported ULTRA now reports HIGH; to retain ULTRA you must provision `(memoryCost: 2 ** 19, timeCost: 4)`. This is a behaviour change to `getSecurityLevel()` only — it does NOT affect ciphertext format, nor decryption of existing ciphertexts, nor any other API.

### Changed

- **`src/crypto-manager.ts`** (Task 18): Default `memoryCost` bumped from `2 ** 16` (64 MiB) to `2 ** 17` (128 MiB) — the OWASP 2026 first-choice tier for Argon2id. The constructor's Argon2 defaults now read from the new exported `SECURITY_THRESHOLDS.HIGH` constant rather than from a literal, so the default and the threshold cannot drift apart.
- **`src/crypto-manager.ts`** (Task 18): `getSecurityLevel()` thresholds updated — ULTRA now requires `memoryCost >= 2 ** 19` (was `2 ** 18`) and HIGH now requires `memoryCost >= 2 ** 17` (was `2 ** 16`). MEDIUM (`2 ** 14`) is unchanged. The ULTRA `timeCost` (4), HIGH `timeCost` (3), and MEDIUM `timeCost` (2) thresholds are unchanged. Anything below MEDIUM still reports LOW.
- **`src/crypto-manager.ts`** (Task 28): Hardcoded threshold values in `getSecurityLevel()` extracted into a single source of truth — the new `SECURITY_THRESHOLDS` const object — and `getSecurityLevel()` now references it. The default Argon2 parameters in the constructor also read from this constant. There is now exactly one place in the source where these magic numbers live.
- **`src/crypto-manager.ts`** (Task 17): JSDoc on `encryptData` rewritten with a `@security` warning describing why `(key, iv)` reuse is catastrophic for AES-GCM (keystream cancellation + GCM auth-subkey leak), the `~2 ** 32` invocations-per-key birthday bound on random 96-bit IVs (NIST SP 800-38D), and a pointer to the high-level methods (`encryptText`/`encryptFile`) that take care of IV uniqueness automatically. JSDoc on `decryptData` extended to spell out that all tag-check failures (wrong key, wrong IV, wrong AAD, tampered ciphertext) surface as the same generic `DECRYPTION_FAILED` code, and that the genericness is intentional to avoid a chosen-ciphertext oracle.
- **`README.md`** (Task 18): "Security Levels" section rewritten to reflect the post-bump thresholds, document the perf regression, list the migration path (`memoryCost: 2 ** 16` for the old behaviour), and explain why existing v1 ciphertexts round-trip without migration. New "Programmatic introspection" subsection shows how to use the `SECURITY_THRESHOLDS` export to assert minimum policy at startup.
- **`README.md`** (Task 17): New "AES-GCM (key, IV) reuse — security boundary for the low-level API" subsection under "Security Features" with the same caveat as the JSDoc, plus an in-line callout above the API references for `encryptData`/`decryptData` that links to the new section. The "Custom Configuration" example was updated to show `2 ** 19` for ULTRA so the snippet matches the post-bump threshold.
- **`README.md`** (Task 18): The constructor-options table now documents the new `memoryCost` default (`131072` / 128 MiB) with a back-reference to the migration note.

### Added

- **`src/crypto-manager.ts`** (Task 28): New module-level export `SECURITY_THRESHOLDS` — a deeply-readonly (typed `as const` AND recursively `Object.freeze`d so even untyped consumers cannot mutate it) record of `{ ULTRA, HIGH, MEDIUM } -> { memoryCost, timeCost }` minimums. JSDoc explains the OWASP 2026 rationale for each tier and how the classifier consumes them.
- **`src/index.ts`** (Task 28): `SECURITY_THRESHOLDS` re-exported from the package entry point so downstream tooling can `import { SECURITY_THRESHOLDS } from '@hiprax/crypto'` and assert that a configured policy meets a baseline at startup. `isValidPassword` is also now exported through the entry point (was already exported from `crypto-manager.ts`; the index re-export makes it discoverable to consumers who only `import` from the root).
- **`src/__tests__/crypto-manager.test.ts`** (Task 18): 3 new tests in the existing `getSecurityLevel` block (ULTRA at the post-bump threshold `2 ** 19`, HIGH at the post-bump threshold `2 ** 17`, MEDIUM-classification of the previous default `2 ** 16`, and HIGH-classification of the previous ULTRA configuration `2 ** 18` — each test explicitly notes that it locks in the threshold change). 2 new tests in the `getSecurityLevel - boundary conditions` block covering the asymmetric "memoryCost meets threshold but timeCost does not" cases under the new thresholds. Plus 1 new test in the `Constructor` block asserting the post-bump default Argon2 parameters explicitly (`memoryCost = 2 ** 17`, `timeCost = 3`, `parallelism = 1`) so a future regression that resets the default is caught immediately.
- **`src/__tests__/crypto-manager.test.ts`** (Task 28): New `SECURITY_THRESHOLDS (Task 28)` describe block with 5 cases — exposed-value checks for each tier (ULTRA / HIGH / MEDIUM), a round-trip invariant that `new CryptoManager({ memoryCost, timeCost: SECURITY_THRESHOLDS.X })` classifies as tier `X` (catches future drift between the table and the classifier), an explicit consistency check that the default `CryptoManager` matches `SECURITY_THRESHOLDS.HIGH` byte-for-byte, and a runtime-immutability check that attempts to mutate `SECURITY_THRESHOLDS.HIGH.memoryCost = 1` are no-ops in non-strict mode and throw in strict mode (because the object is `Object.freeze`d).
- **`src/__tests__/crypto-manager.test.ts`** (Task 17): New documentation test `encryptData with reused (key, iv) is deterministic — security boundary documentation (Task 17 / M17)` in the existing `encryptData/decryptData roundtrip` block. The test deliberately encrypts the same plaintext twice with the same `(key, iv)` and asserts the two `(encrypted, tag)` outputs are byte-identical (proving GCM determinism under fixed `(key, iv)`). It then encrypts a DIFFERENT plaintext with the same `(key, iv)` and asserts that `xor(ciphertext1, ciphertext2) === xor(plaintext1, plaintext2)` — the textbook "two-time pad" leak. The test is heavily commented to explain that this is a guardrail, not a feature endorsement: a future refactor that breaks GCM determinism would silently change a documented security boundary, and this test forces a deliberate review when that happens.
- **`src/__tests__/crypto-manager.test.ts`**: One pre-existing test (`should preserve embedded parameters across round-trip (async)`) given an explicit 30-second per-test timeout because its `(timeCost: 5, parallelism: 3)` configuration exceeded jest's default 5-second timeout under the new memory pressure of the bumped 128 MiB default elsewhere in the suite.

### Backward Compatibility

- **Ciphertext format**: Unchanged. Every existing v0 and v1 ciphertext continues to decrypt successfully. v1 ciphertexts use the parameters embedded in their header (so the constructor default is irrelevant for decryption); v0 ciphertexts continue to use the constructor's currently-configured Argon2id parameters, which is the same contract as before.
- **API surface**: Unchanged. No methods, types, or error codes were removed or renamed. `encryptData` and `decryptData` keep their existing signatures and runtime behaviour — only their JSDoc was strengthened. `getSecurityLevel()` keeps its signature; only its threshold table moved up by one power of two for the HIGH and ULTRA tiers.
- **Performance regression**: NEW encryptions made by users who relied on the default `memoryCost` will be 2× slower and use 2× memory. Users who previously passed an explicit `memoryCost` are unaffected. The opt-back-in path (`memoryCost: 2 ** 16`) is documented in README and CHANGELOG.
- **Threshold change**: Users who introspected `getSecurityLevel()` and asserted exact strings ("must be 'ultra'") will see those assertions fail for configurations that previously passed. The recommended replacement is to compare against `SECURITY_THRESHOLDS.X.memoryCost` / `.timeCost` directly, which gives a stable numeric contract that survives future threshold movements.
- **`SECURITY_THRESHOLDS` is additive**: existing imports of `CryptoManager` and the type/enum exports are unchanged.

## 2026-05-04 (v0.14.0 — Password Handling Hardening)

### Changed

- **`src/crypto-manager.ts`** (Task 13): `validatePassword` now accepts either of two acceptance rules — (a) **passphrase rule (NIST SP 800-63B style)**: at least 20 characters, regardless of character composition, OR (b) **composition rule**: at least 8 characters AND contains at least one uppercase letter, lowercase letter, digit, and **non-alphanumeric character**. The "non-alphanumeric" check uses `/[^A-Za-z0-9]/` (broader than the previous narrow allow-list `/[!@#$%^&*(),.?":{}|<>]/`), so common-but-previously-rejected specials like `_`, `-`, `+`, `[`, `]`, and non-ASCII punctuation now count as "special". Existing strong passwords that satisfied the old composition rule (e.g. `'Test1234!'`) continue to validate unchanged.
- **`src/utils.ts`** (Task 13): `validatePasswordStrength` updated for parity with `CryptoManager.validatePassword` — long passphrases (>= 20 chars) short-circuit to score 5 with empty feedback, and the special-character regex was broadened to `/[^A-Za-z0-9]/`. The two validators no longer disagree on the same input.
- **`src/crypto-manager.ts`** (Task 12): `deriveKey` (Argon2id, async) and `deriveKeySync` (PBKDF2-HMAC-SHA256, sync) both apply `String.prototype.normalize('NFC')` to the password before passing it to the underlying KDF. Without this, `'café'` typed as a precomposed `é` (U+00E9, NFC — what most input methods produce) and the same character typed as `e + U+0301` (combining acute, NFD) would derive different keys despite being visually identical. After this change, NFC and NFD spellings of the same password produce the same key and ciphertexts encrypted under one form decrypt under the other. The flag introduced for Task 14 (`skipPasswordValidation`) does **not** disable normalisation.
- **`src/crypto-manager.ts`** (Task 14): The `CryptoManager` constructor now validates `defaultPassphrase` strength **at construction time** (after the existing empty-string check). A weak passphrase raises `CryptoError(INVALID_PASSWORD, 'WEAK_PASSWORD')` immediately rather than on first encrypt. The validator delegates to a new module-level pure helper `isValidPassword(password)` (also exported for advanced consumers) so the check does not depend on `this` being fully initialised — this avoids any chicken-and-egg ordering hazard between constructor body and instance method dispatch. Users who need to decrypt legacy data encrypted under a weaker password can opt out via the new `skipPasswordValidation: true` constructor option (see Added below). The opt-out applies **only** to the constructor's `defaultPassphrase` strength check; encryption-time validation in `encryptText` / `encryptTextSync` / `encryptFile` / `encryptFileSync` is unchanged, and Unicode NFC normalisation in `deriveKey`/`deriveKeySync` is also unchanged.
- **`README.md`**: "Password Requirements" section rewritten to document the dual acceptance rules (passphrase OR composition), the broadened special-character class, the constructor-time `defaultPassphrase` validation with the `skipPasswordValidation` opt-out, and the NFC normalisation contract. Existing strong passwords that satisfied the old rules continue to validate.

### Added

- **`src/crypto-manager.ts`** (Task 14): New module-level export `isValidPassword(password: string): boolean` — a pure, instance-state-free implementation of the password strength rules. Used by both the public `validatePassword` instance method and the constructor's `defaultPassphrase` validator. Two new module-level constants document the thresholds: `PASSPHRASE_MIN_LENGTH = 20` (NIST passphrase rule) and `PASSWORD_MIN_LENGTH = 8` (composition rule).
- **`src/types.ts`** (Task 14): New `CryptoManagerOptions` field `skipPasswordValidation?: boolean` (default `false`). When `true`, the constructor accepts a weak `defaultPassphrase` without throwing `WEAK_PASSWORD`. JSDoc explicitly notes that the flag does NOT disable encryption-time validation and does NOT disable NFC normalisation.
- **`src/__tests__/crypto-manager.test.ts`**: Added 23 new tests across three describe blocks. The extended `validatePassword` block (7 new cases) covers XKCD-style passphrases at and above 20 chars, the 19-char rejection boundary, the broadened `[^A-Za-z0-9]` special-character class (`_`, `-`, `+`, `=`, `[`, `]`, `'`, backtick, backslash, non-ASCII), and the historical narrow specials (back-compat invariant). The new `NFC password normalisation (Task 12)` block (5 cases) covers Argon2id and PBKDF2 keys produced from NFC vs NFD spellings of `'café'` matching exactly, async and sync text round-trips across normalisation forms, and a sanity-suppression check that NFC does not collapse genuinely different passwords. The new `constructor defaultPassphrase validation (Task 14)` block (10 cases) covers strong / long / weak / 8-char-missing-category passphrases, `skipPasswordValidation` bypass, the explicit NFC-normalisation invariant under bypass, empty-string and undefined preservation, `hasDefaultPassphrase` after passing validation, and the no-op behaviour when bypass is combined with a strong password.
- **`src/__tests__/utils.test.ts`**: Added 3 new `validatePasswordStrength` cases — long passphrase short-circuit (score 5, empty feedback), 19-char rejection still emitting category feedback, and broadened-special-char acceptance for `_`.

### Backward Compatibility

- Existing strong passwords that satisfied the old composition rule (8+ chars with all four categories AND a special char from `[!@#$%^&*(),.?":{}|<>]`) continue to validate. The change is strictly broader: every password that used to pass still passes, and additional passwords are now accepted.
- The constructor's `defaultPassphrase` validation is **technically breaking** for any user who configured a weak `defaultPassphrase`. However, such configurations were already broken at first encrypt (where `validatePassword` rejected the weak passphrase with `WEAK_PASSWORD`); the new behaviour just surfaces the failure earlier. Users with that setup can opt back into the deferred-failure mode via `skipPasswordValidation: true`.
- NFC normalisation is **technically breaking** for any user who happened to encrypt with a deliberately NFD-encoded password. NFC is the canonical form most input methods produce, so this case is rare in practice; affected users can recover their data by passing the original NFD bytes once (which `String.prototype.normalize('NFC')` will canonicalise back). All NFC-encoded passwords (the overwhelming majority) are unaffected.
- The new `skipPasswordValidation` and the existing constructor options are independent — no other behaviour was changed by this release.

## 2026-05-04 (v0.13.0 — Lazy argon2 + ESM-only exports)

### Changed

- **`package.json`** (Task 9): Moved `argon2` from `dependencies` to `optionalDependencies`. Installs on systems without a C++ toolchain (Python + node-gyp) no longer fail outright — `argon2`'s native build can fail and the rest of `@hiprax/crypto` will still install cleanly. Consumers who only use the synchronous (PBKDF2) methods are then fully unaffected by the missing native module.
- **`src/crypto-manager.ts`** (Task 9): Replaced the eager top-level `import argon2 from 'argon2'` with a lazy dynamic `import('argon2')` that fires only on the first async key derivation. The Argon2id type identifier (`= 2`) is now hardcoded in a module-level constant `ARGON2_ID` so that constructing a `CryptoManager` never touches the native module — argon2 is only loaded when `deriveKey` (and therefore `encryptText` / `decryptText` / `encryptFile` / `decryptFile`) are actually called. The first successful load is cached at module scope; the failure case is also cached (sentinel `Symbol('ARGON2_LOAD_FAILED')`) so subsequent async calls fail fast with the same friendly error rather than re-running the import.
- **`src/crypto-manager.ts`** (Task 9): Argon2 module-load failure now surfaces as `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` with message: *"argon2 native module unavailable. Install build tools (Python + node-gyp) or use *Sync methods (PBKDF2)."* The error is preserved through `deriveKey`'s outer try/catch so the specific code is not rewritten as the generic `KEY_DERIVATION_FAILED`.
- **`package.json`** (Task 31): Dropped the `"require"` keys from each entry in the `exports` map (`.`, `./crypto-manager`, `./utils`). The package emits ESM (because `"type": "module"` and TypeScript's `module: "NodeNext"`), so a `"require"` key pointing at ESM output was a footgun: CJS consumers on Node 18-21 hit `ERR_REQUIRE_ESM` despite the package advertising `require` support, and on Node 22+ they got a synthetic namespace shape that depended on the runtime flag. Dropping `"require"` makes Node fail fast with a clear ESM-only message and removes the misleading capability claim.
- **`package.json`**: Added a `"./package.json": "./package.json"` entry to `exports` so tooling can still resolve the package's own manifest under the new exports map (a common compatibility ask once you start declaring `exports`).
- **`package.json`**: Test scripts (`test`, `test:coverage`, `test:watch`) now run via `cross-env NODE_OPTIONS=--experimental-vm-modules` so jest's `unstable_mockModule` is functional. This is required for the new lazy-load tests to actually exercise the module-mocking path; without the flag, `jest.unstable_mockModule` is silently ignored and the real `argon2` module loads.
- **`src/__tests__/crypto-manager.test.ts`** and **`src/__tests__/utils.test.ts`**: Added explicit `import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'`. With `NODE_OPTIONS=--experimental-vm-modules` set, jest no longer auto-injects test globals; the explicit import is the supported pattern in jest's ESM mode.

### Added

- **`src/crypto-manager.ts`** (Task 9): New module-level helper `loadArgon2()` (private) and exported test-only helper `__resetArgon2ModuleCacheForTesting()` for resetting the lazy-load cache between unit tests.
- **`src/__tests__/argon2-lazy-load.test.ts`** (Task 9, new file): 8 new tests covering the lazy-load contract end-to-end: (1) constructing a `CryptoManager` does not load argon2; (2) sync (PBKDF2) round-trips do not load argon2; (3) the first async call lazy-loads argon2 exactly once and subsequent async calls reuse the cached module; (4) `MODULE_NOT_FOUND` surfaces as `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` from `deriveKey`; (5) the same error surfaces from `encryptText`; (6) the failure sentinel is cached so repeated async calls do not retry the import; (7) sync methods continue to work after a failed argon2 load; (8) the loader handles both `default`-property and bare-namespace shapes returned by Node's CJS-ESM interop. Tests use `jest.unstable_mockModule('argon2', factory)` BEFORE dynamically `import()`-ing CryptoManager so the mock is in place when the lazy import resolves. `__resetArgon2ModuleCacheForTesting()` is called between tests to wipe the module-level cache so each test sees a clean slate.
- **`src/__tests__/esm-smoke.test.ts`** (Task 31, new file): 5 new tests that programmatically verify Node's real ESM resolver correctly loads the built `dist/` artefacts: (1) `package.json` declares `type: module`, `engines.node: >=18.0.0`, and the `exports` map has `types` + `import` for each entry but NO `require` key; (2) Node loads `dist/index.js` via `import` and exposes `CryptoManager` as both a named and default export; (3) on Node 18-21, `require()`-ing the dist output emits `ERR_REQUIRE_ESM` (skipped on Node 22+ where `require(esm)` is allowed by default); (4) the subpath exports `./crypto-manager` and `./utils` resolve correctly via real ESM; (5) CJS consumers can still load via dynamic `import()` (the recommended interop path documented in README). Each test runs Node in a child process via `spawnSync(process.execPath, [probeFile])` so it exercises the same loader behaviour that downstream consumers see.
- **`README.md`**: New "Module system" sub-section under Installation explicitly documents the package as ESM-only and provides a `Argon2 native dependency (optional)` block describing the lazy-load behaviour, the `ARGON2_NOT_AVAILABLE` error code, and the two recovery paths (install build tools vs. switch to sync methods). Added a "CommonJS interop" block with a working `await import('@hiprax/crypto')` example for CJS consumers.

### Backward Compatibility

- The `argon2` package is still listed in `package.json` (now under `optionalDependencies`) — npm/yarn/pnpm continue to attempt to install it by default. Existing users with a working toolchain see no behavioural difference.
- The async API surface (`encryptText`, `decryptText`, `encryptFile`, `decryptFile`, `deriveKey`) is unchanged. The only observable behaviour change is the new `ARGON2_NOT_AVAILABLE` error code, which is **only** thrown in environments where `argon2` was previously failing to install or load. Users who never hit that environment continue to see Argon2id derivation work exactly as before.
- The exports-map change is technically breaking only for consumers who were doing `require('@hiprax/crypto')` from CJS code. Such code was **already broken** on Node 18-21 (it threw `ERR_REQUIRE_ESM` despite the misleading exports key) and only worked accidentally on Node 22+ via the `require(esm)` synthetic-namespace path. CJS consumers should switch to `await import('@hiprax/crypto')` as documented in the new README "CommonJS interop" section.
- All ESM consumers (`import { CryptoManager } from '@hiprax/crypto'`) are unaffected.

## 2026-05-04 (Path Validation Hardening)

### Changed

- **`src/utils.ts`** (Tasks 11 + 32): `validatePath` now rejects null bytes (`\0`) and ASCII control characters (codepoints `< 0x20` or `0x7F`) anywhere in the input path with explicit error messages (`"File path contains a null byte"` / `"File path contains control characters"`). Node.js filesystem APIs already reject null bytes, but failing fast in the validator gives a clearer error and prevents the path from ever reaching system calls.
- **`src/utils.ts`** (Task 32): `validatePath` accepts an optional second parameter `options?: { allowedRoot?: string }`. When `allowedRoot` is provided, the resolved input path (via `path.resolve`) must be contained within the resolved `allowedRoot`. Containment is decided by a segment-aware prefix match (resolved input either equals the resolved root OR starts with it followed by `path.sep`), which prevents e.g. `/etc/sec` from accidentally matching `/etc/secret` and catches within-drive cross-traversal that the literal-`..` segment check on its own cannot detect (e.g. `validatePath('C:\\Users\\..\\Windows', { allowedRoot: 'C:\\Users' })` is now correctly rejected because `path.normalize` collapses the cancel-out to `C:\\Windows` which escapes the configured root). On Windows, the comparison is case-insensitive and forward-slash-tolerant; on POSIX, it is case-sensitive. The new parameter is fully optional — calls of the form `validatePath(p)` continue to behave exactly as before.
- **`src/utils.ts`** (Task 11): `sanitizeFilename` now neutralizes literal `..` sequences with `__` AFTER the existing dangerous-character / whitespace replacements (loop-to-convergence so overlapping sequences like `....` are fully scrubbed) so the sanitized name cannot be naively `path.join`'d into a parent-directory traversal. Length truncation now splits the name into `base + ext` via `path.extname` and truncates the **base**, preserving the extension — `'a'.repeat(300) + '.txt'` becomes 251 `a`s + `.txt` (length 255) rather than losing the extension entirely. If sanitization produces an empty result the function still falls back to `'file'`.
- **`src/types.ts`**: `ValidationResult` JSDoc updated to spell out that the result reflects only a **syntactic** check — `validatePath` does not touch the filesystem and therefore cannot detect or prevent traversal via filesystem **symlinks**. Callers needing symlink-aware containment must additionally call `fs.realpath`/`fs.realpathSync` on the resolved path and re-verify the result against their allowed root.

### Added

- **`src/utils.ts`**: New exported interface `ValidatePathOptions` with one optional field, `allowedRoot?: string`, used as the second argument to `validatePath`. Re-exported via the existing `export * from './utils.js'` in `src/index.ts` so consumers can `import type { ValidatePathOptions } from '@hiprax/crypto'`.
- **`src/__tests__/utils.test.ts`**: 42 new tests across three describe blocks. The `validatePath - null bytes and control chars` block (11 tests) covers null bytes at start/middle/end, tab/newline/CR/bell/DEL rejection, a spot-check across the `[0x01, 0x1F]` codepoint range, and acceptance of printable ASCII and high-codepoint Unicode. The `validatePath - allowedRoot containment` block (19 tests) covers equality, direct child, deeply-nested child, escape-via-`..`, the canonical Windows within-drive cross-traversal case, the `/etc/sec` ↔ `/etc/secret` segment-aware boundary, trailing-separator robustness on `allowedRoot`, Windows backslash↔forward-slash interop in both directions, Windows case-insensitive matching and POSIX case-sensitive matching, empty / non-string / control-char `allowedRoot` rejection, backward-compatibility of the legacy single-argument call shape, an empty options object, the literal-`..` check still firing first when `allowedRoot` is set, and control-char rejection running before the `allowedRoot` check. The `sanitizeFilename - traversal hardening + extension preservation` block (12 tests) covers `..` → `__` replacement, `../etc/passwd`-style mixed traversal, overlapping `....` scrub, single-dot preservation, triple-dot safety, extension preservation across long names (single-piece, multi-piece, no-extension), boundary cases at exactly 255 chars and just over, normal short names unchanged, and the `'file'` fallback for whitespace-only input.

### Backward Compatibility

- `validatePath`'s public signature is unchanged for legacy callers — the new `options` parameter is optional and the function behaves identically to the previous single-argument form when omitted.
- `sanitizeFilename`'s public signature is unchanged. Outputs differ only for inputs that previously contained literal `..` sequences (now scrubbed) or that exceeded 255 characters and had a recognizable extension (the extension is now preserved during truncation). All other inputs produce the same output as before.
- `ValidationResult` retains the same shape (`{ isValid: boolean; error?: string }`); only its JSDoc was extended.

## 2026-05-04 (Streaming Decryption + Atomic File Output)

### Changed

- **`src/crypto-manager.ts`** (Task 3): `decryptFile` no longer loads the entire ciphertext into memory before decrypting. The new streaming implementation opens the file once, reads the small front-matter (v1 header + salt + IV) and trailing auth tag via direct file-handle reads, then pipes the bounded body byte range through `crypto.createDecipheriv()` to a temp file with `stream/promises.pipeline()`. Peak memory is bounded by the stream's highWaterMark (Node default 64 KiB) regardless of input size, so multi-GiB ciphertexts decrypt without OOM. Both v0 (legacy, no header) and v1 (preferred, 22-byte header) ciphertext layouts route through the same streaming path.
- **`src/crypto-manager.ts`** (Task 3): `decryptFileSync` now streams in fixed 64 KiB chunks via `fs.openSync`/`fs.readSync`/`fs.writeSync`. The chunk reuse buffer is allocated once and reused across iterations, so peak memory is bounded by `SYNC_DECRYPT_CHUNK_SIZE = 64 * 1024` regardless of input size. Each chunk goes through `decipher.update()`; the auth tag is read out-of-band before the body stream begins, set via `setAuthTag()`, and verified by the closing `decipher.final()`.
- **`src/crypto-manager.ts`** (Task 4): All four file methods (`encryptFile`, `encryptFileSync`, `decryptFile`, `decryptFileSync`) now write to a sibling temp file `${outputPath}.<random16hex>.tmp` and atomically rename to the final `outputPath` only on full success. Readers of `outputPath` no longer observe a half-written ciphertext or plaintext at the canonical location, even if the encryptor is killed mid-stream or the decryptor fails authentication. Pre-existing files at `outputPath` are now preserved on error — previously they were deleted by the catch-block cleanup, which violated user expectations and made retry-after-failure impossible.
- **`src/crypto-manager.ts`** (Task 4): Atomic rename uses `fs.promises.rename`/`fs.renameSync`, which on Windows (Node 18+) maps to `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` and atomically replaces the destination when one exists. A best-effort `copyFile + unlink` fallback handles the rare adversarial Windows case where the target is locked for renaming but not for opening (the fallback is non-atomic but strictly better than leaving the temp file behind).
- **`README.md`**: Updated the `decryptFile` documentation to remove the "reads entire file into memory" implication and reflect the new streaming behaviour, plus a brief note on the atomic-rename guarantee for all four file methods.
- **JSDoc**: Updated `decryptFile`/`decryptFileSync`/`encryptFile`/`encryptFileSync` JSDoc to describe streaming decryption, atomic temp-file output, and the contract that pre-existing outputs are not deleted on failure.

### Added

- **`src/__tests__/crypto-manager.test.ts`**: Added a gated `large-file streaming round-trip (Task 3)` describe block that generates a configurable-size file (default 10 MiB; override via `LARGE_FILE_TEST_MB=N`, skip via `SKIP_LARGE_TESTS=1`) and round-trips it across both v0 and v1 file formats, both async and sync. Comparison is done chunk-by-chunk with `fs.readSync` to avoid loading the test data into memory. Jest timeout is bumped to 120000 for these.
- **`src/__tests__/crypto-manager.test.ts`**: Added a `streaming decrypt boundary cases` describe block that exercises sync chunk-size edges (`SYNC_CHUNK + 1`, `SYNC_CHUNK * 2`) plus a truncated-file failure mode for both async and sync paths to confirm authentication still kicks in.
- **`src/__tests__/crypto-manager.test.ts`**: Replaced the four `cleanup with pre-existing output` blocks (one per file method) with `atomic output (pre-existing target)` blocks. The new tests cover four scenarios per method: (1) on encryption error, the pre-existing output file is preserved unchanged; (2) on a `CryptoError` raised mid-flow, the pre-existing output is preserved and re-throw works; (3) when no pre-existing output exists, encryption error leaves no file at outputPath and no temp file lingers; (4) on success, no temp file lingers in the directory. These match the new atomic-rename contract.
- **`src/__tests__/crypto-manager.test.ts`**: Updated the two `decryptFile`/`decryptFileSync` `secureClear` assertions to reflect that streaming no longer produces a single full-file `secureClear()` call. The new assertions verify that buffers of length 32 (key/salt), 12 (iv), and 16 (tag) all appear among the cleared buffers and that `secureClear()` is invoked at least 4 times during a successful decrypt.

### Backward Compatibility

- File method signatures (`encryptFile`/`encryptFileSync`/`decryptFile`/`decryptFileSync`) are unchanged.
- Both v0 (legacy, no header) and v1 (HPCR magic) ciphertext layouts continue to decrypt correctly via the streaming path; v0 acceptance is still gated by the `legacyMode` constructor option (`'auto'` accepts, `'strict'`/`'reject'` rejects with their respective error codes).
- Pre-existing files at `outputPath` are no longer deleted on encryption/decryption error. This is a behaviour change relative to 0.11.0 and earlier, but is the contract documented in `FIX.md` C5 and the spec in Task 4: the canonical destination is only mutated on full success. Callers that depended on the old "delete on failure" behaviour can replicate it explicitly: `await fs.promises.unlink(outputPath).catch(() => {})` after catching a `CryptoError`.

## 2026-05-04 (PBKDF2 Iteration Bump + secureClear Hardening)

### Changed

- **`src/crypto-manager.ts`**: Default PBKDF2 iteration count for sync key derivation bumped from `100000` to **`600000`** — matches the OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256 (still current in 2026). Brute-force resistance is now ~6× stronger out of the box. The chosen value is embedded in every v1 ciphertext header, so v1 data continues to decrypt correctly even after future iteration-count changes.
- **`src/crypto-manager.ts`** (Task 5): Tightened `secureClear` JSDoc to spell out the limitations explicitly — best-effort only; not guaranteed against V8 string copies, GC-managed allocations, or compiler reordering. Useful only for explicit `Buffer` instances; will not scrub the original input string or any V8-internal copies of derived material.
- **`src/crypto-manager.ts`** (Task 5): Added `secureClear(combined)` calls in `decryptText` and `decryptTextSync` after extraction and decryption complete (placed AFTER the subarray-derived salt/iv/tag/encrypted views are no longer needed). Audited `decryptFile`/`decryptFileSync` and confirmed `secureClear(fileBuffer)` already scrubs all subarray-derived buffers (salt/iv/tag/encryptedData) in one go via the shared underlying memory.

### Added

- **`src/types.ts`**: New constructor option `pbkdf2Iterations?: number` (positive integer, defaults to `600000`) controls the PBKDF2 iteration count used for new sync ciphertexts. The value is embedded in the v1 header.
- **`src/types.ts`**: New constructor option `legacyPbkdf2Iterations?: number` (positive integer, defaults to `100000`) controls the iteration count assumed when decrypting **legacy v0** sync ciphertexts (which carry no embedded iteration count). Has no effect on v1 ciphertexts. Provided so users with legacy data produced under a non-default iteration count can still decrypt it.
- **`src/crypto-manager.ts`**: Constructor validates both new options as positive integers; rejects with codes `INVALID_PBKDF2_ITERATIONS` / `INVALID_LEGACY_PBKDF2_ITERATIONS`.
- **`src/__tests__/crypto-manager.test.ts`**: Added 31 new tests under two top-level `describe` blocks. The PBKDF2 iteration block covers: constructor validation (positive-integer enforcement on both options), default header iteration count (600000), custom iteration round-trips for v1 text and file, cross-instance interop where encryption and decryption use different iteration counts (the embedded value drives decryption), legacy v0 decryption with the default 100000 fallback, legacy v0 decryption with a custom `legacyPbkdf2Iterations` override, the negative case where v0 ciphertext built with non-default iterations fails under default fallback, the assertion that `legacyPbkdf2Iterations` does NOT affect v1 ciphertexts, strict-mode rejection of v0 regardless of iteration count, and `deriveKeySync` default-vs-explicit override consistency. The `secureClear` block uses `jest.spyOn(cm, 'secureClear')` to verify each decrypt path zeroes the combined/fileBuffer container in addition to `key` and `decrypted`.

### Backward Compatibility

- Existing v1 ciphertexts produced with the old default (100k iterations) continue to decrypt correctly because the iteration count is embedded in the v1 header.
- Legacy v0 ciphertexts (no header) continue to decrypt under default `legacyMode: 'auto'` because the new `legacyPbkdf2Iterations` option defaults to 100000 — the historical value baked into all v0 sync ciphertexts. No existing data becomes unreadable as a result of this change.
- New ciphertexts produced after this change use 600k iterations by default and embed that value in their header. They remain readable by older 0.10.x clients only if those clients are also upgraded (the PBKDF2 derivation must use the same iteration count as the encoder; v1 already encoded that count in the header, so existing 0.10.x decoders that respect the header will continue to work).

## 2026-05-04 (Versioned Ciphertext Format)

### Added

- **`src/format.ts`** (new): Versioned ciphertext format module with `packHeader`/`parseHeader` helpers, `MAGIC_BYTES` (`"HPCR"`), version/KDF identifiers, and the `KdfHeaderParams` discriminated union. The new on-disk header is a fixed 22 bytes: 4 magic + 1 version + 1 KDF id + 16-byte parameter block (Argon2id: memoryCost u32 BE + timeCost u32 BE + parallelism u16 BE + 6 reserved bytes; PBKDF2: iterations u32 BE + 12 reserved bytes).
- **`src/types.ts`**: Added `LegacyMode` type (`'auto' | 'strict' | 'reject'`) and `legacyMode` constructor option that controls how legacy v0 ciphertexts are handled (`'auto'` decrypts them, `'strict'` rejects with code `LEGACY_FORMAT_REJECTED`, `'reject'` rejects with `UNSUPPORTED_FORMAT`).
- **`src/crypto-manager.ts`**: All four high-level encrypt methods (`encryptText`, `encryptTextSync`, `encryptFile`, `encryptFileSync`) now prepend the v1 header to every ciphertext they produce. All four decrypt methods (`decryptText`, `decryptTextSync`, `decryptFile`, `decryptFileSync`) auto-detect the v1 magic, parse the header (with bounds-checked `readUInt32BE`/`readUInt16BE`), validate the version (`UNSUPPORTED_VERSION` for anything other than `0x01`), validate that the embedded KDF id matches the path being used (async expects `0` Argon2id, sync expects `1` PBKDF2 — mismatches throw `KDF_MISMATCH`), and use the **embedded** KDF parameters (not the constructor's defaults) for key derivation. This makes cross-instance interop reliable: a CryptoManager configured with stronger defaults can still decrypt ciphertexts produced under weaker defaults, and vice versa.
- **`src/crypto-manager.ts`**: New public method `inspectHeader(input: string | Buffer)` returns the parsed v1 header (or `null` for legacy v0) without decrypting — useful for tooling and verification.
- **`src/crypto-manager.ts`**: New public method `getLegacyMode()` returns the configured legacy-format handling mode.
- **`src/crypto-manager.ts`**: `deriveKey` and `deriveKeySync` accept optional parameter overrides so the embedded header parameters can drive decryption while the constructor's parameters drive new encryptions. Existing call sites that don't pass overrides keep their current behaviour (backward compatible).
- **`src/index.ts`**: Re-exports the new `format.ts` symbols (`packHeader`, `parseHeader`, `hasMagic`, `MAGIC_BYTES`, `HEADER_LENGTH`, `KDF_ID_ARGON2ID`, `KDF_ID_PBKDF2_SHA256`, `FORMAT_VERSION`, `KdfId`, `KdfHeaderParams`, `ParsedHeader`, etc.) and the new `LegacyMode` type from `types.ts`.
- **`src/__tests__/crypto-manager.test.ts`**: Added 50+ new tests covering: format helper round-trips, reserved-byte zero-fill, parameter-range validation, malformed/truncated headers, magic-byte detection, v1 round-trips for text+file across async+sync, embedded-parameter preservation across round-trips, legacy v0 round-trips in `'auto'` mode for text+file across async+sync, `'strict'`/`'reject'` mode rejection codes (`LEGACY_FORMAT_REJECTED`/`UNSUPPORTED_FORMAT`), tampered magic / version / KDF-id detection (`UNSUPPORTED_VERSION`/`UNSUPPORTED_KDF`), KDF mismatch detection when decrypting an async ciphertext via the sync path (and vice-versa), truncated v1 file body, and cross-instance interop where encryption and decryption use different parameter sets.

### Changed

- **`src/crypto-manager.ts`**: Encryption now always emits v1 ciphertext. There is no option to produce v0 going forward. Decryption remains backward-compatible with v0 unless `legacyMode` is set to `'strict'` or `'reject'`.
- **Coverage**: Now 99.09% statements / 94.43% branches / 98.14% functions / 99.08% lines (was 99.4% / 94.93% / 100% / 99.4% — small dip due to `format.ts` defensive paths is well above the 80% threshold).

### Backward Compatibility

- Existing v0 ciphertexts (text or file) produced by versions prior to 0.9.5 continue to decrypt successfully under the default `legacyMode: 'auto'`.
- The public method signatures of `encryptText`/`decryptText`/`encryptFile`/`decryptFile` (and their sync siblings) are unchanged — only the encoded byte layout changes (legitimate consumers should treat the output as opaque).
- `deriveKey`/`deriveKeySync` accept a new optional parameter; existing callers passing only `(password, salt)` continue to work unchanged.

## 2026-02-21 (Test Coverage)

### Added

- **`src/__tests__/crypto-manager.test.ts`**: Added 125+ new tests covering weak password validation for all encrypt methods, non-CryptoError wrapping in all catch blocks, CryptoError re-throw paths, file cleanup with pre-existing output files, mkdir error paths, argon2/pbkdf2/cipher internal error wrapping, encrypt/decrypt roundtrip edge cases (unicode, binary, large text, empty files), cross-instance compatibility with AAD, constructor validation edge cases, key derivation consistency, encryptData/decryptData tamper detection, security level boundary conditions, and password validation edge cases.
- **`src/__tests__/utils.test.ts`**: Added 30+ new tests covering additional validatePath invalid characters, sanitizeFilename edge cases (null, long names, backslash), createBackupPath without extension, all text file extensions, binary file extensions, formatFileSize fractional/small sizes, generateRandomString edge cases (length 1, max length, uniqueness), createProgressBar negative total, validatePasswordStrength additional scoring, sha256 consistency/unicode, generateRandomHex odd/non-integer lengths, getFileInfo for non-text files, and validateFile numeric input.
- Test coverage improved from 92.87% → 99.4% statements, 84.53% → 94.93% branches, 100% functions, 92.81% → 99.4% lines. crypto-manager.ts and types.ts both at 100% statement/line/function coverage.

## 2026-02-21 (Security Audit)

### Security Fixes

- **`src/utils.ts`**: Fixed modulo bias in `generateRandomString` — replaced `randomByte % 62` with rejection sampling (discards bytes >= 248) to ensure uniform character distribution.
- **`src/utils.ts`**: Replaced hand-rolled XOR loop in `secureStringCompare` with `crypto.timingSafeEqual`. Added dummy-buffer comparison for different-length strings to prevent timing leaks on length.
- **`src/crypto-manager.ts`**: Added `secureClear()` calls for decrypted/plaintext buffers in `decryptText`, `decryptTextSync`, `decryptFile`, `decryptFileSync`, and `encryptFileSync` to prevent sensitive data lingering in memory.

### Bug Fixes

- **`src/utils.ts`**: Fixed `validatePath` rejecting valid Windows drive letter paths (e.g., `C:\path`) by stripping the drive prefix before checking for invalid characters.
- **`src/utils.ts`**: Fixed `formatFileSize` crashing on negative values (returned `NaN undefined`) and values exceeding TB range (accessed `undefined` array index). Now returns `'0 Bytes'` for negatives and caps at TB.
- **`src/crypto-manager.ts`**: Fixed file cleanup on error leaving empty 0-byte ghost files — now uses `unlinkSync`/`unlink` to delete partial output files instead of writing empty strings.
- **`src/crypto-manager.ts`**: Fixed misleading JSDoc on `decryptFile` that claimed "streaming for large files" when it actually reads the entire file into memory.

### Added

- **`src/utils.ts`**: Added `isValidBase64Url` function to validate base64url-encoded strings (the format this library actually produces).
- **`src/crypto-manager.ts`**: Added constructor validation for `memoryCost`, `timeCost`, and `parallelism` options — they must be positive integers.
- **`src/__tests__/utils.test.ts`**: Added tests for modulo bias uniformity, `formatFileSize` edge cases, `isValidBase64Url`, and Windows drive letter validation.
- **`src/__tests__/crypto-manager.test.ts`**: Added tests for constructor option validation (invalid `memoryCost`, `timeCost`, `parallelism`).

## 2026-02-21

### Fixed

- **`tsconfig.json`**: Replaced deprecated `moduleResolution: "node"` and `module: "ESNext"` with `"NodeNext"` for both, resolving the TypeScript 7.0 deprecation warning.
- **`jest.config.js`**: Added `tsconfig` override (`module: "ESNext"`, `moduleResolution: "Bundler"`) to ts-jest transform so tests remain compatible with the `NodeNext` module setting.
- **`src/__tests__/utils.test.ts`**: Removed unused `stat` import to fix lint error.
- Installed missing `jiti` dev dependency required by ESLint 9 for loading `.ts` config files.
