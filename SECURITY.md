# Security Policy

`@hiprax/crypto` is a cryptography library. Bugs here can compromise the
confidentiality, integrity, or authenticity of user data, so we treat security
reports as a top priority and would rather hear about a suspected issue than
miss a real one. Thanks for taking the time to investigate.

## Supported Versions

The package is post-1.0 stable. Only the current `1.x` major line receives
security updates; pre-1.0 (`0.x`) lines are end-of-life and will not be
patched. The next major bump (whenever `2.0.0` ships) will establish whether
the previous major continues to receive security fixes; until then, the
single supported line is `1.x`.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| 0.17.x  | :x:                |
| 0.16.x  | :x:                |
| 0.15.x  | :x:                |
| < 0.15  | :x:                |

If you need a fix backported to an unsupported line because you cannot upgrade,
include the constraint in your report and we will evaluate it on a case-by-case
basis. There is no guarantee of a backport.

## Reporting a Vulnerability

**Please do not file public issues, pull requests, or discussions for security
problems.** Public disclosure before a patch is ready puts every other user of
the library at risk.

Use one of these private channels instead:

1. **GitHub Security Advisories (preferred).** Open a draft advisory at
   <https://github.com/Hiprax/crypto/security/advisories/new>. This is private
   to the maintainers, free, and gives us a structured workflow for issuing
   fixes and CVEs. This is the channel we will use to coordinate the fix and
   disclosure with you.
2. **Email.** If GitHub's advisory flow is not available to you, send the
   report to `security@hiprax.dev`. Please include the same information as a
   GitHub advisory would: affected version(s), a clear reproduction (or proof
   of concept), the impact, and any suggested mitigations or patches.

If you would like to encrypt your email, request our PGP key in your initial
contact and we will respond with the current key fingerprint and material.

## Expected Response Times

| Stage                        | Target                                       |
| ---------------------------- | -------------------------------------------- |
| Initial acknowledgement      | Within **72 hours** of receipt               |
| Triage and severity decision | Within **7 days** of acknowledgement         |
| Fix or mitigation timeline   | Communicated alongside triage                |
| Public disclosure            | Coordinated with the reporter once fix ships |

If you have not heard back within 72 hours of submitting a private advisory,
please follow up — it usually means the notification was missed, not ignored.

We will credit the reporter in the advisory and the release notes unless you
prefer to remain anonymous. Please tell us in the report which you prefer.

## Coordinated Disclosure

We follow a standard coordinated-disclosure model:

1. You report the issue privately.
2. We acknowledge, triage, and develop a fix in a private advisory branch.
3. We publish a patched release with the version bumped per
   [semver](https://semver.org/) and the [CHANGELOG](CHANGELOG.md) updated.
4. We publish the GitHub Security Advisory (with CVE if appropriate) once the
   patched version is available, naming the reporter unless they have asked
   to remain anonymous.

We aim to keep the embargo window short — usually no more than 90 days — and
will let you know if we need more time.

## Scope

The following classes of issue are **in scope** for this policy and will be
treated as security incidents:

- **Cryptographic correctness.** Wrong algorithm parameters, incorrect padding,
  authentication-tag verification bypasses, malleable ciphertexts, KDF usage
  bugs, or any deviation from the documented constructions (AES-256-GCM,
  Argon2id, PBKDF2-HMAC-SHA256).
- **Key handling.** Keys derived from the wrong inputs, key material reused
  unsafely (e.g. AES-GCM `(key, iv)` reuse from the high-level API), keys
  leaking through error messages or unexpected return values, or key material
  not being cleared from buffers when documented to be cleared.
- **Side channels.** Timing oracles in password / tag / key comparisons, error
  messages that distinguish wrong-password from corrupt-ciphertext (the
  generic `DECRYPTION_FAILED` is intentional — see the README "Error Handling"
  section).
- **Authenticity bypass.** Any path that lets ciphertext be modified without
  the GCM auth tag flagging it, including header tampering on v1 ciphertexts.
- **Format / parser issues.** Bugs in the ciphertext header parsers — the v1
  header parser (`format.ts` / the pure `format-core.ts`) and the v2 container
  parser (`core.ts`) — that allow malformed input to cause crashes, infinite
  loops, out-of-bounds reads, or the wrong KDF / parameters being applied.
- **Path traversal in the file APIs.** Any path that lets an attacker-supplied
  string write outside the intended directory tree, beyond the documented
  syntactic guarantees of `validatePath`.
- **Vulnerabilities in `argon2` or other runtime dependencies that materially
  weaken the library's guarantees.** These will be fixed by bumping the
  affected dep; please report them privately the same way.

## Out of Scope

The following are **not** treated as security issues by this project. Please
file them as regular GitHub issues instead — we still want the bug reports,
just through the normal channel:

- **Denial of service via large input.** Encrypting a 100 GiB file is going
  to use a lot of disk and memory; that's not a vulnerability, that's how
  encryption works. The library streams inputs where possible (see the
  README "File Encryption" section), but a caller that passes pathologically
  large inputs is responsible for their own resource limits.
- **Vulnerabilities in transitive dev dependencies.** Issues in `jest`,
  `eslint`, `rimraf`, `typescript` etc. that only affect the development
  toolchain and not the published package are tracked through GitHub Issues
  and `npm audit`. If a transitive dep ends up shipped in `dist/`, it
  becomes in scope.
- **Brute-force / password-guessing attacks against weak passwords.** The
  library validates password strength on encryption (see README "Password
  Requirements"), but if a caller bypasses that or chooses a weak password,
  the resulting ciphertext is no stronger than the password. This is a
  limitation of the underlying construction, not a bug.
- **Theoretical attacks against AES-256-GCM, Argon2id, or PBKDF2-HMAC-SHA256
  themselves.** If a generic break of one of these primitives is published,
  we will respond. Generic "quantum computers will eventually break this"
  reports are answered by the documented
  [post-quantum posture](#post-quantum-posture) below and are not actionable
  unless they present a concrete new attack that invalidates it.
- **Missing best-practice hardening that has no documented impact** (e.g.
  "the library should also support XChaCha20"). File those as feature
  requests through GitHub Issues.

## Post-quantum posture

The library's position on quantum computing is documented here so security
reports and audits can reference it directly.

1. **There is no public-key cryptography in this library.** No RSA, no
   elliptic curves, no key exchange, no signatures, no certificates. Shor's
   algorithm — the quantum attack that catastrophically breaks public-key
   cryptography and motivates the NIST PQC standards (FIPS 203 ML-KEM,
   FIPS 204 ML-DSA, FIPS 205 SLH-DSA) — has no target here. Consequently
   there is **no post-quantum migration to perform**: those standards
   replace primitives this library does not use.
2. **Every primitive is treated as quantum-resistant by the relevant
   standards bodies at the parameter sizes used.** AES-256-GCM sits at NIST
   post-quantum security Category 5 and is retained by NSA CNSA 2.0 for
   National Security Systems up to TOP SECRET; NIST IR 8547 explicitly
   excludes the symmetric standards (block ciphers, hash functions, HMAC,
   KDFs) from the PQC transition; BSI TR-02102-1 recommends 256-bit
   symmetric keys for long-term protection, which is what the library uses.
   Grover's algorithm yields only a quadratic speedup that parallelizes
   poorly and is gate-depth limited — NIST's own FAQ states it will provide
   "little or no advantage in attacking AES". The browser build introduces
   **no new primitive**: it uses the same AES-256-GCM, Argon2id, and SHA-256
   (via Web Crypto and WebAssembly `hash-wasm`) over the same wire format, so
   this posture applies unchanged across runtimes. The only cross-runtime
   difference is the Argon2id default memory cost (32 MiB in the browser vs
   128 MiB in Node), which affects brute-force cost, not post-quantum standing.
3. **The residual quantum-relevant risk is password entropy, not the
   cryptography.** Grover halves the effective entropy of an offline
   password search. Mitigations in the design: per-message 32-byte random
   salts (no cross-ciphertext amortization) and the memory-hard Argon2id
   KDF, whose evaluation cost provably carries over into the reversible
   circuits a quantum attacker must build (Blocki-Holman-Lee, TCC 2022).
   Callers with harvest-now-decrypt-later threat models should use the
   async (Argon2id) path with a high-entropy passphrase — see the README
   "Post-Quantum Security" section for caller-facing guidance.
4. **Crypto-agility is built into the wire format.** Each v1 ciphertext
   embeds its KDF identifier and full KDF parameters, so defaults can be
   raised (or a KDF added) in a minor release while old ciphertexts remain
   decryptable; the header's version byte reserves a clean escape hatch
   (`0x02`) should guidance ever require a cipher change. None is needed or
   foreseen.
5. **Hybrid PQC modes (ML-KEM/ML-DSA) are deliberately absent** because the
   library performs no key exchange and no signing; there is nothing to
   hybridize, and adding those primitives would add attack surface without
   adding security.

The distribution channel (npm provenance via Sigstore, registry TLS) relies
on the ecosystem's classical public-key infrastructure. That layer is
outside this package's control, is a real-time integrity mechanism rather
than harvestable ciphertext, and does not affect the confidentiality of
data encrypted with this library.

Primary sources: NIST PQC FAQ
(<https://csrc.nist.gov/projects/post-quantum-cryptography/faqs>);
NIST IR 8547
(<https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf>);
NSA CNSA 2.0 FAQ
(<https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>);
BSI TR-02102-1; Kaplan et al., CRYPTO 2016
(<https://arxiv.org/abs/1602.05973>), whose Simon's-algorithm forgery
applies only in the superposition-query (Q2) model and not to data at
rest; Blocki, Holman & Lee, TCC 2022
(<https://arxiv.org/abs/2110.04191>).

Reports claiming quantum vulnerability are in scope **only** if they
present a concrete attack that invalidates one of the five points above
under a realistic (classical-query, Q1) threat model.

## Browser build (threat-model notes)

As of v1.5.0 the library is isomorphic: the same in-memory async API
(`encryptBytes`/`decryptBytes`/`encryptText`/`decryptText`/
`encryptContainer`/`decryptContainer`) runs in Node and in the browser over
**one** wire format. The browser build uses Web Crypto (SubtleCrypto) for
AES-256-GCM/SHA-256/CSPRNG and WebAssembly `hash-wasm` for Argon2id — the
same primitives as Node, so the cryptographic guarantees above are unchanged.
The differences that are relevant to a threat model are documented here so
reports and audits can reference them:

1. **Weaker memory hygiene than Node.** Web Crypto `importKey` copies the raw
   AES key bytes into an opaque `CryptoKey` object that JavaScript cannot
   reach or zero — so `secureClear` cannot scrub it (the engine does zero the
   transient raw-key copy it owns immediately after import). Combined with the
   immutable, GC-managed nature of V8 strings (passwords, decrypted text), the
   browser cannot forensically wipe key/plaintext material. Treat in-browser
   secret residency as bounded by GC, not by `secureClear`. This is a stronger
   form of the "String-copy memory leaks via V8" caveat below and is **out of
   scope** as a reportable vulnerability, the same as the Node V8 caveat.
2. **Secure-context requirement.** `crypto.subtle` is only exposed in a
   [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)
   (HTTPS or `localhost`). On an insecure origin the engine cannot run and
   throws; serving the app over plain HTTP is a deployment error, not a
   library bug.
3. **Content-Security-Policy.** The browser Argon2id path compiles
   WebAssembly, which a strict CSP blocks unless `script-src` includes
   `'wasm-unsafe-eval'` (strictly narrower than `'unsafe-eval'` — WASM only).
   `hash-wasm` instantiates from inline bytes, so no `connect-src` entry and
   no network fetch are involved; nothing leaves the browser. See the README
   "Content-Security-Policy (WASM)" subsection for the exact header.
4. **No `node:` in the browser graph.** The browser entry
   (`dist/index.browser.js`) imports zero `node:` builtins and references no
   `Buffer`/`process` global; this isolation is enforced continuously in CI by
   an esbuild `platform:'browser'` bundle gate (`npm run check:browser`), so
   `node:crypto`/`node:fs`/`node:stream` can never enter a consumer's bundle.
5. **Node-only methods are unavailable, not silently degraded.** The
   synchronous (PBKDF2), streaming-file, and `Buffer`-typed low-level methods
   throw `CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER')` in the browser
   build rather than falling back to a weaker construction — there is no
   silent security downgrade.

## Security-relevant configuration defaults

For reference, the library currently ships with the following security
defaults. If a reported issue is mitigated by changing one of these,
please call that out explicitly in the report.

- **Default Argon2id parameters** (async paths, Node build): `memoryCost = 2 ** 17`
  (128 MiB), `timeCost = 3`, `parallelism = 1`. Matches the OWASP 2026
  first-choice tier for Argon2id.
- **Default Argon2id parameters** (browser build): `memoryCost = 2 ** 15`
  (32 MiB), `timeCost = 3`, `parallelism = 1` — a lighter default to avoid
  OOM on memory-constrained mobile browsers, still ≈1.68× the OWASP 2025/2026
  Argon2id memory minimum (19 MiB). This is a runtime-specific default, not a
  format change; each ciphertext embeds the exact KDF parameters used, so a
  ciphertext decrypts anywhere that can afford its embedded `memoryCost`.
- **Default PBKDF2 iterations** (sync paths, Node only): `600000`. Matches the
  OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256, still current in 2026.
- **Ciphertext format**: v1 (22-byte versioned header with embedded KDF
  parameters). Legacy v0 ciphertexts are accepted under
  `legacyMode: 'auto'` (the default) and rejected under `'strict'` /
  `'reject'`. The optional v2 **container** format (magic `HPCR`, version
  `0x02`) is a separate, additive envelope — a two-layer KEK/DEK hierarchy,
  confidential encrypted metadata, and an embedded plaintext SHA-256 that is
  re-verified on decrypt (`CONTAINER_INTEGRITY_FAILED` on mismatch). It does
  not touch the v0/v1 paths and each format rejects the other's blobs.
- **AAD**: `"secure-crypto-tool-v2"` by default, configurable per instance.

See the [README](README.md) for the full parameter reference.

## Memory-retention caveats

`secureClear` zeroes Buffer-backed allocations holding key material and
plaintext after use, on a best-effort basis. Two known retention paths
are NOT closed by `secureClear` and are documented here so callers can
make informed decisions:

- **V8 internal string copies.** Password and plaintext strings passed to
  the library (and any intermediate copies V8 creates for hashing,
  interning, or deoptimisation) live in V8's heap as immutable string
  objects. `Buffer.fill(0)` does not reach those copies. They are
  reclaimed only by the V8 garbage collector on its own schedule. This is
  documented in the README "Threat Model" under "String-copy memory
  leaks via V8".
- **`defaultPassphrase` retention.** The `defaultPassphrase` constructor
  option is stored on the `CryptoManager` instance as a regular V8
  string field. This is a deliberate design trade-off (convenience over
  scrubability) and the library cannot zero it. The passphrase remains
  resident for the full lifetime of the manager instance, plus any
  unbounded GC tail for V8-internal copies. For sensitive workloads,
  prefer passing the password explicitly to each encrypt/decrypt call
  rather than configuring a `defaultPassphrase` — that bounds the
  password's V8-string lifetime to the call frame. See the README
  "Default Passphrase" / "Password Requirements" sections for the
  caller-facing version of this guidance.

Reports about additional retention paths (e.g. compiler-emitted register
spills, OS-level swap leaking sensitive pages to disk, debugger
attachment exfiltrating heap snapshots) are welcome but generally fall
under the "side channels" category and are bounded by what the host
environment exposes — see "Side channels" in the Scope section above.
