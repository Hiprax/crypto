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
- **Format / parser issues.** Bugs in the v1 ciphertext header parser
  (`format.ts`) that allow malformed input to cause crashes, infinite loops,
  out-of-bounds reads, or the wrong KDF / parameters being applied.
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
  we will respond — but speculative or "what if quantum computers" reports
  are not actionable in this codebase.
- **Missing best-practice hardening that has no documented impact** (e.g.
  "the library should also support XChaCha20"). File those as feature
  requests through GitHub Issues.

## Security-relevant configuration defaults

For reference, the library currently ships with the following security
defaults. If a reported issue is mitigated by changing one of these,
please call that out explicitly in the report.

- **Default Argon2id parameters** (async paths): `memoryCost = 2 ** 17`
  (128 MiB), `timeCost = 3`, `parallelism = 1`. Matches the OWASP 2026
  first-choice tier for Argon2id.
- **Default PBKDF2 iterations** (sync paths): `600000`. Matches the
  OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256, still current in 2026.
- **Ciphertext format**: v1 (22-byte versioned header with embedded KDF
  parameters). Legacy v0 ciphertexts are accepted under
  `legacyMode: 'auto'` (the default) and rejected under `'strict'` /
  `'reject'`.
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
