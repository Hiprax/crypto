# Crypto

🔐 **High-security encryption/decryption library** using AES-256-GCM and Argon2id for Node.js applications with full TypeScript support.

[![CI](https://github.com/Hiprax/crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/Hiprax/crypto/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Hiprax/crypto/branch/main/graph/badge.svg)](https://codecov.io/gh/Hiprax/crypto)
[![CodeQL](https://github.com/Hiprax/crypto/actions/workflows/codeql.yml/badge.svg)](https://github.com/Hiprax/crypto/actions/workflows/codeql.yml)
[![npm provenance](https://img.shields.io/badge/npm-provenance-brightgreen?logo=npm&logoColor=white)](https://www.npmjs.com/package/@hiprax/crypto)
[![Post-Quantum Ready](https://img.shields.io/badge/post--quantum-ready-blueviolet)](#-post-quantum-security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://img.shields.io/npm/v/@hiprax/crypto)](https://www.npmjs.com/package/@hiprax/crypto)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green.svg)](https://nodejs.org/)

## ✨ Features

- 🔐 **AES-256-GCM** authenticated encryption
- 🔑 **Argon2id** memory-hard key derivation
- 🌐 **Isomorphic (Node + browser)** — the same `encryptBytes` / `decryptBytes` / `encryptText` / `decryptText` run in Node and the browser over **one** wire format, so a ciphertext produced in one runtime decrypts in the other ([details](#-isomorphic-api--browser-support))
- 🔮 **Post-quantum resistant by design** — symmetric-only cryptography, nothing for Shor's algorithm to break ([proofs](#-post-quantum-security))
- 📁 **Streaming file encryption AND decryption** (bounded memory regardless of file size) with atomic temp-file output
- 📦 **Container mode** — an optional authenticated v2 envelope with confidential metadata (filename/mime) and an embedded, re-verified plaintext hash ([details](#-container-mode-v2-envelope))
- 🛡️ **Memory-safe** operations with secure clearing
- ✅ **Strong password** validation with detailed feedback
- 🔄 **Cross-platform** compatibility
- 📝 **Full TypeScript** support with strict typing
- 🧪 **Comprehensive testing** with 80%+ coverage
- 🚀 **Modern ES modules** with tree-shaking support
- 🔒 **Security-focused** with constant-time comparisons
- 🔑 **Default passphrase** support for simplified usage

## 📦 Installation

```bash
npm install @hiprax/crypto
```

### Module system

This package is **ESM-only** (`"type": "module"`). It is not shipped with a CommonJS build because Node.js ESM consumers (the package minimum is Node 22) can use it directly via `import`, and CJS consumers can still load it via dynamic `import()`. See the [CommonJS interop](#commonjs-interop) section below.

The main entry (`.`) is an **[isomorphic](#-isomorphic-api--browser-support)** conditional export: Node resolves the Node build (`dist/index.js`) and browser bundlers resolve a separate, `node:`-free browser build (`dist/index.browser.js`). The `browser` build ships the same in-memory async API over Web Crypto + WebAssembly Argon2id — see [Browser build](#browser-build) and [Isomorphic API & Browser Support](#-isomorphic-api--browser-support).

### Argon2 native dependency (optional, with WASM fallback)

The async key-derivation paths (`encryptText`, `decryptText`, `encryptFile`, `decryptFile`, `deriveKey`) use Argon2id — the gold standard for password hashing. Two providers are supported and tried in order:

1. **Native [`argon2`](https://www.npmjs.com/package/argon2)** — fastest, but requires a working C++ toolchain (Python + node-gyp) at install time on platforms without a prebuilt binary.
2. **WASM [`hash-wasm`](https://www.npmjs.com/package/hash-wasm)** — pure WebAssembly, zero native deps, works everywhere Node.js runs. Roughly 2-3× slower than native at the default 128 MiB profile, but the same RFC 9106 Argon2id reference, so the derived keys are bit-identical between providers and v1 ciphertexts produced by either round-trip across both.

Both packages are declared as **optional dependencies**. The library tries native first (highest performance) and transparently falls back to WASM if native is unavailable. If BOTH are unavailable, async encryption throws `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` with the message:

> `argon2 native module unavailable. Install build tools (Python + node-gyp) or install the optional 'hash-wasm' package for a pure-WASM Argon2id fallback (slower than native but works everywhere). Alternatively, use *Sync methods (PBKDF2). Native error: <msg>. WASM error: <msg>.`

(the trailing `Native error: … WASM error: …` carries the concrete failure reason from each provider.)

To recover from a "both unavailable" error, do any of:

1. Install build tools and reinstall so `argon2`'s `node-gyp` step succeeds (best performance), **or**
2. Install `hash-wasm` explicitly: `npm install hash-wasm` (no build tools needed; transparent fallback once installed), **or**
3. Use the synchronous methods (`encryptTextSync`, `decryptTextSync`, `encryptFileSync`, `decryptFileSync`, `deriveKeySync`) which use PBKDF2-HMAC-SHA256 and have no native-module dependency. Note that PBKDF2 is materially weaker than Argon2id against GPU/ASIC adversaries — prefer (1) or (2) for new ciphertexts.

Note: a successful first load is cached for the lifetime of the process (subsequent async calls reuse the same provider). A failed first load is NOT cached — the next caller retries from scratch, so transient failures (e.g. a temporary FS permission glitch on Windows during a build-tool install) can recover within the same process.

### Browser build

`@hiprax/crypto` is **isomorphic**: the `.` entry is a conditional export, so a browser bundler (webpack 5, Vite/Rollup, esbuild, Next.js) automatically resolves the separate browser build (`dist/index.browser.js`) while Node resolves the Node build (`dist/index.js`). The browser build's import graph contains **zero `node:` builtins** and references no `Buffer`/`process` global, so nothing like `node:crypto`/`node:fs`/`node:stream` is ever dragged into your bundle. Two complementary static gates enforce this continuously (in CI and at publish): an esbuild `platform:'browser'` bundle gate (`npm run check:browser`) fails on any `node:` specifier reaching the browser graph, and an ESLint `no-restricted-globals` (`Buffer`/`process`) + `no-restricted-imports` (`node:*`) override on the isomorphic source files catches a bare `Buffer`/`process` global that esbuild cannot see.

```bash
# The browser build needs the WASM Argon2id provider (Web Crypto has no Argon2id):
npm install @hiprax/crypto hash-wasm
```

```ts
// In a browser (or any bundler that sets the "browser" condition):
import { CryptoManager } from '@hiprax/crypto';

const cm = new CryptoManager(); // Web Crypto + hash-wasm Argon2id, 32 MiB default
const ct = await cm.encryptText('secret', 'MySecureP@ssw0rd123!');
const back = await cm.decryptText(ct, 'MySecureP@ssw0rd123!');
```

Requirements and behavioral differences from Node — the **32 MiB browser Argon2id default**, the **secure-context** requirement, the **CSP `'wasm-unsafe-eval'`** one-liner, the browser **memory-hygiene** caveats, and the Node-only methods that **throw `UNSUPPORTED_IN_BROWSER`** — are all covered under [Isomorphic API & Browser Support](#-isomorphic-api--browser-support). The `./crypto-manager` and `./utils` subpath exports remain **Node-only** (they pull in `node:fs`/`node:path`); import from the package root (`@hiprax/crypto`) in browser code.

### CommonJS interop

`@hiprax/crypto` is ESM-only. The `package.json` `exports` map has no `require` entry in any condition — the `.` entry resolves in JSON source order `browser → node → default`, and each of those branches nests its own `types` + `default` (so a browser bundler resolves `dist/index.browser.js` with the matching `dist/index.browser.d.ts`, while Node resolves `dist/index.js` with `dist/index.d.ts`); none of the branches is a `require` target. The supported and portable interop for CommonJS callers is a dynamic `import()` from an `async` function — it is the only pattern the test suite verifies:

```js
// my-cjs-file.cjs
async function main() {
  const { CryptoManager } = await import('@hiprax/crypto');
  const cm = new CryptoManager();
  const ciphertext = await cm.encryptText('hello', 'MySecureP@ssw0rd123!');
  console.log(ciphertext);
}
main();
```

On Node 22+ (the package minimum) a plain `require('@hiprax/crypto')` call may actually **succeed** via Node's built-in `require(esm)` path (enabled by default for ESM files with no top-level `await`). Do not rely on this: the behavior is undocumented as a stable API, the `require` path is untested by this library, and earlier minor releases of Node 22 may differ. `await import()` is the supported path.

If you need pure-CJS interop, the recommended path is to migrate the calling module to ESM (`"type": "module"` or `.mjs`).

## 🚀 Quick Start

### Basic Usage

#### Asynchronous Operations (Recommended)

```typescript
import { CryptoManager } from '@hiprax/crypto';

const crypto = new CryptoManager();

// Encrypt text
const encrypted = await crypto.encryptText(
  'Hello World',
  'MySecureP@ssw0rd123!'
);
console.log('Encrypted:', encrypted);

// Decrypt text
const decrypted = await crypto.decryptText(encrypted, 'MySecureP@ssw0rd123!');
console.log('Decrypted:', decrypted);
```

#### Synchronous Operations

For scenarios where you need synchronous operations (note: uses PBKDF2 instead of Argon2id for key derivation):

```typescript
import { CryptoManager } from '@hiprax/crypto';

const crypto = new CryptoManager();

// Encrypt text synchronously
const encrypted = crypto.encryptTextSync('Hello World', 'MySecureP@ssw0rd123!');
console.log('Encrypted:', encrypted);

// Decrypt text synchronously
const decrypted = crypto.decryptTextSync(encrypted, 'MySecureP@ssw0rd123!');
console.log('Decrypted:', decrypted);
```

### Using Default Passphrase

You can set a default passphrase when creating the CryptoManager instance, which allows you to encrypt and decrypt without specifying a password each time:

```typescript
import { CryptoManager } from '@hiprax/crypto';

// Create instance with default passphrase
const crypto = new CryptoManager({
  defaultPassphrase: 'MySecureP@ssw0rd123!',
});

// Encrypt text without specifying password
const encrypted = await crypto.encryptText('Hello World');
console.log('Encrypted:', encrypted);

// Decrypt text without specifying password
const decrypted = await crypto.decryptText(encrypted);
console.log('Decrypted:', decrypted);

// You can still override with a custom password
const encryptedWithCustom = await crypto.encryptText(
  'Hello World',
  'CustomP@ssw0rd456!'
);
```

> **Memory-retention caveat.** Configuring `defaultPassphrase` keeps the password resident as a regular V8 string for the full lifetime of the `CryptoManager` instance — and beyond, until V8's garbage collector reclaims any internal copies the engine made along the way (interning, deopt paths, etc.). The library cannot scrub V8 strings; `secureClear` only zero-fills `Buffer`-backed allocations. For long-lived processes that handle sensitive data, **prefer passing the password explicitly to each encrypt/decrypt call**: that bounds the password's V8-string lifetime to the call frame instead of the manager. The convenience of `defaultPassphrase` is appropriate for short-lived scripts, CLI tools, or scopes where the password's residency in process memory is not part of your threat model. See the [Threat Model](#-threat-model) section below for the broader memory-hygiene picture.

### File Encryption

#### Asynchronous File Operations (Recommended)

```typescript
import { CryptoManager } from '@hiprax/crypto';

const crypto = new CryptoManager();

// Encrypt file
await crypto.encryptFile('input.txt', 'output.enc', 'MySecureP@ssw0rd123!');

// Decrypt file
await crypto.decryptFile('output.enc', 'decrypted.txt', 'MySecureP@ssw0rd123!');
```

#### Synchronous File Operations

For scenarios where you need synchronous file operations (note: uses PBKDF2 instead of Argon2id for key derivation):

```typescript
import { CryptoManager } from '@hiprax/crypto';

const crypto = new CryptoManager();

// Encrypt file synchronously
crypto.encryptFileSync('input.txt', 'output.enc', 'MySecureP@ssw0rd123!');

// Decrypt file synchronously
crypto.decryptFileSync('output.enc', 'decrypted.txt', 'MySecureP@ssw0rd123!');
```

### File Encryption with Default Passphrase

#### Asynchronous Operations

```typescript
import { CryptoManager } from '@hiprax/crypto';

// Create instance with default passphrase
const crypto = new CryptoManager({
  defaultPassphrase: 'MySecureP@ssw0rd123!',
});

// Encrypt file without specifying password
await crypto.encryptFile('input.txt', 'output.enc');

// Decrypt file without specifying password
await crypto.decryptFile('output.enc', 'decrypted.txt');

// You can still override with a custom password
await crypto.encryptFile('input.txt', 'output.enc', 'CustomP@ssw0rd456!');
```

#### Synchronous Operations

```typescript
import { CryptoManager } from '@hiprax/crypto';

// Create instance with default passphrase
const crypto = new CryptoManager({
  defaultPassphrase: 'MySecureP@ssw0rd123!',
});

// Encrypt file synchronously without specifying password
crypto.encryptFileSync('input.txt', 'output.enc');

// Decrypt file synchronously without specifying password
crypto.decryptFileSync('output.enc', 'decrypted.txt');

// You can still override with a custom password
crypto.encryptFileSync('input.txt', 'output.enc', 'CustomP@ssw0rd456!');
```

### Custom Configuration

```typescript
import { CryptoManager } from '@hiprax/crypto';

const crypto = new CryptoManager({
  memoryCost: 2 ** 19, // 512MB (post-Task-18 ULTRA tier)
  timeCost: 4, // Higher time cost
  parallelism: 2, // Use 2 threads
  aad: 'my-app-v1', // Custom AAD
});

console.log('Security Level:', crypto.getSecurityLevel()); // 'ultra'
```

Note: in pre-1.0 development (prior to the v0.15.0 dev iteration) the ULTRA tier was `memoryCost: 2 ** 18` (256 MiB). It is `2 ** 19` (512 MiB) in v1.0.0 so the bar tracks OWASP 2026 guidance — the previous ULTRA configuration now classifies as HIGH.

## 📚 API Reference

### CryptoManager

The main class for encryption/decryption operations.

#### Constructor

```typescript
const crypto = new CryptoManager(options?: CryptoManagerOptions);
```

**Options:**

- `memoryCost` (number): Argon2 memory cost (default: **131072** — `2 ** 17`, 128 MiB; OWASP 2026 first-choice tier for Argon2id, see [Security Levels](#security-levels)). Resource-constrained callers (mobile, embedded, low-memory containers) can opt back into the previous 64 MiB profile by passing `memoryCost: 65536` (`2 ** 16`).
- `timeCost` (number): Argon2 time cost (default: 3)
- `parallelism` (number): Argon2 parallelism (default: 1)
- `aad` (string): Custom Additional Authenticated Data (default: 'secure-crypto-tool-v2')
- `defaultPassphrase` (string): Default passphrase to use when no password is provided to encryption/decryption methods
- `legacyMode` (`'auto' | 'strict' | 'reject'`): How to handle legacy (pre-v1) ciphertexts during decryption — `'auto'` (default) accepts them, `'strict'` rejects with `LEGACY_FORMAT_REJECTED`, `'reject'` rejects with `UNSUPPORTED_FORMAT`. New ciphertexts are always produced in v1 format. See [Ciphertext Format](#ciphertext-format-v1).
- `pbkdf2Iterations` (number): PBKDF2 iteration count for sync key derivation (default: **600000** — matches OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256). The chosen value is embedded in every v1 ciphertext header produced by sync paths so it travels with the ciphertext and decryption remains correct even if you change the default later. Must be a positive integer.
- `legacyPbkdf2Iterations` (number): PBKDF2 iteration count assumed when decrypting **legacy v0** sync ciphertexts (those produced before the versioned ciphertext format and which carry no embedded iteration count). Default: 100000 — the value baked into every v0 sync ciphertext produced by versions of this library prior to 0.11.0. Override only if you have legacy data that was produced with a non-default iteration count. Has no effect on v1 ciphertexts.
- `skipPasswordValidation` (boolean): When `true`, the constructor skips strength validation of `defaultPassphrase` only (default: `false`). This does **not** disable encryption-time password validation, and does **not** disable Unicode NFC normalisation — use it solely to construct a manager for decrypting legacy data whose password predates the current strength rules. See [Password Requirements](#password-requirements).
- `legacyHeaderAad` (boolean): Backward-compat shim for v1 ciphertexts produced by **v1.0.0** (default: `false`). When `true`, v1 ciphertext AAD reverts to the v1.0.0 format (just `aad`, header bytes not bound) so v1.0.0-produced ciphertexts still decrypt; the default `false` binds the header bytes into the AAD. Affects v1 ciphertexts only (v0 always uses `aad` alone). Leave `false` for new code; use only as a temporary migration aid. See [Migration: v1.0.0 → v1.1.0](#migration-v100--v110).

#### Methods

##### `encryptText(text: string, password?: string): Promise<string>`

Encrypts text with a password using Argon2id key derivation. If no password is provided and a default passphrase is set, the default passphrase will be used.

```typescript
const encrypted = await crypto.encryptText(
  'Hello World',
  'MySecureP@ssw0rd123!'
);
// Returns: base64url encoded string

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
const encrypted = await crypto.encryptText('Hello World');
```

##### `decryptText(encryptedText: string, password?: string): Promise<string>`

Decrypts text with a password. If no password is provided and a default passphrase is set, the default passphrase will be used.

```typescript
const decrypted = await crypto.decryptText(encrypted, 'MySecureP@ssw0rd123!');
// Returns: original text

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
const decrypted = await crypto.decryptText(encrypted);
```

##### `encryptBytes(data: Uint8Array, password?: string): Promise<Uint8Array>`

**Isomorphic** in-memory encryption — the same method (and the same output bytes) runs in Node and the browser. Encrypts raw bytes with Argon2id key derivation, producing a v1 ciphertext in the text byte layout `[header:22][salt:32][iv:12][tag:16][ciphertext]`. `encryptText` is a thin base64url wrapper over this method, so there is exactly one wire format. The empty `Uint8Array` is accepted and produces a valid authenticated ciphertext; the caller's `data` buffer is never mutated or scrubbed. See [Isomorphic API & Browser Support](#-isomorphic-api--browser-support).

```typescript
const bytes = new TextEncoder().encode('Hello World');
const ct = await crypto.encryptBytes(bytes, 'MySecureP@ssw0rd123!');
// Returns: Uint8Array (v1 ciphertext, HPCR magic)
```

##### `decryptBytes(data: Uint8Array, password?: string): Promise<Uint8Array>`

**Isomorphic** counterpart of `encryptBytes`. Decrypts v1 (Argon2id) or legacy v0 ciphertext bytes, mirroring `decryptText`'s byte path exactly (header parse, embedded-parameter override, header-bound AAD, and the `legacyMode` v0 fallback). Every confidentiality-relevant failure (wrong password, tampering) surfaces as the generic `DECRYPTION_FAILED`.

```typescript
const back = await crypto.decryptBytes(ct, 'MySecureP@ssw0rd123!');
console.log(new TextDecoder().decode(back)); // 'Hello World'
```

##### `encryptTextSync(text: string, password?: string): string`

Synchronous version of text encryption. Uses PBKDF2 for key derivation instead of Argon2id for synchronous operation.

```typescript
const encrypted = crypto.encryptTextSync('Hello World', 'MySecureP@ssw0rd123!');
// Returns: base64url encoded string

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
const encrypted = crypto.encryptTextSync('Hello World');
```

##### `decryptTextSync(encryptedText: string, password?: string): string`

Synchronous version of text decryption. Uses PBKDF2 for key derivation instead of Argon2id for synchronous operation.

```typescript
const decrypted = crypto.decryptTextSync(encrypted, 'MySecureP@ssw0rd123!');
// Returns: original text

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
const decrypted = crypto.decryptTextSync(encrypted);
```

##### `encryptFile(inputPath: string, outputPath: string, password?: string, progress?: ProgressCallback): Promise<void>`

Encrypts a file with a password. Uses streaming, so peak memory is bounded by the stream's high-water mark regardless of input size. Output is written to a sibling temp file (`${outputPath}.<random>.tmp`) and atomically renamed to `outputPath` only on full success — readers of `outputPath` therefore never observe a half-written ciphertext, and any pre-existing file at `outputPath` is preserved if encryption errors out. If no password is provided and a default passphrase is set, the default passphrase will be used. Automatically creates the output directory if it doesn't exist. The optional `progress` callback receives `(bytesProcessed, totalBytes)` events — see [Progress callbacks for file ops](#progress-callbacks-for-file-ops) for the contract.

```typescript
await crypto.encryptFile('input.txt', 'output.enc', 'MySecureP@ssw0rd123!');

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
await crypto.encryptFile('input.txt', 'output.enc');

// With progress callback
await crypto.encryptFile(
  'input.txt',
  'output.enc',
  'MySecureP@ssw0rd123!',
  (processed, total) => {
    const pct = total === 0 ? 100 : Math.round((processed / total) * 100);
    console.log(`encrypt ${pct}% (${processed}/${total} bytes)`);
  }
);
```

##### `decryptFile(inputPath: string, outputPath: string, password?: string, progress?: ProgressCallback): Promise<void>`

Decrypts a file with a password. **Streams** the ciphertext through `crypto.createDecipheriv()` so the full ciphertext never sits in memory at once — multi-GiB ciphertexts decrypt with bounded memory. Output is written to a sibling temp file and atomically renamed to `outputPath` only after `decipher.final()` validates the GCM auth tag. Both v0 (legacy, no header) and v1 (preferred, 22-byte header) ciphertext layouts are supported (subject to the constructor's `legacyMode` for v0). If no password is provided and a default passphrase is set, the default passphrase will be used. Automatically creates the output directory if it doesn't exist. The optional `progress` callback receives `(bytesProcessed, totalBytes)` events where both values are denominated in input ciphertext bytes — see [Progress callbacks for file ops](#progress-callbacks-for-file-ops).

```typescript
await crypto.decryptFile('output.enc', 'decrypted.txt', 'MySecureP@ssw0rd123!');

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
await crypto.decryptFile('output.enc', 'decrypted.txt');

// With progress callback
await crypto.decryptFile(
  'output.enc',
  'decrypted.txt',
  'MySecureP@ssw0rd123!',
  (processed, total) => console.log(`decrypt ${processed}/${total} bytes`)
);
```

##### `encryptFileSync(inputPath: string, outputPath: string, password?: string, progress?: ProgressCallback): void`

Synchronous version of file encryption. Uses PBKDF2 for key derivation instead of Argon2id for synchronous operation. Like the async path, output is staged to a sibling temp file and atomically renamed to `outputPath` only on success; pre-existing files at `outputPath` are preserved on error. The optional `progress` callback fires twice — once before encryption (`0/totalBytes`) and once after the rename succeeds (`totalBytes/totalBytes`); the input is streamed internally in fixed 64 KiB chunks, but the synchronous encrypt path emits no per-chunk progress events between the two. See [Progress callbacks for file ops](#progress-callbacks-for-file-ops).

```typescript
crypto.encryptFileSync('input.txt', 'output.enc', 'MySecureP@ssw0rd123!');

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
crypto.encryptFileSync('input.txt', 'output.enc');

// With progress callback
crypto.encryptFileSync(
  'input.txt',
  'output.enc',
  'MySecureP@ssw0rd123!',
  (processed, total) => console.log(`encrypt ${processed}/${total} bytes`)
);
```

##### `decryptFileSync(inputPath: string, outputPath: string, password?: string, progress?: ProgressCallback): void`

Synchronous version of file decryption. **Streams** the ciphertext through `crypto.createDecipheriv()` in fixed 64 KiB chunks via `fs.readSync`/`fs.writeSync`, so peak memory is bounded regardless of input size. Uses PBKDF2 for key derivation instead of Argon2id for synchronous operation. Both v0 (legacy) and v1 (preferred) ciphertext layouts are supported (subject to `legacyMode`). Output is staged to a sibling temp file and atomically renamed only after `decipher.final()` validates the GCM auth tag. The optional `progress` callback fires once before the body loop, once per body chunk, and once after the rename succeeds — see [Progress callbacks for file ops](#progress-callbacks-for-file-ops).

```typescript
crypto.decryptFileSync('output.enc', 'decrypted.txt', 'MySecureP@ssw0rd123!');

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
crypto.decryptFileSync('output.enc', 'decrypted.txt');

// With progress callback
crypto.decryptFileSync(
  'output.enc',
  'decrypted.txt',
  'MySecureP@ssw0rd123!',
  (processed, total) => console.log(`decrypt ${processed}/${total} bytes`)
);
```

##### `encryptContainer(data: Uint8Array, password?: string, meta?: ContainerMetadataInput): Promise<Uint8Array>`

**Isomorphic** (Node + browser). Encrypts `data` into a self-describing, authenticated **v2 container** — an additive envelope format (magic `HPCR`, version `0x02`) that is separate from the v1 text/file ciphertext. It wraps a random per-message data-encryption key under an Argon2id key-encryption key, stores optional `filename`/`mime` metadata **confidentially** (encrypted, never in cleartext), and embeds the plaintext SHA-256 for an end-to-end integrity check. See [Container Mode](#-container-mode-v2-envelope).

```typescript
const data = new TextEncoder().encode('report contents');
const container = await crypto.encryptContainer(data, 'MySecureP@ssw0rd123!', {
  filename: 'report.txt',
  mime: 'text/plain',
});
// Returns: Uint8Array (v2 container). In Node: writeFileSync('report.hpcr', container).
```

##### `decryptContainer(container: Uint8Array, password?: string): Promise<DecryptedContainer>`

**Isomorphic** counterpart of `encryptContainer`. Returns `{ data, meta }` where `meta` is the authenticated `{ filename?, mime?, size }`. The embedded SHA-256 is re-verified before returning; a mismatch throws `CryptoError` with code `CONTAINER_INTEGRITY_FAILED`. A v0/v1 blob (no `HPCR` magic, or a version byte other than `0x02`) is rejected before any key derivation runs, so `decryptContainer` never accepts a non-container.

```typescript
const { data, meta } = await crypto.decryptContainer(
  container,
  'MySecureP@ssw0rd123!'
);
console.log(meta); // { filename: 'report.txt', mime: 'text/plain', size: 15 }
console.log(new TextDecoder().decode(data)); // 'report contents'
```

##### `validatePassword(password: string): boolean`

Validates password strength.

```typescript
const isValid = crypto.validatePassword('MySecureP@ssw0rd123!');
// Returns: boolean
```

##### `generateSecureRandom(length: number): Buffer`

Generates cryptographically secure random bytes.

```typescript
const random = crypto.generateSecureRandom(32);
// Returns: Buffer
```

##### `deriveKey(password: string, salt: Buffer): Promise<Buffer>`

Derives an encryption key from a password using Argon2id.

```typescript
const salt = crypto.generateSecureRandom(32);
const key = await crypto.deriveKey('MySecureP@ssw0rd123!', salt);
// Returns: 32-byte Buffer
```

##### `deriveKeySync(password: string, salt: Buffer, iterations?: number): Buffer`

Synchronous version of key derivation using PBKDF2 (default: **600,000 iterations**, SHA-256) instead of Argon2id. Pass an explicit `iterations` argument to override the per-instance default (used internally to apply the iteration count embedded in v1 ciphertext headers, but you can also pass it directly when calling `deriveKeySync` yourself).

```typescript
const salt = crypto.generateSecureRandom(32);
// Default iterations (600,000 — current OWASP recommendation)
const key = crypto.deriveKeySync('MySecureP@ssw0rd123!', salt);
// Returns: 32-byte Buffer

// Override iterations explicitly
const customKey = crypto.deriveKeySync('MySecureP@ssw0rd123!', salt, 250000);
```

##### `encryptData(data: Buffer, key: Buffer, iv: Buffer): EncryptionResult`

Low-level AES-256-GCM encryption. Returns `{ encrypted: Buffer, tag: Buffer }`.

> **Security:** the caller is responsible for ensuring each `(key, iv)` pair is used at most once. See [AES-GCM (key, IV) reuse](#aes-gcm-key-iv-reuse--security-boundary-for-the-low-level-api) for the full explanation and recommended pattern. Prefer `encryptText` / `encryptFile` for any code that does not have a specific reason to manage IVs by hand.

```typescript
const key = crypto.generateSecureRandom(32);
const iv = crypto.generateSecureRandom(12); // fresh random IV per message
const { encrypted, tag } = crypto.encryptData(Buffer.from('data'), key, iv);
```

##### `decryptData(encryptedData: Buffer, key: Buffer, iv: Buffer, tag: Buffer): Buffer`

Low-level AES-256-GCM decryption. Returns the decrypted data as a Buffer.

The caller must supply the exact `(key, iv, tag)` that were produced by `encryptData` (and the matching `aad`, configured on the `CryptoManager` instance). Tag-check failure surfaces as `CryptoError` with code `DECRYPTION_FAILED` regardless of which condition failed (wrong key, wrong IV, wrong AAD, or tampered ciphertext) — the generic message is intentional, to avoid leaking which case applied.

```typescript
const decrypted = crypto.decryptData(encrypted, key, iv, tag);
```

##### `secureClear(buffer: Uint8Array): void`

Securely zeroes a buffer to remove sensitive data from memory. The parameter is `Uint8Array` (every Node `Buffer` is a `Uint8Array`, so existing `Buffer` call sites are unaffected); a plain `Uint8Array` — e.g. browser key material — is actually scrubbed rather than silently skipped. Best-effort only: it cannot reach immutable V8 strings or GC-managed copies (see [Threat Model](#-threat-model)).

```typescript
crypto.secureClear(key);
```

##### `getParameters(): EncryptionParameters`

Gets current encryption parameters.

```typescript
const params = crypto.getParameters();
// Returns: object with algorithm details
```

##### `getSecurityLevel(): SecurityLevel`

Gets security level based on configuration.

```typescript
const level = crypto.getSecurityLevel();
// Returns: 'low' | 'medium' | 'high' | 'ultra'
```

##### `hasDefaultPassphrase(): boolean`

Checks if a default passphrase is configured.

```typescript
const hasDefault = crypto.hasDefaultPassphrase();
// Returns: boolean indicating if default passphrase is set
```

##### `getLegacyMode(): LegacyMode`

Returns the configured legacy-format handling mode — one of `'auto'`, `'strict'`, or `'reject'` (see the `legacyMode` constructor option).

```typescript
const mode = crypto.getLegacyMode();
// Returns: 'auto' | 'strict' | 'reject'
```

##### `inspectHeader(input: string | Uint8Array): ParsedHeader | null`

Parses the v1 ciphertext header **without decrypting**. Returns a `ParsedHeader` (`{ version, kdfId, params, headerLen }`) for a v1 ciphertext, or `null` when the input lacks the v1 magic bytes (i.e. a legacy v0 ciphertext). Accepts either a base64url string (text-format output) or a `Uint8Array` (file contents — a Node `Buffer` is a `Uint8Array`, so `Buffer` inputs keep working). String inputs are validated as well-formed base64url **before** decoding and throw `CryptoError` with code `INVALID_BASE64URL` on malformed input — so an invalid string fails fast instead of being mistaken for a v0 ciphertext; byte inputs are read as-is. A buffer that begins with the v1 magic but is otherwise malformed throws a specific parser `CryptoError` (e.g. `TRUNCATED_HEADER`, `UNSUPPORTED_VERSION`). See the worked example under [Ciphertext Format (v1)](#ciphertext-format-v1).

### Types and Enums

The library exports all types, interfaces, and enums for TypeScript consumers:

```typescript
import {
  // Error handling
  CryptoError,
  CryptoErrorType,
  // Enums
  SecurityLevel,
  EncryptionAlgorithm,
  // Interfaces
  type CryptoManagerOptions,
  type EncryptionResult,
  type EncryptionParameters,
  type ValidationResult,
  type FileInfo,
  type RetryConfig,
  type ProgressCallback,
  // Container mode (v2 envelope)
  type ContainerMetadataInput,
  type ContainerMetadata,
  type DecryptedContainer,
} from '@hiprax/crypto';
```

### Utility Functions

Additional utility functions are also exported:

```typescript
import {
  validateFile,
  validatePath,
  generateRandomString,
  validatePasswordStrength,
  generateUUID,
  sha256,
  generateRandomHex,
  secureStringCompare,
  formatFileSize,
  getFileExtension,
  isTextFile,
  sanitizeFilename,
  createBackupPath,
  isValidBase64,
  isValidBase64Url,
  createProgressBar,
  sleep,
  retryWithBackoff,
  getFileInfo,
} from '@hiprax/crypto';

// Validate if file exists and is accessible
const fileValidation = await validateFile('path/to/file.txt');

// Validate if path is valid for writing.
// `validatePath` rejects empty input, null bytes, ASCII control characters
// (codepoints `< 0x20` or `0x7F`), Windows-illegal characters
// (`<`, `>`, `:`, `"`, `|`, `?`, `*` — drive-letter prefix excluded),
// and literal `..` traversal segments after `path.normalize`.
const pathValidation = validatePath('path/to/output.txt');

// Optional: enforce that the input path resolves inside an allowed root.
// Useful for catching within-drive cross-traversal that the literal-`..`
// segment check on its own cannot detect (because `path.normalize`
// collapses internal `..` cancel-outs to a clean path). The check is
// segment-aware (no `/etc/sec` ↔ `/etc/secret` collision) and on Windows
// is case-insensitive and forward-slash-tolerant. NOTE: this is a
// syntactic / resolved-string check; it does NOT defend against
// symlink-based escapes.
const inProject = validatePath('/home/user/project/data/file.txt', {
  allowedRoot: '/home/user/project',
});
// inProject.isValid === true

const escape = validatePath('C:\\Users\\..\\Windows', {
  allowedRoot: 'C:\\Users',
});
// escape.isValid === false, escape.error === 'Path is outside the allowed root'

// Generate secure random string
// (default 32 chars ≈ 190 bits of entropy; request >= 44 chars for a full
// 128-bit post-quantum margin — see the sizing note below this block)
const randomString = generateRandomString(32);

// Validate password strength with detailed feedback
const passwordCheck = validatePasswordStrength('MyPassword123!');
console.log('Score:', passwordCheck.score); // 0-5
console.log('Feedback:', passwordCheck.feedback); // Array of suggestions

// Generate UUID (v4 — 122 random bits; an identifier, NOT a bearer secret)
const uuid = generateUUID();

// Hash string with SHA-256
const hash = sha256('hello world');

// Generate random hex string (each hex char = 4 bits; use >= 64 chars for
// 256-bit bearer secrets — see the sizing note below this block)
const hex = generateRandomHex(16);

// Secure string comparison (constant time)
const isEqual = secureStringCompare('secret', 'secret');

// Format file size
const size = formatFileSize(1024 * 1024); // "1 MB"

// Get file extension (lowercase)
const ext = getFileExtension('photo.JPG'); // ".jpg"

// Check if file is text file
const isText = isTextFile('document.txt');

// Sanitize filename
const safeName = sanitizeFilename('file<name>.txt'); // "file_name_.txt"

// Create backup path
const backupPath = createBackupPath('file.txt'); // "file_2026-06-30T12-00-00_a1b2c3.backup.txt"

// Validate base64
const isValid = isValidBase64('SGVsbG8gV29ybGQ=');

// Validate base64url (the format used by this library's encrypted output)
const isValidUrl = isValidBase64Url('SGVsbG8gV29ybGQ');

// Create progress bar
const progress = createProgressBar(50, 100); // "[████████████████░░░░░░░░░░░░░░] 50%"

// Sleep for specified time
await sleep(1000); // Sleep for 1 second

// Retry with exponential backoff
const result = await retryWithBackoff(
  async () => {
    // Some async operation that might fail
    return await someOperation();
  },
  { maxRetries: 3, baseDelay: 1000 }
);

// Get file information
const fileInfo = await getFileInfo('path/to/file.txt');
console.log('Size:', fileInfo.size);
console.log('Extension:', fileInfo.extension);
console.log('Is Text:', fileInfo.isTextFile);
```

> **Sizing random secrets for a post-quantum margin.** `generateRandomString` and `generateRandomHex` draw from the OS CSPRNG, so their strength is purely a function of length. Grover's algorithm halves the effective entropy of a random secret against a quantum adversary, so to preserve a 128-bit post-quantum margin, size bearer secrets (API keys, session tokens, capability URLs) at **256 bits**: `generateRandomHex(64)` (64 hex chars) or `generateRandomString(44)` (≈262 bits). The defaults (32 chars) are ample for identifiers and classical threat models. `generateUUID` output carries 122 random bits and is designed as a collision-resistant *identifier* — do not use it as an unguessable bearer token where post-quantum unpredictability matters. See [Post-Quantum Security](#-post-quantum-security).

## 🌐 Isomorphic API & Browser Support

`@hiprax/crypto` runs the **same code, over the same wire format, in Node and the browser.** The in-memory async API — `encryptBytes` / `decryptBytes` / `encryptText` / `decryptText` / `encryptContainer` / `decryptContainer` / `inspectHeader` / `validatePassword` / `getParameters` / `getSecurityLevel` — lives in a runtime-agnostic core and is available in both builds. The runtime-specific primitives (CSPRNG, Argon2id, AES-256-GCM, SHA-256) are the only thing that differs: Node uses `node:crypto` + native/WASM Argon2id, the browser uses Web Crypto (SubtleCrypto) + WebAssembly Argon2id (`hash-wasm`). There is **exactly one ciphertext format** — a blob produced in one runtime decrypts in the other.

### Isomorphic in-memory API

`encryptBytes(data, password?)` / `decryptBytes(data, password?)` are the foundation: they take and return `Uint8Array`, and `encryptText` / `decryptText` are thin base64url wrappers over them (one wire format, one code path).

```ts
import { CryptoManager } from '@hiprax/crypto';

const cm = new CryptoManager();
const bytes = new TextEncoder().encode('Hello World'); // any Uint8Array, incl. binary
const ct = await cm.encryptBytes(bytes, 'MySecureP@ssw0rd123!'); // Uint8Array
const back = await cm.decryptBytes(ct, 'MySecureP@ssw0rd123!'); // byte-identical
```

The empty `Uint8Array` is accepted and produces a valid authenticated ciphertext. The caller's `data` buffer is never mutated or scrubbed (it belongs to the caller).

### Cross-runtime interop

Because both runtimes share one format and one KDF (Argon2id, whose native/WASM outputs are bit-identical for the same parameters), a ciphertext crosses the boundary transparently:

```ts
// In the browser (32 MiB Argon2id default):
const ct = await cm.encryptText('secret', 'MySecureP@ssw0rd123!');
// ...transmit `ct` (a base64url string) to a Node service...

// In Node:
const plaintext = await new CryptoManager().decryptText(ct, 'MySecureP@ssw0rd123!');
// -> 'secret'   (Node reads the KDF params embedded in the ciphertext header)
```

The reverse direction (Node → browser) works identically, subject to the memory caveat below.

### Browser usage (and `Blob` output)

Install the WASM Argon2id provider alongside the package (Web Crypto has no Argon2id), import from the package root, and — for large payloads — hand the ciphertext bytes to a `Blob`:

```bash
npm install @hiprax/crypto hash-wasm
```

```ts
import { CryptoManager } from '@hiprax/crypto';

const cm = new CryptoManager();

// Encrypt a File/Blob the user selected, entirely client-side:
async function encryptFileInBrowser(file: File, password: string): Promise<Blob> {
  const plaintext = new Uint8Array(await file.arrayBuffer());
  const ct = await cm.encryptBytes(plaintext, password); // Uint8Array
  return new Blob([ct], { type: 'application/octet-stream' });
}

// Decrypt back to a Blob for download:
async function decryptToBlob(ciphertext: Uint8Array, password: string): Promise<Blob> {
  const plaintext = await cm.decryptBytes(ciphertext, password);
  return new Blob([plaintext]);
}
```

Browser large-file handling is **in-memory** (read the file, `encryptBytes`/`decryptBytes`, hand back a `Blob`): there is no browser streaming, because Web Crypto AES-GCM is one-shot. Peak memory is proportional to the payload size — a documented limit, not a bug.

### Browser Argon2id profile (32 MiB default) and the 128 MiB-decrypt caveat

The Node default is 128 MiB Argon2id (`memoryCost = 2 ** 17`, classified `HIGH`). The **browser default is a lighter 32 MiB** profile (`memoryCost = 2 ** 15`, `timeCost = 3`, `parallelism = 1`) — still ≈1.68× the OWASP 2025/2026 Argon2id memory minimum (19 MiB), but classified `MEDIUM` by `getSecurityLevel()` because 32 MiB is below the `HIGH` threshold. This is a runtime-specific **default**, not a format change; you can pass an explicit `memoryCost`, and every ciphertext carries its own KDF parameters on the wire.

> **⚠️ Decrypt-side memory caveat.** Because each ciphertext header embeds the *exact* `memoryCost` used to derive its key, decrypting a ciphertext produced at 128 MiB requires allocating 128 MiB — which can OOM a memory-constrained mobile browser tab (iOS Safari WASM ceilings are as low as ~64–120 MB). **Data intended to be decrypted in browsers should be encrypted at ≤ the browser memory profile** (e.g. the 32 MiB browser default). The wire format is identical across runtimes; only the affordable KDF cost differs. Node → browser interop is only reliable when the Node side encrypts within the browser's memory budget.

### Content-Security-Policy (WASM)

The browser Argon2id path compiles WebAssembly (`hash-wasm`). Under a strict CSP that sets `script-src` (or `default-src`) without `'unsafe-eval'`, WebAssembly compilation is blocked and throws a `CompileError`. Allow it with the strictly-narrower `'wasm-unsafe-eval'` (WASM only — not JS `eval`):

```http
Content-Security-Policy: script-src 'self' 'wasm-unsafe-eval'
```

`hash-wasm` instantiates from **inline bytes** (the WASM is embedded as base64), so **no `connect-src` entry and no network fetch** are needed. Pages with no CSP run WASM fine. Supported: Chrome/Edge 97+, Firefox 102+, Safari 16+.

### Browser memory-hygiene caveats

The browser build is honest about weaker memory hygiene than Node:

- **Opaque `CryptoKey`.** Web Crypto `importKey` copies the raw key bytes into a `CryptoKey` object the library can no longer reach — so `secureClear` cannot scrub it. The engine zeroes the transient raw-key copy it owns immediately after import, but the `CryptoKey` itself lives until GC.
- **Immutable V8 strings.** As in Node, passwords and decrypted text are JavaScript strings; they are GC-managed and cannot be zeroed (see [Threat Model](#-threat-model)).
- **Secure context required.** `crypto.subtle` is only available in a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (HTTPS or `localhost`). On an insecure origin, `globalThis.crypto.subtle` is `undefined` and the engine throws.

### Node-only methods throw in the browser

The synchronous (PBKDF2) paths, the streaming file paths, and the `Buffer`-typed low-level primitives cannot be expressed with one-shot, async Web Crypto, so in the browser build they are present as throwing stubs that raise `CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER')`: `encryptTextSync`, `decryptTextSync`, `encryptFile`, `decryptFile`, `encryptFileSync`, `decryptFileSync`, `encryptData`, `decryptData`, `deriveKey`, `deriveKeySync`, and `generateSecureRandom`. Use the in-memory async API (`encryptBytes` / `decryptBytes` / `encryptText` / `decryptText` / `encryptContainer` / `decryptContainer`) instead. The `./utils` file helpers are Node-only and are not exported from the browser build.

## 📦 Container Mode (v2 envelope)

Container mode is an **optional, additive** wire format (magic `HPCR`, version `0x02`) for sealing a payload **together with confidential metadata and an end-to-end integrity check**. It is separate from the v1 text/file ciphertext — it does not touch `encryptBytes`/`decryptBytes` — and, like the rest of the in-memory API, it is **isomorphic** (available in Node and the browser). It differs from `encryptBytes` in three ways:

1. **Two-layer keying (KEK/DEK).** An Argon2id key-encryption key (KEK), derived from the password, AES-256-GCM-wraps a fresh random 32-byte data-encryption key (DEK); the DEK encrypts the metadata and the payload.
2. **Confidential metadata.** The optional `filename` / `mime` (plus the derived `size` and the plaintext SHA-256) are packed into a metadata block that is itself encrypted under the DEK — none of it appears in cleartext anywhere in the output.
3. **End-to-end integrity.** The SHA-256 of the plaintext is embedded and re-verified on decrypt (`CONTAINER_INTEGRITY_FAILED` on mismatch), on top of the per-segment GCM authentication.

The AES-GCM AAD of all three segments (DEK-wrap, metadata, payload) is the configured context string (`aad`) bound to the verbatim 22-byte header, so tampering with the version, KDF parameters, or any reserved byte flips every tag — and, exactly like the v1 path, a custom `aad` provides cross-application domain separation: a container sealed by a manager configured with `aad: 'app-A'` cannot be opened by one configured with `aad: 'app-B'`, even with the same password and parameters.

### Usage

```ts
import { CryptoManager } from '@hiprax/crypto';

const cm = new CryptoManager();
const data = new TextEncoder().encode('report contents');

const container = await cm.encryptContainer(data, 'MySecureP@ssw0rd123!', {
  filename: 'report.txt',
  mime: 'text/plain',
});

const { data: back, meta } = await cm.decryptContainer(
  container,
  'MySecureP@ssw0rd123!'
);
console.log(meta); // { filename: 'report.txt', mime: 'text/plain', size: 15 }
```

Container mode is an **in-memory** format (no streaming). Persist or transmit the bytes with the idioms natural to each runtime:

```ts
// Node — a file container:
import { readFileSync, writeFileSync } from 'node:fs';
writeFileSync(
  'report.hpcr',
  await cm.encryptContainer(readFileSync('report.txt'), pw, {
    filename: 'report.txt',
    mime: 'text/plain',
  })
);

// Browser — download as a Blob:
const blob = new Blob([await cm.encryptContainer(bytes, pw, { filename })]);
```

> The container is memory-bounded (the whole payload is held in memory to hash and encrypt it); it is intended for small-to-medium payloads. For arbitrarily large files in Node, prefer the streaming `encryptFile` / `decryptFile` (v1) methods.

### Version isolation

Container mode and the v1 ciphertext path reject each other's blobs:

- Feeding a v2 container to `decryptBytes` / `decryptText` throws `CryptoError` (in the default `legacyMode: 'auto'` the v1 header parser rejects the `0x02` version and the v0 fallback cannot rescue it, surfacing as `DECRYPTION_FAILED`; `strict` / `reject` surface `UNSUPPORTED_VERSION`).
- Feeding a v0/v1 blob to `decryptContainer` is rejected by a pure, DoS-bounded header parse **before any key derivation runs** (no `HPCR` magic → `CONTAINER_INVALID_MAGIC`; wrong version → `CONTAINER_UNSUPPORTED_VERSION`).

### Container error codes

`CONTAINER_INTEGRITY_FAILED` (decrypted payload does not match its embedded SHA-256), `CONTAINER_METADATA_MALFORMED`, `CONTAINER_METADATA_TOO_LARGE` / `CONTAINER_DATA_TOO_LARGE` (field/payload exceeds its wire cap), `INVALID_CONTAINER_META` (non-string `filename`/`mime`), plus the pre-authentication parser codes `TRUNCATED_CONTAINER`, `CONTAINER_INVALID_MAGIC`, `CONTAINER_UNSUPPORTED_VERSION`, `CONTAINER_UNSUPPORTED_KDF`, `CONTAINER_INVALID_HEADER_PARAM`, and `CONTAINER_KDF_PARAMS_OUT_OF_BOUNDS`. The byte layout is documented under [Container Format (v2)](#container-format-v2).

## 🔧 Configuration

### Asynchronous vs Synchronous Operations

The library provides both asynchronous and synchronous versions of encryption/decryption operations:

#### Asynchronous Operations (Recommended)

- Use **Argon2id** for key derivation (more secure)
- Better for performance and scalability
- Non-blocking operations
- Methods: `encryptText()`, `decryptText()`, `encryptFile()`, `decryptFile()`

#### Synchronous Operations

- Use **PBKDF2** for key derivation (less secure but synchronous)
- Blocking operations
- Useful for simple scripts or when async/await is not available
- Methods: `encryptTextSync()`, `decryptTextSync()`, `encryptFileSync()`, `decryptFileSync()`

**Note**: Synchronous operations use PBKDF2 with **600,000 iterations** (SHA-256) by default — matching the OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256 (still current in 2026). The iteration count is configurable via the constructor option `pbkdf2Iterations` and is embedded in every v1 ciphertext header so changing it later does not break old data. Argon2id (used by the async paths) remains the stronger choice for production use because it is memory-hard.

**Backward compatibility**: Versions of this library prior to 0.11.0 used 100,000 PBKDF2 iterations and did not embed the iteration count in the ciphertext. Such legacy v0 ciphertexts continue to decrypt successfully under the default `legacyMode: 'auto'`; the decoder uses `legacyPbkdf2Iterations` (default 100,000) as the assumed iteration count. Override `legacyPbkdf2Iterations` only if you have legacy data that was produced with a non-default value.

**Security upgrade rationale**: Bumping the default from 100,000 → 600,000 reflects the 6× increase in baseline GPU brute-force resistance recommended by OWASP since 2023. Existing v1 ciphertexts produced with the old default would still decrypt correctly because their iteration count is embedded in the header — only legacy v0 sync data is affected, and it remains decryptable under `legacyMode: 'auto'`.

**Important**: Synchronous and asynchronous functions are not compatible with each other due to different key derivation methods. Always use the same type (sync or async) for both encryption and decryption.

### Progress callbacks for file ops

All four file methods accept an optional fourth argument: a `progress` callback of type `ProgressCallback = (bytesProcessed: number, totalBytes: number) => void`. When supplied, the callback is invoked periodically during encryption/decryption so callers can drive UI updates or back-pressure-aware pipelines.

#### Contract

| Method             | Initial event       | Per-chunk events             | Final event                    | Total denomination                |
| ------------------ | ------------------- | ---------------------------- | ------------------------------ | --------------------------------- |
| `encryptFile`      | `(0, totalBytes)`   | per readable `data` event    | `(totalBytes, totalBytes)`     | input file size (plaintext bytes) |
| `decryptFile`      | `(0, totalBytes)`   | per readable `data` event    | `(totalBytes, totalBytes)`     | input file size (ciphertext)      |
| `encryptFileSync`  | `(0, totalBytes)`   | _none_ — no per-chunk events | `(totalBytes, totalBytes)`     | input file size (plaintext bytes) |
| `decryptFileSync`  | `(0, totalBytes)`   | per 64 KiB chunk             | `(totalBytes, totalBytes)`     | input file size (ciphertext)      |

Universal invariants: `processed` is monotonically non-decreasing across events for a single call, every event reports the same `total`, and the **final** invocation always has `processed === total` (so callers can rely on a single "100% done" signal).

#### Throwing inside a progress callback aborts the operation

If the supplied callback throws, the throw propagates out of the file method and aborts the encryption/decryption — the temp file is cleaned up, no partial output is written to `outputPath`, and the original error reaches the caller. The library preserves the caller's error identity (e.g. `instanceof MyError` continues to work) rather than wrapping the throw in `CryptoError(FILE_ENCRYPTION_FAILED)`. This is the intentional design: a callback that throws is a caller-side bug, and silently swallowing it would hand back a "successful" encryption to a caller who thought they had aborted.

If you want best-effort progress reporting that never aborts the underlying op, wrap your callback in a try/catch yourself:

```typescript
await crypto.encryptFile(
  'input.txt',
  'output.enc',
  password,
  (processed, total) => {
    try {
      myUI.updateProgress(processed, total);
    } catch {
      // swallowed — encryption keeps going
    }
  }
);
```

#### Examples

```typescript
import { CryptoManager, ProgressCallback } from '@hiprax/crypto';

const crypto = new CryptoManager();

// Async encrypt with a console progress bar
const printProgress: ProgressCallback = (processed, total) => {
  const pct = total === 0 ? 100 : Math.round((processed / total) * 100);
  process.stdout.write(`\rencrypt ${pct}% (${processed}/${total} bytes)`);
};
await crypto.encryptFile('input.bin', 'output.enc', password, printProgress);

// Async decrypt with the same callback shape
await crypto.decryptFile(
  'output.enc',
  'decrypted.bin',
  password,
  (processed, total) => console.log(`decrypt ${processed}/${total} bytes`)
);

// Sync encrypt — fires once at start and once after the rename
crypto.encryptFileSync(
  'input.bin',
  'output.enc',
  password,
  (processed, total) => console.log(`sync encrypt ${processed}/${total}`)
);

// Sync decrypt — fires per 64 KiB chunk
crypto.decryptFileSync(
  'output.enc',
  'decrypted.bin',
  password,
  (processed, total) => console.log(`sync decrypt ${processed}/${total}`)
);
```

The `progress` argument is fully optional — every call shape that worked before this argument was added continues to work unchanged.

### Security Levels

The library supports different security levels based on Argon2 parameters. The current threshold table is the one that ships with the v1.0.0 stable release; it was last tightened during pre-1.0 development (in the v0.15.0 dev iteration, Task 18) to track OWASP 2026 guidance for Argon2id — the **HIGH** tier moved from `memoryCost: 2^16` (64 MiB) up to `memoryCost: 2^17` (128 MiB), and **ULTRA** moved from `2^18` up to `2^19` (512 MiB):

- **Low**: `memoryCost < 2^14` OR `timeCost < 2` (Fast, less secure — fallback tier)
- **Medium**: `memoryCost: 2^14` (16 MiB), `timeCost: 2` (Balanced — minimum acceptable)
- **High**: `memoryCost: 2^17` (128 MiB), `timeCost: 3` (**Default**, OWASP 2026 first choice)
- **Ultra**: `memoryCost: 2^19` (512 MiB), `timeCost: 4` (Maximum — paranoid tier for offline / async-only workloads)

A configuration is reported at a tier only when **both** `memoryCost` AND `timeCost` clear that tier's minimum; if either parameter falls short, classification falls through to the next-lower tier.

#### Migration note (any pre-1.0 dev release → v1.0.0)

The default `memoryCost` was bumped from `2^16` (64 MiB) to `2^17` (128 MiB) during pre-1.0 development and is the v1.0.0 stable default. This is a **deliberate performance regression** that doubles the memory footprint and roughly doubles the latency of every async key-derivation call. The trade-off buys roughly 2× the GPU brute-force resistance in line with current OWASP guidance.

- **Existing v1 ciphertexts continue to decrypt unchanged.** Each ciphertext header embeds the exact `memoryCost` / `timeCost` / `parallelism` that were used to derive its key, so the decoder applies the embedded values rather than the constructor default. Data encrypted under the old 64 MiB default round-trips under the new default with no migration step.
- **To opt back into the previous 64 MiB profile**, pass `memoryCost: 2 ** 16` to the `CryptoManager` constructor. This is the recommended escape hatch for resource-constrained environments (mobile, embedded, low-memory containers, shared free-tier hosts). Note: a `CryptoManager` configured this way will report `getSecurityLevel() === 'medium'` rather than `'high'`, which accurately reflects the post-bump threshold table.
- **To opt INTO the previous ULTRA classification (256 MiB)**, you now need to supply `memoryCost: 2 ** 19` AND `timeCost: 4` — the previous ULTRA settings (`2 ** 18`, `4`) now classify as HIGH.

#### Programmatic introspection

The threshold table is exported as `SECURITY_THRESHOLDS` so downstream tooling can assert configurations meet a baseline at startup:

```typescript
import { CryptoManager, SECURITY_THRESHOLDS } from '@hiprax/crypto';

const cm = new CryptoManager({
  memoryCost: SECURITY_THRESHOLDS.HIGH.memoryCost,
  timeCost: SECURITY_THRESHOLDS.HIGH.timeCost,
});

// Or assert that whatever was configured meets your minimum:
const params = cm.getParameters();
if (
  params.argon2Options.memoryCost < SECURITY_THRESHOLDS.HIGH.memoryCost ||
  params.argon2Options.timeCost < SECURITY_THRESHOLDS.HIGH.timeCost
) {
  throw new Error('crypto policy below HIGH');
}
```

`SECURITY_THRESHOLDS` is `Object.freeze`d (recursively) and typed `as const`, so consumers cannot mutate it to weaken the bar at runtime.

#### Migration: v1.0.0 → v1.1.0

v1.1.0 ships **two security fixes** that change the on-disk wire format for v1 ciphertexts (a security-fix patch release; v0 ciphertexts are unaffected):

1. **The 22-byte v1 header is now bound to the AES-GCM auth tag** (via the AAD). Pre-fix, an attacker could flip bits in the header's reserved-byte regions (offsets 16–21 for Argon2id, 10–21 for PBKDF2-SHA256) without invalidating the auth tag — a categorical break of the integrity contract. Post-fix, ANY mutation of the header bytes (including reserved-byte regions) flips the GCM tag and decryption fails with `DECRYPTION_FAILED`.
2. **`parseHeader` rejects pathologically-large KDF parameters** with `KDF_PARAMS_OUT_OF_BOUNDS` BEFORE invoking the KDF. Pre-fix, a malicious 100-byte ciphertext could request `memoryCost = 4 GiB` or `iterations = 100M` and pin the host for seconds-to-minutes. Caps: Argon2id `memoryCost <= 2^22` (4 GiB), `timeCost <= 100`, `parallelism <= 64`; PBKDF2 `iterations <= 10_000_000`. Additionally, `parseHeader` enforces the Argon2id RFC 9106 §3.1 cross-field floor `memoryCost >= 8 * parallelism` (code `INVALID_HEADER_PARAM`); no legitimately-produced ciphertext can violate this floor since the constructor enforces it at construction time.

**Impact on existing v1 ciphertexts:** v1 ciphertexts produced by **v1.0.0 specifically** were encrypted with the unbound AAD and therefore will NOT decrypt under v1.1.0's default. Two migration paths:

```typescript
// Option A: re-encrypt under v1.1.0 (recommended).
const cmLegacy = new CryptoManager({ legacyHeaderAad: true });
const cmNew = new CryptoManager(); // v1.1.0 default — header-bound AAD
const plaintext = await cmLegacy.decryptText(v100Ciphertext, password);
const v101Ciphertext = await cmNew.encryptText(plaintext, password);

// Option B: keep using legacyHeaderAad: true at decrypt time.
// Note this opts back in to the v1.0.0 vulnerability where reserved
// bytes are silently mutable. Recommend Option A.
const cmCompat = new CryptoManager({ legacyHeaderAad: true });
const plaintext = await cmCompat.decryptText(v100Ciphertext, password);
```

v0 (legacy unversioned) ciphertexts are unaffected by either change — they always used (and continue to use) just the AAD context string for AAD, and they have no header to subject to the parameter caps.

### Password Requirements

A password is accepted if **either** of the following holds:

1. **Passphrase rule (NIST SP 800-63B style)** — at least **20 characters**, regardless of character composition. This accepts XKCD-style multi-word passphrases like `correct horse battery staple longer` whose entropy comes from word choice rather than category mixing.
2. **Composition rule** — at least **8 characters**, AND contains:
   - at least one uppercase letter (`[A-Z]`)
   - at least one lowercase letter (`[a-z]`)
   - at least one digit (`\d`)
   - at least one **non-alphanumeric** character (any character outside `[A-Za-z0-9]` — so `_`, `-`, `+`, `[`, `]`, non-ASCII punctuation, etc. all count as "special").

Validation runs on `encryptText` / `encryptTextSync` / `encryptFile` / `encryptFileSync` so that newly produced ciphertexts always use a strong key. It does **not** run on decryption — once encrypted, data stays decryptable with whatever password was accepted at encryption time.

`defaultPassphrase` (constructor option) is also validated at construction time so misconfiguration fails fast with `WEAK_PASSWORD` rather than at first use. If you need to decrypt legacy data encrypted under a weaker password, pass `skipPasswordValidation: true` to bypass the constructor check (this does **not** disable encryption-time validation, and does **not** disable Unicode NFC normalisation in `deriveKey`/`deriveKeySync`).

**Memory hygiene of `defaultPassphrase`.** The library stores the configured `defaultPassphrase` on the instance as a plain V8 string. V8 strings are immutable and GC-managed, so `secureClear` (which only zero-fills `Buffer`-backed allocations) cannot scrub them — the password stays resident for the full lifetime of the `CryptoManager` instance plus an unbounded GC tail for any internal V8 string copies. For sensitive workloads, **prefer passing the password explicitly to each `encrypt*` / `decrypt*` call** so the password's V8-string lifetime is bounded by the call frame rather than the manager instance. `defaultPassphrase` is a convenience for short-lived scripts and CLI tools where the additional retention is not part of your threat model. See [Threat Model](#-threat-model) for the broader memory-hygiene picture.

Passwords are NFC-normalised (`String.prototype.normalize('NFC')`) before key derivation. This means `'café'` typed as a precomposed `é` (U+00E9) and the same character typed as `e + U+0301` (combining acute accent) derive the **same** key — visually identical input always produces identical ciphertexts regardless of how the input method composed it.

### Ciphertext Format (v1)

Every ciphertext produced by this library — text or file, async or sync — begins with a 22-byte versioned header. This makes the format self-describing: the KDF used and its exact parameters travel with the ciphertext, so a `CryptoManager` configured with different defaults can still decrypt data produced by another instance.

**Header layout (22 bytes total)**

| Offset | Length | Field          | Meaning                                                        |
| ------ | ------ | -------------- | -------------------------------------------------------------- |
| 0      | 4      | `magic`        | ASCII `"HPCR"` — identifies a v1 ciphertext                    |
| 4      | 1      | `version`      | `0x01` — current format version                                |
| 5      | 1      | `kdf-id`       | `0x00` = Argon2id (async paths), `0x01` = PBKDF2-SHA256 (sync) |
| 6      | 16     | `kdf-params`   | KDF-specific parameter block (see below)                       |

**KDF parameter block (16 bytes, big-endian)**

For Argon2id (`kdf-id = 0x00`):

```text
[memoryCost: 4 bytes BE u32][timeCost: 4 bytes BE u32][parallelism: 2 bytes BE u16][reserved: 6 bytes zero]
```

For PBKDF2-SHA256 (`kdf-id = 0x01`):

```text
[iterations: 4 bytes BE u32][reserved: 12 bytes zero]
```

**Full ciphertext layouts**

Text (base64url-encoded):

```text
[v1 header: 22][salt: 32][iv: 12][tag: 16][ciphertext: variable]
```

File (binary):

```text
[v1 header: 22][salt: 32][iv: 12][ciphertext: variable][tag: 16]
```

The tag-position difference (text vs file) is unchanged from the legacy format: file encryption streams the ciphertext and only knows the auth tag once the stream completes, so it must append the tag at the end.

**Backward compatibility (v0)**

Ciphertexts produced before this format was introduced (no magic bytes) are still accepted by default. The constructor option `legacyMode` controls this behaviour:

- `'auto'` (default): legacy v0 ciphertexts are decrypted using the parameters configured on this `CryptoManager`.
- `'strict'`: legacy v0 ciphertexts are rejected with `CryptoError` code `LEGACY_FORMAT_REJECTED`.
- `'reject'`: legacy v0 ciphertexts are rejected with `CryptoError` code `UNSUPPORTED_FORMAT`.

Encryption always produces v1 — there is no option to fall back to v0.

```typescript
import { CryptoManager } from '@hiprax/crypto';

// Default: accept legacy v0 ciphertexts.
const auto = new CryptoManager();

// Refuse to decrypt anything that lacks the v1 header.
const strict = new CryptoManager({ legacyMode: 'strict' });

// Inspect the format of an existing ciphertext without decrypting:
const encrypted = await auto.encryptText('hello', 'MyP@ssw0rd123!');
const header = auto.inspectHeader(encrypted);
console.log(header); // { version: 1, kdfId: 0, params: { kind: 'argon2id', ... }, headerLen: 22 }
```

**Decryption error codes specific to the format header**

- `UNSUPPORTED_VERSION`: header magic matches but the version byte is not `0x01`.
- `UNSUPPORTED_KDF`: header KDF identifier is unknown.
- `KDF_MISMATCH`: ciphertext was produced by the sync path but is being decrypted by the async path (or vice-versa).
- `INVALID_MAGIC`: only emitted by the low-level `parseHeader` helper when the magic check fails (the high-level decrypt methods treat that case as v0 and apply `legacyMode`).
- `TRUNCATED_HEADER`, `INVALID_HEADER_PARAM`: defensive parser errors for malformed v1 input.
- `LEGACY_FORMAT_REJECTED` / `UNSUPPORTED_FORMAT`: emitted in `'strict'`/`'reject'` modes when a v0 ciphertext is presented.

### Container Format (v2)

[Container mode](#-container-mode-v2-envelope) is an **additive, separate** wire format — it reuses the 22-byte header shape but stamps version `0x02` and does **not** touch the v0/v1 text/file paths. It seals a payload under a two-layer key hierarchy (an Argon2id key-encryption key wraps a random data-encryption key), encrypts a confidential metadata block, and embeds the plaintext SHA-256 for an end-to-end integrity check. All three GCM segments are bound to the verbatim header AAD.

```text
[magic "HPCR": 4][version 0x02: 1][kdf-id 0x00 (Argon2id): 1][kdf-params: 16]   # 22-byte header (AAD)
[salt: 32]
[kekIv: 12][wrappedDek: 32][kekTag: 16]                        # random 32-byte DEK, AES-256-GCM-wrapped under the Argon2id KEK
[metaIv: 12][metaLen: 4 BE u32][encMeta: metaLen][metaTag: 16] # confidential metadata, encrypted under the DEK
[dataIv: 12][encData: variable][dataTag: 16]                   # payload, encrypted under the DEK
```

The `kdf-params` block is the same Argon2id layout as v1 (`[memoryCost u32BE][timeCost u32BE][parallelism u16BE][reserved 6×0x00]`); containers are always Argon2id. The `encMeta` segment decrypts (under the DEK) to a canonical serialization of `{ flags, size, sha256, filename?, mime? }` — the filename/mime bytes are present **only** inside this encrypted block and never in cleartext. After the payload decrypts, its SHA-256 (and length) are re-checked against the sealed-in values; a mismatch throws `CONTAINER_INTEGRITY_FAILED`. See [Container Mode](#-container-mode-v2-envelope) for the API and error codes.

## 🛡️ Security Features

### Cryptographic Security

- **AES-256-GCM**: Authenticated encryption with Galois/Counter Mode
- **Argon2id**: Memory-hard key derivation function (winner of Password Hashing Competition)
- **Secure Random**: Uses Node.js `crypto.randomBytes()` for all random generation
- **Constant-time Operations**: Secure string comparison to prevent timing attacks

### AES-GCM (key, IV) reuse — security boundary for the low-level API

> **WARNING.** The low-level `encryptData(data, key, iv)` / `decryptData(data, key, iv, tag)` methods place the IV-uniqueness obligation on the caller. AES-GCM is **catastrophically broken** if a `(key, iv)` pair is ever used to encrypt two different plaintexts — an observer can XOR the two ciphertexts to recover the XOR of the plaintexts (the keystream cancels), and additionally the GCM authentication subkey leaks, which lets the attacker forge authenticated ciphertexts under that key. The integrity guarantee is gone.
>
> When you call `encryptData` directly:
>
> - **Use a fresh random IV for every message.** Generate it with `cm.generateSecureRandom(12)` and never persist or reuse it under the same key.
> - **Cap each key at roughly `2 ** 32` invocations.** With random 96-bit IVs, collisions become non-negligible beyond this birthday bound (NIST SP 800-38D); rotate the key — for example, by re-deriving from a fresh per-message salt — well before then.
> - **Treat `encryptData` with a fixed `(key, iv)` as deterministic by design.** This is *not* a feature, it is a symptom of the attack surface above. The test `encryptData with reused (key, iv) is deterministic — security boundary documentation` in the test suite locks this property in as a guardrail.
>
> The high-level methods (`encryptText`/`encryptFile` and their `Sync` siblings) do **not** expose this footgun: they generate a fresh random IV per message AND derive a fresh key from a fresh per-message salt, so a `(key, iv)` collision across two messages is computationally negligible. Prefer the high-level API for any work that does not have a specific reason to manage IVs by hand.

### Memory Security

- **Secure Clearing**: Sensitive data is zeroed from memory after use
- **No Memory Leaks**: Proper cleanup of cryptographic materials
- **Buffer Management**: Safe handling of cryptographic buffers

### Input Validation

- **Path Sanitization**: Prevents path traversal attacks
- **Type Safety**: Full TypeScript support prevents type-related vulnerabilities
- **Parameter Validation**: Comprehensive input validation with detailed error messages

## 🔮 Post-Quantum Security

**Every byte this library encrypts is protected by cryptography that the world's leading standards bodies treat as quantum-resistant.** Not by accident — by design: the library is _symmetric-only_, and symmetric cryptography at 256-bit strength survives the quantum era.

Quantum computers threaten cryptography through two very different algorithms:

- **Shor's algorithm** completely breaks public-key cryptography — RSA, Diffie-Hellman, ECDH, ECDSA, all elliptic curves. This is the catastrophic, exponential break driving the global post-quantum migration. **This library contains zero public-key cryptography** — no key exchange, no signatures, no certificates — so there is nothing for Shor's algorithm to attack.
- **Grover's algorithm** yields only a _quadratic_ speedup against symmetric cryptography: a 256-bit key drops to roughly 128-bit effective strength — still far beyond any conceivable attack, and in practice even that figure is pessimistic for the attacker because Grover parallelizes poorly and is gate-depth limited. Every key, salt, and KDF output in this library is 256-bit.

The NIST post-quantum standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) replace **public-key** primitives only; NIST states explicitly that its symmetric standards are **not** part of the PQC transition. A symmetric-only library therefore needs **no post-quantum migration** — no algorithm swap, no format change, and nothing for consumers to update, ever, for quantum reasons.

This posture is **identical in the browser build.** The [isomorphic browser build](#-isomorphic-api--browser-support) uses the same symmetric primitives (AES-256-GCM, Argon2id, SHA-256) over the same wire format — Web Crypto and WebAssembly Argon2id are different *implementations* of the same algorithms, not different algorithms. The only cross-runtime difference is the Argon2id default *memory cost* (32 MiB in the browser vs 128 MiB in Node), which changes brute-force cost, not the post-quantum standing of any primitive.

### Primitive-by-primitive

| Primitive                          | Role                     | Post-quantum status                                                                                                                                                                                                              |
| ---------------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AES-256-GCM**                    | Authenticated encryption | NIST post-quantum security **Category 5** (the highest tier). NSA CNSA 2.0 retains AES-256 for National Security Systems **up to TOP SECRET** in the quantum era. BSI recommends 256-bit symmetric keys for long-term protection. |
| **Argon2id** (async KDF)           | Password → key           | Memory-hardness _survives_ quantum evaluation: peer-reviewed analysis shows the memory cost carries over into the reversible circuits Grover requires, making every quantum guess astronomically expensive.                       |
| **PBKDF2-HMAC-SHA256** (sync KDF)  | Password → key           | HMAC and KDF constructions are listed by NIST IR 8547 among the symmetric standards that will **not** be transitioned. 256-bit output ≈ 128-bit effective post-quantum strength.                                                  |
| **SHA-256** (utility)              | Hashing                  | 256-bit preimage strength = NIST post-quantum **Category 5**.                                                                                                                                                                     |
| **CSPRNG** (`crypto.randomBytes`)  | Salts, IVs               | OS-level SP 800-90A DRBGs reseeded from kernel entropy; quantum computing changes nothing structural about their security.                                                                                                        |

### The proofs

These are not marketing claims — each one traces to an official standards-body position or peer-reviewed result:

1. **NIST, Post-Quantum Cryptography FAQ** — Grover's algorithm "will provide little or no advantage in attacking AES", key lengths do not need to be doubled, and even AES-128 "will remain secure for decades to come". <https://csrc.nist.gov/projects/post-quantum-cryptography/faqs>
2. **NIST IR 8547, _Transition to Post-Quantum Cryptography Standards_** — symmetric standards (block ciphers, hash functions, HMAC, KDFs) are excluded from the PQC transition; AES-256 anchors security **Category 5**; the 2030/2035 deprecation timelines apply to RSA/ECC only. <https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf>
3. **NSA, Commercial National Security Algorithm Suite 2.0** — retains AES-256 as the symmetric cipher for National Security Systems up to TOP SECRET; only public-key algorithms are replaced (by ML-KEM / ML-DSA). <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>
4. **BSI TR-02102-1** (Germany's federal cyber-security agency) — the impact of quantum computers on symmetric mechanisms is far milder than on asymmetric ones; 256-bit keys are recommended for high or long-term protection needs. <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf>
5. **Amy, Di Matteo, Gheorghiu, Mosca, Parent & Schanck (SAC 2016)** — a fault-tolerant Grover preimage attack on SHA-256 costs ≈2^153.8 surface-code cycles of _depth_, vastly above the naive 2^128 query count, because Grover cannot be parallelized efficiently. <https://arxiv.org/abs/1603.09383>
6. **Blocki, Holman & Lee (TCC 2022)**, with the EUROCRYPT 2025 follow-up — memory-hard functions retain their cost inside the reversible circuits a quantum attacker must build; cheap memory-erasing classical strategies do not translate into cheap quantum circuits. <https://arxiv.org/abs/2110.04191>, <https://eprint.iacr.org/2024/334>
7. **Song, Eum, Kwon, Sim, Lee & Seo (2023)** — a concrete Grover-oracle quantum circuit for Argon2, quantifying the enormous qubit and depth cost of attacking a memory-hard KDF on quantum hardware. <https://eprint.iacr.org/2023/1150>
8. **Kaplan, Leurent, Leverrier & Naya-Plasencia (CRYPTO 2016)** — the only known "quantum break" of GCM (a Simon's-algorithm forgery) requires the attacker to query your _live keyed encryption device in quantum superposition_ (the "Q2" model) — a scenario that cannot arise against encrypted data at rest. Even within that model, GCM's _confidentiality_ core (CTR mode) remains provably secure. <https://arxiv.org/abs/1602.05973>

### The one honest caveat: the password is the battlefield

A quantum computer will not break AES-256 — it will try to guess your password. Grover's algorithm halves the effective entropy of a password search, so the _password_, not the cipher, is the residual quantum attack surface. Three design properties blunt that attack:

- Every ciphertext uses a fresh **32-byte random salt**, so an attacker cannot amortize one search across many ciphertexts — precomputation and batch attacks are dead on arrival.
- On the async path, every single guess must pay the full **Argon2id memory-hard evaluation** (128 MiB at the Node default profile; 32 MiB at the browser default) — which on quantum hardware must be built as a reversible circuit holding the entire memory array in logical qubits, an astronomical overhead (proofs 6-7 above).
- The sync PBKDF2 path is equally quantum-resistant at the primitive level, but it is not memory-hard — prefer the async (Argon2id) methods for long-lived, high-value data.

**Recommendation for "harvest now, decrypt later" threat models:** use the async (Argon2id) methods with a high-entropy passphrase — for example **8-10 randomly generated diceware words (≈103-129 bits of entropy)**. Even against an idealized Grover attacker that leaves ≈52-65 bits of _quantum-effective_ entropy where every guess costs a full memory-hard KDF evaluation — comfortably out of reach.

### Why there is no Kyber/Dilithium "hybrid mode"

Because it would be security theater. ML-KEM (Kyber) protects **key exchange**; ML-DSA (Dilithium) provides **digital signatures**. This library performs neither: keys are derived locally from your password, and nothing is ever negotiated over a wire or signed. There is no classical key exchange to hybridize and no signature scheme to upgrade. Bolting PQC primitives onto a symmetric-only design would add attack surface and dependencies without adding security.

### Crypto-agility, just in case

Every v1 ciphertext embeds its own KDF identifier and full KDF parameters in the [versioned header](#ciphertext-format-v1), so stronger defaults or an additional KDF can ship in a **minor release** while every old ciphertext remains decryptable forever — they are self-describing. The header's version byte (`0x01`) reserves a clean, well-defined escape hatch (`0x02`) for a cipher change if cryptographic guidance ever demands one; none is needed or foreseen. One layer is deliberately out of this library's hands: the distribution channel (npm provenance signatures, registry TLS) relies on the ecosystem's classical public-key infrastructure. That layer is npm's and Sigstore's to migrate, is a real-time integrity check rather than harvestable ciphertext, and has no bearing on the confidentiality of anything you encrypt.

The formal, audit-facing version of this posture lives in [SECURITY.md](SECURITY.md#post-quantum-posture).

## 🧪 Testing

Run the test suite:

```bash
npm test
```

Run tests with coverage:

```bash
npm run test:coverage
```

Run tests in watch mode:

```bash
npm run test:watch
```

The Node suite runs under Jest (`npm test`, aliased as `npm run test:node`). The **real-browser** suite runs under [Vitest Browser Mode](https://vitest.dev/guide/browser/) in headless Chromium — it imports the built browser entry and proves cross-runtime interop (a Node-produced ciphertext decrypts in a real browser):

```bash
npm run build          # the browser suite imports dist/index.browser.js
npm run test:browser   # headless Chromium via Playwright
```

Two static isolation gates back the browser build and run in CI on every push: `npm run check:browser` (an esbuild `platform:'browser'` bundle that fails on any `node:` specifier reaching the browser graph) and `npm run check:exports` (`publint` + `@arethetypeswrong/cli`).

## ⚡ Benchmarks

A [tinybench](https://github.com/tinylibs/tinybench)-driven benchmark suite lives in [`bench/`](bench/). It measures the four end-to-end paths that are most representative of real workloads — Argon2id and PBKDF2 key derivation, `encryptText` at 1 KiB and 1 MiB, and `encryptFile` / `decryptFile` streaming on a 10 MiB payload — against the compiled `dist/` output, so build first:

```bash
npm run build
npm run bench
```

The full suite takes roughly **2-5 minutes** on a modern laptop. Argon2id at the default 128 MiB / `t=3` / `p=1` profile dominates the wall time (each derivation takes ~150-300 ms), and every encrypt path performs one derivation per call. To run a single bench file in isolation:

```bash
node bench/kdf.mjs            # Argon2id + PBKDF2 only
node bench/encrypt-text.mjs   # 1 KiB and 1 MiB text encrypt
node bench/encrypt-file.mjs   # 10 MiB encrypt + decrypt streaming
```

Benchmarks are intentionally **not** wired into CI — the absolute numbers vary too much between hosted-runner generations to be useful as a regression check, and 128 MiB Argon2id is too slow for the matrix budget. See [`bench/README.md`](bench/README.md) for the full output format and per-case methodology notes.

## 🔍 Error Handling

The library uses custom error types for better error handling:

```typescript
import { CryptoError, CryptoErrorType } from '@hiprax/crypto';

try {
  await crypto.encryptText('', '');
} catch (error) {
  if (error instanceof CryptoError) {
    console.log('Error Type:', error.type);
    console.log('Error Code:', error.code);
    console.log('Message:', error.message);
  }
}
```

### Error Types

- `INVALID_PASSWORD`: Password-related errors
- `INVALID_INPUT`: Invalid input parameters
- `ENCRYPTION_FAILED`: Encryption operation failures
- `DECRYPTION_FAILED`: Decryption operation failures
- `FILE_ERROR`: File system errors
- `MEMORY_ERROR`: Memory-related errors
- `VALIDATION_ERROR`: Validation failures

`CryptoError.type` is one of the categories above; the more specific `CryptoError.code` string distinguishes individual failures. Notable codes beyond the format/parser codes above: `UNSUPPORTED_IN_BROWSER` (type `INVALID_INPUT`) — a Node-only method was called on the [browser build](#-isomorphic-api--browser-support); `ARGON2_NOT_AVAILABLE` (type `MEMORY_ERROR`) — no Argon2id provider is available (install `hash-wasm` or, in Node, native build tools); and the [container-mode codes](#container-error-codes) such as `CONTAINER_INTEGRITY_FAILED`.

## 📦 Development

### Building

```bash
npm run build
```

### Linting

```bash
npm run lint
npm run lint:fix
```

### Formatting

```bash
npm run format
```

### Type Checking

```bash
npm run type-check
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 🛡️ Threat Model

A cryptography library is only as useful as its honesty about what it does and does not protect against. The list below is descriptive, not aspirational — it documents the actual security boundary of this codebase. The companion [SECURITY.md](SECURITY.md) covers the disclosure policy and the formal in-scope / out-of-scope split for vulnerability reports; the section below is the engineering-level rationale.

### What this library defends against (in scope)

- **Confidentiality of plaintext** under a strong password, against a passive observer who captures the ciphertext at rest or in transit. Confidentiality is bounded by AES-256-GCM and the chosen KDF (Argon2id or PBKDF2-HMAC-SHA256 — see [Security Levels](#security-levels)).
- **Ciphertext indistinguishability under chosen-plaintext attack (IND-CPA).** Each encryption draws a fresh 32-byte salt and a fresh 96-bit IV from the OS CSPRNG, so two encryptions of the same plaintext under the same password are distinct ciphertexts and cannot be correlated by an observer who has seen previous outputs. AES-256-GCM's underlying CTR-mode keystream provides the standard IND-CPA guarantee.
- **Authenticity and integrity of ciphertext (including the v1 header).** AES-256-GCM produces a 128-bit authentication tag covering the salt, IV, ciphertext body, and AAD. As of v1.1.0 the AAD bound to v1 ciphertexts includes the configured AAD context string (`"secure-crypto-tool-v2"` by default) **concatenated with the verbatim 22 bytes of the v1 header** — so any single-bit modification to the ciphertext, salt, IV, header (including the reserved-byte regions inside the KDF parameter block), or AAD context causes `decrypt*` to fail with `DECRYPTION_FAILED` rather than return wrong plaintext. v0 (legacy) ciphertexts use just the AAD context string for AAD, since they have no header to bind. v1 ciphertexts produced by v1.0.0 (which pre-dates the header binding) can be decrypted by setting the constructor option `legacyHeaderAad: true` — see [Migration: v1.0.0 → v1.1.0](#migration-v100--v110) below.
- **DoS protection at the v1 header parser.** `parseHeader` enforces conservative upper bounds on the parsed KDF parameters: `memoryCost <= 2^22` (4 GiB), `timeCost <= 100`, `parallelism <= 64` for Argon2id; `iterations <= 10_000_000` for PBKDF2-SHA256. Out-of-range parameters surface as `CryptoError(INVALID_INPUT, 'KDF_PARAMS_OUT_OF_BOUNDS')` BEFORE any KDF work runs, so a malicious 100-byte ciphertext cannot pin gigabytes of RAM or block the event loop for minutes. The same caps apply to `inspectHeader` so tooling-facing introspection sees the same bounded values as decrypt.
- **Format integrity.** The v1 ciphertext header (`HPCR` magic + version + KDF id + KDF params) is parsed with explicit length checks and bounded numeric ranges; malformed input surfaces as `CryptoError` with a specific code (`TRUNCATED_HEADER`, `INVALID_HEADER_PARAM`, `KDF_PARAMS_OUT_OF_BOUNDS`, `UNSUPPORTED_VERSION`, etc.) rather than a crash, infinite loop, or out-of-bounds read. See [Ciphertext Format (v1)](#ciphertext-format-v1).
- **Path traversal in the file APIs (syntactic).** `validatePath` rejects null bytes, ASCII control characters (`< 0x20` or `0x7F`), Windows-illegal characters, and literal `..` segments after `path.normalize`. The optional `allowedRoot` option performs a segment-aware resolved-prefix containment check so within-drive cross-traversal (e.g. `C:\\Users\\..\\Windows` against `allowedRoot: 'C:\\Users'`) is caught even though `path.normalize` collapses the `..` to a clean string. `sanitizeFilename` neutralises literal `..` sequences and preserves the file extension when truncating to 255 chars.
- **Constant-time comparison primitives.** `secureStringCompare` uses `crypto.timingSafeEqual` so equal-length string compares do not leak bytewise differences via timing. (Length itself is leaked — see Out of Scope.)
- **Memory hygiene for buffer-resident secrets.** `secureClear` zeroes Buffer-backed allocations holding key material and plaintext after use, on a best-effort basis (see Out of Scope for the V8 caveat).

### What this library does NOT defend against (out of scope)

- **Rubber-hose cryptanalysis.** If the password is coerced out of the user, the library cannot help. Strong-password validation does not survive an attacker who can compel the user to reveal it.
- **Weak passwords.** Encryption is only as strong as the password. The library validates strength at encryption time (8-char composition rule OR ≥20-char passphrase rule — see [Password Requirements](#password-requirements)), but the caller is responsible for sourcing high-entropy inputs and protecting against credential reuse. A weak password makes Argon2id/PBKDF2 brute-force tractable regardless of the parameters.
- **Side-channel attacks beyond constant-time comparison.** The library uses `crypto.timingSafeEqual` for tag/string comparisons, but it does NOT defend against cache-timing, power-analysis, electromagnetic-emanation, or microarchitectural side channels in the underlying AES-256-GCM, Argon2id, or PBKDF2 implementations (which run in OpenSSL via Node.js's `crypto` module and the `argon2` native addon). Hardened deployments must rely on the host's mitigations (microcode, hypervisor isolation, etc.).
- **Low password entropy against a future quantum adversary.** The primitives themselves are quantum-resistant — the library contains no public-key cryptography for Shor's algorithm to break, and AES-256, Argon2id, and PBKDF2-HMAC-SHA256 retain ≥128-bit effective strength under Grover's algorithm per NIST, NSA CNSA 2.0, and BSI guidance (see [Post-Quantum Security](#-post-quantum-security) for the full posture and sources). What no cipher can fix is a weak password: Grover halves the effective entropy of the password search space, so a "harvest now, decrypt later" adversary with future quantum capability attacks the password, not AES-256. If that adversary is in your threat model, use the async (Argon2id) path with a high-entropy passphrase (e.g. 8-10 random diceware words, ≈103-129 bits). The deliberate absence of a Kyber/Dilithium hybrid mode is not a gap: those standards replace key exchange and signatures, and this library performs neither.
- **OS CSPRNG compromise.** All randomness (salt, IV, temp-file suffix) is sourced from `crypto.randomBytes`/`crypto.randomUUID`, which delegate to the host OS's CSPRNG (`getrandom(2)` on Linux, `BCryptGenRandom` on Windows, `SecRandomCopyBytes` on macOS). If the OS RNG is backdoored, virtualised onto a deterministic shim, or seeded with insufficient entropy at boot, the library inherits that compromise — IVs may collide, salts may be predictable, and the IND-CPA guarantee degrades. Detecting OS-level RNG compromise is outside the library's scope.
- **String-copy memory leaks via V8.** `secureClear` zeroes the underlying `ArrayBuffer` slab of a Buffer, but V8 may have already created internal string copies of password or plaintext data for hashing, interning, or deoptimisation paths. Those copies are unreachable to `Buffer.fill(0)` and live until garbage collection. Treat `secureClear` as defence-in-depth, not as a forensic-grade wipe. The same caveat applies — more directly, by deliberate retention rather than incidental V8 behaviour — to `CryptoManager` instances configured with `defaultPassphrase`: the library stores the passphrase as a regular V8 string for the manager's lifetime and cannot scrub it. For sensitive workloads, pass the password explicitly to each `encrypt*` / `decrypt*` call instead of configuring `defaultPassphrase`. See [Password Requirements](#password-requirements) for the full retention discussion.
- **Symlink-based path traversal.** `validatePath` is a syntactic check; it does not call `fs.realpath` and does not prevent a path like `/safe/dir/symlinkToEtc` from escaping via the symlink. Callers that need symlink-safe path validation must perform their own `realpath`-based check or operate inside a chroot/sandbox.
- **Length leaks in comparison.** `secureStringCompare` only protects against bytewise timing differences within an equal-length compare. The lengths of the inputs are leaked via the early-return-on-length-mismatch path. For comparing values where length itself is sensitive, hash both sides first.
- **Denial of service via legitimate-input resource exhaustion.** A caller that asks the library to encrypt a 100 GiB file will see 100 GiB of disk and memory pressure on the streaming write — that is a workload property, not a vulnerability. Argon2id at the default `memoryCost: 2^17` allocates 128 MiB per derivation; an attacker who can trigger many concurrent derivations against a single host can DoS it. Rate-limiting and resource sandboxing are caller responsibilities. Note: DoS *via maliciously-crafted ciphertext headers* (asking the parser to honour a `memoryCost = 4 GiB` or `iterations = 100M`) is **in scope** and is rejected with `KDF_PARAMS_OUT_OF_BOUNDS` before any KDF work runs — see "What this library defends against" above.

### Reporting

For the formal vulnerability disclosure policy, scope rules, supported-versions table, and contact channels, see [SECURITY.md](SECURITY.md).

## 📜 Changelog

Release notes for every version live in [CHANGELOG.md](CHANGELOG.md). The CHANGELOG is bundled into the published npm tarball, so it is also available offline at `node_modules/@hiprax/crypto/CHANGELOG.md` after install.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/@hiprax/crypto)
- [GitHub Repository](https://github.com/Hiprax/crypto)
- [Issue Tracker](https://github.com/Hiprax/crypto/issues)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)

## ⚠️ Security Notice

This library is designed for security but should be used as part of a comprehensive security strategy. Always:

- Use strong, unique passwords
- Keep your dependencies updated
- Follow security best practices
- Consider additional security measures for critical applications

For the full security policy — including the [Threat Model](#-threat-model) section above for what is and isn't in scope — see [SECURITY.md](SECURITY.md).

### Reporting a Vulnerability

If you believe you have found a security issue in `@hiprax/crypto`, **please do not file a public issue**. Read [SECURITY.md](SECURITY.md) for the full disclosure policy and report the issue privately via [GitHub Security Advisories](https://github.com/Hiprax/crypto/security/advisories/new) or by emailing `security@hiprax.dev`. Initial acknowledgements are sent within 72 hours.

## 🆘 Support

For support, please:

1. Check the [documentation](https://github.com/Hiprax/crypto#readme)
2. Search [existing issues](https://github.com/Hiprax/crypto/issues)
3. Create a new issue if needed

---

**Made with ❤️ for secure applications**
