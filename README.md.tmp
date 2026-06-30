# Crypto

🔐 **High-security encryption/decryption library** using AES-256-GCM and Argon2id for Node.js applications with full TypeScript support.

[![CI](https://github.com/Hiprax/crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/Hiprax/crypto/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Hiprax/crypto/branch/main/graph/badge.svg)](https://codecov.io/gh/Hiprax/crypto)
[![CodeQL](https://github.com/Hiprax/crypto/actions/workflows/codeql.yml/badge.svg)](https://github.com/Hiprax/crypto/actions/workflows/codeql.yml)
[![npm provenance](https://img.shields.io/badge/npm-provenance-brightgreen?logo=npm&logoColor=white)](https://www.npmjs.com/package/@hiprax/crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://img.shields.io/npm/v/@hiprax/crypto)](https://www.npmjs.com/package/@hiprax/crypto)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green.svg)](https://nodejs.org/)

## ✨ Features

- 🔐 **AES-256-GCM** authenticated encryption
- 🔑 **Argon2id** memory-hard key derivation
- 📁 **Streaming file encryption AND decryption** (bounded memory regardless of file size) with atomic temp-file output
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

This package is **ESM-only** (`"type": "module"`). It is not shipped with a CommonJS build because Node.js 18+ ESM consumers can use it directly via `import`, and CJS consumers can still load it via dynamic `import()`. See the [CommonJS interop](#commonjs-interop) section below.

### Argon2 native dependency (optional, with WASM fallback)

The async key-derivation paths (`encryptText`, `decryptText`, `encryptFile`, `decryptFile`, `deriveKey`) use Argon2id — the gold standard for password hashing. Two providers are supported and tried in order:

1. **Native [`argon2`](https://www.npmjs.com/package/argon2)** — fastest, but requires a working C++ toolchain (Python + node-gyp) at install time on platforms without a prebuilt binary.
2. **WASM [`hash-wasm`](https://www.npmjs.com/package/hash-wasm)** — pure WebAssembly, zero native deps, works everywhere Node.js runs. Roughly 2-3× slower than native at the default 128 MiB profile, but the same RFC 9106 Argon2id reference, so the derived keys are bit-identical between providers and v1 ciphertexts produced by either round-trip across both.

Both packages are declared as **optional dependencies**. The library tries native first (highest performance) and transparently falls back to WASM if native is unavailable. If BOTH are unavailable, async encryption throws `CryptoError(MEMORY_ERROR, 'ARGON2_NOT_AVAILABLE')` with the message:

> `argon2 native module unavailable. Install build tools (Python + node-gyp) or install the optional 'hash-wasm' package for a pure-WASM Argon2id fallback (slower than native but works everywhere). Alternatively, use *Sync methods (PBKDF2).`

To recover from a "both unavailable" error, do any of:

1. Install build tools and reinstall so `argon2`'s `node-gyp` step succeeds (best performance), **or**
2. Install `hash-wasm` explicitly: `npm install hash-wasm` (no build tools needed; transparent fallback once installed), **or**
3. Use the synchronous methods (`encryptTextSync`, `decryptTextSync`, `encryptFileSync`, `decryptFileSync`, `deriveKeySync`) which use PBKDF2-HMAC-SHA256 and have no native-module dependency. Note that PBKDF2 is materially weaker than Argon2id against GPU/ASIC adversaries — prefer (1) or (2) for new ciphertexts.

Note: a successful first load is cached for the lifetime of the process (subsequent async calls reuse the same provider). A failed first load is NOT cached — the next caller retries from scratch, so transient failures (e.g. a temporary FS permission glitch on Windows during a build-tool install) can recover within the same process.

### CommonJS interop

`@hiprax/crypto` is ESM-only. The `package.json` `exports` map intentionally has no `require` entry so that CommonJS consumers receive a clear `ERR_REQUIRE_ESM` from Node rather than a confusing partial namespace. To use the library from a CommonJS file, use a dynamic `import()`:

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

Synchronous version of file encryption. Uses PBKDF2 for key derivation instead of Argon2id for synchronous operation. Like the async path, output is staged to a sibling temp file and atomically renamed to `outputPath` only on success; pre-existing files at `outputPath` are preserved on error. The optional `progress` callback fires twice — once before encryption (`0/totalBytes`) and once after the rename succeeds (`totalBytes/totalBytes`) — because the sync encrypt path reads the entire input in a single `readFileSync` call. See [Progress callbacks for file ops](#progress-callbacks-for-file-ops).

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

##### `secureClear(buffer: Buffer): void`

Securely zeroes a buffer to remove sensitive data from memory.

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
const randomString = generateRandomString(32);

// Validate password strength with detailed feedback
const passwordCheck = validatePasswordStrength('MyPassword123!');
console.log('Score:', passwordCheck.score); // 0-5
console.log('Feedback:', passwordCheck.feedback); // Array of suggestions

// Generate UUID
const uuid = generateUUID();

// Hash string with SHA-256
const hash = sha256('hello world');

// Generate random hex string
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
const backupPath = createBackupPath('file.txt'); // "file_2024-01-01T12-00-00.backup.txt"

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
| `encryptFileSync`  | `(0, totalBytes)`   | _none_ — sync reads in one go | `(totalBytes, totalBytes)`     | input file size (plaintext bytes) |
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
2. **`parseHeader` rejects pathologically-large KDF parameters** with `KDF_PARAMS_OUT_OF_BOUNDS` BEFORE invoking the KDF. Pre-fix, a malicious 100-byte ciphertext could request `memoryCost = 4 GiB` or `iterations = 100M` and pin the host for seconds-to-minutes. Caps: Argon2id `memoryCost <= 2^22` (4 GiB), `timeCost <= 100`, `parallelism <= 64`; PBKDF2 `iterations <= 10_000_000`.

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
- **Post-quantum security.** AES-256-GCM, Argon2id, and PBKDF2-HMAC-SHA256 are not post-quantum primitives. AES-256 retains a useful security margin against Grover's algorithm (effective ~128-bit security), but symmetric KDFs derived from low-entropy passwords offer no quantum-resistance gain. There is no Kyber/Dilithium hybrid mode in this library; if your threat model includes a "harvest now, decrypt later" adversary with future quantum capability, this library is not sufficient on its own.
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
