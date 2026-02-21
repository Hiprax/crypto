# Changelog

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
