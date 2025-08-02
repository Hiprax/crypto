# Crypto

🔐 **High-security encryption/decryption library** using AES-256-GCM and Argon2id for Node.js applications with full TypeScript support.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)

## ✨ Features

- 🔐 **AES-256-GCM** authenticated encryption
- 🔑 **Argon2id** memory-hard key derivation
- 📁 **File streaming** for large files
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

## 🚀 Quick Start

### Basic Usage

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

### File Encryption

```typescript
import { CryptoManager } from '@hiprax/crypto';

const crypto = new CryptoManager();

// Encrypt file
await crypto.encryptFile('input.txt', 'output.enc', 'MySecureP@ssw0rd123!');

// Decrypt file
await crypto.decryptFile('output.enc', 'decrypted.txt', 'MySecureP@ssw0rd123!');
```

### File Encryption with Default Passphrase

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

### Custom Configuration

```typescript
import { CryptoManager } from '@hiprax/crypto';

const crypto = new CryptoManager({
  memoryCost: 2 ** 18, // 256MB (ultra security)
  timeCost: 4, // Higher time cost
  parallelism: 2, // Use 2 threads
  aad: 'my-app-v1', // Custom AAD
});

console.log('Security Level:', crypto.getSecurityLevel()); // 'ultra'
```

## 📚 API Reference

### CryptoManager

The main class for encryption/decryption operations.

#### Constructor

```typescript
const crypto = new CryptoManager(options?: CryptoManagerOptions);
```

**Options:**

- `memoryCost` (number): Argon2 memory cost (default: 65536)
- `timeCost` (number): Argon2 time cost (default: 3)
- `parallelism` (number): Argon2 parallelism (default: 1)
- `aad` (string): Custom Additional Authenticated Data (default: 'secure-crypto-tool-v2')
- `defaultPassphrase` (string): Default passphrase to use when no password is provided to encryption/decryption methods

#### Methods

##### `encryptText(text: string, password?: string): Promise<string>`

Encrypts text with a password. If no password is provided and a default passphrase is set, the default passphrase will be used.

```typescript
const encrypted = await crypto.encryptText(
  'Hello World',
  'MySecureP@ssw0rd123!'
);
// Returns: base64 encoded string

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

##### `encryptFile(inputPath: string, outputPath: string, password?: string, progressCallback?: ProgressCallback): Promise<void>`

Encrypts a file with a password. If no password is provided and a default passphrase is set, the default passphrase will be used.

```typescript
await crypto.encryptFile('input.txt', 'output.enc', 'MySecureP@ssw0rd123!');

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
await crypto.encryptFile('input.txt', 'output.enc');
```

##### `decryptFile(inputPath: string, outputPath: string, password?: string, progressCallback?: ProgressCallback): Promise<void>`

Decrypts a file with a password. If no password is provided and a default passphrase is set, the default passphrase will be used.

```typescript
await crypto.decryptFile('output.enc', 'decrypted.txt', 'MySecureP@ssw0rd123!');

// With default passphrase
const crypto = new CryptoManager({ defaultPassphrase: 'MySecureP@ssw0rd123!' });
await crypto.decryptFile('output.enc', 'decrypted.txt');
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
  isTextFile,
  sanitizeFilename,
  createBackupPath,
  isValidBase64,
  createProgressBar,
  sleep,
  retryWithBackoff,
  getFileInfo,
} from '@hiprax/crypto';

// Validate if file exists and is accessible
const fileValidation = await validateFile('path/to/file.txt');

// Validate if path is valid for writing
const pathValidation = validatePath('path/to/output.txt');

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

// Check if file is text file
const isText = isTextFile('document.txt');

// Sanitize filename
const safeName = sanitizeFilename('file<name>.txt'); // "file_name_.txt"

// Create backup path
const backupPath = createBackupPath('file.txt'); // "file_2024-01-01T12-00-00.backup.txt"

// Validate base64
const isValid = isValidBase64('SGVsbG8gV29ybGQ=');

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

### Security Levels

The library supports different security levels based on Argon2 parameters:

- **Low**: `memoryCost: 2^12, timeCost: 1` (Fast, less secure)
- **Medium**: `memoryCost: 2^14, timeCost: 2` (Balanced)
- **High**: `memoryCost: 2^16, timeCost: 3` (Default, secure)
- **Ultra**: `memoryCost: 2^18, timeCost: 4` (Maximum security)

### Password Requirements

Passwords must meet the following criteria:

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

## 🛡️ Security Features

### Cryptographic Security

- **AES-256-GCM**: Authenticated encryption with Galois/Counter Mode
- **Argon2id**: Memory-hard key derivation function (winner of Password Hashing Competition)
- **Secure Random**: Uses Node.js `crypto.randomBytes()` for all random generation
- **Constant-time Operations**: Secure string comparison to prevent timing attacks

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

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/@hiprax/crypto)
- [GitHub Repository](https://github.com/Hiprax/crypto)
- [Issue Tracker](https://github.com/Hiprax/crypto/issues)

## ⚠️ Security Notice

This library is designed for security but should be used as part of a comprehensive security strategy. Always:

- Use strong, unique passwords
- Keep your dependencies updated
- Follow security best practices
- Consider additional security measures for critical applications

## 🆘 Support

For support, please:

1. Check the [documentation](https://github.com/Hiprax/crypto#readme)
2. Search [existing issues](https://github.com/Hiprax/crypto/issues)
3. Create a new issue if needed

---

**Made with ❤️ for secure applications**
