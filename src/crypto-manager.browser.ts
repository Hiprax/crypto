/**
 * Browser build of the @hiprax/crypto `CryptoManager`.
 *
 * This is the browser-facing counterpart of the Node `CryptoManager`
 * (`./crypto-manager.js`). Both `extends CryptoCore`; the shared, isomorphic
 * surface — the in-memory async API (`encryptBytes`/`decryptBytes`/
 * `encryptText`/`decryptText`), `inspectHeader`, `validatePassword`,
 * `getParameters`, `getSecurityLevel`, `secureClear`, and the full constructor
 * option-validation — lives entirely on {@link CryptoCore} and behaves
 * identically here. The ONLY differences from the Node build are:
 *
 *  1. **Engine.** This class injects the {@link webEngine} (SubtleCrypto +
 *     hash-wasm Argon2id) instead of the Node engine, so its import graph
 *     contains ZERO `node:` builtins and references NO Node global (`Buffer`,
 *     `process`). That is what lets a bundler ship it to the browser without
 *     dragging in `node:crypto`/`node:fs`/`node:stream`.
 *
 *  2. **Default Argon2id cost.** The browser default is a lighter 32 MiB
 *     profile (see {@link BROWSER_ARGON2_PROFILE}) rather than the Node
 *     128 MiB HIGH tier, to avoid OOM on memory-constrained mobile browsers.
 *     The wire format is unchanged — each ciphertext embeds the exact KDF
 *     params it was produced with — so a browser-produced ciphertext decrypts
 *     in Node and vice-versa.
 *
 *  3. **Node-only methods throw.** The `Buffer`-typed low-level primitives,
 *     the synchronous (PBKDF2) paths, and the file/streaming paths cannot be
 *     expressed with one-shot, async Web Crypto, so they are present as
 *     throwing stubs that raise `CryptoError(INVALID_INPUT,
 *     'UNSUPPORTED_IN_BROWSER')` pointing callers at the in-memory API.
 *
 * **Isomorphic-file rule (enforced by ESLint `no-restricted-globals` /
 * `no-restricted-imports`):** this file must never touch `Buffer`/`process`
 * or import any `node:*` builtin. It stays on `Uint8Array` and the shared pure
 * modules so the browser bundle can include it.
 */

import type { CryptoManagerOptions, ProgressCallback } from './types.js';
import { CryptoError, CryptoErrorType } from './types.js';
import { CryptoCore, SECURITY_THRESHOLDS, isValidPassword } from './core.js';
import { webEngine } from './engine.web.js';

// Re-export the shared threshold table and the pure password validator so
// browser consumers importing from this module (and, transitively, from
// `./index.browser.js`) see the same surface the Node build exposes from
// `./crypto-manager.js`.
export { SECURITY_THRESHOLDS, isValidPassword };

// The v2 container version byte, mirroring the identical re-export in
// `./crypto-manager.js`. `encryptContainer` is part of the isomorphic core, so
// the browser produces v2 blobs too and must be able to name their version;
// keeping the two managers symmetrical is what stops the constant from
// reaching only half the audience. Value only (a `number`), so it adds nothing
// Node-typed to the browser declaration graph.
export { CONTAINER_VERSION } from './core.js';

/**
 * Browser default Argon2id cost profile: 32 MiB (`memoryCost = 2 ** 15`) /
 * `timeCost = 3` / `parallelism = 1`.
 *
 * Chosen lighter than the Node 128 MiB HIGH default so that decrypting a
 * self-produced ciphertext (which allocates exactly the embedded `memoryCost`)
 * stays well within the WASM memory ceilings of memory-constrained mobile
 * browsers, while remaining comfortably above the OWASP 2025/2026 Argon2id
 * minimum of 19 MiB. Classified as `MEDIUM` by {@link CryptoCore.getSecurityLevel}
 * (32 MiB is below the `HIGH` 128 MiB threshold). This is a runtime-specific
 * DEFAULT, not a format change — callers may still pass an explicit
 * `memoryCost`, and every ciphertext carries its own KDF params on the wire.
 */
const BROWSER_ARGON2_PROFILE = {
  memoryCost: 2 ** 15, // 32 MiB
  timeCost: 3,
  parallelism: 1,
} as const;

/**
 * Isomorphic (`Uint8Array`-based) counterpart of the Node `EncryptionResult`
 * (`{ encrypted: Buffer; tag: Buffer }`). Used only as the declared return type
 * of the {@link CryptoManager.encryptData} throwing stub. Declared LOCALLY with
 * `Uint8Array` — rather than importing the Node `EncryptionResult` — so this
 * browser file (and its emitted `.d.ts`) never names the Node-only `Buffer`
 * type. The method always throws, so the shape is purely documentary and every
 * stub keeps a `Buffer`-free signature.
 */
type BrowserEncryptionResult = { encrypted: Uint8Array; tag: Uint8Array };

/**
 * Browser high-security encryption manager. Provides the isomorphic async
 * in-memory API (inherited from {@link CryptoCore}) over Web Crypto +
 * hash-wasm; the Node-only file/stream/sync/`Buffer`-typed methods throw
 * {@link CryptoError} `UNSUPPORTED_IN_BROWSER`.
 */
export class CryptoManager extends CryptoCore {
  /**
   * Construct a browser `CryptoManager`. All option validation and the shared
   * isomorphic API live in {@link CryptoCore}; this constructor only injects
   * the {@link webEngine} and the browser default Argon2id profile
   * ({@link BROWSER_ARGON2_PROFILE} — 32 MiB / t=3 / p=1).
   *
   * @param options - see {@link CryptoManagerOptions}
   */
  constructor(options: CryptoManagerOptions = {}) {
    super(options, webEngine, {
      memoryCost: BROWSER_ARGON2_PROFILE.memoryCost,
      timeCost: BROWSER_ARGON2_PROFILE.timeCost,
      parallelism: BROWSER_ARGON2_PROFILE.parallelism,
    });
  }

  /**
   * Shared throw for every Node-only method that the browser build cannot
   * implement. Raises `CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER')`
   * with an actionable message pointing at the in-memory async API. Returns
   * `never`, so a caller stub needs no `return` and its declared return type
   * is satisfied.
   *
   * @param method - the name of the unavailable method (for the message)
   */
  private unsupportedInBrowser(method: string): never {
    throw new CryptoError(
      `${method}() is not available in the browser build of @hiprax/crypto. ` +
        'The browser build exposes only the async, in-memory API — use ' +
        'encryptBytes / decryptBytes (or encryptText / decryptText) instead. ' +
        'File, streaming, synchronous (PBKDF2), and Buffer-typed low-level ' +
        'operations require the Node build (the "node" export condition).',
      CryptoErrorType.INVALID_INPUT,
      'UNSUPPORTED_IN_BROWSER'
    );
  }

  // ---------------------------------------------------------------------------
  // Node-only methods — throwing stubs.
  //
  // These mirror the Node `CryptoManager` API shape so tooling and readers see
  // the same surface, but they cannot be implemented with one-shot, async Web
  // Crypto (no synchronous KDF, no streaming AES-GCM, no `Buffer`). Each raises
  // `CryptoError(INVALID_INPUT, 'UNSUPPORTED_IN_BROWSER')` via the shared
  // `unsupportedInBrowser` helper, matching its Node counterpart's call
  // contract: the synchronous methods throw synchronously, and the `async`
  // methods (`deriveKey`, `encryptFile`, `decryptFile`) REJECT — so a caller's
  // `try/await/catch` OR `.catch()` handles the failure exactly as it would
  // against the Node build (a synchronous throw would slip past a `.catch()`).
  // Parameters are intentionally unused (`_`-prefixed).
  // ---------------------------------------------------------------------------

  /** Node-only. Throws `UNSUPPORTED_IN_BROWSER`; use the in-memory API. */
  public generateSecureRandom(_length: number): Uint8Array {
    this.unsupportedInBrowser('generateSecureRandom');
  }

  /** Node-only. Rejects with `UNSUPPORTED_IN_BROWSER`; use `encryptBytes`/`decryptBytes`. */
  public async deriveKey(
    _password: string,
    _salt: Uint8Array,
    _overrides?: { memoryCost: number; timeCost: number; parallelism: number }
  ): Promise<Uint8Array> {
    this.unsupportedInBrowser('deriveKey');
  }

  /** Node-only (sync/PBKDF2). Throws `UNSUPPORTED_IN_BROWSER`. */
  public deriveKeySync(
    _password: string,
    _salt: Uint8Array,
    _iterations?: number
  ): Uint8Array {
    this.unsupportedInBrowser('deriveKeySync');
  }

  /** Node-only (Buffer-typed low-level). Throws `UNSUPPORTED_IN_BROWSER`. */
  public encryptData(
    _data: Uint8Array,
    _key: Uint8Array,
    _iv: Uint8Array,
    _aadOverride?: Uint8Array
  ): BrowserEncryptionResult {
    this.unsupportedInBrowser('encryptData');
  }

  /** Node-only (Buffer-typed low-level). Throws `UNSUPPORTED_IN_BROWSER`. */
  public decryptData(
    _encryptedData: Uint8Array,
    _key: Uint8Array,
    _iv: Uint8Array,
    _tag: Uint8Array,
    _aadOverride?: Uint8Array
  ): Uint8Array {
    this.unsupportedInBrowser('decryptData');
  }

  /** Node-only (sync/PBKDF2). Throws `UNSUPPORTED_IN_BROWSER`; use `encryptText`. */
  public encryptTextSync(_text: string, _password?: string): string {
    this.unsupportedInBrowser('encryptTextSync');
  }

  /** Node-only (sync/PBKDF2). Throws `UNSUPPORTED_IN_BROWSER`; use `decryptText`. */
  public decryptTextSync(_encryptedText: string, _password?: string): string {
    this.unsupportedInBrowser('decryptTextSync');
  }

  /** Node-only (streaming file I/O). Rejects with `UNSUPPORTED_IN_BROWSER`. */
  public async encryptFile(
    _inputPath: string,
    _outputPath: string,
    _password?: string,
    _progress?: ProgressCallback
  ): Promise<void> {
    this.unsupportedInBrowser('encryptFile');
  }

  /** Node-only (streaming file I/O). Rejects with `UNSUPPORTED_IN_BROWSER`. */
  public async decryptFile(
    _inputPath: string,
    _outputPath: string,
    _password?: string,
    _progress?: ProgressCallback
  ): Promise<void> {
    this.unsupportedInBrowser('decryptFile');
  }

  /** Node-only (chunked sync file I/O). Throws `UNSUPPORTED_IN_BROWSER`. */
  public encryptFileSync(
    _inputPath: string,
    _outputPath: string,
    _password?: string,
    _progress?: ProgressCallback
  ): void {
    this.unsupportedInBrowser('encryptFileSync');
  }

  /** Node-only (chunked sync file I/O). Throws `UNSUPPORTED_IN_BROWSER`. */
  public decryptFileSync(
    _inputPath: string,
    _outputPath: string,
    _password?: string,
    _progress?: ProgressCallback
  ): void {
    this.unsupportedInBrowser('decryptFileSync');
  }
}

// Default export mirrors `./crypto-manager.js` (Node) so the browser entry can
// re-export both the named and default `CryptoManager`.
export default CryptoManager;
