/**
 * Browser entry point for @hiprax/crypto.
 *
 * The conditional `exports` map (added in Phase 7) points the `browser`
 * condition at the compiled form of this module, so bundlers (webpack, Vite/
 * Rollup, esbuild, Next.js) resolve `@hiprax/crypto` here while Node resolves
 * `./index.js`. It mirrors `./index.ts` with three deliberate differences that
 * keep the browser graph free of any `node:` builtin and any `Buffer` global:
 *
 *  1. **Browser `CryptoManager`.** Re-exports the {@link CryptoManager} from
 *     `./crypto-manager.browser.js` (Web engine, 32 MiB Argon2id default,
 *     Node-only methods throwing `UNSUPPORTED_IN_BROWSER`) instead of the Node
 *     class.
 *  2. **Pure format layer.** Re-exports `./format-core.js` (the
 *     `Uint8Array`/`DataView` module) instead of `./format.js`, whose thin
 *     Node wrapper returns `Buffer`s and references the `Buffer` global.
 *  3. **No file utilities.** Omits `./utils.js` entirely — it is Node-only
 *     (`node:fs`/`node:path`) and has no meaning in the browser.
 *
 * The header constants/types (`HEADER_LENGTH`, `parseHeader`, `packHeader`,
 * `ParsedHeader`, the KDF/DoS caps, …) still reach browser consumers via the
 * `./format-core.js` re-export, and the base64url/hex/UTF-8 codecs via
 * `./codec.js`, so the browser surface is the full isomorphic API minus the
 * Node-only file helpers.
 */

export {
  CryptoManager,
  SECURITY_THRESHOLDS,
  isValidPassword,
  // v2 container version byte (0x02), mirroring `./index.ts`. `FORMAT_VERSION`
  // (0x01) arrives below via `./format-core.js`; this is its container-format
  // counterpart. Container mode lives on the isomorphic core, so the browser
  // build produces v2 blobs and must be able to name their version too.
  CONTAINER_VERSION,
} from './crypto-manager.browser.js';
export * from './types.js';
export * from './format-core.js';
export * from './codec.js';

// Default export mirrors `./index.ts`.
import { CryptoManager } from './crypto-manager.browser.js';
export default CryptoManager;
