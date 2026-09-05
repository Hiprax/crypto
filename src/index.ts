// Main entry point for the secure-crypto package
export {
  CryptoManager,
  SECURITY_THRESHOLDS,
  isValidPassword,
  // v2 container version byte (0x02). `FORMAT_VERSION` (0x01) arrives below via
  // `./format.js`; this is its container-format counterpart, so a consumer can
  // classify a blob by name rather than by a magic number. Sourced from
  // `./crypto-manager.js` (which pass-throughs it from `./core.js`) to keep
  // this entry and `./index.browser.ts` structurally identical.
  CONTAINER_VERSION,
} from './crypto-manager.js';
// `EncryptionResult` moved out of `./types.js` into the Node-only
// `./crypto-manager.js` because it names the `Buffer` global and `./types.js`
// is re-exported by the browser entry. Re-exported here so
// `import type { EncryptionResult } from '@hiprax/crypto'` keeps working.
// It MUST be its own `export type` statement: `verbatimModuleSyntax` rejects a
// type placed in the value-export block above.
export type { EncryptionResult } from './crypto-manager.js';
export * from './utils.js';
export * from './types.js';
export * from './format.js';
export * from './codec.js';

// Default export
import { CryptoManager } from './crypto-manager.js';
export default CryptoManager;
