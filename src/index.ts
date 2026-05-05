// Main entry point for the secure-crypto package
export {
  CryptoManager,
  SECURITY_THRESHOLDS,
  isValidPassword,
} from './crypto-manager.js';
export * from './utils.js';
export * from './types.js';
export * from './format.js';

// Default export
import { CryptoManager } from './crypto-manager.js';
export default CryptoManager;
