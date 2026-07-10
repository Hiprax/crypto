/**
 * Runtime-agnostic cryptographic engine contract for @hiprax/crypto.
 *
 * This module is PURE and TYPE-ONLY: it declares nothing but an interface and
 * therefore references no Node global, no Node builtin, and no `Buffer`. The
 * shared (isomorphic) core depends only on this interface; each runtime
 * supplies a concrete implementation — `engine.node.ts` (`nodeEngine`, via
 * `node:crypto`) for Node and `engine.web.ts` (`webEngine`, via SubtleCrypto +
 * hash-wasm) for the browser. Localising every runtime-specific quirk behind
 * this one seam is what lets a single wire format round-trip across Node and
 * the browser byte-for-byte.
 *
 * Two contract points are deliberate and MUST hold identically in every
 * implementation:
 *
 *  1. **The GCM authentication tag is returned SEPARATELY.** `aeadEncrypt`
 *     yields `{ ciphertext, tag }` as two distinct byte arrays, and
 *     `aeadDecrypt` takes the tag as a distinct argument. This matches Node's
 *     `getAuthTag()` / `setAuthTag()` shape directly. The Web Crypto engine —
 *     whose `subtle.encrypt`/`subtle.decrypt` use the "tag appended to
 *     ciphertext" (`C‖T`) convention — hides that splice/join internally so
 *     the shared core assembles the wire format the same way for both
 *     runtimes.
 *
 *  2. **Password NFC normalisation is the CALLER's responsibility.** The core
 *     normalises the password to Unicode NFC before calling
 *     {@link CryptoEngine.deriveArgon2id}; the engine hashes the exact string
 *     it is handed. This mirrors the existing `deriveKey`/`deriveKeySync`
 *     behaviour (which normalise once, at the call site) and keeps
 *     normalisation from being duplicated — or, worse, diverging — across the
 *     Node and Web engines.
 */

/**
 * The minimal set of primitive cryptographic operations the shared core needs.
 *
 * Every method takes and returns plain `Uint8Array` byte arrays (no `Buffer`),
 * so the interface is identical in Node and the browser.
 */
export interface CryptoEngine {
  /**
   * Return `length` cryptographically secure random bytes.
   *
   * Synchronous in both runtimes (Node `crypto.randomBytes`,
   * browser `crypto.getRandomValues`).
   *
   * @param length - number of random bytes to produce
   * @returns a fresh `Uint8Array` of exactly `length` random bytes
   */
  randomBytes(length: number): Uint8Array;

  /**
   * Derive a raw Argon2id key of `params.hashLength` bytes.
   *
   * The caller MUST have already NFC-normalised `password` (see the module
   * contract note). `salt` is used verbatim. Both the Node and Web engines
   * implement RFC 9106 Argon2id and produce bit-identical output for the same
   * `(password, salt, memoryCost, timeCost, parallelism, hashLength)` tuple, so
   * a ciphertext derived under one engine decrypts under the other.
   *
   * @param password - the (already NFC-normalised) password string
   * @param salt - the raw salt bytes
   * @param params - Argon2id cost parameters and desired output length
   * @returns the raw derived key bytes (length === `params.hashLength`)
   */
  deriveArgon2id(
    password: string,
    salt: Uint8Array,
    params: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
      hashLength: number;
    }
  ): Promise<Uint8Array>;

  /**
   * Encrypt `plaintext` with AES-256-GCM.
   *
   * The 16-byte authentication tag is returned SEPARATELY from the ciphertext
   * (see the module contract note) so the shared core can lay out the wire
   * format identically across runtimes.
   *
   * @param key - 32-byte AES-256 key
   * @param iv - 12-byte GCM nonce (must be unique per key)
   * @param plaintext - data to encrypt
   * @param aad - Additional Authenticated Data bound to the tag
   * @returns the ciphertext and the 16-byte tag as distinct byte arrays
   */
  aeadEncrypt(
    key: Uint8Array,
    iv: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }>;

  /**
   * Decrypt `ciphertext` with AES-256-GCM and verify the tag.
   *
   * Any authentication failure (wrong key/IV/AAD, tampered ciphertext, or a
   * mismatched tag) throws `CryptoError(DECRYPTION_FAILED)` with a generic
   * message — the failure modes are deliberately indistinguishable to avoid a
   * decryption oracle.
   *
   * @param key - 32-byte AES-256 key
   * @param iv - 12-byte GCM nonce
   * @param ciphertext - data to decrypt
   * @param tag - the 16-byte authentication tag produced by encryption
   * @param aad - Additional Authenticated Data (must equal the encrypt-time AAD)
   * @returns the recovered plaintext bytes
   */
  aeadDecrypt(
    key: Uint8Array,
    iv: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    aad: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Compute the SHA-256 digest of `data`.
   *
   * @param data - input bytes
   * @returns the 32-byte digest
   */
  sha256(data: Uint8Array): Promise<Uint8Array>;
}
