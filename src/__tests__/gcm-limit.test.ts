/**
 * AES-GCM per-invocation size bound (Phase 6 — gcm-limit).
 *
 * NIST SP 800-38D section 5.2.1.1 caps the plaintext of ONE AES-GCM
 * invocation at 2^39 - 256 bits == 2^36 - 32 bytes (68 719 476 704 B, ~64
 * GiB). Past that the 32-bit block counter wraps, keystream is reused, and
 * the ciphertext has neither confidentiality nor authenticity. Neither
 * OpenSSL's EVP layer nor `crypto.createCipheriv` enforces it, so this
 * library does — at every AES-GCM entry point, with no opt-out.
 *
 * What this suite pins:
 *   1. The exact boundary: `MAX_GCM_PLAINTEXT_BYTES` equals the standard's
 *      value, that value itself is ACCEPTED, and value + 1 is refused with
 *      `CryptoError(INVALID_INPUT, 'DATA_TOO_LARGE_FOR_GCM')`.
 *   2. Every entry point enforces it: the in-memory `encryptBytes` /
 *      `decryptBytes`, the low-level `encryptData` / `decryptData`, and all
 *      four file paths.
 *   3. Refusal happens BEFORE any irreversible or expensive work — no key
 *      derivation, no cipher object, no temp file, no output file.
 *
 * **Why sizes are faked, and only sizes.** A 64 GiB fixture is not something
 * a test suite can honestly produce: it would need 64 GiB of disk or RAM and
 * minutes of wall clock per case. The size is therefore the ONE thing faked;
 * every other participant is the real thing (a real scratch file, the real
 * `CryptoManager`, the real `node:crypto`). Two mechanisms, matched to how
 * each entry point learns a length:
 *
 *   - In-memory paths read `.length` off the caller's buffer, so the tests
 *     shadow `length` with `Object.defineProperty` on a REAL, correctly
 *     formed ciphertext/plaintext buffer. The bytes are genuine; only the
 *     reported length is not.
 *   - File paths read the size from the filesystem, so the tests replace
 *     `node:fs`'s `fstatSync` and `node:fs/promises`'s `open` via
 *     `jest.unstable_mockModule` + a dynamic `await import('../crypto-manager')`.
 *     `jest.spyOn` CANNOT be used for these: `crypto-manager.ts` imports them
 *     as NAMED ESM bindings, and a namespace spy does not intercept a live
 *     binding. (`jest.spyOn` IS correct for `node:crypto`, which
 *     `crypto-manager.ts` and `engine.node.ts` both take as a DEFAULT import
 *     of the shared core-module exports object — the "no cipher was ever
 *     constructed" negatives below rely on exactly that. Each such negative is
 *     paired with a positive control that arms the SAME spy in the SAME module
 *     generation, so none of them can pass vacuously.)
 *
 * The mocked-`node:fs` factories spread a namespace captured by a STATIC
 * import at the top of this file. Static imports link before any module body
 * runs, so those namespaces are guaranteed to be the real modules regardless
 * of what any earlier test in this file registered — and spreading them keeps
 * the other dozen named exports (`existsSync`, `openSync`, `readSync`,
 * `createWriteStream`, `mkdir`, `rename`, ...) real, which is what lets the
 * scratch fixtures actually work.
 *
 * Because a dynamically imported `../crypto-manager` lives in a fresh module
 * generation after `jest.resetModules()`, its `CryptoError` is a DIFFERENT
 * class object from this file's statically imported one. Every mocked case
 * therefore re-imports `../types` in the same generation so `instanceof`
 * means something.
 */
import {
  describe,
  it,
  expect,
  jest,
  beforeAll,
  afterAll,
  afterEach,
} from '@jest/globals';
import * as realFs from 'node:fs';
import * as realFsp from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import nodeCrypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

import {
  MAX_GCM_PLAINTEXT_BYTES,
  assertGcmPlaintextLimit,
} from '../format-core';
import { CryptoManager } from '../crypto-manager';
import { CryptoError, CryptoErrorType } from '../types';

/**
 * The bound, written out in full rather than recomputed from the constant, so
 * an edit to `MAX_GCM_PLAINTEXT_BYTES` cannot silently move the goalposts.
 * 2^39 - 256 bits / 8 = 2^36 - 32 bytes.
 */
const NIST_LIMIT_BYTES = 68_719_476_704;

/** Test-only low-cost Argon2id profile (production default is 128 MiB). */
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;

const PASSWORD = 'correct horse battery staple';

/** Per-suite scratch directory; every case creates its own sub-directory. */
const TEST_DIR = realFs.mkdtempSync(
  path.join(os.tmpdir(), 'hiprax-crypto-gcm-limit-')
);

/** Fresh, isolated sub-directory for one case. */
function makeCaseDir(label: string): string {
  const dir = path.join(
    TEST_DIR,
    `${label}-${nodeCrypto.randomBytes(6).toString('hex')}`
  );
  realFs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Shadow a byte buffer's `length` with an implausibly large value while
 * leaving its real bytes intact.
 *
 * `length` is an accessor on `%TypedArray%.prototype` and is not an
 * integer-indexed key, so an own data property legitimately shadows it. This
 * fakes ONLY the reported size — the guard under test reads exactly that
 * property, and nothing downstream of the guard is supposed to run.
 */
function withFakedLength<T extends Uint8Array>(
  bytes: T,
  fakeLength: number
): T {
  Object.defineProperty(bytes, 'length', {
    value: fakeLength,
    configurable: true,
    writable: false,
    enumerable: false,
  });
  return bytes;
}

/** Every `.tmp` file left behind anywhere under `dir`. */
function tmpFilesIn(dir: string): string[] {
  return realFs.readdirSync(dir).filter(name => name.endsWith('.tmp'));
}

/**
 * Assert a value is the typed refusal this phase introduces.
 *
 * The `code` assertion is doing the real work here: every one of these call
 * sites is wrapped in a try/catch that rewrites a non-`CryptoError` into a
 * generic `ENCRYPTION_FAILED` / `DECRYPTION_FAILED` / `FILE_ENCRYPTION_FAILED`
 * / `SYNC_FILE_DECRYPTION_FAILED`, so a guard placed on the wrong side of one
 * of those blocks shows up right here as the wrong code. (Spelling those four
 * out as extra `not.toBe` lines would be decoration — they cannot fail
 * independently of the positive assertion above them.)
 */
function expectGcmRefusal(
  error: unknown,
  ErrorClass: typeof CryptoError,
  ErrorTypes: typeof CryptoErrorType
): void {
  expect(error).toBeInstanceOf(ErrorClass);
  const err = error as CryptoError;
  expect(err.code).toBe('DATA_TOO_LARGE_FOR_GCM');
  expect(err.type).toBe(ErrorTypes.INVALID_INPUT);
  expect(err.message).toContain('800-38D');
  expect(err.message).toContain(String(NIST_LIMIT_BYTES));
}

/** Run `fn`, returning whatever it threw (or `undefined` if it did not). */
async function captureThrow(fn: () => unknown): Promise<unknown> {
  try {
    await fn();
  } catch (err) {
    return err;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// 1. The boundary itself (pure — nothing mocked, nothing to mock).
// ---------------------------------------------------------------------------

describe('assertGcmPlaintextLimit — the NIST SP 800-38D §5.2.1.1 boundary', () => {
  it('exposes the standard bound of 2**36 - 32 bytes', () => {
    expect(MAX_GCM_PLAINTEXT_BYTES).toBe(NIST_LIMIT_BYTES);
    expect(MAX_GCM_PLAINTEXT_BYTES).toBe(2 ** 36 - 32);
    // 2^39 - 256 bits, stated as bits, is the form the standard uses.
    expect(MAX_GCM_PLAINTEXT_BYTES * 8).toBe(2 ** 39 - 256);
    // The value must be exactly representable, or "limit + 1" is meaningless.
    expect(Number.isSafeInteger(MAX_GCM_PLAINTEXT_BYTES)).toBe(true);
    expect(MAX_GCM_PLAINTEXT_BYTES + 1).not.toBe(MAX_GCM_PLAINTEXT_BYTES);
  });

  it('accepts every length up to and including the exact limit', () => {
    for (const accepted of [
      0,
      1,
      16,
      MAX_GCM_PLAINTEXT_BYTES - 1,
      MAX_GCM_PLAINTEXT_BYTES,
    ]) {
      expect(assertGcmPlaintextLimit(accepted)).toBeUndefined();
    }
  });

  it('refuses exactly one byte past the limit with the default code', () => {
    const error = ((): unknown => {
      try {
        assertGcmPlaintextLimit(MAX_GCM_PLAINTEXT_BYTES + 1);
      } catch (err) {
        return err;
      }
      return undefined;
    })();

    expectGcmRefusal(error, CryptoError, CryptoErrorType);
    // The message must name the offending length as well as the limit, so an
    // operator can tell how far over they are without re-deriving it.
    expect((error as CryptoError).message).toContain(
      String(MAX_GCM_PLAINTEXT_BYTES + 1)
    );
  });

  it('reports the caller-supplied code instead of the default when given one', () => {
    expect(() =>
      assertGcmPlaintextLimit(MAX_GCM_PLAINTEXT_BYTES + 1, 'CUSTOM_CODE')
    ).toThrow(
      expect.objectContaining({
        code: 'CUSTOM_CODE',
        type: CryptoErrorType.INVALID_INPUT,
      }) as unknown as Error
    );
  });
});

// ---------------------------------------------------------------------------
// 2. In-memory entry points. Real buffers, real CryptoManager, faked `.length`.
// ---------------------------------------------------------------------------

describe('in-memory AES-GCM entry points refuse an oversized payload', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('encryptBytes refuses before generating entropy or a cipher', async () => {
    const cm = new CryptoManager(LOW_COST);
    const randomSpy = jest.spyOn(nodeCrypto, 'randomBytes');
    const cipherSpy = jest.spyOn(nodeCrypto, 'createCipheriv');

    const oversized = withFakedLength(
      new Uint8Array([1, 2, 3]),
      MAX_GCM_PLAINTEXT_BYTES + 1
    );

    const error = await captureThrow(() =>
      cm.encryptBytes(oversized, PASSWORD)
    );
    expectGcmRefusal(error, CryptoError, CryptoErrorType);

    // Negatives: no salt/IV was drawn and no cipher was built, i.e. the guard
    // really is ahead of the KDF and the AEAD, not merely ahead of the return.
    expect(randomSpy).not.toHaveBeenCalled();
    expect(cipherSpy).not.toHaveBeenCalled();
  });

  it('decryptBytes refuses an oversized body before deriving a key', async () => {
    const cm = new CryptoManager(LOW_COST);
    // A genuine, well-formed v1 ciphertext — only its reported length lies.
    const real = await cm.encryptBytes(new Uint8Array([9, 9, 9]), PASSWORD);
    const decipherSpy = jest.spyOn(nodeCrypto, 'createDecipheriv');

    const oversized = withFakedLength(
      real,
      MAX_GCM_PLAINTEXT_BYTES + 1 + 22 + 60
    );

    const error = await captureThrow(() =>
      cm.decryptBytes(oversized, PASSWORD)
    );
    expectGcmRefusal(error, CryptoError, CryptoErrorType);
    expect(decipherSpy).not.toHaveBeenCalled();
  });

  it('encryptData refuses without constructing a cipher, and keeps the typed code', () => {
    const cm = new CryptoManager(LOW_COST);
    const cipherSpy = jest.spyOn(nodeCrypto, 'createCipheriv');
    const key = nodeCrypto.randomBytes(32);
    const iv = nodeCrypto.randomBytes(12);

    const oversized = withFakedLength(
      Buffer.from([1, 2, 3]),
      MAX_GCM_PLAINTEXT_BYTES + 1
    );

    let error: unknown;
    try {
      cm.encryptData(oversized, key, iv);
    } catch (err) {
      error = err;
    }
    // `encryptData`'s own try/catch rewrites everything into the generic
    // `ENCRYPTION_FAILED`; the guard must sit outside it. `expectGcmRefusal`
    // asserts precisely that.
    expectGcmRefusal(error, CryptoError, CryptoErrorType);
    expect(cipherSpy).not.toHaveBeenCalled();
  });

  it('decryptData refuses without constructing a decipher, and keeps the typed code', () => {
    const cm = new CryptoManager(LOW_COST);
    const key = nodeCrypto.randomBytes(32);
    const iv = nodeCrypto.randomBytes(12);
    const tag = nodeCrypto.randomBytes(16);
    const decipherSpy = jest.spyOn(nodeCrypto, 'createDecipheriv');

    const oversized = withFakedLength(
      Buffer.from([1, 2, 3]),
      MAX_GCM_PLAINTEXT_BYTES + 1
    );

    let error: unknown;
    try {
      cm.decryptData(oversized, key, iv, tag);
    } catch (err) {
      error = err;
    }
    expectGcmRefusal(error, CryptoError, CryptoErrorType);
    expect(decipherSpy).not.toHaveBeenCalled();
  });

  it('still round-trips a payload AT the limit boundary check (in-memory, real bytes)', async () => {
    // Positive control for the four negatives above: with a truthful length,
    // the very same call path builds a cipher and completes. Without this, a
    // guard that rejected EVERYTHING would pass every assertion above.
    const cm = new CryptoManager(LOW_COST);
    const cipherSpy = jest.spyOn(nodeCrypto, 'createCipheriv');
    const decipherSpy = jest.spyOn(nodeCrypto, 'createDecipheriv');

    const plaintext = new Uint8Array([7, 7, 7, 7]);
    const ciphertext = await cm.encryptBytes(plaintext, PASSWORD);
    const recovered = await cm.decryptBytes(ciphertext, PASSWORD);

    expect(Array.from(recovered)).toEqual(Array.from(plaintext));
    expect(cipherSpy).toHaveBeenCalled();
    expect(decipherSpy).toHaveBeenCalled();

    // The low-level Buffer primitives get their own control rather than
    // riding on the bytes API: they are the two entry points whose guard had
    // to be lifted OUT of a catch-all try block, so "the guard did not break
    // the happy path" has to be shown on the exact same methods.
    cipherSpy.mockClear();
    decipherSpy.mockClear();
    const key = nodeCrypto.randomBytes(32);
    const iv = nodeCrypto.randomBytes(12);
    const payload = Buffer.from('low-level round trip');
    const { encrypted, tag } = cm.encryptData(payload, key, iv);
    expect(cm.decryptData(encrypted, key, iv, tag)).toEqual(payload);
    expect(cipherSpy).toHaveBeenCalledTimes(1);
    expect(decipherSpy).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// 3. File entry points. Real scratch files; only the reported SIZE is faked.
// ---------------------------------------------------------------------------

/**
 * Register `node:fs` / `node:fs/promises` mocks that report `fakeSize` for the
 * input file, then import a fresh `../crypto-manager` that binds them.
 *
 * Pass `null` for `fakeSize` to install the very same mocks in passthrough
 * mode (real sizes, real reads). That is not a no-op: it puts a truthful run
 * through the SAME post-`resetModules()` module generation the oversize cases
 * use, which is what proves the `node:crypto` spies actually reach that
 * generation — without it, every `not.toHaveBeenCalled()` below could pass
 * simply because the spy was watching the wrong module instance.
 *
 * `fstatSync` covers the two sync paths. `open` covers the two async paths: it
 * returns the REAL `FileHandle` behind a `Proxy` overriding `stat()` and
 * `read()`. Everything else on the handle (`createReadStream`, `close`, `fd`)
 * is the real thing.
 *
 * **Only TAIL reads are synthesised.** A read whose range ends at or past
 * `fakeSize` is zero-filled and reports the full requested length, because a
 * genuine file of `fakeSize` bytes really does have readable bytes at its
 * tail: `decryptFile` reads the trailing 16-byte auth tag BEFORE it computes
 * `bodyLen`, so without this it would die with `INVALID_ENCRYPTED_FILE_SIZE`
 * and the case would go green-then-red for the wrong reason. Every other read
 * returns the REAL `bytesRead`, which matters for the red side: if a guard is
 * deleted, the body loop hits a short read almost immediately and fails with
 * `Unexpected EOF while reading ...` instead of grinding through ~10^6
 * synthetic 64 KiB chunks and dying on Jest's default timeout — a timeout
 * names no defect.
 *
 * Returns the fresh module generation plus the real handles that were opened,
 * so a caller can assert the descriptor was closed.
 */
async function importManagerWithFakedFileSize(
  fakeSize: number | null
): Promise<{
  CryptoManager: typeof CryptoManager;
  CryptoError: typeof CryptoError;
  CryptoErrorType: typeof CryptoErrorType;
  openedHandles: FileHandle[];
}> {
  jest.resetModules();

  const openedHandles: FileHandle[] = [];

  /** True when this read reaches the tail of the (possibly faked) file. */
  const isTailRead = (position: number, length: number): boolean =>
    fakeSize !== null &&
    typeof position === 'number' &&
    position + length >= fakeSize;

  jest.unstable_mockModule('node:fs', () => ({
    ...realFs,
    fstatSync: (fd: number): realFs.Stats => {
      const real = realFs.fstatSync(fd);
      return fakeSize === null
        ? real
        : ({ ...real, size: fakeSize } as realFs.Stats);
    },
    readSync: (
      fd: number,
      buffer: Buffer,
      offset: number,
      length: number,
      position: number
    ): number => {
      const bytesRead = realFs.readSync(fd, buffer, offset, length, position);
      if (bytesRead < length && isTailRead(position, length)) {
        buffer.fill(0, offset + bytesRead, offset + length);
        return length;
      }
      return bytesRead;
    },
  }));

  jest.unstable_mockModule('node:fs/promises', () => ({
    ...realFsp,
    open: async (filePath: string, flags: string): Promise<FileHandle> => {
      const handle = await realFsp.open(filePath, flags);
      openedHandles.push(handle);
      return new Proxy(handle, {
        get(target, prop, receiver): unknown {
          if (prop === 'stat' && fakeSize !== null) {
            return async (): Promise<unknown> => ({
              ...(await target.stat()),
              size: fakeSize,
            });
          }
          if (prop === 'read') {
            return async (
              buffer: Buffer,
              offset: number,
              length: number,
              position: number
            ): Promise<{ bytesRead: number; buffer: Buffer }> => {
              const result = await target.read(
                buffer,
                offset,
                length,
                position
              );
              if (result.bytesRead < length && isTailRead(position, length)) {
                buffer.fill(0, offset + result.bytesRead, offset + length);
                return { bytesRead: length, buffer };
              }
              return result;
            };
          }
          const value: unknown = Reflect.get(target, prop, receiver);
          return typeof value === 'function'
            ? (value as (...args: unknown[]) => unknown).bind(target)
            : value;
        },
      }) as FileHandle;
    },
  }));

  const managerModule = await import('../crypto-manager');
  const typesModule = await import('../types');

  return {
    CryptoManager: managerModule.CryptoManager,
    CryptoError: typesModule.CryptoError,
    CryptoErrorType: typesModule.CryptoErrorType,
    openedHandles,
  };
}

describe('file AES-GCM entry points refuse an oversized file', () => {
  // Fixtures are produced with the REAL, unmocked modules in beforeAll, before
  // any mock registration exists.
  let plaintextFile: string;
  let asyncCiphertextFile: string;
  let syncCiphertextFile: string;

  beforeAll(async (): Promise<void> => {
    const fixtures = makeCaseDir('fixtures');
    plaintextFile = path.join(fixtures, 'plain.txt');
    realFs.writeFileSync(plaintextFile, 'a small, entirely real file');

    const cm = new CryptoManager(LOW_COST);
    asyncCiphertextFile = path.join(fixtures, 'async.enc');
    await cm.encryptFile(plaintextFile, asyncCiphertextFile, PASSWORD);
    syncCiphertextFile = path.join(fixtures, 'sync.enc');
    cm.encryptFileSync(plaintextFile, syncCiphertextFile, PASSWORD);
  });

  afterEach(() => {
    jest.restoreAllMocks();
    jest.resetModules();
  });

  afterAll(() => {
    realFs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it('encryptFileSync refuses before the KDF, the temp file, or a cipher', async () => {
    const mod = await importManagerWithFakedFileSize(
      MAX_GCM_PLAINTEXT_BYTES + 1
    );
    const dir = makeCaseDir('enc-sync');
    const outputPath = path.join(dir, 'out.enc');

    const cipherSpy = jest.spyOn(nodeCrypto, 'createCipheriv');
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    const cm = new mod.CryptoManager(LOW_COST);
    const error = await captureThrow(() =>
      cm.encryptFileSync(plaintextFile, outputPath, PASSWORD)
    );

    expectGcmRefusal(error, mod.CryptoError, mod.CryptoErrorType);
    expect(cipherSpy).not.toHaveBeenCalled();
    expect(pbkdf2Spy).not.toHaveBeenCalled();
    expect(tmpFilesIn(dir)).toEqual([]);
    expect(realFs.existsSync(outputPath)).toBe(false);
    expect(realFs.readdirSync(dir)).toEqual([]);
  });

  it('encryptFile refuses before the KDF, the temp file, or a cipher, and closes the input', async () => {
    const mod = await importManagerWithFakedFileSize(
      MAX_GCM_PLAINTEXT_BYTES + 1
    );
    const dir = makeCaseDir('enc-async');
    const outputPath = path.join(dir, 'out.enc');

    const cipherSpy = jest.spyOn(nodeCrypto, 'createCipheriv');

    const cm = new mod.CryptoManager(LOW_COST);
    const error = await captureThrow(() =>
      cm.encryptFile(plaintextFile, outputPath, PASSWORD)
    );

    expectGcmRefusal(error, mod.CryptoError, mod.CryptoErrorType);
    expect(cipherSpy).not.toHaveBeenCalled();
    expect(tmpFilesIn(dir)).toEqual([]);
    expect(realFs.existsSync(outputPath)).toBe(false);
    expect(realFs.readdirSync(dir)).toEqual([]);
    // The input handle was opened exactly once and closed on the way out —
    // refusing must not leak the descriptor.
    expect(mod.openedHandles).toHaveLength(1);
    expect((mod.openedHandles[0] as FileHandle).fd).toBe(-1);
  });

  it('decryptFileSync refuses BEFORE the 600 000-iteration PBKDF2 and before the temp file exists', async () => {
    // The hoist this phase performs is exactly what this case pins: with the
    // guard left where `bodyLen` used to be computed, `deriveKeySync` and
    // `openSync(tempPath, 'w')` would both have already run.
    const mod = await importManagerWithFakedFileSize(
      MAX_GCM_PLAINTEXT_BYTES + 83
    );
    const dir = makeCaseDir('dec-sync');
    const outputPath = path.join(dir, 'out.txt');

    const decipherSpy = jest.spyOn(nodeCrypto, 'createDecipheriv');
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    const cm = new mod.CryptoManager(LOW_COST);
    const error = await captureThrow(() =>
      cm.decryptFileSync(syncCiphertextFile, outputPath, PASSWORD)
    );

    expectGcmRefusal(error, mod.CryptoError, mod.CryptoErrorType);
    expect(pbkdf2Spy).not.toHaveBeenCalled();
    expect(decipherSpy).not.toHaveBeenCalled();
    expect(tmpFilesIn(dir)).toEqual([]);
    expect(realFs.existsSync(outputPath)).toBe(false);
    expect(realFs.readdirSync(dir)).toEqual([]);
  });

  it('decryptFile refuses before the KDF and the temp file, and closes the input', async () => {
    const mod = await importManagerWithFakedFileSize(
      MAX_GCM_PLAINTEXT_BYTES + 83
    );
    const dir = makeCaseDir('dec-async');
    const outputPath = path.join(dir, 'out.txt');

    const decipherSpy = jest.spyOn(nodeCrypto, 'createDecipheriv');

    const cm = new mod.CryptoManager(LOW_COST);
    const error = await captureThrow(() =>
      cm.decryptFile(asyncCiphertextFile, outputPath, PASSWORD)
    );

    expectGcmRefusal(error, mod.CryptoError, mod.CryptoErrorType);
    expect(decipherSpy).not.toHaveBeenCalled();
    expect(tmpFilesIn(dir)).toEqual([]);
    expect(realFs.existsSync(outputPath)).toBe(false);
    expect(realFs.readdirSync(dir)).toEqual([]);
    expect(mod.openedHandles).toHaveLength(1);
    expect((mod.openedHandles[0] as FileHandle).fd).toBe(-1);
  });

  it('arms the same spies in the SAME mocked module generation (anti-vacuity)', async () => {
    // The four cases above rest entirely on `not.toHaveBeenCalled()`: the
    // filesystem negatives are empty whether the guard fires early or late,
    // because the outer catch unlinks the temp file either way. So the spies
    // are the only thing that distinguishes "refused before the KDF" from
    // "refused after it" — and they are installed on this file's STATICALLY
    // imported `node:crypto`, while the manager under test comes from a fresh
    // generation created by `jest.resetModules()`. If a spy did not reach that
    // generation, all four negatives would pass vacuously.
    //
    // This control closes that hole directly: same helper, same
    // `resetModules()`, same mocked `node:fs` / `node:fs/promises`, same
    // dynamically imported manager — only the size is truthful. The spies MUST
    // record calls here, which is exactly what proves they would have recorded
    // them above had the guard been misplaced.
    const mod = await importManagerWithFakedFileSize(null);
    const dir = makeCaseDir('same-generation');
    const enc = path.join(dir, 'sg.enc');
    const dec = path.join(dir, 'sg.txt');

    const cipherSpy = jest.spyOn(nodeCrypto, 'createCipheriv');
    const decipherSpy = jest.spyOn(nodeCrypto, 'createDecipheriv');
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    const cm = new mod.CryptoManager(LOW_COST);
    cm.encryptFileSync(plaintextFile, enc, PASSWORD);
    cm.decryptFileSync(enc, dec, PASSWORD);

    expect(realFs.readFileSync(dec)).toEqual(
      realFs.readFileSync(plaintextFile)
    );
    expect(cipherSpy).toHaveBeenCalled();
    expect(decipherSpy).toHaveBeenCalled();
    expect(pbkdf2Spy).toHaveBeenCalled();
    expect(tmpFilesIn(dir)).toEqual([]);
  });

  it('leaves an ordinary, truthfully-sized file round-trip working (positive control)', async () => {
    // Anti-vacuity for all four cases above. With the spies still armed and
    // the real (unmocked) modules in play, the same four methods must build
    // their ciphers, write their temp files, and produce correct output. A
    // guard that refused unconditionally would fail here.
    jest.resetModules();
    const dir = makeCaseDir('round-trip');
    const encAsync = path.join(dir, 'rt-async.enc');
    const decAsync = path.join(dir, 'rt-async.txt');
    const encSync = path.join(dir, 'rt-sync.enc');
    const decSync = path.join(dir, 'rt-sync.txt');

    const cipherSpy = jest.spyOn(nodeCrypto, 'createCipheriv');
    const decipherSpy = jest.spyOn(nodeCrypto, 'createDecipheriv');
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    const cm = new CryptoManager(LOW_COST);
    const expected = realFs.readFileSync(plaintextFile);

    await cm.encryptFile(plaintextFile, encAsync, PASSWORD);
    await cm.decryptFile(encAsync, decAsync, PASSWORD);
    cm.encryptFileSync(plaintextFile, encSync, PASSWORD);
    cm.decryptFileSync(encSync, decSync, PASSWORD);

    expect(realFs.readFileSync(decAsync)).toEqual(expected);
    expect(realFs.readFileSync(decSync)).toEqual(expected);
    expect(cipherSpy).toHaveBeenCalled();
    expect(decipherSpy).toHaveBeenCalled();
    expect(pbkdf2Spy).toHaveBeenCalled();
    // And nothing transient survived a successful run either.
    expect(tmpFilesIn(dir)).toEqual([]);
  });
});
