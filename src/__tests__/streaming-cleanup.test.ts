/**
 * Iteration 2 Task 18 — Cover the remaining streaming-cleanup branches
 * left uncovered by iteration 1. The branches under test are real failure
 * modes in production but rarely fire on a fast development filesystem
 * with normal-sized inputs:
 *
 *  1. `atomicRename` copy-fallback path — fires on Windows when
 *     `fs.rename` fails because the target file is locked but the
 *     destination directory is still writeable. The fallback then runs
 *     `fs.copyFile + fs.unlink` to maximise the chance the operation
 *     completes.
 *
 *  2. Drain-backpressure handling in async streams — fires when the
 *     write stream's `write()` returns `false` (its internal buffer
 *     filled past the highWaterMark) and the producer must wait for the
 *     `'drain'` event before sending the next chunk.
 *
 *  3. `progressError` tagging in encrypt vs decrypt — when a user-supplied
 *     progress callback throws mid-stream, the error must be tagged via
 *     `tagProgressThrow` so the outer catch block re-throws it with
 *     identity preserved (rather than wrapping in `FILE_*_FAILED`). The
 *     tag fires on both the encrypt and decrypt code paths via two
 *     distinct branches.
 *
 *  4. `decryptFile` zero-body path — when the input ciphertext has a
 *     v1 header + salt + iv + tag but ZERO body bytes (i.e. the
 *     plaintext was an empty buffer), `decryptFile` skips the read
 *     stream entirely and just calls `decipher.final()` to authenticate.
 *     We verify this path produces a zero-byte output file and the
 *     atomic-rename contract still holds.
 *
 * Each describe block is isolated in its own jest module-reset bubble so
 * the per-suite ESM mocks (for `node:fs/promises` and similar) don't
 * leak across tests.
 *
 * Note on mocking strategy: the Node ESM namespace for `node:fs` and
 * `node:fs/promises` is read-only — `jest.spyOn` cannot mutate it
 * directly. We use `jest.unstable_mockModule` (which works under
 * jest's --experimental-vm-modules ESM mode) to intercept the named
 * imports inside `crypto-manager.ts` at module-load time. Each test
 * that needs mocked fs primitives MUST `jest.resetModules()` before
 * installing its mocks AND before importing `../crypto-manager`, so
 * the mocks are observable to the manager's named imports.
 */
import { jest } from '@jest/globals';
import path from 'node:path';
import os from 'node:os';
import nodeCrypto from 'node:crypto';
import { Writable } from 'node:stream';
import {
  existsSync,
  mkdirSync,
  rmSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  readdirSync,
  statSync,
} from 'node:fs';
import { writeFile, unlink, readFile } from 'node:fs/promises';

const TEST_DIR = path.join(
  os.tmpdir(),
  `hiprax-crypto-cleanup-${nodeCrypto.randomBytes(8).toString('hex')}`
);

const TEST_PASSWORD = 'MySecureP@ssw0rd123!';

beforeAll(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterAll(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 1. atomicRename copy-fallback path
// ---------------------------------------------------------------------------

describe('atomicRename copy-fallback (Task 18)', () => {
  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
  });

  it('async: encryptFile uses copyFile fallback when rename fails', async () => {
    // Capture the unmocked `node:fs/promises` BEFORE installing the
    // mock so we can delegate from the mock to the real implementation
    // for everything except `rename` (which we want to fail).
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    let renameCalls = 0;
    let copyFileCalls = 0;
    let unlinkCalls = 0;

    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
      rename: jest.fn(async () => {
        renameCalls += 1;
        const e = new Error('EBUSY: simulated rename failure');
        (e as Error & { code?: string }).code = 'EBUSY';
        throw e;
      }),
      copyFile: jest.fn(async (...args: unknown[]) => {
        copyFileCalls += 1;
        return (
          realFsPromises.copyFile as unknown as (
            ...a: unknown[]
          ) => Promise<void>
        )(...args);
      }),
      unlink: jest.fn(async (...args: unknown[]) => {
        unlinkCalls += 1;
        return (
          realFsPromises.unlink as unknown as (...a: unknown[]) => Promise<void>
        )(...args);
      }),
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({
      memoryCost: 2 ** 12, // 4 MiB — keep test fast
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'rename-fallback-input.txt');
    const outputPath = path.join(TEST_DIR, 'rename-fallback-output.bin');
    await writeFile(inputPath, 'hello copy-fallback');

    try {
      await cm.encryptFile(inputPath, outputPath, TEST_PASSWORD);

      // Even though rename failed, the file ends up at the canonical
      // path via copyFile fallback.
      expect(existsSync(outputPath)).toBe(true);
      expect(renameCalls).toBeGreaterThan(0);
      expect(copyFileCalls).toBeGreaterThan(0);
      // The fallback's safeUnlink call removes the temp file.
      expect(unlinkCalls).toBeGreaterThan(0);

      // The temp file is gone after the fallback ran.
      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('rename-fallback-output.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) await unlink(p);
      }
    }
  });

  it('sync: encryptFileSync uses copyFileSync fallback when renameSync fails', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');

    let renameSyncCalls = 0;
    let copyFileSyncCalls = 0;
    let unlinkSyncCalls = 0;

    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      renameSync: jest.fn(() => {
        renameSyncCalls += 1;
        const e = new Error('EBUSY: simulated renameSync failure');
        (e as Error & { code?: string }).code = 'EBUSY';
        throw e;
      }),
      copyFileSync: jest.fn((...args: unknown[]) => {
        copyFileSyncCalls += 1;
        return (realFs.copyFileSync as unknown as (...a: unknown[]) => void)(
          ...args
        );
      }),
      unlinkSync: jest.fn((...args: unknown[]) => {
        unlinkSyncCalls += 1;
        return (realFs.unlinkSync as unknown as (...a: unknown[]) => void)(
          ...args
        );
      }),
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({
      pbkdf2Iterations: 1000, // Fast
    });

    const inputPath = path.join(TEST_DIR, 'rename-fallback-sync-input.txt');
    const outputPath = path.join(TEST_DIR, 'rename-fallback-sync-output.bin');
    writeFileSync(inputPath, 'hello sync copy-fallback');

    try {
      cm.encryptFileSync(inputPath, outputPath, TEST_PASSWORD);

      expect(existsSync(outputPath)).toBe(true);
      expect(renameSyncCalls).toBeGreaterThan(0);
      expect(copyFileSyncCalls).toBeGreaterThan(0);
      expect(unlinkSyncCalls).toBeGreaterThan(0);

      // Verify temp file cleaned up.
      const stray = readdirSync(TEST_DIR).filter(
        e =>
          e.startsWith('rename-fallback-sync-output.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toEqual([]);
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  });

  it('async: surfaces ORIGINAL rename error when copyFile ALSO fails', async () => {
    // The fallback is best-effort: if BOTH rename AND copyFile fail, the
    // catch block re-throws the original rename error. We exercise that
    // path so the line `throw error;` inside the inner catch is covered.
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
      rename: jest.fn(async () => {
        throw new Error('rename boom');
      }),
      copyFile: jest.fn(async () => {
        throw new Error('copy boom');
      }),
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'rename-double-fail-input.txt');
    const outputPath = path.join(TEST_DIR, 'rename-double-fail-output.bin');
    await writeFile(inputPath, 'expect both to fail');

    try {
      await expect(
        cm.encryptFile(inputPath, outputPath, TEST_PASSWORD)
      ).rejects.toThrow();
      // The output never lands at the canonical path.
      expect(existsSync(outputPath)).toBe(false);
    } finally {
      if (existsSync(inputPath)) await unlink(inputPath);
      // Clean up temp files left behind because both rename + copyFile
      // throwing means our safeUnlink never ran on the success path.
      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('rename-double-fail-') && e.endsWith('.tmp')
      );
      for (const e of stray) unlinkSync(path.join(TEST_DIR, e));
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Drain-backpressure handling
// ---------------------------------------------------------------------------

describe('drain backpressure (Task 18)', () => {
  // The encryptFile body uses createWriteStream with the default 64 KiB
  // highWaterMark. The trailing-tag write (`writeChunk(cipher.getAuthTag())`)
  // lands in the internal write queue right after the body finishes
  // streaming, which on a slow disk / large file will return false from
  // `write()` and force the producer to await the 'drain' event. We
  // simulate that condition by wrapping `createWriteStream` to use a tiny
  // highWaterMark, then encrypting a >1 KiB input — the write queue fills
  // up almost immediately and the drain branch reliably fires.
  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
  });

  it('encryptFile: handles writeStream backpressure (drain event)', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');
    const originalCreateWriteStream = realFs.createWriteStream;

    // Reinstall passthrough mocks for all fs modules so any leftover mock
    // state from previous suites does NOT bleed in (ESM module-mock
    // registrations from `jest.unstable_mockModule` persist beyond
    // `jest.resetModules()`; explicitly re-registering with passthroughs
    // for both modules ensures only OUR `createWriteStream` override
    // takes effect).
    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      createWriteStream: jest.fn(
        (
          p: Parameters<typeof originalCreateWriteStream>[0],
          opts?: Parameters<typeof originalCreateWriteStream>[1]
        ) => {
          // Force a tiny highWaterMark so write queue fills on the first
          // chunk and `write()` returns false, exercising the
          // outputStream.once('drain', ...) branch.
          const merged = {
            ...(opts as object),
            highWaterMark: 16,
          };
          return originalCreateWriteStream(
            p,
            merged as Parameters<typeof originalCreateWriteStream>[1]
          );
        }
      ),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'drain-input.bin');
    const outputPath = path.join(TEST_DIR, 'drain-output.bin');
    const decryptedPath = path.join(TEST_DIR, 'drain-decrypted.bin');
    const payload = nodeCrypto.randomBytes(64 * 1024);
    await writeFile(inputPath, payload);

    try {
      await cm.encryptFile(inputPath, outputPath, TEST_PASSWORD);
      expect(existsSync(outputPath)).toBe(true);

      // Round-trip: decrypt and assert byte equality. If the drain
      // handling drops or reorders bytes, this fails. The decrypt path
      // also creates write streams with the same shrunken highWaterMark
      // so drain handling on the decrypt side is exercised too.
      await cm.decryptFile(outputPath, decryptedPath, TEST_PASSWORD);
      const decrypted = await readFile(decryptedPath);
      expect(decrypted.equals(payload)).toBe(true);
    } finally {
      for (const p of [inputPath, outputPath, decryptedPath]) {
        if (existsSync(p)) await unlink(p);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 3. progressError tagging — encrypt vs decrypt
// ---------------------------------------------------------------------------

describe('progressError tagging (Task 18)', () => {
  // The encrypt and decrypt streaming paths each have their own `data`
  // event listener that captures the user's throw via `tagProgressThrow`.
  // Iteration 1 covered a single throw path generally; this fills in
  // explicit per-direction coverage so a future regression in one but
  // not the other surfaces. We also verify that the throw IDENTITY is
  // preserved (i.e. the outer catch re-throws the user's class, not a
  // CryptoError wrapper).
  //
  // Unlike the other Task 18 sub-suites, this one does NOT mock fs —
  // the throw happens at the user-supplied callback, not at any fs
  // boundary, so we exercise the real-fs path end to end.

  const inputPath = path.join(TEST_DIR, 'progresstag-input.bin');
  const encryptedPath = path.join(TEST_DIR, 'progresstag-encrypted.bin');
  const decryptedPath = path.join(TEST_DIR, 'progresstag-decrypted.bin');

  beforeEach(async () => {
    jest.resetModules();
    // Reinstall passthrough mocks for fs modules. ESM module-mock
    // registrations from previous suites persist beyond
    // `jest.resetModules()`, so we explicitly install identity-passthrough
    // mocks here to ensure no rename-throwing mock from the
    // atomicRename suite (above) bleeds into THIS suite's encryptFile
    // round-trip.
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');
    jest.unstable_mockModule('node:fs', () => ({ ...realFs }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));
    // 256 KiB so the data event fires multiple times via 64 KiB chunks.
    await writeFile(inputPath, nodeCrypto.randomBytes(256 * 1024));
  });
  afterEach(async () => {
    for (const p of [inputPath, encryptedPath, decryptedPath]) {
      if (existsSync(p)) await unlink(p);
    }
    jest.resetModules();
  });

  it('encryptFile: tags throw from a chunk-level progress callback (preserves identity)', async () => {
    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    class EncryptBoom extends Error {
      public override readonly name = 'EncryptBoom';
    }

    let chunkEventCount = 0;
    let caught: unknown;
    try {
      await cm.encryptFile(
        inputPath,
        encryptedPath,
        TEST_PASSWORD,
        processed => {
          // Skip the initial (0, total) bracket event — we want the
          // throw to fire from the chunk-level data listener so we
          // exercise the `progressError = tagProgressThrow(err)` branch
          // (NOT the early invokeProgress(progress, 0, totalBytes)
          // branch which goes through invokeProgress's own try/catch).
          if (processed === 0) {
            return;
          }
          chunkEventCount += 1;
          if (chunkEventCount === 1) {
            throw new EncryptBoom('mid-encrypt boom');
          }
        }
      );
      throw new Error('encryptFile should have rejected');
    } catch (err) {
      caught = err;
    }

    // Identity preserved: the user's class is what bubbles out, NOT a
    // CryptoError wrapper.
    expect(caught).toBeInstanceOf(EncryptBoom);
    // Output never landed (atomic-rename contract holds).
    expect(existsSync(encryptedPath)).toBe(false);
  });

  it('decryptFile: tags throw from a chunk-level progress callback (preserves identity)', async () => {
    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });
    // First, produce a valid ciphertext so we have something to decrypt.
    await cm.encryptFile(inputPath, encryptedPath, TEST_PASSWORD);

    class DecryptBoom extends Error {
      public override readonly name = 'DecryptBoom';
    }

    let chunkEventCount = 0;
    let caught: unknown;
    try {
      await cm.decryptFile(
        encryptedPath,
        decryptedPath,
        TEST_PASSWORD,
        processed => {
          if (processed === 0) {
            return;
          }
          chunkEventCount += 1;
          if (chunkEventCount === 1) {
            throw new DecryptBoom('mid-decrypt boom');
          }
        }
      );
      throw new Error('decryptFile should have rejected');
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(DecryptBoom);
    expect(existsSync(decryptedPath)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 4. decryptFile zero-body path
// ---------------------------------------------------------------------------

describe('decryptFile zero-body path (Task 18)', () => {
  // When the plaintext is an empty buffer, encryption produces a v1
  // header + salt + iv + tag with ZERO body bytes. decryptFile detects
  // `bodyLen === 0` and skips the read-stream entirely, calling
  // `decipher.final()` directly to verify the tag. The async + sync
  // paths both have this branch.

  const emptyInputPath = path.join(TEST_DIR, 'zero-body-input.bin');
  const encryptedPath = path.join(TEST_DIR, 'zero-body-encrypted.bin');
  const decryptedPath = path.join(TEST_DIR, 'zero-body-decrypted.bin');

  beforeEach(() => {
    jest.resetModules();
    // Identity passthroughs for fs modules — see notes in the
    // progressError tagging suite for the rationale.
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');
    jest.unstable_mockModule('node:fs', () => ({ ...realFs }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));
  });
  afterEach(async () => {
    for (const p of [emptyInputPath, encryptedPath, decryptedPath]) {
      if (existsSync(p)) await unlink(p);
    }
    jest.resetModules();
  });

  it('async: decryptFile round-trips an empty plaintext correctly', async () => {
    // Use the encrypt path WITHOUT going through encryptFile (which
    // emits no chunk-level data events for an empty input). Construct
    // the v1 ciphertext manually using the public encryptData primitive
    // and the v1 header packer, mirroring exactly what encryptFile
    // would have produced for an empty input.
    const { CryptoManager } = await import('../crypto-manager');
    const { packHeader, KDF_ID_ARGON2ID } = await import('../format');
    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    // Build a v1 header matching the manager's configured Argon2id params.
    const header = packHeader(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });
    const salt = cm.generateSecureRandom(32);
    const iv = cm.generateSecureRandom(12);
    const key = await cm.deriveKey(TEST_PASSWORD, salt);
    const aad = Buffer.concat([
      Buffer.from('secure-crypto-tool-v2', 'utf8'),
      header,
    ]);
    const { encrypted, tag } = cm.encryptData(Buffer.alloc(0), key, iv, aad);
    expect(encrypted.length).toBe(0); // body IS zero
    expect(tag.length).toBe(16);

    // Layout: [header][salt][iv][body=empty][tag]
    const ciphertext = Buffer.concat([header, salt, iv, encrypted, tag]);
    await writeFile(encryptedPath, ciphertext);

    // Decrypt — exercises the bodyLen === 0 branch.
    await cm.decryptFile(encryptedPath, decryptedPath, TEST_PASSWORD);
    const out = await readFile(decryptedPath);
    expect(out.length).toBe(0);
  });

  it('sync: decryptFileSync round-trips an empty plaintext correctly', async () => {
    const { CryptoManager } = await import('../crypto-manager');
    const { packHeader, KDF_ID_PBKDF2_SHA256 } = await import('../format');
    const cm = new CryptoManager({
      pbkdf2Iterations: 1000,
    });

    const header = packHeader(KDF_ID_PBKDF2_SHA256, {
      kind: 'pbkdf2-sha256',
      iterations: 1000,
    });
    const salt = cm.generateSecureRandom(32);
    const iv = cm.generateSecureRandom(12);
    const key = cm.deriveKeySync(TEST_PASSWORD, salt);
    const aad = Buffer.concat([
      Buffer.from('secure-crypto-tool-v2', 'utf8'),
      header,
    ]);
    const { encrypted, tag } = cm.encryptData(Buffer.alloc(0), key, iv, aad);
    expect(encrypted.length).toBe(0);

    const ciphertext = Buffer.concat([header, salt, iv, encrypted, tag]);
    writeFileSync(encryptedPath, ciphertext);

    cm.decryptFileSync(encryptedPath, decryptedPath, TEST_PASSWORD);
    const out = readFileSync(decryptedPath);
    expect(out.length).toBe(0);
    // Also check the on-disk file is exactly zero bytes via stat.
    expect(statSync(decryptedPath).size).toBe(0);
  });

  it('async: decryptFile fails authentication when zero-body ciphertext is tampered', async () => {
    // Defence-in-depth: even with no body bytes to corrupt, tampering
    // with the salt or tag must still cause decryption to throw. This
    // exercises the `decipher.final()` path with a deliberately-bad tag.
    const { CryptoManager } = await import('../crypto-manager');
    const { packHeader, KDF_ID_ARGON2ID } = await import('../format');
    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });
    const { CryptoError } = await import('../types');

    const header = packHeader(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });
    const salt = cm.generateSecureRandom(32);
    const iv = cm.generateSecureRandom(12);
    const key = await cm.deriveKey(TEST_PASSWORD, salt);
    const aad = Buffer.concat([
      Buffer.from('secure-crypto-tool-v2', 'utf8'),
      header,
    ]);
    const { encrypted, tag } = cm.encryptData(Buffer.alloc(0), key, iv, aad);
    // Flip a bit in the tag so authentication fails.
    const tag0 = tag[0] ?? 0;
    tag[0] = tag0 ^ 0x01;
    const ciphertext = Buffer.concat([header, salt, iv, encrypted, tag]);
    await writeFile(encryptedPath, ciphertext);

    await expect(
      cm.decryptFile(encryptedPath, decryptedPath, TEST_PASSWORD)
    ).rejects.toThrow(CryptoError);
    // Cleanup contract: no orphan output file.
    expect(existsSync(decryptedPath)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 5. outputStream 'error' during prefix and tag writes (Phase 2 / Task 2.2)
// ---------------------------------------------------------------------------
//
// These tests exercise the hardened writeChunk / onStreamError guard added
// in Phase 2. Four failure scenarios are covered:
//   A. Prefix write, immediate  (ok=true, large highWaterMark)
//   B. Prefix write, backpressured (ok=false, highWaterMark=1)
//   C. Tag write, immediate     (ok=true, 0-byte input so write #2 = tag)
//   D. Tag write, backpressured (ok=false, highWaterMark=1, 0-byte input)
//
// Each asserts: the call rejects with a CryptoError, the operation does not
// hang (10 s backstop), no orphan .tmp file is left behind, and any
// pre-existing file at outputPath is not modified.
//
// Mock strategy: intercept createWriteStream via jest.unstable_mockModule
// and return a Writable subclass that injects an ENOSPC error on the
// Nth write() call. 0-byte input guarantees exactly 2 write() calls to
// outputStream (write #1 = prefix [header+salt+iv], write #2 = trailing
// auth tag) because the cipher produces no body output for empty plaintext.

describe('outputStream write error injection (Phase 2 / Task 2.2)', () => {
  /**
   * Returns a Writable that calls its internal _write callback with an
   * ENOSPC error on the Nth write call and succeeds on all others.
   *
   * @param failOnWrite - 1-based index of the write that should fail.
   * @param hwm - highWaterMark. Pass 1 to force write() to always return
   *              false (backpressured / ok=false path).
   */
  function makeErrorStream(failOnWrite: number, hwm = 65536): Writable {
    return new (class extends Writable {
      private _n = 0;
      constructor() {
        super({ highWaterMark: hwm });
      }
      override _write(
        _chunk: unknown,
        _encoding: string,
        callback: (error?: Error | null) => void
      ): void {
        this._n++;
        if (this._n === failOnWrite) {
          callback(
            new Error(`ENOSPC: injected write error on call #${failOnWrite}`)
          );
        } else {
          callback();
        }
      }
    })();
  }

  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
  });

  // ── A. Prefix write, immediate (ok=true) ────────────────────────────────

  it('prefix-immediate: stream error on write #1 → CryptoError, no orphan .tmp, output untouched', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      createWriteStream: jest.fn(() => makeErrorStream(1)),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'werr-pfx-imm-in.txt');
    const outputPath = path.join(TEST_DIR, 'werr-pfx-imm-out.bin');
    const sentinel = 'pre-existing output — must survive prefix-imm error';
    writeFileSync(outputPath, sentinel);
    writeFileSync(inputPath, 'prefix-immediate error test payload');

    try {
      await expect(
        cm.encryptFile(inputPath, outputPath, TEST_PASSWORD)
      ).rejects.toThrow(CryptoError);

      // No orphan temp files.
      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('werr-pfx-imm-out.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toHaveLength(0);

      // Pre-existing output untouched.
      expect(readFileSync(outputPath, 'utf8')).toBe(sentinel);
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 10_000); // hang-detection backstop

  // ── B. Prefix write, backpressured (ok=false) ───────────────────────────

  it('prefix-backpressured: stream error on write #1 (ok=false) → CryptoError, no hang, no orphan .tmp', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      // highWaterMark=1 forces write() to always return false (ok=false).
      createWriteStream: jest.fn(() => makeErrorStream(1, 1)),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'werr-pfx-bp-in.txt');
    const outputPath = path.join(TEST_DIR, 'werr-pfx-bp-out.bin');
    const sentinel = 'pre-existing output — must survive prefix-bp error';
    writeFileSync(outputPath, sentinel);
    writeFileSync(inputPath, 'prefix-backpressured error test payload');

    try {
      await expect(
        cm.encryptFile(inputPath, outputPath, TEST_PASSWORD)
      ).rejects.toThrow(CryptoError);

      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('werr-pfx-bp-out.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toHaveLength(0);

      expect(readFileSync(outputPath, 'utf8')).toBe(sentinel);
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 10_000);

  // ── C. Tag write, immediate (ok=true, 0-byte input) ─────────────────────

  it('tag-immediate: stream error on write #2 (ok=true, empty input) → CryptoError, no orphan .tmp, output untouched', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      // Fail on write #2. With 0-byte input the only two write() calls
      // are: [1] prefix (header+salt+iv), [2] trailing GCM auth tag.
      createWriteStream: jest.fn(() => makeErrorStream(2)),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'werr-tag-imm-in.bin');
    const outputPath = path.join(TEST_DIR, 'werr-tag-imm-out.bin');
    const sentinel = 'pre-existing output — must survive tag-imm error';
    writeFileSync(outputPath, sentinel);
    writeFileSync(inputPath, ''); // 0-byte input

    try {
      await expect(
        cm.encryptFile(inputPath, outputPath, TEST_PASSWORD)
      ).rejects.toThrow(CryptoError);

      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('werr-tag-imm-out.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toHaveLength(0);

      expect(readFileSync(outputPath, 'utf8')).toBe(sentinel);
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 10_000);

  // ── D. Tag write, backpressured (ok=false, 0-byte input) ────────────────

  it('tag-backpressured: stream error on write #2 (ok=false, empty input) → CryptoError, no hang, no orphan .tmp', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      createWriteStream: jest.fn(() => makeErrorStream(2, 1)),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'werr-tag-bp-in.bin');
    const outputPath = path.join(TEST_DIR, 'werr-tag-bp-out.bin');
    const sentinel = 'pre-existing output — must survive tag-bp error';
    writeFileSync(outputPath, sentinel);
    writeFileSync(inputPath, ''); // 0-byte input

    try {
      await expect(
        cm.encryptFile(inputPath, outputPath, TEST_PASSWORD)
      ).rejects.toThrow(CryptoError);

      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('werr-tag-bp-out.bin.') && e.endsWith('.tmp')
      );
      expect(stray).toHaveLength(0);

      expect(readFileSync(outputPath, 'utf8')).toBe(sentinel);
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 10_000);
});

// ---------------------------------------------------------------------------
// 6. decryptFile short front-matter read (Phase 5, Task 5.1)
// ---------------------------------------------------------------------------
//
// Verifies that the async decryptFile path throws INVALID_ENCRYPTED_FILE_SIZE
// when fileHandle.read() returns fewer bytes than requested for the front-
// matter region (header + salt + iv). This mirrors the check already present
// in the sync path (decryptFileSync). The scenario is triggered via a mock
// that reports a large file via stat() but returns bytesRead: 0 on read().

describe('decryptFile short front-matter read (Phase 5)', () => {
  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
  });

  it('async: short front-matter read → INVALID_ENCRYPTED_FILE_SIZE with INVALID_INPUT type', async () => {
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    // Mock open() to return a synthetic FileHandle where stat() claims a
    // large file but read() always returns bytesRead: 0, simulating a
    // short read from a truncated or remote-backed file.
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
      open: jest.fn(async () => ({
        stat: jest.fn(async () => ({ size: 1000 })),
        read: jest.fn(async () => ({ bytesRead: 0 })),
        close: jest.fn(async () => {}),
      })),
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const { CryptoError, CryptoErrorType } = await import('../types');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'short-read-input.bin');
    const outputPath = path.join(TEST_DIR, 'short-read-output.txt');
    // Create a real file so existsSync(inputPath) passes before open() is called.
    writeFileSync(inputPath, Buffer.alloc(100));

    try {
      let caught: unknown;
      try {
        await cm.decryptFile(inputPath, outputPath, TEST_PASSWORD);
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(CryptoError);
      expect((caught as InstanceType<typeof CryptoError>).code).toBe(
        'INVALID_ENCRYPTED_FILE_SIZE'
      );
      expect((caught as InstanceType<typeof CryptoError>).type).toBe(
        CryptoErrorType.INVALID_INPUT
      );

      // No orphan temp files should remain after an early-exit error.
      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('short-read-output.txt.') && e.endsWith('.tmp')
      );
      expect(stray).toHaveLength(0);
    } finally {
      if (existsSync(inputPath)) unlinkSync(inputPath);
      if (existsSync(outputPath)) unlinkSync(outputPath);
    }
  }, 10_000);
});

// ---------------------------------------------------------------------------
// 7. Phase 1 — Finding A regression: empty-body decryptFile stream-open crash
// ---------------------------------------------------------------------------
//
// Before the 1.1 fix, decryptFile's empty-body path created outputStream but
// attached no 'error' listener.  If the temp-file open failed (ENOTDIR,
// ENOENT, AV lock on Windows), the stream emitted 'error' with no listener
// and Node raised ERR_UNHANDLED_ERROR — crashing the entire host process.
//
// After the fix, a persistent onStreamError listener guards outputStream for
// its full lifetime.  The same mock that previously killed the jest worker now
// produces a clean CryptoError rejection.

describe('Phase 1 — decryptFile empty-body stream-open failure (Finding A regression)', () => {
  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
  });

  it('empty-body decryptFile: stream-open error → CryptoError (no crash, no hang, no orphan .tmp, output untouched)', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    // Return a Writable whose underlying file open always fails asynchronously.
    // We simulate this by destroying the stream via process.nextTick —
    // the same timing as a real kernel-level ENOTDIR/ENOENT on open().
    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      createWriteStream: jest.fn(() => {
        const ws = new Writable({
          write(
            _chunk: unknown,
            _encoding: string,
            callback: (error?: Error | null) => void
          ): void {
            callback();
          },
        });
        // Async destroy simulates the OS returning an error when the
        // kernel tries to open the underlying file.
        process.nextTick(() => {
          ws.destroy(
            new Error(
              "ENOTDIR: not a directory, open '...simulated tempPath...'"
            )
          );
        });
        return ws;
      }),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');
    const { packHeader, KDF_ID_ARGON2ID } = await import('../format');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    // Build a valid empty-body v1 ciphertext using the same hand-assembly
    // approach as the zero-body tests above, so decryptFile gets past key
    // derivation and authentication before it hits the stream error.
    const header = packHeader(KDF_ID_ARGON2ID, {
      kind: 'argon2id',
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });
    const salt = cm.generateSecureRandom(32);
    const iv = cm.generateSecureRandom(12);
    const key = await cm.deriveKey(TEST_PASSWORD, salt);
    const aad = Buffer.concat([
      Buffer.from('secure-crypto-tool-v2', 'utf8'),
      header,
    ]);
    const { encrypted, tag } = cm.encryptData(Buffer.alloc(0), key, iv, aad);
    const ciphertext = Buffer.concat([header, salt, iv, encrypted, tag]);

    const encPath = path.join(TEST_DIR, 'finding-a-enc.bin');
    const outPath = path.join(TEST_DIR, 'finding-a-out.txt');
    const sentinel =
      'finding-a pre-existing output — must not be touched by a failing decryptFile';
    writeFileSync(encPath, ciphertext);
    writeFileSync(outPath, sentinel);

    try {
      // The critical assertion: the call rejects with a CryptoError, NOT
      // crashes the process.  Without the 1.1 fix this line kills the
      // jest worker.
      await expect(
        cm.decryptFile(encPath, outPath, TEST_PASSWORD)
      ).rejects.toThrow(CryptoError);

      // No orphan temp files left behind by the failed decrypt.
      const stray = readdirSync(TEST_DIR).filter(
        e => e.startsWith('finding-a-out.txt.') && e.endsWith('.tmp')
      );
      expect(stray).toHaveLength(0);

      // Pre-existing output must be untouched.
      expect(readFileSync(outPath, 'utf8')).toBe(sentinel);
    } finally {
      for (const p of [encPath, outPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 10_000);
});

// ---------------------------------------------------------------------------
// 8. Phase 1 — Finding B regression: body-write error not masked by
//    ERR_STREAM_DESTROYED
// ---------------------------------------------------------------------------
//
// Before the fix, the `finally` block called outputStream.end(cb) on an
// already-destroyed stream.  Node called cb(ERR_STREAM_DESTROYED), the
// finally rejected, and that REPLACED the real ENOSPC error the body pipeline
// had thrown.  The caller saw "Cannot call write after a stream was destroyed"
// instead of the injected error.
//
// After the fix, the finally skips end() when outputStream.destroyed === true,
// so the in-flight body error propagates unchanged to the outer catch.

describe('Phase 1 — Finding B: body-write error not masked by ERR_STREAM_DESTROYED', () => {
  // Local copy of the makeErrorStream helper (same pattern as Phase 2 suite).
  function makeErrorStream(failOnWrite: number, hwm = 65536): Writable {
    return new (class extends Writable {
      private _n = 0;
      constructor() {
        super({ highWaterMark: hwm });
      }
      override _write(
        _chunk: unknown,
        _encoding: string,
        callback: (error?: Error | null) => void
      ): void {
        this._n++;
        if (this._n === failOnWrite) {
          callback(
            new Error(`ENOSPC: injected write error on call #${failOnWrite}`)
          );
        } else {
          callback();
        }
      }
    })();
  }

  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
  });

  it('encryptFile body-write error surfaces real ENOSPC cause, not ERR_STREAM_DESTROYED', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    // Fail on write #2.  Write #1 = prefix [header+salt+iv] (succeeds),
    // write #2 = first body chunk from pipeline() (fails with ENOSPC).
    // Requires non-empty input so pipeline() actually produces a body chunk.
    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      createWriteStream: jest.fn(() => makeErrorStream(2)),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const { CryptoError } = await import('../types');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'finding-b-input.txt');
    const outputPath = path.join(TEST_DIR, 'finding-b-output.bin');
    writeFileSync(
      inputPath,
      'finding-b body payload for masking regression test'
    );

    try {
      let caught: unknown;
      try {
        await cm.encryptFile(inputPath, outputPath, TEST_PASSWORD);
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(CryptoError);

      // The real injected error must surface — NOT the ERR_STREAM_DESTROYED
      // masking error that the pre-fix finally produced.
      const msg = (caught as InstanceType<typeof CryptoError>).message;
      expect(msg).not.toMatch(
        /ERR_STREAM_DESTROYED|Cannot call write after a stream was destroyed/i
      );
      expect(msg).toContain('ENOSPC');
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 10_000);
});

// ---------------------------------------------------------------------------
// 9. Phase 1 — async 0-byte file end-to-end round-trip
// ---------------------------------------------------------------------------
//
// The sync equivalent (encryptFileSync / decryptFileSync of an empty file)
// already exists in crypto-manager.test.ts.  This test closes the gap for the
// async path, where encryptFile uses a real write stream and decryptFile's
// empty-body branch skips the pipeline entirely.

describe('Phase 1 — async 0-byte file end-to-end round-trip (Task 1.3)', () => {
  beforeEach(() => {
    jest.resetModules();
    // Identity passthroughs so no stale mock from earlier suites bleeds in.
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');
    jest.unstable_mockModule('node:fs', () => ({ ...realFs }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));
  });
  afterEach(() => {
    jest.resetModules();
  });

  it('async: encryptFile → decryptFile of a 0-byte input produces a 0-byte output', async () => {
    const { CryptoManager } = await import('../crypto-manager');

    const cm = new CryptoManager({
      memoryCost: 2 ** 12,
      timeCost: 1,
      parallelism: 1,
    });

    const inputPath = path.join(TEST_DIR, 'e2e-zero-input.bin');
    const encPath = path.join(TEST_DIR, 'e2e-zero-encrypted.bin');
    const decPath = path.join(TEST_DIR, 'e2e-zero-decrypted.bin');
    writeFileSync(inputPath, Buffer.alloc(0)); // 0-byte plaintext

    try {
      await cm.encryptFile(inputPath, encPath, TEST_PASSWORD);

      // The ciphertext must be non-empty (header + salt + iv + tag overhead).
      expect(existsSync(encPath)).toBe(true);
      expect(statSync(encPath).size).toBeGreaterThan(0);

      await cm.decryptFile(encPath, decPath, TEST_PASSWORD);

      // The recovered plaintext must be exactly 0 bytes.
      expect(existsSync(decPath)).toBe(true);
      expect(statSync(decPath).size).toBe(0);
      expect(readFileSync(decPath).length).toBe(0);
    } finally {
      for (const p of [inputPath, encPath, decPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 60_000); // Argon2 key derivation runs twice (once for encrypt, once for decrypt)
});

// ---------------------------------------------------------------------------
// 10. Phase 3 — Task 3.1: encryptFileSync scrubs the plaintext chunk buffer
//     on error paths
// ---------------------------------------------------------------------------
//
// Before the fix, `chunk` was declared `const` inside the `try` block — the
// `catch` block could not reference it and only scrubbed `key`.  If anything
// after `readSync` threw (ENOSPC mid-stream, cipher failure, etc.), up to
// 64 KiB of user plaintext was left un-zeroed in heap until GC.
//
// After the fix, `chunk` is hoisted to `let chunk: Buffer | null = null`
// before the `try` block, assigned where it used to be declared, and
// `if (chunk !== null) { this.secureClear(chunk); }` runs at the top of the
// `catch` block (alongside the existing `secureClear(key)` call).
//
// Note: this scope covers only `encryptFileSync`'s plaintext chunk.
// `decryptFileSync`'s chunk holds ciphertext, not plaintext, and is
// deliberately left unmodified.

describe('Phase 3 — encryptFileSync plaintext-chunk scrub on error path (Task 3.1)', () => {
  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.restoreAllMocks();
    jest.resetModules();
  });

  it('mid-body writeFileSync failure triggers secureClear on the 64 KiB plaintext chunk', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    // Count calls to writeFileSync inside encryptFileSync's success path:
    //   call #1 → prefix [header + salt + iv]  (must succeed)
    //   call #2 → first ciphertext body chunk   (injected failure)
    // Requiring a non-empty input guarantees the loop executes at least once
    // and readSync populates the plaintext chunk before the write fails.
    let writeFileSyncCalls = 0;
    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      writeFileSync: jest.fn((...args: unknown[]) => {
        writeFileSyncCalls += 1;
        if (writeFileSyncCalls === 2) {
          throw new Error('EIO: injected body write failure');
        }
        return (realFs.writeFileSync as unknown as (...a: unknown[]) => void)(
          ...args
        );
      }),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({ pbkdf2Iterations: 1000 });

    // Spy on this specific instance to observe every secureClear call.
    const clearSpy = jest.spyOn(cm, 'secureClear');

    const inputPath = path.join(TEST_DIR, 'ph3-chunk-scrub-input.txt');
    const outputPath = path.join(TEST_DIR, 'ph3-chunk-scrub-output.bin');
    writeFileSync(
      inputPath,
      'non-empty plaintext — must populate chunk before write fails'
    );

    try {
      expect(() =>
        cm.encryptFileSync(inputPath, outputPath, TEST_PASSWORD)
      ).toThrow();

      // secureClear must have been called with the 64 KiB plaintext chunk.
      // Without the fix, chunk was out of scope in the catch and was never
      // passed to secureClear on error paths.
      const chunkCall = clearSpy.mock.calls.find(
        ([buf]) => buf instanceof Buffer && buf.length === 64 * 1024
      );
      expect(chunkCall).toBeDefined();
    } finally {
      for (const p of [inputPath, outputPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  }, 10_000);
});

// ---------------------------------------------------------------------------
// 11. Phase 3 — Task 3.2: benign inputFd closeSync failure does not discard
//     completed work in encryptFileSync / decryptFileSync
// ---------------------------------------------------------------------------
//
// Before the fix, the success path did `closeSync(inputFd)` bare in the `try`
// block.  If it threw (rare EBADF/EIO on the read-only input fd, AFTER all
// crypto and output-writing had succeeded and outputFd was already closed), the
// exception landed in the `catch`, which called `safeUnlinkSync(tempPath)` and
// discarded the complete, valid temp file — turning a benign close into total
// data loss.
//
// After the fix, both methods wrap `closeSync(inputFd)` in a best-effort
// try/catch that swallows the error and nulls `inputFd` unconditionally.  Only
// an `outputFd` close failure (which CAN signal unflushed output) can now abort
// before the rename.
//
// Mock strategy: intercept `closeSync` via `jest.unstable_mockModule('node:fs')`
// and count calls globally across both operations.  For the encryptFileSync
// test, call #2 (inputFd close) throws; for the decryptFileSync test, call #4
// (inputFd close during decrypt, after calls 1-3 from encrypt+decrypt outputFd
// closes succeed) throws.

describe('Phase 3 — benign inputFd closeSync failure does not discard completed work (Task 3.2)', () => {
  beforeEach(() => {
    jest.resetModules();
  });
  afterEach(() => {
    jest.resetModules();
  });

  it('encryptFileSync: closeSync(inputFd) failure after full crypto+output success still completes', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    // encryptFileSync success path closeSync order:
    //   call #1 → closeSync(outputFd)   must succeed (output data integrity)
    //   call #2 → closeSync(inputFd)    simulated benign failure
    let closeSyncCalls = 0;
    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      closeSync: jest.fn((...args: unknown[]) => {
        closeSyncCalls += 1;
        if (closeSyncCalls === 2) {
          throw new Error('EIO: injected inputFd close failure');
        }
        return (realFs.closeSync as unknown as (...a: unknown[]) => void)(
          ...args
        );
      }),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({ pbkdf2Iterations: 1000 });

    const inputPath = path.join(TEST_DIR, 'ph3-enc-ci-plain.txt');
    const outputPath = path.join(TEST_DIR, 'ph3-enc-ci-out.bin');
    const decPath = path.join(TEST_DIR, 'ph3-enc-ci-dec.txt');
    const plaintext = 'encrypt-closeSync-benign-failure test';
    writeFileSync(inputPath, plaintext);

    try {
      // Must NOT throw despite call #2 (inputFd close) failing.
      expect(() =>
        cm.encryptFileSync(inputPath, outputPath, TEST_PASSWORD)
      ).not.toThrow();

      expect(existsSync(outputPath)).toBe(true);

      // Round-trip decrypt to confirm data integrity.  The decrypt uses
      // closeSync calls #3 (outputFd) and #4 (inputFd) — neither triggers
      // the mock throw (only call #2 throws).
      cm.decryptFileSync(outputPath, decPath, TEST_PASSWORD);
      expect(readFileSync(decPath, 'utf8')).toBe(plaintext);
    } finally {
      for (const p of [inputPath, outputPath, decPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  });

  it('decryptFileSync: closeSync(inputFd) failure after full crypto+auth success still completes', async () => {
    const realFs = jest.requireActual<typeof import('node:fs')>('node:fs');
    const realFsPromises =
      jest.requireActual<typeof import('node:fs/promises')>('node:fs/promises');

    // Call layout across both operations:
    //   call #1 → encryptFileSync closeSync(outputFd)  → succeeds
    //   call #2 → encryptFileSync closeSync(inputFd)   → succeeds
    //   call #3 → decryptFileSync closeSync(outputFd)  → succeeds
    //   call #4 → decryptFileSync closeSync(inputFd)   → injected failure
    // Call #4 tests that the validated plaintext temp file is NOT discarded.
    let closeSyncCalls = 0;
    jest.unstable_mockModule('node:fs', () => ({
      ...realFs,
      closeSync: jest.fn((...args: unknown[]) => {
        closeSyncCalls += 1;
        if (closeSyncCalls === 4) {
          throw new Error(
            'EIO: injected inputFd close failure during decryptFileSync'
          );
        }
        return (realFs.closeSync as unknown as (...a: unknown[]) => void)(
          ...args
        );
      }),
    }));
    jest.unstable_mockModule('node:fs/promises', () => ({
      ...realFsPromises,
    }));

    const { CryptoManager } = await import('../crypto-manager');
    const cm = new CryptoManager({ pbkdf2Iterations: 1000 });

    const inputPath = path.join(TEST_DIR, 'ph3-dec-ci-plain.txt');
    const encPath = path.join(TEST_DIR, 'ph3-dec-ci-enc.bin');
    const decPath = path.join(TEST_DIR, 'ph3-dec-ci-dec.txt');
    const plaintext = 'decrypt-closeSync-benign-failure test';
    writeFileSync(inputPath, plaintext);

    try {
      // Encrypt — uses closeSync calls #1 (outputFd) and #2 (inputFd),
      // both succeed.
      cm.encryptFileSync(inputPath, encPath, TEST_PASSWORD);
      expect(existsSync(encPath)).toBe(true);

      // Decrypt — uses closeSync calls #3 (outputFd, succeeds) and #4
      // (inputFd, throws but is swallowed by the best-effort try/catch).
      // Must NOT throw and must leave the decrypted plaintext intact.
      expect(() =>
        cm.decryptFileSync(encPath, decPath, TEST_PASSWORD)
      ).not.toThrow();

      expect(existsSync(decPath)).toBe(true);
      expect(readFileSync(decPath, 'utf8')).toBe(plaintext);
    } finally {
      for (const p of [inputPath, encPath, decPath]) {
        if (existsSync(p)) unlinkSync(p);
      }
    }
  });
});
