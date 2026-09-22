/**
 * Pre-authentication KDF cost policy (issue #2 — decrypt-side KDF ceilings).
 *
 * A v1 ciphertext header and a v2 container header both carry the Argon2id /
 * PBKDF2 cost parameters that produced them, and both are UNAUTHENTICATED: the
 * AES-GCM tag that covers them cannot be checked until a key has been derived,
 * and deriving that key is exactly the expensive step the header controls. The
 * wire-format caps in `format-core.ts` bound what the format can EXPRESS
 * (`memoryCost <= 2**22` = 4 GiB, `timeCost <= 100`, `parallelism <= 64`,
 * `iterations <= 10_000_000`); they say nothing about what a given process is
 * willing to SPEND before it knows the ciphertext is genuine. At those caps an
 * ~87-byte input buys roughly 400 GiB-passes of Argon2id (measured ~531 CPU
 * seconds) plus 4 GiB of resident memory, or 4.65 s of fully-blocked event loop
 * on the synchronous PBKDF2 paths.
 *
 * `decryptKdfLimits` is that second, per-instance budget. This suite pins it.
 *
 * What it pins:
 *   1. Every decrypt entry point that consumes header-derived parameters
 *      enforces the budget: `decryptBytes`, `decryptText`, `decryptContainer`,
 *      `decryptTextSync`, `decryptFile`, `decryptFileSync`. A future sixth path
 *      that forgets the check fails the table below rather than a researcher.
 *   2. Refusal happens BEFORE the KDF runs. Every case asserts the negative —
 *      the derivation was never invoked — and each negative is paired with a
 *      positive control arming the SAME spy on an in-budget ciphertext, so none
 *      of them can pass vacuously. **The spy target differs by path, and
 *      choosing the wrong one makes the negative vacuous rather than failing
 *      loudly**: the isomorphic and container paths derive through
 *      `CryptoCore.deriveKeyBytes`, which calls `engine.deriveArgon2id`, so
 *      `nodeEngine` is the right target; the Node `decryptFile` path derives
 *      through `CryptoManager.deriveKey`, which awaits `loadArgon2()` and calls
 *      `hasher.hash(...)` directly and never touches the engine primitive, so
 *      that case spies on `deriveKey` itself; and the synchronous paths reach
 *      `crypto.pbkdf2Sync` on the shared `node:crypto` module object.
 *   3. Each of the five ceilings is independently load-bearing, including the
 *      two that a pure `memoryCost x timeCost` budget is structurally blind to:
 *      `timeCost` and `parallelism` bound OS thread churn (libargon2 is built
 *      with threading and sets `ctx.threads = parallelism`, creating `lanes`
 *      threads per sync point per pass), and `maxWork` catches combinations in
 *      which each axis is individually legal.
 *   4. The boundary is inclusive: a value exactly AT a ceiling is accepted.
 *
 * Costs are kept low deliberately. Post-fix nothing here derives a key at all,
 * so the over-budget cases are cheap by construction; the in-budget positive
 * controls use a LOW_COST profile.
 */
import { describe, it, expect, jest, afterAll, afterEach } from '@jest/globals';
import * as realFs from 'node:fs';
import nodeCrypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

import {
  packHeader,
  KDF_ID_ARGON2ID,
  KDF_ID_PBKDF2_SHA256,
  DEFAULT_DECRYPT_KDF_LIMITS,
  resolveDecryptKdfLimits,
  assertKdfWithinDecryptLimits,
} from '../format-core';
import { CryptoManager } from '../crypto-manager';
import { nodeEngine } from '../engine.node';
import { CryptoError, CryptoErrorType } from '../types';

/** Test-only low-cost Argon2id profile (production default is 128 MiB). */
const LOW_COST = { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 } as const;
/** Test-only low iteration count for the synchronous PBKDF2 paths. */
const LOW_ITERS = 1000;

const PASSWORD = 'correct horse battery staple';

const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** Per-suite scratch directory; every case creates its own sub-directory. */
const TEST_DIR = realFs.mkdtempSync(
  path.join(os.tmpdir(), 'hiprax-crypto-decrypt-kdf-limits-')
);

function makeCaseDir(label: string): string {
  const dir = path.join(
    TEST_DIR,
    `${label}-${nodeCrypto.randomBytes(6).toString('hex')}`
  );
  realFs.mkdirSync(dir, { recursive: true });
  return dir;
}

afterAll(() => {
  realFs.rmSync(TEST_DIR, { recursive: true, force: true });
});

afterEach(() => {
  jest.restoreAllMocks();
});

interface Argon2idCost {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

/**
 * Build a v1 Argon2id ciphertext by hand. `packHeader` validates field WIDTH
 * only — the wire-format caps are applied at parse time — which is what lets a
 * test request a cost no honest producer would.
 *
 * The body is random: every assertion here is about work that must not happen,
 * so the bytes downstream of the guard are never reached.
 */
function craftArgon2idBlob(cost: Argon2idCost, tagFirst: boolean): Buffer {
  const header = packHeader(KDF_ID_ARGON2ID, { kind: 'argon2id', ...cost });
  const salt = nodeCrypto.randomBytes(SALT_LENGTH);
  const iv = nodeCrypto.randomBytes(IV_LENGTH);
  const tag = nodeCrypto.randomBytes(TAG_LENGTH);
  const body = nodeCrypto.randomBytes(1);
  // Text/in-memory layout puts the tag before the body; the file layout appends it.
  return Buffer.concat(
    tagFirst
      ? [Buffer.from(header), salt, iv, tag, body]
      : [Buffer.from(header), salt, iv, body, tag]
  );
}

function craftPbkdf2Blob(iterations: number, tagFirst: boolean): Buffer {
  const header = packHeader(KDF_ID_PBKDF2_SHA256, {
    kind: 'pbkdf2-sha256',
    iterations,
  });
  const salt = nodeCrypto.randomBytes(SALT_LENGTH);
  const iv = nodeCrypto.randomBytes(IV_LENGTH);
  const tag = nodeCrypto.randomBytes(TAG_LENGTH);
  const body = nodeCrypto.randomBytes(1);
  return Buffer.concat(
    tagFirst
      ? [Buffer.from(header), salt, iv, tag, body]
      : [Buffer.from(header), salt, iv, body, tag]
  );
}

/** Rewrite the Argon2id cost fields of an already-built v1/v2 header in place. */
function retargetArgon2idCost(
  blob: Uint8Array,
  cost: Argon2idCost
): Uint8Array {
  const copy = Uint8Array.from(blob);
  const view = new DataView(copy.buffer, copy.byteOffset, copy.byteLength);
  view.setUint32(6, cost.memoryCost, false);
  view.setUint32(10, cost.timeCost, false);
  view.setUint16(14, cost.parallelism, false);
  return copy;
}

async function captureError(invoke: () => unknown): Promise<CryptoError> {
  let thrown: unknown;
  try {
    await invoke();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(CryptoError);
  return thrown as CryptoError;
}

/**
 * The four over-budget shapes, one per ceiling, chosen so that EVERY one is
 * computationally trivial if the guard fails to fire — a test suite must not
 * need 4 GiB to prove that 4 GiB is refused.
 */
const OVER_BUDGET: ReadonlyArray<{
  label: string;
  cost: Argon2idCost;
  axis: RegExp;
}> = [
  {
    label: 'parallelism above the ceiling (thread churn; m*t is blind to it)',
    cost: { memoryCost: 2 ** 12, timeCost: 1, parallelism: 32 },
    axis: /parallelism/i,
  },
  {
    label: 'timeCost above the ceiling',
    cost: { memoryCost: 2 ** 12, timeCost: 50, parallelism: 1 },
    axis: /timeCost/i,
  },
  {
    label: 'memoryCost above the ceiling',
    cost: { memoryCost: 2 ** 21, timeCost: 1, parallelism: 1 },
    axis: /memoryCost/i,
  },
  {
    label: 'each axis legal but the work product over the ceiling',
    cost: { memoryCost: 2 ** 19, timeCost: 9, parallelism: 1 },
    axis: /work/i,
  },
];

describe('decrypt KDF cost policy — the async Argon2id in-memory paths', () => {
  for (const variant of OVER_BUDGET) {
    it(`decryptBytes refuses ${variant.label} without deriving a key`, async () => {
      const cm = new CryptoManager(LOW_COST);
      const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');
      const blob = craftArgon2idBlob(variant.cost, true);

      const err = await captureError(() => cm.decryptBytes(blob, PASSWORD));

      expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
      expect(err.type).toBe(CryptoErrorType.INVALID_INPUT);
      expect(err.message).toMatch(variant.axis);
      expect(deriveSpy).not.toHaveBeenCalled();
    });
  }

  it('decryptText refuses an over-budget ciphertext without deriving a key', async () => {
    const cm = new CryptoManager(LOW_COST);
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');
    const blob = craftArgon2idBlob(
      { memoryCost: 2 ** 21, timeCost: 1, parallelism: 1 },
      true
    );

    const err = await captureError(() =>
      cm.decryptText(blob.toString('base64url'), PASSWORD)
    );

    expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
    expect(deriveSpy).not.toHaveBeenCalled();
  });

  it('POSITIVE CONTROL: the same spy records a derivation for an in-budget ciphertext', async () => {
    const cm = new CryptoManager(LOW_COST);
    const real = await cm.encryptBytes(
      new TextEncoder().encode('hi'),
      PASSWORD
    );
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const out = await cm.decryptBytes(real, PASSWORD);

    expect(new TextDecoder().decode(out)).toBe('hi');
    expect(deriveSpy).toHaveBeenCalledTimes(1);
  }, 30_000);
});

describe('decrypt KDF cost policy — the synchronous PBKDF2 paths', () => {
  it('decryptTextSync refuses an over-budget iteration count without deriving a key', () => {
    const cm = new CryptoManager({ ...LOW_COST, pbkdf2Iterations: LOW_ITERS });
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');
    const blob = craftPbkdf2Blob(9_000_000, true);

    let thrown: unknown;
    try {
      cm.decryptTextSync(blob.toString('base64url'), PASSWORD);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBeInstanceOf(CryptoError);
    const err = thrown as CryptoError;
    expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
    expect(err.type).toBe(CryptoErrorType.INVALID_INPUT);
    expect(err.message).toMatch(/iterations/i);
    expect(pbkdf2Spy).not.toHaveBeenCalled();
  });

  it('POSITIVE CONTROL: the same spy records a derivation for an in-budget sync ciphertext', () => {
    const cm = new CryptoManager({ ...LOW_COST, pbkdf2Iterations: LOW_ITERS });
    const real = cm.encryptTextSync('hi', PASSWORD);
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    expect(cm.decryptTextSync(real, PASSWORD)).toBe('hi');
    expect(pbkdf2Spy).toHaveBeenCalledTimes(1);
  });
});

describe('decrypt KDF cost policy — the streaming file paths', () => {
  it('decryptFile refuses an over-budget header before deriving a key or writing a temp file', async () => {
    const cm = new CryptoManager(LOW_COST);
    const dir = makeCaseDir('dec-async');
    const input = path.join(dir, 'in.bin');
    const output = path.join(dir, 'out.bin');
    realFs.writeFileSync(
      input,
      craftArgon2idBlob(
        { memoryCost: 2 ** 21, timeCost: 1, parallelism: 1 },
        false
      )
    );
    // NOT `nodeEngine.deriveArgon2id`: the Node `decryptFile` path derives
    // through `CryptoManager.deriveKey`, which awaits `loadArgon2()` and calls
    // `hasher.hash(...)` directly rather than going through the engine
    // primitive. A spy on the engine here could never fire with OR without the
    // guard, which would make the negative vacuous. `deriveKey` is the real
    // boundary for this path, and `jest.spyOn` calls through, so the positive
    // control below proves the spy is wired to something live.
    const deriveSpy = jest.spyOn(cm, 'deriveKey');

    const err = await captureError(() =>
      cm.decryptFile(input, output, PASSWORD)
    );

    expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
    expect(deriveSpy).not.toHaveBeenCalled();
    expect(realFs.existsSync(output)).toBe(false);
    expect(realFs.readdirSync(dir).filter(n => n.endsWith('.tmp'))).toEqual([]);
  });

  it('POSITIVE CONTROL: the same deriveKey spy records a derivation for an in-budget file', async () => {
    const cm = new CryptoManager(LOW_COST);
    const dir = makeCaseDir('dec-async-control');
    const plain = path.join(dir, 'plain.txt');
    const sealed = path.join(dir, 'sealed.bin');
    const opened = path.join(dir, 'opened.txt');
    realFs.writeFileSync(plain, 'hello');
    await cm.encryptFile(plain, sealed, PASSWORD);
    const deriveSpy = jest.spyOn(cm, 'deriveKey');

    await cm.decryptFile(sealed, opened, PASSWORD);

    expect(realFs.readFileSync(opened, 'utf8')).toBe('hello');
    expect(deriveSpy).toHaveBeenCalledTimes(1);
  }, 30_000);

  it('decryptFileSync refuses an over-budget iteration count before the KDF or a temp file', () => {
    const cm = new CryptoManager({ ...LOW_COST, pbkdf2Iterations: LOW_ITERS });
    const dir = makeCaseDir('dec-sync');
    const input = path.join(dir, 'in.bin');
    const output = path.join(dir, 'out.bin');
    realFs.writeFileSync(input, craftPbkdf2Blob(9_000_000, false));
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    let thrown: unknown;
    try {
      cm.decryptFileSync(input, output, PASSWORD);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).toBeInstanceOf(CryptoError);
    expect((thrown as CryptoError).code).toBe(
      'KDF_COST_EXCEEDS_DECRYPT_LIMITS'
    );
    expect(pbkdf2Spy).not.toHaveBeenCalled();
    expect(realFs.existsSync(output)).toBe(false);
    expect(realFs.readdirSync(dir).filter(n => n.endsWith('.tmp'))).toEqual([]);
  });

  it('POSITIVE CONTROL: the same pbkdf2Sync spy records a derivation for an in-budget file', () => {
    const cm = new CryptoManager({ ...LOW_COST, pbkdf2Iterations: LOW_ITERS });
    const dir = makeCaseDir('dec-sync-control');
    const plain = path.join(dir, 'plain.txt');
    const sealed = path.join(dir, 'sealed.bin');
    const opened = path.join(dir, 'opened.txt');
    realFs.writeFileSync(plain, 'hello');
    cm.encryptFileSync(plain, sealed, PASSWORD);
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    cm.decryptFileSync(sealed, opened, PASSWORD);

    expect(realFs.readFileSync(opened, 'utf8')).toBe('hello');
    expect(pbkdf2Spy).toHaveBeenCalledTimes(1);
  });
});

describe('decrypt KDF cost policy — the v2 container path', () => {
  it('decryptContainer refuses an over-budget header without deriving a key', async () => {
    const cm = new CryptoManager(LOW_COST);
    const sealed = await cm.encryptContainer(
      new TextEncoder().encode('payload'),
      PASSWORD,
      { filename: 'a.txt' }
    );
    const tampered = retargetArgon2idCost(sealed, {
      memoryCost: 2 ** 21,
      timeCost: 1,
      parallelism: 1,
    });
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const err = await captureError(() =>
      cm.decryptContainer(tampered, PASSWORD)
    );

    expect(err.code).toBe('CONTAINER_KDF_COST_EXCEEDS_DECRYPT_LIMITS');
    expect(err.type).toBe(CryptoErrorType.INVALID_INPUT);
    expect(deriveSpy).not.toHaveBeenCalled();
  }, 30_000);

  it('decryptContainer reports the CONTAINER-prefixed code for a below-floor header too', async () => {
    // The container path passes BOTH custom codes, so the floor branch needs its
    // own case: the over-budget test above only proves `exceedsCode` is wired.
    const cm = new CryptoManager(LOW_COST);
    const sealed = await cm.encryptContainer(
      new TextEncoder().encode('payload'),
      PASSWORD
    );
    // LOW_COST is 2 ** 14 * 1 = 16 384 work, so a floor above that refuses it.
    const strict = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: { minWork: 2 ** 15 },
    });
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const err = await captureError(() =>
      strict.decryptContainer(sealed, PASSWORD)
    );

    expect(err.code).toBe('CONTAINER_KDF_COST_BELOW_DECRYPT_MINIMUM');
    expect(err.type).toBe(CryptoErrorType.INVALID_INPUT);
    expect(deriveSpy).not.toHaveBeenCalled();
  }, 30_000);

  it('POSITIVE CONTROL: the same engine spy records a derivation for an in-budget container', async () => {
    const cm = new CryptoManager(LOW_COST);
    const sealed = await cm.encryptContainer(
      new TextEncoder().encode('payload'),
      PASSWORD,
      { filename: 'a.txt' }
    );
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const opened = await cm.decryptContainer(sealed, PASSWORD);

    expect(new TextDecoder().decode(opened.data)).toBe('payload');
    expect(opened.meta.filename).toBe('a.txt');
    expect(deriveSpy).toHaveBeenCalledTimes(1);
  }, 30_000);
});

describe('decrypt KDF cost policy — floors bind the headerless fallback too', () => {
  // A headerless blob carries no attacker-supplied parameters, so before v1.9.0
  // the floor was skipped entirely and the blob was answered at this instance's
  // own fallback cost. That made the floor trivially bypassable: strip the
  // header and the sync paths derive at `legacyPbkdf2Iterations` (100 000 by
  // default), six times below a typical 600 000 floor. The check now asks
  // whether the derivation ABOUT TO HAPPEN meets the floor, which closes the
  // bypass without refusing input that genuinely satisfies it.

  /**
   * A v0-shaped blob: no header at all. `body` bytes of payload follow the
   * salt + iv + tag front matter, which is enough to clear every
   * minimum-size check on both the in-memory and the file paths.
   */
  function v0Blob(body = 1): Buffer {
    return Buffer.concat([
      nodeCrypto.randomBytes(SALT_LENGTH),
      nodeCrypto.randomBytes(IV_LENGTH),
      nodeCrypto.randomBytes(TAG_LENGTH),
      nodeCrypto.randomBytes(body),
    ]);
  }

  it('refuses a headerless blob whose PBKDF2 fallback count is below the floor, without deriving', () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      legacyPbkdf2Iterations: LOW_ITERS,
      decryptKdfLimits: { minPbkdf2Iterations: 600_000 },
    });
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    let thrown: unknown;
    try {
      cm.decryptTextSync(v0Blob().toString('base64url'), PASSWORD);
    } catch (err) {
      thrown = err;
    }

    expect((thrown as CryptoError).code).toBe(
      'FALLBACK_KDF_COST_BELOW_DECRYPT_MINIMUM'
    );
    expect((thrown as CryptoError).type).toBe(CryptoErrorType.INVALID_INPUT);
    expect((thrown as CryptoError).message).toMatch(/legacyPbkdf2Iterations/);
    // The whole point: no derivation was paid for an input that cannot satisfy
    // the floor.
    expect(pbkdf2Spy).not.toHaveBeenCalled();
  });

  it('ACCEPTS a headerless blob whose PBKDF2 fallback count meets the floor', () => {
    // The false-positive guard. An operator whose v0 data was produced at a
    // count that already satisfies the floor keeps the documented remedy of
    // raising `legacyPbkdf2Iterations` rather than switching `legacyMode`.
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      legacyPbkdf2Iterations: 2000,
      decryptKdfLimits: { minPbkdf2Iterations: 2000 },
    });
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    let thrown: unknown;
    try {
      cm.decryptTextSync(v0Blob().toString('base64url'), PASSWORD);
    } catch (err) {
      thrown = err;
    }

    // Accepted by the policy, derived at the fallback count, and only THEN
    // failed GCM on the random body — which is what proves the floor let it by.
    expect((thrown as CryptoError).code).toBe('DECRYPTION_FAILED');
    expect(pbkdf2Spy).toHaveBeenCalledTimes(1);
    expect(pbkdf2Spy.mock.calls[0]?.[2]).toBe(2000);
  });

  it('refuses a headerless blob whose Argon2id fallback work is below minWork, without deriving', async () => {
    // LOW_COST work is 2 ** 14 * 1 = 16 384.
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: { minWork: 2 ** 15 },
    });
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const err = await captureError(() => cm.decryptBytes(v0Blob(), PASSWORD));

    expect(err.code).toBe('FALLBACK_KDF_COST_BELOW_DECRYPT_MINIMUM');
    expect(err.type).toBe(CryptoErrorType.INVALID_INPUT);
    expect(err.message).toMatch(/minWork/);
    expect(deriveSpy).not.toHaveBeenCalled();
  });

  it('ACCEPTS a headerless blob whose Argon2id fallback work meets minWork exactly', async () => {
    // The boundary is inclusive here too: 16 384 work against a 16 384 floor.
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: { minWork: 2 ** 14 },
    });
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const err = await captureError(() => cm.decryptBytes(v0Blob(), PASSWORD));

    expect(err.code).toBe('DECRYPTION_FAILED');
    expect(deriveSpy).toHaveBeenCalledTimes(1);
  }, 30_000);

  it('is inert when no floor is configured', async () => {
    // Both floors default to 0, so nothing about the headerless path changes
    // for the overwhelming majority of managers.
    const cm = new CryptoManager(LOW_COST);
    expect(cm.getDecryptKdfLimits().minWork).toBe(0);
    expect(cm.getDecryptKdfLimits().minPbkdf2Iterations).toBe(0);
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const err = await captureError(() => cm.decryptBytes(v0Blob(), PASSWORD));

    expect(err.code).toBe('DECRYPTION_FAILED');
    expect(deriveSpy).toHaveBeenCalledTimes(1);
  }, 30_000);

  it('also fires on the legacyMode auto fallback taken by a KDF-mismatched v1 ciphertext', () => {
    // `headerKdfParams` is null not only for a genuine v0 blob but for anything
    // the 'auto' catch routes to the v0 path — here a v1 Argon2id ciphertext fed
    // to the synchronous path, whose `assertKdfMatches` throws KDF_MISMATCH.
    // The fallback cost is the same, so the same question is the right one.
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      legacyPbkdf2Iterations: LOW_ITERS,
      decryptKdfLimits: { minPbkdf2Iterations: 600_000 },
    });
    const argon2idV1 = craftArgon2idBlob(LOW_COST, true);
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    let thrown: unknown;
    try {
      cm.decryptTextSync(argon2idV1.toString('base64url'), PASSWORD);
    } catch (err) {
      thrown = err;
    }

    expect((thrown as CryptoError).code).toBe(
      'FALLBACK_KDF_COST_BELOW_DECRYPT_MINIMUM'
    );
    expect(pbkdf2Spy).not.toHaveBeenCalled();
  });

  it('decryptFile refuses a headerless file whose Argon2id fallback work is below minWork, without deriving', async () => {
    // The two FILE paths need their own cases: they are separate call sites,
    // and a mutation that neuters either of them leaves every other case in
    // this describe green. Verified by neutering both and observing the suite
    // stay at 1238 passing before these two were added.
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: { minWork: 2 ** 15 },
    });
    const dir = makeCaseDir('fallback-floor-async');
    const input = path.join(dir, 'in.bin');
    const output = path.join(dir, 'out.bin');
    realFs.writeFileSync(input, v0Blob(64));
    // `cm.deriveKey`, NOT `nodeEngine.deriveArgon2id`: this path derives through
    // `CryptoManager.deriveKey`, so an engine spy could never fire with OR
    // without the guard and the negative would be vacuous.
    const deriveSpy = jest.spyOn(cm, 'deriveKey');

    const err = await captureError(() =>
      cm.decryptFile(input, output, PASSWORD)
    );

    expect(err.code).toBe('FALLBACK_KDF_COST_BELOW_DECRYPT_MINIMUM');
    expect(err.type).toBe(CryptoErrorType.INVALID_INPUT);
    expect(deriveSpy).not.toHaveBeenCalled();
    // Nothing was written, and no temp file was left behind.
    expect(realFs.existsSync(output)).toBe(false);
    expect(realFs.readdirSync(dir).filter(n => n.endsWith('.tmp'))).toEqual([]);
  });

  it('POSITIVE CONTROL: the same deriveKey spy fires for a headerless file that meets minWork', async () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: { minWork: 2 ** 14 },
    });
    const dir = makeCaseDir('fallback-floor-async-ok');
    const input = path.join(dir, 'in.bin');
    const output = path.join(dir, 'out.bin');
    realFs.writeFileSync(input, v0Blob(64));
    const deriveSpy = jest.spyOn(cm, 'deriveKey');

    const err = await captureError(() =>
      cm.decryptFile(input, output, PASSWORD)
    );

    // Past the floor, derived, then failed GCM on the random body.
    expect(err.code).toBe('FILE_DECRYPTION_FAILED');
    expect(deriveSpy).toHaveBeenCalledTimes(1);
  }, 30_000);

  it('decryptFileSync refuses a headerless file whose PBKDF2 fallback count is below the floor, without deriving', () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      legacyPbkdf2Iterations: LOW_ITERS,
      decryptKdfLimits: { minPbkdf2Iterations: 600_000 },
    });
    const dir = makeCaseDir('fallback-floor-sync');
    const input = path.join(dir, 'in.bin');
    const output = path.join(dir, 'out.bin');
    realFs.writeFileSync(input, v0Blob(64));
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    let thrown: unknown;
    try {
      cm.decryptFileSync(input, output, PASSWORD);
    } catch (err) {
      thrown = err;
    }

    expect((thrown as CryptoError).code).toBe(
      'FALLBACK_KDF_COST_BELOW_DECRYPT_MINIMUM'
    );
    expect(pbkdf2Spy).not.toHaveBeenCalled();
    expect(realFs.existsSync(output)).toBe(false);
    expect(realFs.readdirSync(dir).filter(n => n.endsWith('.tmp'))).toEqual([]);
  });

  it('POSITIVE CONTROL: the same pbkdf2Sync spy fires for a headerless file that meets the floor', () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      legacyPbkdf2Iterations: 2000,
      decryptKdfLimits: { minPbkdf2Iterations: 2000 },
    });
    const dir = makeCaseDir('fallback-floor-sync-ok');
    const input = path.join(dir, 'in.bin');
    const output = path.join(dir, 'out.bin');
    realFs.writeFileSync(input, v0Blob(64));
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    let thrown: unknown;
    try {
      cm.decryptFileSync(input, output, PASSWORD);
    } catch (err) {
      thrown = err;
    }

    expect((thrown as CryptoError).code).toBe('SYNC_FILE_DECRYPTION_FAILED');
    expect(pbkdf2Spy).toHaveBeenCalledTimes(1);
    expect(pbkdf2Spy.mock.calls[0]?.[2]).toBe(2000);
  });

  it('refuses headerless input outright under legacyMode strict, ahead of the floor check', () => {
    // Unchanged behaviour, kept because it is the other documented remedy and
    // because it proves `enforceLegacyMode` still runs first.
    const strict = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      legacyMode: 'strict',
      decryptKdfLimits: { minPbkdf2Iterations: 600_000 },
    });
    let strictThrown: unknown;
    try {
      strict.decryptTextSync(v0Blob().toString('base64url'), PASSWORD);
    } catch (err) {
      strictThrown = err;
    }
    expect((strictThrown as CryptoError).code).toBe('LEGACY_FORMAT_REJECTED');
  });
});

describe('decrypt KDF cost policy — the boundary is inclusive', () => {
  /**
   * Boundaries are exercised against TIGHT EXPLICIT limits rather than the
   * generous defaults, so that an accepted case runs a cheap real derivation
   * instead of a 512 MiB one. An explicit limit is honoured exactly and never
   * widened, which is what makes this possible.
   */
  const TIGHT = {
    maxMemoryCost: 2 ** 14,
    maxTimeCost: 2,
    maxParallelism: 2,
    maxWork: 2 ** 15,
    maxPbkdf2Iterations: 5000,
  } as const;

  const atLimit: ReadonlyArray<{ label: string; cost: Argon2idCost }> = [
    {
      label: 'memoryCost exactly at maxMemoryCost',
      cost: { memoryCost: 2 ** 14, timeCost: 1, parallelism: 1 },
    },
    {
      label: 'timeCost exactly at maxTimeCost',
      cost: { memoryCost: 2 ** 12, timeCost: 2, parallelism: 1 },
    },
    {
      label: 'parallelism exactly at maxParallelism',
      cost: { memoryCost: 2 ** 12, timeCost: 1, parallelism: 2 },
    },
    {
      label: 'work exactly at maxWork',
      cost: { memoryCost: 2 ** 14, timeCost: 2, parallelism: 1 },
    },
  ];

  for (const variant of atLimit) {
    it(`accepts ${variant.label} and proceeds to the KDF`, async () => {
      const cm = new CryptoManager({ ...LOW_COST, decryptKdfLimits: TIGHT });
      const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');
      const blob = craftArgon2idBlob(variant.cost, true);

      const err = await captureError(() => cm.decryptBytes(blob, PASSWORD));

      // The policy let it through; the random body then fails GCM, which is
      // the proof that the ciphertext was not refused up front.
      expect(err.code).toBe('DECRYPTION_FAILED');
      expect(deriveSpy).toHaveBeenCalledTimes(1);
    }, 30_000);
  }

  const overLimit: ReadonlyArray<{ label: string; cost: Argon2idCost }> = [
    {
      label: 'memoryCost one KiB over',
      cost: { memoryCost: 2 ** 14 + 1, timeCost: 1, parallelism: 1 },
    },
    {
      label: 'timeCost one pass over',
      cost: { memoryCost: 2 ** 12, timeCost: 3, parallelism: 1 },
    },
    {
      label: 'parallelism one lane over',
      cost: { memoryCost: 2 ** 12, timeCost: 1, parallelism: 3 },
    },
  ];

  for (const variant of overLimit) {
    it(`refuses ${variant.label} without deriving a key`, async () => {
      const cm = new CryptoManager({ ...LOW_COST, decryptKdfLimits: TIGHT });
      const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

      const err = await captureError(() =>
        cm.decryptBytes(craftArgon2idBlob(variant.cost, true), PASSWORD)
      );

      expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
      expect(deriveSpy).not.toHaveBeenCalled();
    });
  }

  it('accepts PBKDF2 iterations exactly at the ceiling and refuses one more', () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      decryptKdfLimits: TIGHT,
    });

    let atErr: unknown;
    try {
      cm.decryptTextSync(
        craftPbkdf2Blob(5000, true).toString('base64url'),
        PASSWORD
      );
    } catch (err) {
      atErr = err;
    }
    expect((atErr as CryptoError).code).toBe('DECRYPTION_FAILED');

    let overErr: unknown;
    try {
      cm.decryptTextSync(
        craftPbkdf2Blob(5001, true).toString('base64url'),
        PASSWORD
      );
    } catch (err) {
      overErr = err;
    }
    expect((overErr as CryptoError).code).toBe(
      'KDF_COST_EXCEEDS_DECRYPT_LIMITS'
    );
  });

  it('refuses a work product over the ceiling while every axis stays individually legal', async () => {
    // The `atLimit` loop above already pins that a product exactly AT `maxWork`
    // is accepted. This is the complementary case and the reason `maxWork`
    // exists: with `maxWork` one KiB-pass lower, the SAME header — whose
    // memoryCost and timeCost are each still within their own ceilings — is
    // refused on the product alone.
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: { ...TIGHT, maxWork: 2 ** 15 - 1 },
    });
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');
    const cost: Argon2idCost = {
      memoryCost: 2 ** 14,
      timeCost: 2,
      parallelism: 1,
    };
    const limits = cm.getDecryptKdfLimits();
    expect(cost.memoryCost).toBeLessThanOrEqual(limits.maxMemoryCost);
    expect(cost.timeCost).toBeLessThanOrEqual(limits.maxTimeCost);
    expect(cost.memoryCost * cost.timeCost).toBeGreaterThan(limits.maxWork);

    const err = await captureError(() =>
      cm.decryptBytes(craftArgon2idBlob(cost, true), PASSWORD)
    );

    expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
    expect(err.message).toMatch(/work \(memoryCost x timeCost\)/);
    expect(deriveSpy).not.toHaveBeenCalled();
  });
});

describe('decrypt KDF cost policy — a manager can always read its own output', () => {
  it('widens an omitted ceiling to this instance own cost, above the runtime default', () => {
    // 2**21 memoryCost and timeCost 40 both exceed the Node defaults
    // (2**19 / 10), and the work product 2**21 * 40 exceeds 2**22 as well.
    const cm = new CryptoManager({
      memoryCost: 2 ** 21,
      timeCost: 40,
      parallelism: 1,
    });
    const limits = cm.getDecryptKdfLimits();

    expect(limits.maxMemoryCost).toBe(2 ** 21);
    expect(limits.maxTimeCost).toBe(40);
    expect(limits.maxWork).toBe(2 ** 21 * 40);
    // A ciphertext this manager produces is therefore inside its own budget.
    expect(2 ** 21 * 40).toBeLessThanOrEqual(limits.maxWork);
  });

  it('widens the PBKDF2 ceiling to a deliberately high configured count', () => {
    const cm = new CryptoManager({ pbkdf2Iterations: 5_000_000 });
    expect(cm.getDecryptKdfLimits().maxPbkdf2Iterations).toBe(5_000_000);
  });

  it('does NOT widen a ceiling the caller set explicitly', () => {
    const cm = new CryptoManager({
      memoryCost: 2 ** 21,
      timeCost: 1,
      parallelism: 1,
      decryptKdfLimits: { maxMemoryCost: 2 ** 16 },
    });
    // An explicit limit is a deliberate policy statement, even one that makes
    // this manager unable to read its own output (a legitimate shape for a
    // service that seals for cold storage but accepts only cheap input).
    expect(cm.getDecryptKdfLimits().maxMemoryCost).toBe(2 ** 16);
  });

  it('returns a copy, so a caller cannot mutate the policy', () => {
    const cm = new CryptoManager(LOW_COST);
    const first = cm.getDecryptKdfLimits();
    first.maxMemoryCost = 1;
    expect(cm.getDecryptKdfLimits().maxMemoryCost).not.toBe(1);
  });
});

describe('decrypt KDF cost policy — opt-in floors', () => {
  const CHEAP: Argon2idCost = {
    memoryCost: 2 ** 12,
    timeCost: 1,
    parallelism: 1,
  };

  it('has no floor by default, so a deliberately cheap ciphertext is honoured', async () => {
    const cm = new CryptoManager(LOW_COST);
    expect(cm.getDecryptKdfLimits().minWork).toBe(0);
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const err = await captureError(() =>
      cm.decryptBytes(craftArgon2idBlob(CHEAP, true), PASSWORD)
    );

    expect(err.code).toBe('DECRYPTION_FAILED');
    expect(deriveSpy).toHaveBeenCalledTimes(1);
  }, 30_000);

  it('refuses a below-floor ciphertext when minWork is set, without deriving a key', async () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: { minWork: 2 ** 16 },
    });
    const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

    const err = await captureError(() =>
      cm.decryptBytes(craftArgon2idBlob(CHEAP, true), PASSWORD)
    );

    expect(err.code).toBe('KDF_COST_BELOW_DECRYPT_MINIMUM');
    expect(err.type).toBe(CryptoErrorType.INVALID_INPUT);
    expect(deriveSpy).not.toHaveBeenCalled();
  });

  it('refuses a below-floor PBKDF2 iteration count when minPbkdf2Iterations is set', () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      decryptKdfLimits: { minPbkdf2Iterations: 600_000 },
    });
    const pbkdf2Spy = jest.spyOn(nodeCrypto, 'pbkdf2Sync');

    let thrown: unknown;
    try {
      cm.decryptTextSync(
        craftPbkdf2Blob(1000, true).toString('base64url'),
        PASSWORD
      );
    } catch (err) {
      thrown = err;
    }

    expect((thrown as CryptoError).code).toBe('KDF_COST_BELOW_DECRYPT_MINIMUM');
    expect(pbkdf2Spy).not.toHaveBeenCalled();
  });
});

describe('decrypt KDF cost policy — legacyMode cannot mask it', () => {
  // `legacyMode: 'auto'` swallows a header-parse failure and retries the blob
  // as v0. The policy check sits outside that catch on purpose, so the new
  // codes must surface in ALL THREE modes rather than degrading to the generic
  // DECRYPTION_FAILED / INVALID_ENCRYPTED_DATA_SIZE that `auto` otherwise
  // reports.
  for (const legacyMode of ['auto', 'strict', 'reject'] as const) {
    it(`surfaces the specific code under legacyMode: '${legacyMode}'`, async () => {
      const cm = new CryptoManager({ ...LOW_COST, legacyMode });
      const deriveSpy = jest.spyOn(nodeEngine, 'deriveArgon2id');

      const err = await captureError(() =>
        cm.decryptBytes(
          craftArgon2idBlob(
            { memoryCost: 2 ** 21, timeCost: 1, parallelism: 1 },
            true
          ),
          PASSWORD
        )
      );

      expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
      expect(deriveSpy).not.toHaveBeenCalled();
    });
  }
});

describe('decrypt KDF cost policy — what it deliberately does NOT cover', () => {
  // These three cases pin INTENTIONAL exemptions. Each is documented and load
  // bearing, and each was previously unpinned, so a future contributor could
  // have "helpfully" closed one and broken the documented pattern with a green
  // suite. Every case therefore pairs the exemption with proof that the policy
  // DOES fire on the same parameters through the high-level path — otherwise it
  // would only be asserting that some call did not throw, which a broken policy
  // also satisfies.

  /** Tight, explicit ceilings. Explicit ones are never widened. */
  const TIGHT_LIMITS = {
    maxMemoryCost: 2 ** 14,
    maxTimeCost: 1,
    maxWork: 2 ** 14,
    maxPbkdf2Iterations: 1000,
  } as const;

  /** Over TIGHT_LIMITS, but cheap enough to actually run. */
  const OVER_BUDGET_COST = {
    memoryCost: 2 ** 15,
    timeCost: 1,
    parallelism: 1,
  } as const;
  const OVER_BUDGET_ITERS = 5000;

  it('inspectHeader classifies an over-budget header instead of refusing it', async () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: TIGHT_LIMITS,
    });
    const blob = craftArgon2idBlob(OVER_BUDGET_COST, true);

    // The exemption: it parses and returns, applying the wire-format caps only.
    const header = cm.inspectHeader(blob);
    // Narrow by throwing rather than asserting non-null, so the rest of the
    // case cannot run against a null and report a confusing failure.
    if (header === null) {
      throw new Error('inspectHeader returned null for a v1 ciphertext');
    }
    expect(header.params).toEqual({
      kind: 'argon2id',
      ...OVER_BUDGET_COST,
    });

    // The pairing that makes the assertion above mean something: the same bytes
    // through the decrypt path ARE refused, so the exemption is specific to
    // inspectHeader rather than the policy being broken outright.
    const err = await captureError(() => cm.decryptBytes(blob, PASSWORD));
    expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');

    // And the documented pre-screen recipe reaches the same verdict by hand,
    // which is the whole reason inspectHeader is allowed to stay permissive:
    // the caller can apply the budget without the classifier doing it for them.
    expect(() =>
      assertKdfWithinDecryptLimits(header.params, cm.getDecryptKdfLimits())
    ).toThrow(CryptoError);
  });

  it('deriveKey honours caller-supplied overrides the decrypt path would refuse', async () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      decryptKdfLimits: TIGHT_LIMITS,
    });
    const salt = nodeCrypto.randomBytes(SALT_LENGTH);

    // The exemption: the cost parameters are the CALLER's, not a ciphertext's.
    const key = await cm.deriveKey(PASSWORD, salt, OVER_BUDGET_COST);
    expect(key).toHaveLength(32);

    // Paired proof the budget is genuinely in force on this manager.
    const err = await captureError(() =>
      cm.decryptBytes(craftArgon2idBlob(OVER_BUDGET_COST, true), PASSWORD)
    );
    expect(err.code).toBe('KDF_COST_EXCEEDS_DECRYPT_LIMITS');
  }, 30_000);

  it('deriveKeySync honours a caller-supplied iteration count the decrypt path would refuse', () => {
    const cm = new CryptoManager({
      ...LOW_COST,
      pbkdf2Iterations: LOW_ITERS,
      legacyPbkdf2Iterations: LOW_ITERS,
      decryptKdfLimits: TIGHT_LIMITS,
    });
    const salt = nodeCrypto.randomBytes(SALT_LENGTH);

    const key = cm.deriveKeySync(PASSWORD, salt, OVER_BUDGET_ITERS);
    expect(key).toHaveLength(32);

    let thrown: unknown;
    try {
      cm.decryptTextSync(
        craftPbkdf2Blob(OVER_BUDGET_ITERS, true).toString('base64url'),
        PASSWORD
      );
    } catch (err) {
      thrown = err;
    }
    expect((thrown as CryptoError).code).toBe(
      'KDF_COST_EXCEEDS_DECRYPT_LIMITS'
    );
  });
});

describe('resolveDecryptKdfLimits fails CLOSED on an incoherent resolution', () => {
  // The function is exported from both entry points, so "malformed input is a
  // documented precondition" is not an adequate contract: before v1.9.0 a
  // non-numeric `own` produced NaN ceilings, every `>` comparison against NaN
  // is false, and the resulting policy accepted every ciphertext while looking
  // like it was in force.
  const OWN = {
    memoryCost: 2 ** 14,
    timeCost: 1,
    parallelism: 1,
    pbkdf2Iterations: 600_000,
    legacyPbkdf2Iterations: 100_000,
  };

  it('throws instead of returning an all-accepting policy for a NaN instance cost', () => {
    let thrown: unknown;
    try {
      resolveDecryptKdfLimits(undefined, DEFAULT_DECRYPT_KDF_LIMITS.node, {
        ...OWN,
        memoryCost: Number.NaN,
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(CryptoError);
    expect((thrown as CryptoError).code).toBe('INVALID_DECRYPT_KDF_LIMITS');
    expect((thrown as CryptoError).type).toBe(CryptoErrorType.INVALID_INPUT);
    expect((thrown as CryptoError).message).toMatch(/maxMemoryCost/);
  });

  it('throws for a fractional instance cost that survives the widening max', () => {
    // The fraction has to WIN its `Math.max` to reach the resolved object; a
    // `timeCost` of 1.5 would be absorbed by the default of 10 and resolve to a
    // clean integer, so this case would pass vacuously. 10.5 is what actually
    // lands a non-integer in `maxTimeCost`.
    let thrown: unknown;
    try {
      resolveDecryptKdfLimits(undefined, DEFAULT_DECRYPT_KDF_LIMITS.node, {
        ...OWN,
        timeCost: 10.5,
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(CryptoError);
    expect((thrown as CryptoError).code).toBe('INVALID_DECRYPT_KDF_LIMITS');
    expect((thrown as CryptoError).message).toMatch(/maxTimeCost/);
  });

  it('still resolves a well-formed call unchanged', () => {
    const resolved = resolveDecryptKdfLimits(
      undefined,
      DEFAULT_DECRYPT_KDF_LIMITS.node,
      OWN
    );
    expect(resolved).toEqual({ ...DEFAULT_DECRYPT_KDF_LIMITS.node });
  });
});
