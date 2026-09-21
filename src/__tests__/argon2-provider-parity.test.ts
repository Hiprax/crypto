/**
 * Real-provider Argon2id known-answer parity tests (Phase 2).
 *
 * These tests are the REAL evidence that the three interchangeable Argon2id
 * providers — native `argon2`, the runtime's own `crypto.argon2` (Node >=
 * 24.7.0) and pure-WASM `hash-wasm` — implement the RFC 9106 reference
 * identically and therefore produce bit-identical raw key material for the
 * same input tuple. Ciphertext round-tripping between hosts that happen to
 * resolve different providers depends on exactly that.
 *
 * Unlike the wiring tests in `argon2-lazy-load.test.ts` (which mock both
 * providers with a fixed constant to check only the adapter's parameter
 * pass-through and Buffer conversion), THIS file registers NO module mocks
 * at all: it runs the genuine, locally-installed KDFs and compares their
 * output against a vector computed live from both providers at
 * implementation time.
 *
 * Availability gating (Core Principle 4): `argon2` is a native optional
 * dependency; on a host where its prebuild and node-gyp both failed, the
 * library's documented behaviour is graceful fallback. So availability is
 * settled by the "probe IS the call" pattern — a real derivation inside a
 * try/catch which, on throw, performs a logged early-return SKIP rather than
 * failing the suite. A bare `import('argon2')` is NOT a sufficient probe: a
 * broken native `.node` binding still imports (the JS wrapper loads the
 * binding lazily), so only an actual hash attempt distinguishes "available"
 * from "present but broken". `hash-wasm` is pure WASM and expected to be
 * present, but is probed the same way. The built-in is gated on
 * `typeof crypto.argon2Sync === 'function'` instead, because its absence is a
 * runtime-version fact rather than an install outcome: it landed in Node
 * 24.7.0 and this package supports Node >= 22.
 *
 * TWO REFINEMENTS OF THAT PATTERN, both load-bearing, both easy to undo by
 * accident. First, the two multi-tuple cases at the end probe availability
 * ONCE, at the KAT's known-good parameters, and then leave every measured call
 * UN-caught — see `availableRawLegs` for why a per-call catch is actively
 * dangerous there. Second, the KAT cases above are one-shot and keep their
 * try/catch around the single derivation they make, which is the right shape
 * for them. So "every test wraps its derivation" is no longer true of this
 * file, and should not be re-introduced as a convention.
 */
import { describe, it, expect } from '@jest/globals';
import crypto from 'node:crypto';
import { argon2id } from 'hash-wasm';
import {
  CryptoManager,
  __resetArgon2ModuleCacheForTesting,
  __peekArgon2ProviderForTesting,
} from '../crypto-manager';
import { CryptoError } from '../types';

// ----------------------------------------------------------------------------
// Known-answer vector.
// ----------------------------------------------------------------------------
//
// Computed live at implementation time from the REAL installed providers —
// argon2@0.44.0 (native) AND hash-wasm@4.12.0 (pure WASM) — with the exact
// parameters below. Both providers produced this identical 32-byte output;
// the value is NEVER authored from memory.
//
//   password    = 'parity-vector-password'  (ASCII; NFC is a no-op)
//   salt        = 32 bytes, values 0x00..0x1f
//   memoryCost  = 4096 KiB (4 MiB)
//   timeCost    = 2
//   parallelism = 1
//   hashLength  = 32
//
// Re-verified 2026-09-21 after the optional `argon2` dependency moved to
// ^0.45.1: the native adapter still resolves `provider === 'native'` and still
// derives this exact vector, so the value above is a cross-VERSION invariant
// too, not only a cross-provider one. The version recorded above is the one
// the vector was first computed from; it is history, not a pin.
const KAT_HEX =
  '79fce5dc8932db4e5d85f8d32c1d8f2206188c3c1bcbe5ef555bab13c595567b';
const KAT_PASSWORD = 'parity-vector-password';
const KAT_SALT = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const KAT_MEMORY_COST = 4096;
const KAT_TIME_COST = 2;
const KAT_PARALLELISM = 1;
const KAT_HASH_LENGTH = 32;

/** A `(memoryCost, timeCost, parallelism)` triple: the unit of a parity claim. */
type ParityTuple = {
  readonly memory: number;
  readonly timeCost: number;
  readonly parallelism: number;
};

/** The KAT's own tuple, used for every availability probe below. */
const KAT_TUPLE: ParityTuple = {
  memory: KAT_MEMORY_COST,
  timeCost: KAT_TIME_COST,
  parallelism: KAT_PARALLELISM,
};

/** One Argon2id implementation, reduced to `(tuple, password) -> hex digest`. */
type ParityLeg = {
  readonly name: string;
  readonly digest: (tuple: ParityTuple, password: string) => Promise<string>;
};

/** Argon2id through Node's own primitive, with the mapping the adapter uses. */
function builtinDigest(tuple: ParityTuple, password: string): string {
  return Buffer.from(
    crypto.argon2Sync('argon2id', {
      message: password,
      nonce: KAT_SALT,
      parallelism: tuple.parallelism,
      tagLength: KAT_HASH_LENGTH,
      memory: tuple.memory,
      passes: tuple.timeCost,
    })
  ).toString('hex');
}

/** Argon2id through the real `hash-wasm` package, same mapping as the adapter. */
async function wasmDigest(
  tuple: ParityTuple,
  password: string
): Promise<string> {
  const out = await argon2id({
    password,
    salt: KAT_SALT,
    iterations: tuple.timeCost,
    parallelism: tuple.parallelism,
    memorySize: tuple.memory,
    hashLength: KAT_HASH_LENGTH,
    outputType: 'binary',
  });
  return Buffer.from(out).toString('hex');
}

/**
 * The RAW providers this host can actually run, each already proven to work by
 * ONE probe at the KAT's known-good parameters.
 *
 * WHY AVAILABILITY IS DECIDED ONCE, SEPARATELY FROM THE MEASUREMENT — this is
 * the load-bearing part, and the obvious shape is wrong. `hash-wasm`'s
 * `argon2id` throws for two unrelated reasons: the WASM module failing to load,
 * which is a supported host state and a legitimate skip, and its OWN parameter
 * validator rejecting the tuple (`memorySize < 8 * parallelism`,
 * `iterations < 1`). A `try`/`catch` wrapped around the measurement cannot tell
 * those apart — and the second one is precisely the cross-provider divergence
 * this file exists to detect. Swallowing it as "unavailable" would turn the
 * finding into a green skip: a provider that started rejecting the
 * `memoryCost === 8 * parallelism` floor would look like an uninstalled
 * package, and a ciphertext stored at that floor would be quietly
 * undecryptable on every host resolving it. So the probe uses parameters known
 * to be accepted, and every measured call afterwards is left UN-caught.
 *
 * The built-in needs no call-probe: its absence is a runtime-VERSION fact
 * (Node >= 24.7.0), so `typeof` is the honest test.
 */
async function availableRawLegs(): Promise<ParityLeg[]> {
  const legs: ParityLeg[] = [];

  if (typeof crypto.argon2Sync === 'function') {
    legs.push({
      name: 'node',
      digest: (tuple, password) =>
        Promise.resolve(builtinDigest(tuple, password)),
    });
  }

  try {
    await wasmDigest(KAT_TUPLE, KAT_PASSWORD);
    legs.push({ name: 'wasm', digest: wasmDigest });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[skip] hash-wasm unavailable: ${String(err)}`);
  }

  return legs;
}

/**
 * The native addon, reached through the library's real adapter rather than
 * through the package, because this file registers no module mocks and
 * `deriveKey` IS the adapter. Returns `null` when the chain resolves something
 * else, which is the documented graceful-fallback state on a host whose
 * node-gyp build failed.
 *
 * Only `ARGON2_NOT_AVAILABLE` counts as "not installed"; any other throw is a
 * regression and is re-thrown, for the same reason the raw probe above is
 * narrow. Note the returned leg NFC-normalises its password, because
 * `deriveKey` does — so it may only be compared against a raw digest of an
 * already-NFC string.
 */
async function availableNativeLeg(): Promise<ParityLeg | null> {
  __resetArgon2ModuleCacheForTesting();
  try {
    const probe = new CryptoManager(toManagerOptions(KAT_TUPLE));
    await probe.deriveKey(KAT_PASSWORD, KAT_SALT);
  } catch (err) {
    if (
      !(err instanceof CryptoError) ||
      (err as InstanceType<typeof CryptoError>).code !== 'ARGON2_NOT_AVAILABLE'
    ) {
      throw err;
    }
    return null;
  }
  if ((await __peekArgon2ProviderForTesting()) !== 'native') {
    return null;
  }
  return {
    name: 'native',
    digest: async (tuple, password): Promise<string> => {
      const manager = new CryptoManager(toManagerOptions(tuple));
      const hex = (await manager.deriveKey(password, KAT_SALT)).toString('hex');
      // Cheap tripwire, re-checked per call: a transient rejection would clear
      // the module cache (`loadArgon2`'s compare-and-swap) and the next call
      // could resolve a DIFFERENT provider, at which point this leg would be
      // comparing some other implementation against itself.
      expect(await __peekArgon2ProviderForTesting()).toBe('native');
      return hex;
    },
  };
}

/** `ParityTuple` -> the constructor options that reproduce it. */
function toManagerOptions(tuple: ParityTuple): {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
} {
  return {
    memoryCost: tuple.memory,
    timeCost: tuple.timeCost,
    parallelism: tuple.parallelism,
  };
}

/**
 * Assert every leg agrees on `tuple`, and hand back the agreed digest.
 * Fails naming the disagreeing leg rather than reporting a bare hex mismatch.
 */
async function agreedDigest(
  legs: readonly ParityLeg[],
  tuple: ParityTuple,
  password: string
): Promise<string> {
  const measured: Array<[string, string]> = [];
  for (const leg of legs) {
    measured.push([leg.name, await leg.digest(tuple, password)]);
  }
  const first = measured[0];
  expect(first).toBeDefined();
  const reference = (first as [string, string])[1];
  expect(reference).toHaveLength(KAT_HASH_LENGTH * 2);
  for (const [name, hex] of measured) {
    expect({ provider: name, hex }).toEqual({ provider: name, hex: reference });
  }
  return reference;
}

describe('Argon2id cross-provider known-answer parity (real providers, no mocks)', () => {
  it('native argon2 derives the pinned KAT vector', async () => {
    // Probe IS the call: run the real derivation through the library's
    // native adapter. The cache is reset first so provider selection is
    // observable via the peek hook afterwards.
    __resetArgon2ModuleCacheForTesting();
    const manager = new CryptoManager({
      memoryCost: KAT_MEMORY_COST,
      timeCost: KAT_TIME_COST,
      parallelism: KAT_PARALLELISM,
    });

    let derivedHex: string;
    try {
      const key = await manager.deriveKey(KAT_PASSWORD, KAT_SALT);
      derivedHex = key.toString('hex');
    } catch (err) {
      // Both providers genuinely unavailable — the documented graceful
      // fallback state. Skip rather than fail (Core Principle 4).
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] Argon2id unavailable, skipping native KAT: ${String(err)}`
      );
      return;
    }

    // Only trust this as the NATIVE vector when native actually ran. On a
    // broken-native/working-WASM host deriveKey succeeds via the fallback,
    // in which case this native-specific assertion must not run — the
    // WASM test below still covers that host. Honest provider claim.
    const provider = await __peekArgon2ProviderForTesting();
    if (provider !== 'native') {
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] native argon2 unavailable (resolved provider: ${String(
          provider
        )}); native KAT covered by the hash-wasm test`
      );
      return;
    }

    expect(derivedHex).toBe(KAT_HEX);
  });

  it('hash-wasm argon2id derives the pinned KAT vector', async () => {
    // Probe IS the call: invoke the real hash-wasm `argon2id` directly with
    // the exact parameter mapping the library's WASM adapter uses
    // (iterations=timeCost, memorySize=memoryCost, outputType='binary').
    let derivedHex: string;
    try {
      const out = await argon2id({
        password: KAT_PASSWORD,
        salt: KAT_SALT,
        iterations: KAT_TIME_COST,
        parallelism: KAT_PARALLELISM,
        memorySize: KAT_MEMORY_COST,
        hashLength: KAT_HASH_LENGTH,
        outputType: 'binary',
      });
      derivedHex = Buffer.from(out).toString('hex');
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] hash-wasm unavailable, skipping WASM KAT: ${String(err)}`
      );
      return;
    }

    expect(derivedHex).toBe(KAT_HEX);
  });

  it('node built-in crypto.argon2 derives the pinned KAT vector', async () => {
    // Probe IS the call, with one difference from its two siblings: the
    // built-in's absence is a runtime-VERSION fact, not an install outcome, so
    // it is cheap and honest to test for the function up front rather than to
    // catch a throw. It landed in Node 24.7.0 and this package supports
    // Node >= 22.
    if (typeof crypto.argon2Sync !== 'function') {
      // eslint-disable-next-line no-console
      console.warn(
        '[skip] node:crypto.argon2Sync unavailable (Node < 24.7.0), ' +
          'skipping built-in KAT'
      );
      return;
    }

    // Called directly, with the exact parameter mapping `engine.node.ts`'s
    // `importNodeBuiltinArgon2` uses: `memory` counts 1 KiB blocks (the same
    // unit as this library's `memoryCost`), `passes` is the time cost and
    // `tagLength` is the output length. Going through the primitive rather
    // than through the library is what makes this a statement about NODE
    // rather than about our adapter — the adapter's own wiring is pinned in
    // `argon2-node-builtin.test.ts` and `argon2-lazy-load.test.ts`.
    const derived = crypto.argon2Sync('argon2id', {
      message: KAT_PASSWORD,
      nonce: KAT_SALT,
      parallelism: KAT_PARALLELISM,
      tagLength: KAT_HASH_LENGTH,
      memory: KAT_MEMORY_COST,
      passes: KAT_TIME_COST,
    });

    expect(Buffer.from(derived).toString('hex')).toBe(KAT_HEX);
  });

  it('every available Argon2id provider agrees at the awkward memory, parallelism and time-cost tuples', async () => {
    // The KAT above uses a comfortable, round parameter set. What actually
    // decides whether the providers are interchangeable IN THE FIELD is their
    // behaviour at the edges of the parameter space, because each ciphertext
    // carries its own KDF parameters in its header and a decrypting host may
    // resolve a different provider than the encrypting one did. Five tuples,
    // each chosen for a specific hazard:
    //
    //   (m=8,  t=2, p=1)  the exact `memoryCost === 8 * parallelism` floor.
    //                     This library's constructor and `parseHeader` both
    //                     enforce ">=", while `@types/node`'s JSDoc for
    //                     `memory` says "must be greater than `8 *
    //                     parallelism`". If a provider were really strictly
    //                     greater, a stored ciphertext at exactly the floor
    //                     would decrypt under the others and throw
    //                     ERR_OUT_OF_RANGE under that one. It does not: the
    //                     JSDoc wording is loose, and this case is what keeps
    //                     that answer from having to be re-probed.
    //   (m=9,  t=2, p=1)  not a multiple of `4 * parallelism`. Node documents
    //                     that `memory` is rounded down to such a multiple;
    //                     the providers must round the same way or diverge
    //                     silently. (They agree, and the digest still differs
    //                     from the `m=8` row, because the RAW `m` enters the
    //                     Argon2 pre-hash before the block count is aligned.)
    //   (m=100,t=2, p=7)  the same rounding question with p > 1, where the
    //                     multiple is 28 and the floor is 56 — so it is
    //                     simultaneously above the floor and mid-interval.
    //   (m=8,  t=1, p=1)  both minima at once.
    //   (m=4096,t=1,p=1)  the KAT tuple with `timeCost` dropped to 1, so the
    //                     ONLY thing that differs from the pinned vector is
    //                     the pass count.
    //
    // The last two exist for a reason the first three do not cover, and it is
    // the same hazard as the `8 * parallelism` floor one parameter over.
    // `@types/node` declares `passes` as "must be greater than 1", yet this
    // library accepts any positive `timeCost` and `parseHeader` accepts any
    // positive value, so a v1 header can legally carry `timeCost = 1` — and
    // this repository PRODUCES such ciphertexts (`bench/codec.mjs` builds a
    // manager at `timeCost: 1`). If a provider ever enforced that documented
    // bound, such a ciphertext would decrypt on a host that resolved one
    // provider and be permanently unreadable on a host that resolved another,
    // which is exactly the failure this whole file exists to rule out. It is
    // not enforced today; that is a measurement, and this is where it is kept.
    // `parallelism` carries the identical "must be greater than 1" wording and
    // is the MORE consequential instance, since `p = 1` is this library's
    // default and therefore sits in essentially every ciphertext it has ever
    // produced — four of these five tuples, and the KAT, pin it.
    //
    // Every side is COMPUTED here. Hard-coding a digest would turn a parity
    // claim into a second known-answer test and would pin whichever provider
    // the author happened to run.
    //
    // WHAT RUNS WHERE. The legs are whichever providers the host actually has,
    // not a fixed three: on Node 22 there is no built-in and the comparison is
    // native against `hash-wasm`; on a host whose node-gyp build failed it is
    // the built-in against `hash-wasm`. That is deliberate — gating the whole
    // case on the built-in, as an earlier revision did, made it assert NOTHING
    // on the `engines.node` floor and in the release job, both of which run
    // Node 22. Two legs is the minimum for a parity claim to mean anything, so
    // fewer than two skips.
    const tuples: readonly ParityTuple[] = [
      { memory: 8, timeCost: KAT_TIME_COST, parallelism: 1 },
      { memory: 9, timeCost: KAT_TIME_COST, parallelism: 1 },
      { memory: 100, timeCost: KAT_TIME_COST, parallelism: 7 },
      { memory: 8, timeCost: 1, parallelism: 1 },
      { memory: KAT_MEMORY_COST, timeCost: 1, parallelism: KAT_PARALLELISM },
    ];

    const nativeLeg = await availableNativeLeg();
    const legs: ParityLeg[] = [
      ...(await availableRawLegs()),
      ...(nativeLeg === null ? [] : [nativeLeg]),
    ];
    if (legs.length < 2) {
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] only ${legs.length} Argon2id provider(s) available ` +
          `(${legs.map(l => l.name).join(', ') || 'none'}); a parity claim ` +
          'needs at least two'
      );
      return;
    }

    const agreed: string[] = [];
    for (const tuple of tuples) {
      agreed.push(await agreedDigest(legs, tuple, KAT_PASSWORD));
    }

    // NEGATIVES, and without them the agreement above would be worth little.
    // Each tuple must produce its OWN digest: if `memory`, `parallelism` or
    // `passes` were being dropped on the floor by every provider, every row
    // would agree and every row would be the same bytes. And none of them may
    // be the comfortable KAT vector, which is the one digest an implementation
    // that ignored these parameters entirely would be most likely to return —
    // the last tuple differs from the KAT in nothing but `timeCost`, so that
    // check is specifically what proves the pass count reaches the primitive.
    expect(agreed).toHaveLength(tuples.length);
    expect(new Set(agreed).size).toBe(tuples.length);
    expect(agreed).not.toContain(KAT_HEX);
  });

  it('every available Argon2id provider agrees on a multi-byte, non-ASCII password', async () => {
    // Every vector above uses an ASCII password, which leaves this release's
    // headline claim — bit-identical keys across providers, therefore no
    // stored ciphertext is affected — resting on something none of them
    // exercises: that they all turn a JavaScript string into the SAME bytes
    // before hashing. Native `argon2` does `Buffer.from(password)`, `hash-wasm`
    // runs a `TextEncoder`, and Node's built-in accepts `message: string` and
    // converts internally. ASCII is byte-identical under UTF-8, Latin-1 and
    // ASCII alike, so an ASCII vector is STRUCTURALLY incapable of catching a
    // divergence there: one adapter "simplified" to
    // `Buffer.from(password, 'latin1')` would derive a different key for every
    // user whose passphrase carries an accent, write ciphertext no other
    // provider could open, and leave every other case in this file green.
    //
    // The password spans all four UTF-8 widths — ASCII, a two-byte Latin-1
    // supplement character, a three-byte CJK character and a four-byte astral
    // emoji, which is a surrogate PAIR in UTF-16 and therefore where a
    // code-unit-versus-code-point confusion surfaces first. An unpaired
    // surrogate is deliberately NOT used: that is the one input where encoders
    // legitimately differ in how they substitute U+FFFD, so pinning it would
    // be over-specification rather than hardening. It carries no compatibility
    // characters either, so it distinguishes NFC from NFD but NOT from NFKC;
    // the library's normalisation TARGET is pinned in `crypto-manager.test.ts`.
    //
    // The NFD form is carried alongside for two reasons. It proves the
    // agreement is not an artefact of one byte pattern, and its digest must
    // DIFFER from the NFC one — which is the primitive-level fact that makes
    // `deriveKey`'s `normalize('NFC')` load-bearing rather than decorative.
    const NON_ASCII_NFC = 'café-münchen-日本語-🔐-Ω'.normalize('NFC');
    const NON_ASCII_NFD = NON_ASCII_NFC.normalize('NFD');
    // Sanity, so the NFC/NFD half below cannot pass vacuously on a runtime
    // whose normaliser did nothing.
    expect(NON_ASCII_NFD).not.toBe(NON_ASCII_NFC);
    expect(Buffer.byteLength(NON_ASCII_NFD, 'utf8')).not.toBe(
      Buffer.byteLength(NON_ASCII_NFC, 'utf8')
    );

    // Only the RAW legs can take an NFD password: the native leg reaches the
    // addon through `deriveKey`, which NFC-normalises first, so it cannot
    // measure a non-NFC input at all. It joins below instead, where that
    // normalisation is itself the thing under test.
    const rawLegs = await availableRawLegs();
    if (rawLegs.length === 0) {
      // eslint-disable-next-line no-console
      console.warn(
        '[skip] no raw Argon2id primitive available; non-ASCII parity needs ' +
          'at least one'
      );
      return;
    }

    const digests: Record<string, string> = {};
    for (const [form, password] of [
      ['nfc', NON_ASCII_NFC],
      ['nfd', NON_ASCII_NFD],
    ] as const) {
      digests[form] = await agreedDigest(rawLegs, KAT_TUPLE, password);
    }

    // NEGATIVES. The two normalisation forms are different bytes, so they must
    // be different keys — a provider that silently normalised, or one that
    // truncated the password at the first multi-byte character, would collapse
    // them. And neither may be the ASCII KAT vector, which is what an
    // implementation that ignored `message` entirely would return.
    expect(digests['nfd']).not.toBe(digests['nfc']);
    expect(digests['nfc']).not.toBe(KAT_HEX);
    expect(digests['nfd']).not.toBe(KAT_HEX);

    // Now the same password through the LIBRARY, which is what brings the
    // native adapter into the claim. Two properties at once, and the second is
    // why both inputs are asserted against `nfc` rather than against
    // `digests[form]`:
    //
    //   1. Whichever provider the host resolves agrees with the raw primitive
    //      above — the cross-provider claim, now for a multi-byte password.
    //   2. `deriveKey` NFC-normalises before hashing (`crypto-manager.ts`), so
    //      the NFD input must come back as the NFC digest. Checking that
    //      against a digest computed from the PRIMITIVE, rather than against
    //      another library call, is what makes it evidence: `crypto-manager
    //      .test.ts` already pins NFC == NFD through one manager, which cannot
    //      distinguish "normalises correctly" from "normalises to something".
    const resolvedProviders: Array<string | null> = [];
    for (const [form, password] of [
      ['nfc', NON_ASCII_NFC],
      ['nfd', NON_ASCII_NFD],
    ] as const) {
      __resetArgon2ModuleCacheForTesting();
      const manager = new CryptoManager(toManagerOptions(KAT_TUPLE));
      const libraryHex = (await manager.deriveKey(password, KAT_SALT)).toString(
        'hex'
      );
      const provider = await __peekArgon2ProviderForTesting();
      resolvedProviders.push(provider);

      expect(provider).not.toBeNull();
      expect(libraryHex).toBe(digests['nfc']);
      if (form === 'nfd') {
        // NEGATIVE, and the whole point of carrying the NFD form: without the
        // normalisation this would be the NFD digest, which the block above
        // proved is a different value.
        expect(libraryHex).not.toBe(digests['nfd']);
      }
    }

    // Honest reporting of how much this run actually crossed. When the library
    // resolves the same single provider the raw layer used, the comparison
    // degenerates to that provider against itself and only the normalisation
    // half remains a real claim.
    const crossed = new Set([
      ...rawLegs.map(l => l.name),
      ...resolvedProviders,
    ]);
    if (crossed.size < 2) {
      // eslint-disable-next-line no-console
      console.warn(
        `[skip] only one Argon2id implementation participated (${[...crossed].join(', ')}); ` +
          'the non-ASCII parity claim is not cross-provider on this host'
      );
    }
  });
});
