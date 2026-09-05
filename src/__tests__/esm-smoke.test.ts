/**
 * ESM smoke test (Task 31).
 *
 * Confirms that the published shape of the package works as expected for
 * a Node.js ESM consumer. The test file actually compiles + loads the
 * `dist/` output (not `src/`) so it exercises the same artefacts that
 * end up in the npm tarball. It also runs `node --input-type=module
 * --eval` in a subprocess to verify Node's real ESM resolver — ts-jest
 * loads files through its own ESM transformer, which would mask
 * exports-map mistakes that real Node would catch.
 *
 * Since the isomorphic (Node + browser) work, the root `.` export is
 * CONDITIONAL (`browser` → `node` → `default`, each nesting `types` +
 * `default`), so this suite also
 * asserts that condition set + order and loads the built browser entry
 * (`dist/index.browser.js`) under Node to prove it exposes `CryptoManager`
 * while its Node-only methods throw `UNSUPPORTED_IN_BROWSER`.
 *
 * What this test does NOT cover:
 *   - The dynamic-`import()` workaround for CommonJS callers (because
 *     spinning up a `--input-type=commonjs` worker would execute on the
 *     same Node and the same package, which gives no signal that
 *     subscribers in foreign projects can do the same).
 *   - The pre-publish behaviour of `npm pack` — that's enforced
 *     elsewhere (CI / `prepublishOnly`).
 */
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

// Locate the repo root from the cwd at jest startup (jest sets cwd to
// the project root) rather than relying on `__dirname`, which is not
// reliably defined in jest's ESM mode.
const REPO_ROOT = process.cwd();
const DIST_DIR = path.join(REPO_ROOT, 'dist');
const DIST_INDEX = path.join(DIST_DIR, 'index.js');
const DIST_BROWSER_INDEX = path.join(DIST_DIR, 'index.browser.js');

// Unique per-suite scratch directory. mkdtempSync creates the directory
// atomically with a random suffix — the CodeQL-approved secure pattern
// for temp-directory creation. Each test creates its own sub-directory.
const TEST_DIR = mkdtempSync(
  path.join(os.tmpdir(), 'hiprax-crypto-esm-smoke-')
);

/**
 * Every `.d.ts` a browser consumer's compiler reaches from the `browser`
 * export condition: `dist/index.browser.d.ts` plus everything it (transitively)
 * re-exports. Verified against the real resolution graph — a fixture resolving
 * `@hiprax/crypto` with `customConditions: ["browser"]` pulls in exactly these
 * seven files, while the Node condition pulls in `index.d.ts`,
 * `crypto-manager.d.ts`, `format.d.ts`, `utils.d.ts` and `engine.node.d.ts`
 * instead (those may reference `Buffer` freely and are deliberately NOT listed).
 */
const BROWSER_DECLARATION_GRAPH = [
  'index.browser.d.ts',
  'crypto-manager.browser.d.ts',
  'core.d.ts',
  'types.d.ts',
  'format-core.d.ts',
  'codec.d.ts',
  'engine.d.ts',
];

// Word-boundary identifier matches, NOT substring matches: `ArrayBuffer`,
// `SharedArrayBuffer` and `BufferSource` are Web/ES globals that are perfectly
// legal in the browser graph, and a blunt `includes('Buffer')` would reject
// them. `\bBuffer\b` matches `Buffer` and `Buffer.from` but not `ArrayBuffer`
// (no word boundary between `y` and `B`) and not `BufferSource` (none between
// `r` and `S`). Non-global so `lastIndex` cannot make `test()` stateful.
const NODE_BUFFER_RE = /\bBuffer\b/;
const NODE_NAMESPACE_RE = /\bNodeJS\s*\./;

/**
 * Remove TypeScript comments from declaration source, preserving one output
 * entry per input line so offenders can be reported with a real line number.
 *
 * String and template literals are *tracked* but not removed: their contents
 * are code and stay in the scanned text; the tracking exists only so a `//`
 * or `/*` sequence inside a literal cannot be mistaken for the start of a
 * comment (which would silently truncate the rest of the line and weaken the
 * scan into a false pass).
 */
function stripTsComments(source: string): string[] {
  const lines: string[] = [];
  let current = '';
  let inBlockComment = false;
  let inLineComment = false;
  let quote: string | null = null;

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i] as string;
    const next = source[i + 1];

    if (ch === '\n') {
      lines.push(current);
      current = '';
      inLineComment = false;
      // A block comment survives a newline; a string literal cannot legally
      // span one in a `.d.ts`, so reset it defensively rather than letting a
      // stray quote swallow the remainder of the file.
      quote = null;
      continue;
    }

    if (inLineComment) continue;

    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        i += 1;
      }
      continue;
    }

    if (quote !== null) {
      current += ch;
      if (ch === '\\') {
        const escaped = source[i + 1];
        if (escaped !== undefined && escaped !== '\n') {
          current += escaped;
          i += 1;
        }
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      inBlockComment = true;
      i += 1;
      continue;
    }
    if (ch === '/' && next === '/') {
      inLineComment = true;
      i += 1;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      current += ch;
      continue;
    }
    current += ch;
  }

  lines.push(current);
  return lines;
}

describe('ESM smoke (Task 31)', () => {
  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    for (const artefact of [DIST_INDEX, DIST_BROWSER_INDEX]) {
      if (!existsSync(artefact)) {
        throw new Error(
          `Built artefact not found at ${artefact}. ` +
            'Run `npm run build` before running the ESM smoke test.'
        );
      }
    }
  });

  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it('package.json declares ESM with a conditional root export and no require anywhere', () => {
    // Read the published package.json directly so we test the shipped
    // configuration, not whatever ts-jest happens to imply.
    const pkgPath = path.join(REPO_ROOT, 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as {
      type?: string;
      engines?: { node?: string };
      exports?: Record<
        string,
        | string
        | {
            types?: string;
            import?: string;
            require?: string;
            browser?: string;
            node?: string;
            default?: string;
          }
      >;
    };
    expect(pkg.type).toBe('module');
    expect(pkg.engines).toBeDefined();
    const engines = pkg.engines;
    expect(engines && engines.node).toMatch(/>=22\.0\.0/);

    expect(pkg.exports).toBeDefined();
    const exportsMap = pkg.exports;
    if (!exportsMap) {
      throw new Error('package.json must define an exports map');
    }

    // The root `.` export is CONDITIONAL: it routes bundlers (which set the
    // `browser` condition) to the browser build and Node (which sets `node`)
    // to the Node build, over ONE ESM format. Each condition NESTS its own
    // `types` (first) + `default` — a browser consumer resolves the browser
    // declarations (`index.browser.d.ts`), never the Node-only, `Buffer`-typed
    // ones. Assert the exact condition set AND order (`browser` → `node` →
    // `default` last, the catch-all), each with `types` first.
    const rootEntry = exportsMap['.'];
    expect(typeof rootEntry).toBe('object');
    type CondBranch = {
      types?: string;
      default?: string;
      import?: string;
      require?: string;
      browser?: string;
    };
    const root = rootEntry as {
      browser?: CondBranch;
      node?: CondBranch;
      default?: CondBranch;
      types?: string;
      import?: string;
      require?: string;
    };
    expect(Object.keys(root)).toEqual(['browser', 'node', 'default']);
    // No hoisted top-level `types`/`require`/`import` on the root — the per-
    // condition branches carry them.
    expect(root.types).toBeUndefined();
    expect(root.require).toBeUndefined();
    expect(root.import).toBeUndefined();
    // Each branch is an object with `types` FIRST, then `default`, and no
    // `require`. The browser branch resolves the browser build + its own
    // declarations; `node`/`default` resolve the Node build + Node declarations.
    const branches: Array<[keyof typeof root, RegExp]> = [
      ['browser', /index\.browser\.js$/],
      ['node', /index\.js$/],
      ['default', /index\.js$/],
    ];
    for (const [cond, targetRe] of branches) {
      const branch = root[cond] as CondBranch;
      expect(typeof branch).toBe('object');
      expect(Object.keys(branch)).toEqual(['types', 'default']);
      expect(branch.require).toBeUndefined();
      expect(branch.default).toMatch(targetRe);
    }
    // The browser branch's declarations must be the browser `.d.ts`; the Node
    // branches must be the Node `.d.ts` (NOT the browser one).
    expect((root.browser as CondBranch).types).toMatch(
      /index\.browser\.d\.ts$/
    );
    expect((root.browser as CondBranch).default).toMatch(/index\.browser\.js$/);
    expect((root.node as CondBranch).types).toMatch(/index\.d\.ts$/);
    expect((root.node as CondBranch).types).not.toMatch(
      /index\.browser\.d\.ts$/
    );
    expect((root.node as CondBranch).default).not.toMatch(
      /index\.browser\.js$/
    );
    expect((root.default as CondBranch).types).toMatch(/index\.d\.ts$/);
    expect((root.default as CondBranch).default).not.toMatch(
      /index\.browser\.js$/
    );

    // The Node-only subpath exports keep the simple `{ types, import }` shape
    // — no `browser` condition (they are documented Node-only) and never a
    // `require` condition.
    for (const key of ['./crypto-manager', './utils']) {
      const entry = exportsMap[key];
      expect(entry).toBeDefined();
      expect(typeof entry).toBe('object');
      const obj = entry as {
        types?: string;
        import?: string;
        require?: string;
        browser?: string;
      };
      expect(obj.types).toMatch(/\.d\.ts$/);
      expect(obj.import).toMatch(/\.js$/);
      expect(obj.require).toBeUndefined();
      expect(obj.browser).toBeUndefined();
    }
  });

  it('Node loads dist/index.js via real ESM resolver and exposes CryptoManager', () => {
    // Run a subprocess that imports the built file through Node's own
    // ESM loader. If the exports map were misconfigured (e.g.
    // `require` pointing to ESM, or missing `import`), this would
    // surface as a Node-level error, not a ts-jest abstraction.
    const tmpDir = path.join(
      TEST_DIR,
      `esm-${crypto.randomBytes(8).toString('hex')}`
    );
    mkdirSync(tmpDir, { recursive: true });
    const probeFile = path.join(tmpDir, 'probe.mjs');

    // Use Node's `pathToFileURL` so Windows backslash paths don't trip
    // the ESM loader (which only accepts `file://` URLs).
    const distUrl = pathToFileURL(DIST_INDEX).href;

    writeFileSync(
      probeFile,
      `
import * as mod from ${JSON.stringify(distUrl)};
const ok =
  typeof mod.CryptoManager === 'function' &&
  typeof mod.default === 'function' &&
  mod.CryptoManager === mod.default;
process.stdout.write(ok ? 'OK' : 'BAD: ' + JSON.stringify(Object.keys(mod)));
`,
      'utf8'
    );

    try {
      const result = spawnSync(process.execPath, [probeFile], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 30_000,
        windowsHide: true,
      });

      // Node's stderr can contain ExperimentalWarning lines, but the
      // exit code MUST be 0 and stdout MUST contain 'OK'.
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('OK');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Node loads dist/index.browser.js and Node-only methods throw UNSUPPORTED_IN_BROWSER', () => {
    // The `browser` export condition points bundlers at
    // dist/index.browser.js. That entry's import graph contains ZERO `node:`
    // specifiers (enforced continuously by `npm run check:browser`), so it
    // also loads cleanly under Node's own ESM resolver here. Loading it under
    // Node lets us assert two guarantees without spinning up a browser:
    //   1. `CryptoManager` is exported and the named export === the default
    //      export (same shape as the Node build).
    //   2. A Node-only method throws `CryptoError` with code
    //      `UNSUPPORTED_IN_BROWSER` — the browser build's throwing stub —
    //      proving the browser surface is the async in-memory subset, not the
    //      full Node API (file/stream/sync/Buffer-typed methods are absent).
    const tmpDir = path.join(
      TEST_DIR,
      `browser-${crypto.randomBytes(8).toString('hex')}`
    );
    mkdirSync(tmpDir, { recursive: true });
    const probeFile = path.join(tmpDir, 'probe.mjs');

    const browserUrl = pathToFileURL(DIST_BROWSER_INDEX).href;

    writeFileSync(
      probeFile,
      `
import * as mod from ${JSON.stringify(browserUrl)};
const CM = mod.CryptoManager;
let threw = false;
let code = '';
let name = '';
try {
  const cm = new CM();
  // generateSecureRandom is Node-only (Buffer-typed CSPRNG); the browser
  // build stubs it to throw synchronously.
  cm.generateSecureRandom(16);
} catch (err) {
  threw = true;
  code = err && err.code;
  name = err && err.name;
}
const ok =
  typeof CM === 'function' &&
  typeof mod.default === 'function' &&
  CM === mod.default &&
  threw &&
  name === 'CryptoError' &&
  code === 'UNSUPPORTED_IN_BROWSER';
process.stdout.write(
  ok
    ? 'OK'
    : 'BAD: ' + JSON.stringify({ threw, name, code, keys: Object.keys(mod) })
);
`,
      'utf8'
    );

    try {
      const result = spawnSync(process.execPath, [probeFile], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 30_000,
        windowsHide: true,
      });

      expect(result.status).toBe(0);
      expect(result.stdout).toContain('OK');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('publishes the AES-GCM bound symmetrically from the Node AND browser entries', () => {
    // Asymmetry tripwire. `src/index.ts` re-exports `./format.js` (an explicit
    // NAMED re-export list) while `src/index.browser.ts` re-exports
    // `./format-core.js` with `export *`. Anything added to `format-core.ts`
    // therefore reaches browser consumers automatically and Node consumers
    // only if someone remembers to extend the named list. A missing entry
    // there type-checks, lints, bundles and passes every other test — the
    // symbol is simply invisible to half the audience. This test is the only
    // thing that would catch it, so it checks BOTH entries in one probe and
    // requires the two constants to be identical.
    //
    // Both entries are loaded through Node's real ESM resolver (not ts-jest's
    // transformer) against the built `dist/`, so it is the shipped artefacts
    // that are asserted.
    const tmpDir = path.join(
      TEST_DIR,
      `gcm-export-${crypto.randomBytes(8).toString('hex')}`
    );
    mkdirSync(tmpDir, { recursive: true });
    const probeFile = path.join(tmpDir, 'probe.mjs');

    const nodeUrl = pathToFileURL(DIST_INDEX).href;
    const browserUrl = pathToFileURL(DIST_BROWSER_INDEX).href;

    writeFileSync(
      probeFile,
      `
import * as node from ${JSON.stringify(nodeUrl)};
import * as browser from ${JSON.stringify(browserUrl)};

const EXPECTED = 2 ** 36 - 32;
const problems = [];

for (const [label, mod] of [['node', node], ['browser', browser]]) {
  if (mod.MAX_GCM_PLAINTEXT_BYTES !== EXPECTED) {
    problems.push(label + '.MAX_GCM_PLAINTEXT_BYTES=' + mod.MAX_GCM_PLAINTEXT_BYTES);
  }
  if (typeof mod.assertGcmPlaintextLimit !== 'function') {
    problems.push(label + '.assertGcmPlaintextLimit=' + typeof mod.assertGcmPlaintextLimit);
  } else {
    // The helper must be live and enforcing, not a stub that resolved to
    // something callable: the boundary passes, boundary+1 throws the typed
    // error, and both entries agree on the code.
    try {
      mod.assertGcmPlaintextLimit(EXPECTED);
    } catch {
      problems.push(label + ': rejected the exact boundary');
    }
    let code = null;
    try {
      mod.assertGcmPlaintextLimit(EXPECTED + 1);
    } catch (err) {
      code = err && err.code;
    }
    if (code !== 'DATA_TOO_LARGE_FOR_GCM') {
      problems.push(label + ': boundary+1 code=' + code);
    }
  }
}

if (node.MAX_GCM_PLAINTEXT_BYTES !== browser.MAX_GCM_PLAINTEXT_BYTES) {
  problems.push('entries disagree on the bound');
}

process.stdout.write(problems.length === 0 ? 'OK' : 'BAD: ' + JSON.stringify(problems));
`,
      'utf8'
    );

    try {
      const result = spawnSync(process.execPath, [probeFile], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 30_000,
        windowsHide: true,
      });

      expect(result.stdout).toContain('OK');
      expect(result.stdout).not.toContain('BAD');
      expect(result.status).toBe(0);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('names the v2 container version from both entries, and it matches the wire byte', () => {
    // `FORMAT_VERSION` (0x01) has always reached both entries through the
    // format module, but `CONTAINER_VERSION` (0x02) lived only in `core.ts`,
    // so a consumer could not name the version of a format this library
    // PRODUCES — container mode is on the isomorphic core, so both runtimes
    // emit v2 blobs. This pins four things that a plain "the export exists"
    // check would miss:
    //
    //   1. Both entries expose it and agree on the value (the same asymmetry
    //      tripwire as the AES-GCM bound above: `index.ts` re-exports a named
    //      list while `index.browser.ts` re-exports `format-core.js` with
    //      `export *`, so half-wired constants type-check and lint cleanly).
    //   2. It equals the byte actually written at offset 4 by a REAL
    //      `encryptContainer` call — not a literal that drifted from the
    //      packer. A `CONTAINER_VERSION = 3` typo passes an `=== 0x02`-free
    //      check but fails here.
    //   3. It is distinguishable from `FORMAT_VERSION`, which is the whole
    //      point of exporting it (routing a blob without decrypting it).
    //   4. `inspectHeader` on a container throws `UNSUPPORTED_VERSION` rather
    //      than returning `null` — the documented reason a consumer needs the
    //      constant instead of using `inspectHeader` as a format sniffer.
    //
    // Negative half: the browser entry must still export NOTHING from
    // `./utils.js`. That list is DERIVED from `dist/utils.js` at run time
    // rather than hard-coded, so adding a Node-only helper cannot slip past
    // a stale literal.
    const tmpDir = path.join(
      TEST_DIR,
      `container-version-${crypto.randomBytes(8).toString('hex')}`
    );
    mkdirSync(tmpDir, { recursive: true });
    const probeFile = path.join(tmpDir, 'probe.mjs');

    const nodeUrl = pathToFileURL(DIST_INDEX).href;
    const browserUrl = pathToFileURL(DIST_BROWSER_INDEX).href;
    const utilsUrl = pathToFileURL(path.join(DIST_DIR, 'utils.js')).href;

    writeFileSync(
      probeFile,
      `
import * as node from ${JSON.stringify(nodeUrl)};
import * as browser from ${JSON.stringify(browserUrl)};
import * as utils from ${JSON.stringify(utilsUrl)};

const problems = [];

for (const [label, mod] of [['node', node], ['browser', browser]]) {
  if (mod.CONTAINER_VERSION !== 0x02) {
    problems.push(label + '.CONTAINER_VERSION=' + String(mod.CONTAINER_VERSION));
  }
  if (mod.FORMAT_VERSION !== 0x01) {
    problems.push(label + '.FORMAT_VERSION=' + String(mod.FORMAT_VERSION));
  }
  if (mod.CONTAINER_VERSION === mod.FORMAT_VERSION) {
    problems.push(label + ': the two version constants are indistinguishable');
  }
}

if (node.CONTAINER_VERSION !== browser.CONTAINER_VERSION) {
  problems.push('entries disagree on CONTAINER_VERSION');
}

// The constant must match the byte a real container carries. Use a cheap
// Argon2id profile: this asserts the FORMAT, not the KDF strength.
const cm = new node.CryptoManager({
  memoryCost: 8192,
  timeCost: 1,
  parallelism: 1,
});
const password = 'MyP@ssw0rd123!';
const container = await cm.encryptContainer(
  new TextEncoder().encode('phase-10'),
  password,
  { filename: 'note.txt' }
);
if (container[4] !== node.CONTAINER_VERSION) {
  problems.push(
    'wire byte ' + container[4] + ' != CONTAINER_VERSION ' + node.CONTAINER_VERSION
  );
}

// A v1 ciphertext must carry the OTHER constant at the same offset, so the
// two are genuinely a discriminator and not both trivially true.
const v1 = await cm.encryptBytes(new TextEncoder().encode('phase-10'), password);
if (v1[4] !== node.FORMAT_VERSION) {
  problems.push('v1 wire byte ' + v1[4] + ' != FORMAT_VERSION ' + node.FORMAT_VERSION);
}

// inspectHeader is a v1 inspector: a container throws, it does not return
// null. Both documented input forms are checked — the byte path and the
// base64url-string path, which decodes only a 32-char prefix and so could
// plausibly have diverged from the byte path on a non-0x01 version.
for (const [form, value] of [
  ['bytes', container],
  ['string', node.bytesToBase64url(container)],
]) {
  let inspectCode = null;
  let inspectType = null;
  let inspectReturned = 'did-not-return';
  try {
    inspectReturned = JSON.stringify(cm.inspectHeader(value));
  } catch (err) {
    inspectCode = err && err.code;
    inspectType = err && err.type;
  }
  if (inspectCode !== 'UNSUPPORTED_VERSION' || inspectType !== 'DECRYPTION_FAILED') {
    problems.push(
      'inspectHeader(container as ' + form + ') -> returned ' + inspectReturned +
        ' / type=' + inspectType + ' code=' + inspectCode
    );
  }
}

// Positive control for the line above: on a real v1 ciphertext the same call
// must SUCCEED and report version 1. Without this, an inspectHeader that
// threw UNSUPPORTED_VERSION on everything would pass the container check.
try {
  const v1Header = cm.inspectHeader(v1);
  if (!v1Header || v1Header.version !== node.FORMAT_VERSION) {
    problems.push('inspectHeader(v1) -> ' + JSON.stringify(v1Header));
  }
} catch (err) {
  problems.push('inspectHeader(v1) threw ' + (err && err.code));
}

// Negative half: no Node-only file helper may be reachable from the browser
// entry. Derived from the real \`dist/utils.js\` export list.
const browserKeys = new Set(Object.keys(browser));
const leaked = Object.keys(utils).filter(k => browserKeys.has(k));
if (leaked.length > 0) {
  problems.push('browser entry leaks utils exports: ' + leaked.join(','));
}
if (Object.keys(utils).length === 0) {
  problems.push('utils export list is empty — the negative check would be vacuous');
}

process.stdout.write(problems.length === 0 ? 'OK' : 'BAD: ' + JSON.stringify(problems));
`,
      'utf8'
    );

    try {
      const result = spawnSync(process.execPath, [probeFile], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 60_000,
        windowsHide: true,
      });

      expect(result.stdout).toContain('OK');
      expect(result.stdout).not.toContain('BAD');
      expect(result.status).toBe(0);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Node refuses to load dist/index.js via require() (ESM-only contract)', () => {
    // We don't have a CJS build, so a `require()` call from a CJS
    // worker MUST fail. This locks in the ESM-only contract: if a
    // future change accidentally restores a `require` exports key
    // pointing at ESM output, the ERR_REQUIRE_ESM error type changes
    // (synthetic namespace on Node 22+, etc.) and this test starts
    // returning a different error.
    //
    // This test is skipped on Node 22+ where `require(esm)` is allowed
    // by default — there, `require()` succeeds via the synthetic
    // namespace path and the negative assertion no longer holds. We
    // still want the rest of the suite to validate the package shape.
    const major = Number(process.versions.node.split('.')[0]);
    if (major >= 22) {
      // Node 22+ permits require(esm) under default flags.
      return;
    }

    const tmpDir = path.join(
      TEST_DIR,
      `cjs-${crypto.randomBytes(8).toString('hex')}`
    );
    mkdirSync(tmpDir, { recursive: true });
    const probeFile = path.join(tmpDir, 'probe.cjs');

    writeFileSync(
      probeFile,
      `
try {
  const mod = require(${JSON.stringify(DIST_INDEX)});
  // If require() returns an object with CryptoManager, the ESM-only
  // contract has been silently broken — surface that loudly.
  if (mod && typeof mod.CryptoManager === 'function') {
    process.stdout.write('UNEXPECTED_SUCCESS');
    process.exit(0);
  }
  process.stdout.write('UNEXPECTED_RETURN_SHAPE');
  process.exit(0);
} catch (err) {
  // ERR_REQUIRE_ESM is the canonical CJS-loads-ESM failure on Node
  // 18-21. Newer/older Nodes may use a slightly different code; we
  // accept any error whose code starts with ERR_REQUIRE.
  process.stdout.write(err.code || err.message);
  process.exit(0);
}
`,
      'utf8'
    );

    try {
      const result = spawnSync(process.execPath, [probeFile], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 30_000,
        windowsHide: true,
      });
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('ERR_REQUIRE_ESM');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Node loads ./crypto-manager and ./utils subpath exports', () => {
    const tmpDir = path.join(
      TEST_DIR,
      `subpath-${crypto.randomBytes(8).toString('hex')}`
    );
    mkdirSync(tmpDir, { recursive: true });
    const probeFile = path.join(tmpDir, 'probe.mjs');

    const cmUrl = pathToFileURL(path.join(DIST_DIR, 'crypto-manager.js')).href;
    const utilsUrl = pathToFileURL(path.join(DIST_DIR, 'utils.js')).href;

    writeFileSync(
      probeFile,
      `
import { CryptoManager } from ${JSON.stringify(cmUrl)};
import * as utils from ${JSON.stringify(utilsUrl)};
const ok =
  typeof CryptoManager === 'function' &&
  typeof utils.validatePath === 'function' &&
  typeof utils.generateUUID === 'function';
process.stdout.write(ok ? 'OK' : 'BAD');
`,
      'utf8'
    );

    try {
      const result = spawnSync(process.execPath, [probeFile], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 30_000,
        windowsHide: true,
      });
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('OK');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('CommonJS consumers can still load via dynamic import()', () => {
    // The README documents that CJS consumers must use a dynamic
    // import() to interop with this package. Verify that pattern
    // actually works against the built artefact. This is the
    // recommended migration path for downstream CJS users.
    const tmpDir = path.join(
      TEST_DIR,
      `dynamic-${crypto.randomBytes(8).toString('hex')}`
    );
    mkdirSync(tmpDir, { recursive: true });
    const probeFile = path.join(tmpDir, 'probe.cjs');

    const distUrl = pathToFileURL(DIST_INDEX).href;

    writeFileSync(
      probeFile,
      `
(async () => {
  try {
    const mod = await import(${JSON.stringify(distUrl)});
    if (typeof mod.CryptoManager === 'function') {
      process.stdout.write('OK');
    } else {
      process.stdout.write('BAD');
    }
  } catch (err) {
    process.stdout.write('THREW: ' + (err.code || err.message));
  }
})();
`,
      'utf8'
    );

    try {
      const result = spawnSync(process.execPath, [probeFile], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 30_000,
        windowsHide: true,
      });
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('OK');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

/**
 * Browser DECLARATION-purity regression guard.
 *
 * Pins the invariant: **no `.d.ts` a browser consumer resolves may name a
 * Node-only type.** A single `Buffer` field anywhere in
 * `dist/index.browser.d.ts` or anything it re-exports is a hard
 * `TS2591 Cannot find name 'Buffer'` for every browser-only TypeScript project
 * (no `@types/node`, `"types": []`, `"skipLibCheck": false`) — which is exactly
 * what shipped in 1.5.0 via `types.ts`'s `EncryptionResult`.
 *
 * WHY THIS EXISTS ALONGSIDE `npm run check:types:browser`. That script is the
 * authoritative gate: it actually compiles a browser-condition consumer. This
 * test is the fast, in-suite tripwire that runs on every `npm test`, needs no
 * temp package fixture, and — unlike the compile gate — reports the offending
 * file and line directly. Neither of the other two static gates can see this
 * defect class at all:
 *   - ESLint's `no-restricted-globals` override on the isomorphic files does
 *     NOT fire on a TYPE-position `Buffer` (it only inspects value references),
 *     so `export interface X { y: Buffer }` lints clean.
 *   - `npm run check:browser` bundles with esbuild, which erases types before
 *     it ever resolves them.
 *
 * To see this test fail: add `foo: Buffer;` to an interface in any of the seven
 * sources behind {@link BROWSER_DECLARATION_GRAPH} — `src/index.browser.ts`,
 * `src/crypto-manager.browser.ts`, `src/core.ts`, `src/types.ts`,
 * `src/format-core.ts`, `src/codec.ts`, `src/engine.ts` — and rebuild.
 *
 * `src/engine.web.ts` is deliberately NOT one of them, and the distinction is
 * worth stating because it is counterintuitive: the Web engine is very much in
 * the browser RUNTIME graph, but it is not in the browser DECLARATION graph.
 * `crypto-manager.browser.ts` imports `webEngine` as a constructor-local VALUE
 * only, so declaration emit never needs to name the module — verified: no file
 * in the graph carries an import edge to `./engine.web.js`, and the closure
 * test below asserts the reachable set equals exactly those seven. A
 * type-position `Buffer` in `engine.web.ts` would therefore redden neither this
 * test nor `npm run check:types:browser`, because no browser consumer's
 * compiler ever resolves `dist/engine.web.d.ts`. That file is guarded instead
 * by `npm run check:browser` (no `node:` specifier in the bundled graph) and by
 * the ESLint isomorphic-file override (no value-position `Buffer`/`process`).
 */
describe('browser declaration purity (dist/*.d.ts)', () => {
  beforeAll(() => {
    for (const name of BROWSER_DECLARATION_GRAPH) {
      const file = path.join(DIST_DIR, name);
      if (!existsSync(file)) {
        throw new Error(
          `Browser declaration not found at ${file}. ` +
            'Run `npm run build` before running the ESM smoke test.'
        );
      }
    }
  });

  it('covers the ENTIRE graph reachable from the browser entry, with nothing extra', () => {
    // Guards against the one way the scan below could silently under-cover: a
    // future module joining the browser graph while `BROWSER_DECLARATION_GRAPH`
    // stays a stale hand-written list. Walk the real re-export closure from
    // `index.browser.d.ts` and require it to equal the declared list exactly.
    // (The `check:types:browser` compile gate follows resolution itself and so
    // never goes stale; this keeps the fast in-suite tripwire honest too.)
    const seen = new Set<string>();
    const queue = ['index.browser.d.ts'];
    while (queue.length > 0) {
      const name = queue.shift() as string;
      if (seen.has(name)) continue;
      seen.add(name);
      const file = path.join(DIST_DIR, name);
      if (!existsSync(file)) {
        throw new Error(
          `Browser declaration not found at ${file}. ` +
            'Run `npm run build` before running the ESM smoke test.'
        );
      }
      // Comments are stripped first, so a JSDoc line mentioning `./format.js`
      // (the Node-only wrapper, deliberately NOT in the browser graph) cannot
      // pull a Node module into the walk.
      const code = stripTsComments(readFileSync(file, 'utf8')).join('\n');
      for (const match of code.matchAll(/from\s+['"]\.\/([\w.-]+)\.js['"]/g)) {
        queue.push(`${match[1]}.d.ts`);
      }
    }

    expect([...seen].sort()).toEqual([...BROWSER_DECLARATION_GRAPH].sort());
    // Negative: the Node-only modules must NOT be reachable from the browser
    // entry. If `index.browser.ts` ever re-exported `./format.js` or
    // `./utils.js` again, the equality above would fail — this states why.
    for (const nodeOnly of [
      'index.d.ts',
      'crypto-manager.d.ts',
      'format.d.ts',
      'utils.d.ts',
      'engine.node.d.ts',
    ]) {
      expect(seen.has(nodeOnly)).toBe(false);
    }
  });

  it('names no Node-only type (`Buffer`, `NodeJS.*`) on any code line of the browser declaration graph', () => {
    const offenders: string[] = [];
    const codeLineCounts = new Map<string, number>();

    for (const name of BROWSER_DECLARATION_GRAPH) {
      const file = path.join(DIST_DIR, name);
      const lines = stripTsComments(readFileSync(file, 'utf8'));

      codeLineCounts.set(
        name,
        lines.filter(line => line.trim().length > 0).length
      );

      lines.forEach((line, index) => {
        if (NODE_BUFFER_RE.test(line) || NODE_NAMESPACE_RE.test(line)) {
          offenders.push(`${name}:${index + 1}: ${line.trim()}`);
        }
      });
    }

    // The primary assertion, reported as the offending lines themselves so a
    // failure names the file and line rather than just flipping a boolean.
    expect(offenders).toEqual([]);

    // Anti-vacuity: a stripper bug that ate whole files would make the check
    // above pass trivially. Every declaration in the graph must have left real
    // code behind, and the graph as a whole must be substantial.
    for (const name of BROWSER_DECLARATION_GRAPH) {
      expect(codeLineCounts.get(name)).toBeGreaterThan(0);
    }
    const total = [...codeLineCounts.values()].reduce((a, b) => a + b, 0);
    expect(total).toBeGreaterThan(100);
  });

  it('keeps `EncryptionResult` on the Node surface only, out of the browser graph', () => {
    // The 1.5.0 defect and its fix, pinned from both sides. `EncryptionResult`
    // is `Buffer`-typed and is produced ONLY by the Node `encryptData`, so it
    // must be declared in (and re-exported from) the Node declarations and be
    // absent from the browser entry. The browser build's own throwing
    // `encryptData` stub returns a local, unexported `Uint8Array`-shaped type,
    // so nothing on the browser surface needs the name.
    // Comments are stripped on BOTH halves of this test, so neither a doc
    // comment quoting the declaration (false pass) nor one explaining the move
    // (false fail) can decide the outcome. Only real code counts.
    const nodeIndex = stripTsComments(
      readFileSync(path.join(DIST_DIR, 'index.d.ts'), 'utf8')
    ).join('\n');
    const nodeManager = stripTsComments(
      readFileSync(path.join(DIST_DIR, 'crypto-manager.d.ts'), 'utf8')
    ).join('\n');
    expect(nodeManager).toMatch(/export interface EncryptionResult\b/);
    expect(nodeIndex).toMatch(
      /export type \{ EncryptionResult \} from '\.\/crypto-manager\.js';/
    );

    // The negative half: it must NOT be reachable from the browser entry, and
    // `types.d.ts` (which the browser entry re-exports wholesale) must no
    // longer declare it.
    //
    // Comments are stripped first, deliberately. The point of this assertion is
    // that no browser-facing DECLARATION names the type; prose that *explains
    // why it is absent* is legitimate and must not red the suite. Scanning raw
    // text would make the test hostage to documentation: turning the comment at
    // the top of `src/types.ts` into a JSDoc attached to the next declaration
    // would make `tsc` emit it into `dist/types.d.ts` and fail this line over a
    // sentence.
    const browserFacing = ['index.browser.d.ts', 'types.d.ts'];
    for (const name of browserFacing) {
      const code = stripTsComments(
        readFileSync(path.join(DIST_DIR, name), 'utf8')
      ).join('\n');
      expect(code).not.toMatch(/\bEncryptionResult\b/);
    }
  });

  it('check:types:browser passes when the temp directory is not its own realpath', () => {
    // Regression pin for a real defect in `scripts/check-browser-types.mjs`:
    // its "did we resolve the browser graph?" guard compared TypeScript's
    // reported file names against the raw fixture root. TypeScript REALPATHS
    // every `node_modules` resolution, so whenever the temp directory is not
    // already its own realpath the two never share a prefix, the guard sees
    // zero package files and throws — a false RED on a perfectly clean package.
    //
    // That is not hypothetical: GitHub's `windows-latest` runners set `TEMP` to
    // the 8.3 short form `C:\Users\RUNNER~1\AppData\Local\Temp`, which is what
    // `os.tmpdir()` returns, while TypeScript reports the expanded
    // `C:/Users/runneradmin/...`. Both Windows CI legs would have gone red.
    //
    // A symlinked `TMPDIR` reproduces the identical mismatch on POSIX, which is
    // what this test does. It is NOT skipped: on Windows (where creating a
    // symlink needs Developer Mode or elevation) it still runs the gate, just
    // through the platform's ordinary temp directory, so the gate is executed
    // as a subprocess on every platform and only the symlink hop is
    // POSIX-only.
    const scratch = path.join(
      TEST_DIR,
      `realpath-${crypto.randomBytes(8).toString('hex')}`
    );
    const realTmp = path.join(scratch, 'real');
    mkdirSync(realTmp, { recursive: true });

    let tmpForChild = realTmp;
    if (process.platform !== 'win32') {
      const linkedTmp = path.join(scratch, 'linked');
      symlinkSync(realTmp, linkedTmp, 'dir');
      // Precondition: the path we hand the child really is NOT its own
      // realpath. Without this the test could pass while proving nothing.
      expect(realpathSync(linkedTmp)).not.toBe(linkedTmp);
      tmpForChild = linkedTmp;
    }

    const result = spawnSync(
      process.execPath,
      [path.join(REPO_ROOT, 'scripts', 'check-browser-types.mjs')],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 120_000,
        windowsHide: true,
        env: {
          ...process.env,
          TMPDIR: tmpForChild,
          TMP: tmpForChild,
          TEMP: tmpForChild,
        },
      }
    );

    // The full observable outcome: clean exit, the OK line, and — the negative
    // — no trace of the guard having misfired.
    expect(result.stdout + result.stderr).not.toMatch(
      /WRONG declaration graph|No package declarations were resolved/
    );
    expect(result.stdout).toContain('[check:types:browser] OK');
    expect(result.status).toBe(0);
  });

  it('comment stripper distinguishes prose, code and Web `*Buffer*` identifiers', () => {
    // Guards the guard: if `stripTsComments` were broken, the scan above would
    // pass vacuously. This pins the three discriminations it must make.
    const sample = [
      '/**',
      ' * Prose mentioning Buffer and NodeJS.Timeout must be ignored.',
      ' */',
      "export declare const url: 'https://example.test/a//b';",
      '/** One-line block comment naming Buffer. */',
      'export interface Keep {',
      '  a: ArrayBuffer;',
      '  b: BufferSource;',
      '  c: SharedArrayBuffer;',
      '}',
      'export interface Leak { d: Buffer; } // trailing comment: Buffer',
      'export interface Ns { e: NodeJS.Timeout; }',
    ].join('\n');

    const lines = stripTsComments(sample);
    const flagged = lines
      .map((line, index) => ({ line, number: index + 1 }))
      .filter(
        ({ line }) => NODE_BUFFER_RE.test(line) || NODE_NAMESPACE_RE.test(line)
      )
      .map(({ number }) => number);

    // Exactly the two genuine leaks — the comment-only mentions (lines 2 and
    // 5, and the trailing comment on line 11) and the three Web `*Buffer*`
    // globals (lines 7-9) are all correctly left alone.
    expect(flagged).toEqual([11, 12]);

    // The string literal survives intact, proving the `//` inside it did not
    // start a line comment and swallow the rest of the line.
    expect(lines[3]).toContain("'https://example.test/a//b';");
    // And the prose lines really were emptied, not merely unmatched.
    expect(lines[1]?.trim()).toBe('');
    expect(lines[4]?.trim()).toBe('');
  });
});
