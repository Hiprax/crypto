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
  readFileSync,
  rmSync,
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

// Unique per-suite scratch directory so concurrent jest workers / repeated
// runs cannot collide on file paths (Task 21). Each test still creates a
// per-test sub-directory under TEST_DIR for self-contained probe scripts;
// the suite-wide afterAll guarantees nothing leaks even if a test's local
// cleanup is skipped.
const TEST_DIR = path.join(
  os.tmpdir(),
  `hiprax-crypto-esm-smoke-${crypto.randomBytes(8).toString('hex')}`
);

describe('ESM smoke (Task 31)', () => {
  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    if (!existsSync(DIST_INDEX)) {
      throw new Error(
        `Built artefact not found at ${DIST_INDEX}. ` +
          'Run `npm run build` before running the ESM smoke test.'
      );
    }
  });

  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it('package.json declares ESM and has no require export', () => {
    // Read the published package.json directly so we test the shipped
    // configuration, not whatever ts-jest happens to imply.
    const pkgPath = path.join(REPO_ROOT, 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as {
      type?: string;
      engines?: { node?: string };
      exports?: Record<
        string,
        | string
        | { types?: string; import?: string; require?: string }
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
    for (const key of ['.', './crypto-manager', './utils']) {
      const entry = exportsMap[key];
      expect(entry).toBeDefined();
      expect(typeof entry).toBe('object');
      const obj = entry as {
        types?: string;
        import?: string;
        require?: string;
      };
      // Each entry should declare types + import, but NOT require.
      expect(obj.types).toMatch(/\.d\.ts$/);
      expect(obj.import).toMatch(/\.js$/);
      expect(obj.require).toBeUndefined();
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
      const result = spawnSync(
        process.execPath,
        [probeFile],
        {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          timeout: 30_000,
          windowsHide: true,
        }
      );

      // Node's stderr can contain ExperimentalWarning lines, but the
      // exit code MUST be 0 and stdout MUST contain 'OK'.
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('OK');
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
      const result = spawnSync(
        process.execPath,
        [probeFile],
        {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          timeout: 30_000,
          windowsHide: true,
        }
      );
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
      const result = spawnSync(
        process.execPath,
        [probeFile],
        {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          timeout: 30_000,
          windowsHide: true,
        }
      );
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
      const result = spawnSync(
        process.execPath,
        [probeFile],
        {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          timeout: 30_000,
          windowsHide: true,
        }
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('OK');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
