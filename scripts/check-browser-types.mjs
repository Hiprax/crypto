#!/usr/bin/env node
/**
 * Browser DECLARATION-purity gate for @hiprax/crypto.
 *
 * Type-checks a throwaway browser-only consumer project against the built
 * `dist/`, with **no Node types available at all** (`"types": []`, no
 * `@types/node` in the fixture's `node_modules`) and `"skipLibCheck": false`.
 * Any Node type that has leaked into the browser declaration graph — a
 * `Buffer`, a `NodeJS.*`, anything only `@types/node` defines — surfaces here
 * as a hard compile error.
 *
 * WHY THIS GATE EXISTS (none of the pre-existing gates can see this defect):
 *   - `npm run check:browser` bundles with esbuild, which **erases types**; a
 *     type-position `Buffer` is invisible to it.
 *   - The ESLint `no-restricted-globals` override on the isomorphic files does
 *     NOT fire on a type-position `Buffer` (verified: `export interface P { x:
 *     Buffer }` lints clean under `@typescript-eslint/parser`).
 *   - `npm run check:exports` (`attw --profile esm-only`) exercises only the
 *     `node16` and `bundler` resolution modes; it never activates the `browser`
 *     export condition, so it resolves the NODE declaration entry.
 *   - `npm run type-check` compiles the repo itself, where `@types/node` is
 *     installed and `Buffer` is legitimately in scope.
 * A *compile* against the browser condition, with Node types withheld, is the
 * only construction that observes it.
 *
 * RESOLUTION MECHANISM — deliberately a copied package, never a `paths` alias.
 * The fixture materialises a real `<tmp>/node_modules/@hiprax/crypto/`
 * containing the repo's `package.json` plus a copy of `dist/`, so TypeScript
 * resolves the import through the package's own `exports` map and honours
 * `customConditions: ["browser"]`. A `tsconfig` `paths` mapping would NOT work:
 * `paths` bypasses `exports` entirely (TypeScript #60460, closed "Working as
 * Intended") and `customConditions` applies only when resolution goes through
 * an `exports`/`imports` field — so a `paths` fixture would silently type-check
 * the **Node** declaration graph, which references `Buffer` legitimately and
 * everywhere, making this gate both permanently red and a measurement of the
 * wrong thing. (It also needs `baseUrl`, which TypeScript 6 rejects outright.)
 * A symlink resolves correctly but requires Developer Mode or elevation on
 * Windows; `fs.cpSync` is portable everywhere and `dist/` is a couple of dozen
 * small files.
 *
 * Cross-platform by construction: pure Node `fs`/`path` APIs, the TypeScript
 * compiler driven through its JS API (no shell, no `tsc` shim, no POSIX-only
 * path form), and a temp directory from `os.tmpdir()`.
 */
import ts from 'typescript';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);
const distDir = path.join(repoRoot, 'dist');
const pkgJsonPath = path.join(repoRoot, 'package.json');

// The gate reads `dist/`, so the build must precede it. Fail loudly rather
// than silently type-checking an empty package.
const browserDecl = path.join(distDir, 'index.browser.d.ts');
if (!existsSync(browserDecl)) {
  console.error(
    `[check:types:browser] Browser declarations not found at ${browserDecl}.\n` +
      'Run `npm run build` before this check.'
  );
  process.exit(1);
}

/**
 * The browser-only consumer. It imports the package's value exports AND a
 * type-only export, then actually *uses* them, so the declarations are
 * instantiated rather than merely parsed.
 */
const APP_TS = `// Browser-only consumer probe for @hiprax/crypto.
// No \`@types/node\`, no \`Buffer\`, no \`process\` — exactly what a Vite/webpack
// front-end project looks like to the compiler.
import CryptoManagerDefault, {
  CryptoManager,
  SECURITY_THRESHOLDS,
  isValidPassword,
} from '@hiprax/crypto';
import type { ParsedHeader } from '@hiprax/crypto';

// The default export and the named export must be the same class.
const Ctor: typeof CryptoManager = CryptoManagerDefault;

const manager = new Ctor({ skipPasswordValidation: true });

export async function probe(password: string): Promise<number> {
  const plaintext: Uint8Array = new Uint8Array([1, 2, 3]);
  const sealed: Uint8Array = await manager.encryptBytes(plaintext, password);
  const header: ParsedHeader | null = manager.inspectHeader(sealed);
  const opened: Uint8Array = await manager.decryptBytes(sealed, password);
  const strong: boolean = isValidPassword(password);
  const memoryFloor: number = SECURITY_THRESHOLDS.HIGH.memoryCost;
  return (
    sealed.length +
    opened.length +
    memoryFloor +
    (header === null ? 0 : header.headerLen) +
    (strong ? 1 : 0)
  );
}
`;

/**
 * The consumer's compiler configuration. `types: []` withholds every ambient
 * type package, `skipLibCheck: false` forces the shipped `.d.ts` to be checked
 * rather than trusted, and `customConditions: ["browser"]` (which requires
 * `moduleResolution: "bundler"`) is what routes resolution through the
 * `browser` branch of the package's `exports` map.
 */
const TSCONFIG = {
  compilerOptions: {
    target: 'ES2022',
    module: 'ESNext',
    moduleResolution: 'bundler',
    strict: true,
    noEmit: true,
    types: [],
    lib: ['ES2022', 'DOM'],
    customConditions: ['browser'],
    skipLibCheck: false,
  },
  files: ['app.ts'],
};

const fixtureDir = mkdtempSync(
  path.join(os.tmpdir(), 'hiprax-crypto-browsertypes-')
);
const pkgDir = path.join(fixtureDir, 'node_modules', '@hiprax', 'crypto');
// TypeScript reports realpath'd file names for `node_modules` resolutions, so
// the fixture's real path is needed for any path comparison (see the guard
// below for the full Windows-8.3 / symlinked-TMPDIR explanation).
let realFixtureDir = fixtureDir;
try {
  realFixtureDir = realpathSync.native(fixtureDir);
} catch {
  // Just created; fall back to the literal path.
}

let ok = false;
try {
  // --- Materialise the fixture -------------------------------------------
  mkdirSync(pkgDir, { recursive: true });
  cpSync(pkgJsonPath, path.join(pkgDir, 'package.json'));
  cpSync(distDir, path.join(pkgDir, 'dist'), { recursive: true });

  const tsconfigPath = path.join(fixtureDir, 'tsconfig.json');
  writeFileSync(tsconfigPath, `${JSON.stringify(TSCONFIG, null, 2)}\n`, 'utf8');
  writeFileSync(path.join(fixtureDir, 'app.ts'), APP_TS, 'utf8');

  // --- Type-check it with the repo's own TypeScript ------------------------
  const configFile = ts.readConfigFile(tsconfigPath, ts.sys.readFile);
  if (configFile.error) {
    throw new Error(
      ts.flattenDiagnosticMessageText(configFile.error.messageText, '\n')
    );
  }
  const parsed = ts.parseJsonConfigFileContent(
    configFile.config,
    ts.sys,
    fixtureDir,
    undefined,
    tsconfigPath
  );

  // Anti-vacuity: a fixture whose root file failed to materialise would
  // type-check nothing and report a triumphant zero. Refuse to be green for
  // the wrong reason.
  if (parsed.fileNames.length !== 1) {
    throw new Error(
      '[check:types:browser] fixture is broken: expected exactly one root ' +
        `file (app.ts), got ${JSON.stringify(parsed.fileNames)}.`
    );
  }

  const host = ts.createCompilerHost(parsed.options, true);
  const program = ts.createProgram({
    rootNames: parsed.fileNames,
    options: parsed.options,
    host,
    // `getPreEmitDiagnostics` folds these in, so they are NOT concatenated
    // again below — doing so would double-report every config-file error.
    configFileParsingDiagnostics: parsed.errors,
  });

  // Anti-vacuity, part two, and the check that makes the copied-package
  // resolution self-verifying: the program must have actually pulled in the
  // BROWSER declaration entry. If `customConditions` ever stopped being
  // honoured (a `paths` alias, a dropped condition, an `exports` regression),
  // TypeScript would silently resolve `dist/index.d.ts` — the Node graph,
  // where `Buffer` is legitimate — and this gate would be measuring something
  // else entirely. Assert the graph before trusting the diagnostics.
  //
  // The comparison MUST be realpath- and case-aware, and this is not
  // theoretical. TypeScript realpaths every `node_modules` resolution (it
  // replaces a resolved external-library path with its real path unless the
  // difference is casing only), so the file names it reports need not share a
  // textual prefix with the directory this script created:
  //   - GitHub's `windows-latest` runners set `TEMP` to the 8.3 short form
  //     `C:\Users\RUNNER~1\AppData\Local\Temp`, which is what `os.tmpdir()`
  //     returns, while TypeScript reports the expanded `C:/Users/runneradmin/…`;
  //   - any `TMPDIR` that traverses a symlink does the same on Linux/macOS
  //     (reproducible locally with `TMPDIR=<symlink-to-tmp>`);
  //   - Windows paths additionally compare case-insensitively.
  // Comparing the raw strings makes this guard throw "no package declarations
  // were resolved" on a perfectly clean package — a false RED that would break
  // both Windows CI legs and every `prepublishOnly` on such a machine.
  const normalize = filePath => {
    const absolute = path.resolve(filePath).split(path.sep).join('/');
    return process.platform === 'win32' ? absolute.toLowerCase() : absolute;
  };

  let realPkgDir = pkgDir;
  try {
    realPkgDir = realpathSync.native(pkgDir);
  } catch {
    // We just created this directory, so this should not happen; fall back to
    // the literal path rather than failing the gate for an unrelated reason.
  }
  const packageRoots = [...new Set([normalize(pkgDir), normalize(realPkgDir)])];
  const relativeToPackage = filePath => {
    const normalized = normalize(filePath);
    for (const root of packageRoots) {
      if (normalized.startsWith(`${root}/`)) {
        return normalized.slice(root.length + 1);
      }
    }
    return null;
  };

  const resolvedPackageFiles = program
    .getSourceFiles()
    .map(file => relativeToPackage(file.fileName))
    .filter(relative => relative !== null);
  if (!resolvedPackageFiles.includes('dist/index.browser.d.ts')) {
    throw new Error(
      '[check:types:browser] fixture resolved the WRONG declaration graph: ' +
        'dist/index.browser.d.ts is not in the program.\n' +
        (resolvedPackageFiles.includes('dist/index.d.ts')
          ? 'It resolved the NODE entry (dist/index.d.ts) instead — the ' +
            '`browser` export condition was not honoured.'
          : 'No package declarations were resolved at all.') +
        `\nResolved: ${JSON.stringify(resolvedPackageFiles)}`
    );
  }

  const allDiagnostics = ts.getPreEmitDiagnostics(program);
  const diagnostics = allDiagnostics.filter(
    d => d.category === ts.DiagnosticCategory.Error
  );

  // Report every diagnostic with a path the reader can act on: files inside
  // the copied package print as `@hiprax/crypto/<rel>` so `dist/types.d.ts:143`
  // reads the same as it does in the repository.
  // Uses the same realpath-aware comparison as the guard above; a raw prefix
  // test would silently degrade to absolute temp paths on Windows/symlinked
  // TMPDIR, which is cosmetic here but needlessly confusing in a failure.
  const label = fileName => {
    const insidePackage = relativeToPackage(fileName);
    if (insidePackage !== null) {
      return `@hiprax/crypto/${insidePackage}`;
    }
    const normalized = normalize(fileName);
    for (const root of [normalize(fixtureDir), normalize(realFixtureDir)]) {
      if (normalized.startsWith(`${root}/`)) {
        return `<fixture>/${normalized.slice(root.length + 1)}`;
      }
    }
    return path.resolve(fileName);
  };

  // Print EVERY diagnostic, not only the errors, so a suggestion or warning
  // that hints at a coming break is still visible; only errors gate.
  for (const diagnostic of allDiagnostics) {
    const severity =
      diagnostic.category === ts.DiagnosticCategory.Error
        ? 'error'
        : diagnostic.category === ts.DiagnosticCategory.Warning
          ? 'warning'
          : 'info';
    const message = ts.flattenDiagnosticMessageText(
      diagnostic.messageText,
      '\n    '
    );
    if (diagnostic.file && diagnostic.start !== undefined) {
      const { line, character } = ts.getLineAndCharacterOfPosition(
        diagnostic.file,
        diagnostic.start
      );
      console.error(
        `  • ${label(diagnostic.file.fileName)}:${line + 1}:${character + 1} ` +
          `- ${severity} TS${diagnostic.code}: ${message}`
      );
    } else {
      console.error(`  • ${severity} TS${diagnostic.code}: ${message}`);
    }
  }

  if (diagnostics.length > 0) {
    console.error(
      `\n[check:types:browser] FAILED — ${diagnostics.length} type error(s). ` +
        'A Node-only type (e.g. `Buffer`, `NodeJS.*`) has reached the browser\n' +
        'declaration graph (`dist/index.browser.d.ts` and everything it\n' +
        're-exports), so a browser-only TypeScript consumer cannot compile\n' +
        'against this package. Move the offending declaration into a Node-only\n' +
        'module (e.g. `src/crypto-manager.ts`) instead of `src/types.ts`.'
    );
  } else {
    console.log(
      '[check:types:browser] OK — a browser-only consumer ' +
        '(customConditions=["browser"], types=[], skipLibCheck=false) ' +
        'type-checks against dist/ with 0 errors.'
    );
    ok = true;
  }
} finally {
  rmSync(fixtureDir, { recursive: true, force: true });
}

// `process.exitCode` (not `process.exit()`) so stdout/stderr flush completely
// before the process ends naturally.
process.exitCode = ok ? 0 : 1;
