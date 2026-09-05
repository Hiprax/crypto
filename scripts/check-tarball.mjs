#!/usr/bin/env node
/**
 * Published-tarball gate for @hiprax/crypto.
 *
 * `npm pack --dry-run` on its own asserts NOTHING. It exits 0 for any tarball
 * contents whatsoever and fails only if packing itself errors, so using it as a
 * "verify the tarball" step checks that npm works, not that the artifact is
 * right. This script turns that listing into a real gate, in both directions.
 *
 * FLOOR — what must be PRESENT. Every path the `exports` map resolves to, plus
 * `package.json` and the documentation named in `files`. The list is derived
 * from `package.json` at run time rather than hard-coded, so an exports map
 * that grows a subpath is covered automatically, and one that points at a file
 * the tarball does not carry fails here. That is a broken-on-arrival publish
 * which `publint` and `attw` cannot see: both inspect the working tree, not the
 * packed file list, so a `dist/` file excluded by `files`/`.npmignore` looks
 * fine to them and 404s for the consumer.
 *
 * CEILING — what must be ABSENT. Sources, tests, benchmarks, CI, tooling
 * config, lockfiles, env files, credential material, source maps and
 * editor/backup scratch files. The sharpest case, and the reason this gate
 * exists at all, is npm's packlist force-include list: it overrides BOTH the
 * `files` allowlist AND `.npmignore` for any ROOT file whose stem is
 * `readme` / `license` / `licence` / `copying`, in any extension. A scratch
 * `README.md.tmp` or `LICENSE.tmp` left in the repo root therefore SHIPS to the
 * registry, and no configuration suppresses it. Measured by probe, 2026-09-05:
 * `README.md.tmp` and `README.junk` were both included; `READMEXYZ.junk`,
 * `CHANGELOG.md.tmp` and `package.json.tmp` were correctly excluded. The globs
 * are root-anchored, which is why a backup kept in a subdirectory is safe.
 *
 * Deliberately NOT a file count. Pinning "31 files" turns the gate red on every
 * legitimate new `dist/` module, which trains maintainers to edit the gate
 * instead of reading it — the one failure mode a gate must never have. The
 * count is reported for the operator and gates nothing.
 *
 * Cross-platform by construction. It asks the REAL npm what it would pack,
 * because a standalone `npm-packlist` can drift from the installed npm and this
 * gate must describe the artifact that actually ships. npm is invoked as
 * `node <npm-cli.js>` via `process.env.npm_execpath` (which npm sets for every
 * `npm run` child), so there is no `npm.cmd` shim and no shell — the same
 * no-shim rule `check-browser-types.mjs` follows. `--ignore-scripts` keeps the
 * child from re-entering the lifecycle or triggering a rebuild mid-check; it
 * reads whatever `dist/` the preceding `build` step produced.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const TAG = '[check:tarball]';
const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);

const pkg = JSON.parse(
  readFileSync(path.join(repoRoot, 'package.json'), 'utf8')
);

/**
 * Every `./`-relative target reachable in the `exports` map, at any nesting
 * depth and under any condition, normalised to a tarball-relative path.
 */
const collectExportTargets = (node, out = new Set()) => {
  if (typeof node === 'string') {
    if (node.startsWith('./')) out.add(node.slice(2));
    return out;
  }
  if (node && typeof node === 'object') {
    for (const value of Object.values(node)) collectExportTargets(value, out);
  }
  return out;
};

/**
 * Documentation the package promises to ship. These are the legal and security
 * surface of the release: a tarball without LICENSE or SECURITY.md is a real
 * defect even though every code path still works.
 */
const REQUIRED_DOCS = ['README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md'];

const required = new Set([
  'package.json',
  ...collectExportTargets(pkg.exports ?? {}),
  ...REQUIRED_DOCS,
]);

/**
 * Paths that must never appear in the tarball, each with the reason reported
 * on failure so the message says what to do, not merely what matched.
 *
 * The `.ts` rule uses a negative lookbehind so declarations still ship: a
 * published `.d.ts` is the type surface, a published `.ts` is the source.
 */
const FORBIDDEN = [
  [/^src\//, 'TypeScript sources (only dist/ ships)'],
  [/^bench\//, 'benchmark suite'],
  [/^scripts\//, 'build and gate scripts'],
  [/^\.github\//, 'CI workflows'],
  [/^coverage\//, 'coverage output'],
  [/(^|\/)node_modules\//, 'installed dependencies'],
  [/(^|\/)__tests__\//, 'test suite'],
  [/\.(test|spec)\.[cm]?[jt]s$/, 'test file'],
  [/(?<!\.d)\.[cm]?ts$/, 'TypeScript source (only .d.ts may ship)'],
  [/\.map$/, 'source or declaration map'],
  [/\.(tmp|bak|orig|backup|swp|swo)$/, 'scratch or backup file'],
  [/~$/, 'editor backup file'],
  [/(^|\/)\.env(\.|$)/, 'environment file'],
  [/(^|\/)CLAUDE\.md$/i, 'local working file'],
  [/(^|\/)PLAN\.md$/i, 'local working file'],
  [/(^|\/)phases\.json$/, 'local working file'],
  [/orchestrator/i, 'local working file'],
  [/(^|\/)package-lock\.json$/, 'lockfile'],
  [
    /(^|\/)(tsconfig|jest\.config|vitest\.config|eslint\.config)\./,
    'tooling config',
  ],
  [/(^|\/)\.prettierrc/, 'tooling config'],
  [/(^|\/)\.npmrc$/, 'registry config (can carry an auth token)'],
  [/\.(pem|key|crt|p12|pfx)$/, 'credential material'],
];

/** Ask the installed npm what it would actually pack. */
const packListing = () => {
  const args = ['pack', '--dry-run', '--json', '--ignore-scripts'];
  const npmCli = process.env['npm_execpath'];
  const options = {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  };

  // Preferred: run npm's own JS entry point under this Node binary. No shell,
  // no `npm.cmd` shim, identical on Windows and POSIX.
  if (npmCli && npmCli.endsWith('.js')) {
    return execFileSync(process.execPath, [npmCli, ...args], options);
  }
  // Fallback for a bare `node scripts/check-tarball.mjs`, where npm sets no
  // `npm_execpath`. `shell` is required on Windows to resolve `npm.cmd`; the
  // argument vector is entirely literal, so there is nothing to inject.
  return execFileSync('npm', args, {
    ...options,
    shell: process.platform === 'win32',
  });
};

let raw;
try {
  raw = packListing();
} catch (err) {
  console.error(
    `${TAG} FAILED — could not run \`npm pack --dry-run\`.\n` +
      (err && err.stderr ? String(err.stderr) : String(err && err.message))
  );
  process.exitCode = 1;
  process.exit();
}

// npm prints its notices to stderr, but be tolerant of a stray leading line.
const parseListing = text => {
  try {
    return JSON.parse(text);
  } catch {
    const start = text.indexOf('[');
    if (start === -1) return null;
    try {
      return JSON.parse(text.slice(start));
    } catch {
      return null;
    }
  }
};

const parsed = parseListing(raw);
const entry = Array.isArray(parsed) ? parsed[0] : parsed;

if (!entry || !Array.isArray(entry.files)) {
  console.error(
    `${TAG} FAILED — \`npm pack --dry-run --json\` returned no file list. ` +
      'This gate cannot verify the artifact, so it fails closed rather than ' +
      'reporting a tarball it never inspected.'
  );
  process.exitCode = 1;
  process.exit();
}

// npm reports POSIX-style paths on every platform; normalise defensively so a
// Windows run cannot silently match nothing.
const files = entry.files.map(f => String(f.path).replace(/\\/g, '/'));
const present = new Set(files);

const missing = [...required].filter(f => !present.has(f)).sort();
const violations = [];
for (const file of files) {
  for (const [pattern, why] of FORBIDDEN) {
    if (pattern.test(file)) {
      violations.push({ file, why });
      break;
    }
  }
}

if (missing.length > 0 || violations.length > 0) {
  console.error(
    `${TAG} FAILED — the tarball is not what this package promises.\n`
  );
  if (missing.length > 0) {
    console.error(
      '  Missing (named by the `exports` map or the `files` docs, but not packed):'
    );
    for (const file of missing) console.error(`    • ${file}`);
    console.error(
      '\n  Fix: run `npm run build`, then check the `files` allowlist and ' +
        '`.npmignore`.\n'
    );
  }
  if (violations.length > 0) {
    console.error('  Must not be published:');
    for (const { file, why } of violations) {
      console.error(`    • ${file}  (${why})`);
    }
    console.error(
      '\n  Fix: delete the file, or exclude it via `.npmignore` / the `files`\n' +
        '  allowlist. Note that neither can exclude a ROOT file whose stem is\n' +
        '  readme/license/licence/copying — npm force-includes those, so such a\n' +
        '  file must be deleted or moved into a subdirectory.\n'
    );
  }
  process.exitCode = 1;
  process.exit();
}

const size = entry.unpackedSize ?? 0;
console.log(
  `${TAG} OK — ${files.length} files, ${(size / 1024).toFixed(1)} KiB unpacked; ` +
    `all ${required.size} required paths present, no forbidden path packed.`
);
process.exitCode = 0;
