#!/usr/bin/env node
/**
 * Browser-graph isolation gate for @hiprax/crypto.
 *
 * Bundles the compiled browser entry (`dist/index.browser.js`) with esbuild's
 * JavaScript API under `platform: 'browser'`. esbuild does NOT auto-external
 * Node builtins for the browser platform, so the instant any `node:` specifier
 * is reachable from the browser entry's import graph, resolution fails and this
 * script exits non-zero. That is the hard, continuous proof that
 * `node:crypto` / `node:fs` / `node:stream` never enter the browser bundle.
 *
 * Cross-platform by construction: it uses the in-memory esbuild API
 * (`write: false`) rather than the POSIX-only `--outfile=/dev/null` CLI form,
 * which resolves to a Windows-invalid path (this repo and CI both run on
 * Windows as well as Linux).
 *
 * A dedicated `onResolve` hook turns any `node:` specifier into a clear,
 * actionable error naming the offending builtin and its importer — a crisper
 * signal than esbuild's generic "Could not resolve", and belt-and-suspenders
 * against a future config that might mark `node:` builtins external.
 *
 * Scope note: this gate catches `node:` SPECIFIERS only, not a bare `Buffer` /
 * `process` GLOBAL. The latter is covered by the ESLint `no-restricted-globals`
 * override scoped to the isomorphic source files (see `eslint.config.ts`).
 */
import { build } from 'esbuild';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);
const entry = path.join(repoRoot, 'dist', 'index.browser.js');

if (!existsSync(entry)) {
  console.error(
    `[check:browser] Browser entry not found at ${entry}.\n` +
      'Run `npm run build` before this check.'
  );
  process.exit(1);
}

/**
 * esbuild plugin: reject any `node:`-prefixed import reachable from the browser
 * graph with an explicit, importer-aware error.
 */
const nodeBuiltinGuard = {
  name: 'node-builtin-guard',
  setup(pluginBuild) {
    pluginBuild.onResolve({ filter: /^node:/ }, (args) => ({
      errors: [
        {
          text:
            `Browser graph must not import the Node builtin "${args.path}"` +
            (args.importer ? ` (imported from ${args.importer})` : ''),
        },
      ],
    }));
  },
};

let ok = false;
try {
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    platform: 'browser',
    format: 'esm',
    write: false,
    logLevel: 'silent',
    metafile: true,
    plugins: [nodeBuiltinGuard],
  });

  const moduleCount = Object.keys(result.metafile.inputs).length;
  const bytes = result.outputFiles.reduce(
    (total, file) => total + file.contents.length,
    0
  );
  console.log(
    '[check:browser] OK — browser bundle resolved with no Node builtins ' +
      `(${moduleCount} modules, ${(bytes / 1024).toFixed(1)} KiB).`
  );
  ok = true;
} catch (err) {
  console.error(
    '[check:browser] FAILED — the browser entry graph reaches a Node builtin ' +
      '(`node:*`) or otherwise did not bundle for platform=browser:\n'
  );
  const messages = err && Array.isArray(err.errors) ? err.errors : [];
  if (messages.length > 0) {
    for (const message of messages) {
      const loc = message.location
        ? ` [${message.location.file}:${message.location.line}:${message.location.column}]`
        : '';
      console.error(`  • ${message.text}${loc}`);
    }
  } else {
    console.error(err && err.stack ? err.stack : String(err));
  }
  ok = false;
}

// Use `process.exitCode` (not `process.exit()`) so stdout/stderr flush fully
// before the process terminates naturally — esbuild unrefs its service child,
// so nothing keeps the event loop alive once the build settles.
process.exitCode = ok ? 0 : 1;
