/**
 * Gate-surface tests.
 *
 * The project's quality gates are only worth what they are still configured to
 * run. Two of them are one edit away from being silently hollowed out:
 *
 *   1. `prepublishOnly` and the everyday gate command. They used to be two
 *      hand-chained lists of the same scripts, which is a drift hazard: adding
 *      a gate to one and forgetting the other means a release ships without a
 *      check that every working session ran. `prepublishOnly` is now defined as
 *      exactly `npm run verify`, and this suite pins that, plus the exact set
 *      and order of the gates `verify` chains, plus the existence of every
 *      script it names.
 *
 *   2. The Jest coverage thresholds. They are a ONE-WAY RATCHET holding the
 *      measured `All files` values floored to integers. Lowering one, or adding
 *      a `collectCoverageFrom` exclusion to shrink the denominator, is the
 *      cheapest possible way to turn a red run green while making the suite
 *      weaker. Both moves fail here.
 *
 * Both read the real repo-root files (not a fixture), because the shipped
 * configuration is the thing under test.
 */
import { describe, it, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// jest sets cwd to the project root; `__dirname` is not reliably defined in
// jest's ESM mode (same convention as esm-smoke.test.ts).
const REPO_ROOT = process.cwd();

/**
 * The gates `npm run verify` must chain, in order.
 *
 * Order is asserted, not just membership, and it is load-bearing:
 * `lint`/`type-check` run before `build` so a syntactically broken `src/` is
 * reported by the tools that explain it rather than by `tsc`'s emit, and the
 * four `check:*` gates run last because all four read the freshly built
 * `dist/`. A `verify` that ran `check:browser` before `build` would be
 * validating the PREVIOUS build's output.
 */
const VERIFY_GATES = [
  'lint',
  'type-check',
  'build',
  'test',
  'check:browser',
  'check:types:browser',
  'check:exports',
  'check:tarball',
] as const;

/**
 * The ratchet floor. These are the measured `All files` coverage values floored
 * to integers (2026-09-05: statements 95.94, branches 87.20, functions 97.98,
 * lines 95.96). The configured thresholds may be RAISED above these when a run
 * measures higher; they may never fall below them.
 */
const COVERAGE_FLOOR = {
  statements: 95,
  branches: 87,
  functions: 97,
  lines: 95,
} as const;

/**
 * The only coverage exclusions this project has agreed to: declaration files,
 * the test files themselves, and the `__tests__` directory (which may hold
 * non-`.test.ts` helpers). Anything else excluded is a shrunken denominator.
 */
const ALLOWED_COVERAGE_EXCLUSIONS = [
  '!src/**/*.d.ts',
  '!src/**/*.test.ts',
  '!src/**/*.spec.ts',
  '!src/__tests__/**',
];

type PackageJson = { scripts?: Record<string, string> };

const readPackageJson = (): PackageJson =>
  JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')
  ) as PackageJson;

/**
 * `npm run a && npm test` -> `['a', 'test']`.
 *
 * `npm test` is npm's built-in alias for `npm run test`, and that is the form
 * the chain actually uses, so both spellings resolve to the same script name.
 */
const parseNpmRunChain = (command: string): string[] =>
  command
    .split('&&')
    .map(part => part.trim())
    .map(part => /^npm (?:run\s+(\S+)|(test|start))$/.exec(part))
    .map(match => (match ? ((match[1] ?? match[2]) as string) : ''))
    .filter(name => name.length > 0);

describe('gate surface: npm scripts', () => {
  it('defines `verify` as exactly the eight gates, in the order that keeps them meaningful', () => {
    const scripts = readPackageJson().scripts ?? {};
    const verify = scripts['verify'];
    expect(typeof verify).toBe('string');

    expect(parseNpmRunChain(verify as string)).toEqual([...VERIFY_GATES]);

    // Every segment is an `npm run <script>` joined by `&&`: no `;`, no `||`,
    // no `|| true`, no backgrounding. A `;` or `||` between two gates makes a
    // failing gate non-fatal, which is exactly the silent-hollowing this suite
    // exists to catch.
    expect(verify).not.toMatch(/\|\|/);
    expect(verify).not.toMatch(/;/);
    expect(verify).not.toMatch(/--passWithNoTests|--exit-zero|\bexit 0\b/);

    // Each named gate must actually exist as a script, otherwise `verify`
    // fails for the wrong reason (or, worse, npm's error is mistaken for the
    // gate's own failure).
    for (const gate of VERIFY_GATES) {
      expect(Object.keys(scripts)).toContain(gate);
      expect(scripts[gate]).toBeTruthy();
    }
  });

  it('defines `prepublishOnly` as `npm run verify` so the release gate cannot drift from the session gate', () => {
    const scripts = readPackageJson().scripts ?? {};

    // The negative that matters: `prepublishOnly` must NOT re-chain the gates
    // itself. A hand-written copy is what allowed the two to diverge before,
    // and a copy that merely happens to match today is still a drift hazard —
    // so this asserts delegation, not equivalence.
    expect(scripts['prepublishOnly']).toBe('npm run verify');
  });

  it('keeps every gate script able to fail: no swallowed failure, no committed test filter', () => {
    const scripts = readPackageJson().scripts ?? {};

    // Pinning the CHAIN is only half the job. `verify` can name all seven
    // gates and still gate nothing if one of the gates itself is hollowed out
    // — `"lint": "eslint src || true"` leaves every assertion above green
    // while removing lint from the gauntlet entirely. So each gate's own
    // command body is checked for the ways a non-zero exit gets discarded.
    const SWALLOWED_FAILURE = [
      /\|\|\s*true/, // `cmd || true`
      /\|\|\s*:/, // `cmd || :` (the `:` builtin, a quieter `true`)
      /\|\|\s*exit\s+0/, // `cmd || exit 0`
      /;\s*exit\s+0/, // `cmd ; exit 0`
      /set\s+\+e/, // disables abort-on-error for the rest of the script
      /--exit-zero/, // ruff/clippy-style "report but never fail"
      /--passWithNoTests/, // an empty suite is a green suite
      /continue-on-error/,
    ];

    for (const gate of VERIFY_GATES) {
      const body = scripts[gate];
      expect(typeof body).toBe('string');
      for (const pattern of SWALLOWED_FAILURE) {
        expect(body as string).not.toMatch(pattern);
      }
    }

    // A filter flag committed into the test gate silently shrinks the suite to
    // whatever subset the flag names, which is a deleted test wearing a
    // disguise. (`--coverage` and `--ci` are fine; only selection is banned.)
    const testScript = scripts['test'] as string;
    for (const filterFlag of [
      /(^|\s)-t(\s|=)/,
      /--testNamePattern/,
      /--testPathPattern/,
      /(^|\s)--grep(\s|=)/,
      /(^|\s)--onlyFailures(\s|$)/,
    ]) {
      expect(testScript).not.toMatch(filterFlag);
    }
  });

  it('keeps the four static packaging gates in the chain', () => {
    // This is NOT redundant with the exact-chain assertion above, and it must
    // not be "simplified" away. That one compares against the VERIFY_GATES
    // constant declared in THIS file, so an edit that drops a gate from
    // `package.json` AND from the constant keeps it green. These four names
    // are literals, so the same edit fails here. They are also the four gates
    // with no local developer habit behind them — nobody runs `attw` or packs
    // a tarball by hand — so if one quietly leaves `verify`, nothing else in
    // the repo notices.
    const verify = readPackageJson().scripts?.['verify'] ?? '';
    const chain = parseNpmRunChain(verify);
    expect(chain).toContain('check:browser');
    expect(chain).toContain('check:types:browser');
    expect(chain).toContain('check:exports');
    expect(chain).toContain('check:tarball');
  });
});

describe('gate surface: coverage ratchet', () => {
  it('holds every coverage threshold at or above the measured floor', async () => {
    const configUrl = pathToFileURL(
      path.join(REPO_ROOT, 'jest.config.js')
    ).href;
    const mod = (await import(configUrl)) as {
      default: {
        coverageThreshold?: { global?: Record<string, number> };
        collectCoverageFrom?: string[];
      };
    };
    const global = mod.default.coverageThreshold?.global;
    expect(global).toBeDefined();

    for (const [metric, floor] of Object.entries(COVERAGE_FLOOR)) {
      const configured = (global as Record<string, number>)[metric];
      expect(typeof configured).toBe('number');
      expect(configured).toBeGreaterThanOrEqual(floor);
    }

    // The ratchet is meaningless if the denominator can be shrunk instead:
    // excluding a poorly covered source file raises every percentage without
    // testing a single line. Only the agreed exclusions may appear.
    const patterns = mod.default.collectCoverageFrom ?? [];
    expect(patterns).toContain('src/**/*.ts');
    expect(patterns.filter(p => p.startsWith('!'))).toEqual(
      ALLOWED_COVERAGE_EXCLUSIONS
    );
  });
});
