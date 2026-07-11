/**
 * Vitest configuration — REAL-browser suite only.
 *
 * The Node suite stays on Jest (`npm run test` / `npm run test:node`); this
 * config adds a SEPARATE browser suite that runs inside a real headless
 * Chromium via Vitest Browser Mode (Playwright provider). It exists to prove
 * the crown-jewel guarantee — one wire format that round-trips Node <-> browser
 * — inside an actual browser engine (SubtleCrypto + hash-wasm WASM Argon2id),
 * not merely a Node process emulating one.
 *
 * Design notes:
 *  - `test.include` is scoped to the browser specs under
 *    `src/__tests__/browser/` (files ending `.browser.test.ts`) so Vitest runs
 *    ONLY the browser specs and never the Jest Node suite. The
 *    reciprocal exclusion (Jest ignoring this glob) lives in `jest.config.js`
 *    (`testPathIgnorePatterns`), so the two runners never collide.
 *  - Globals are OFF (Vitest's default): the browser specs import
 *    `describe`/`it`/`expect` explicitly from `'vitest'`, mirroring the Node
 *    suite's explicit `@jest/globals` convention.
 *  - The specs import the BUILT browser entry (`dist/index.browser.js`), so
 *    `npm run build` is a prerequisite (the CI `browser-tests` job builds
 *    first). That graph is `node:`-free by construction (enforced by
 *    `npm run check:browser`), so Vite bundles it for the browser cleanly.
 *  - Argon2id (hash-wasm, WASM) at the repo's low-cost test profile takes a
 *    handful of hundred milliseconds per derivation; the suite loops over many
 *    of them, so `testTimeout` is raised well above Vitest's 5s default.
 *  - `@vitest/browser-playwright` is the Vitest v4 Playwright provider package
 *    (v4 split the provider out of `@vitest/browser`).
 *
 * Excluded from the published tarball via `.npmignore` (and the `package.json`
 * `files` allowlist, which ships only `dist/` + docs).
 */
import { defineConfig } from 'vitest/config';
import { playwright } from '@vitest/browser-playwright';

export default defineConfig({
  test: {
    // Run ONLY the real-browser specs; the Jest Node suite is out of scope for
    // Vitest (and vice-versa).
    include: ['src/__tests__/browser/**/*.browser.test.ts'],
    // Argon2id (WASM) derivations loop across sizes/vectors; give each test
    // plenty of headroom over the 5s default.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    browser: {
      enabled: true,
      headless: true,
      // Vitest v4 Playwright provider (from `@vitest/browser-playwright`).
      provider: playwright(),
      // A single headless Chromium instance is sufficient: the one-wire-format
      // interop guarantee is engine-, not vendor-, specific.
      instances: [{ browser: 'chromium' }],
      // Keep the working tree clean — do not write screenshot artifacts on a
      // failing assertion (the failure message + stack are enough to debug).
      screenshotFailures: false,
    },
  },
});
