export default {
  preset: 'ts-jest/presets/default-esm',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: {
          module: 'ESNext',
          moduleResolution: 'Bundler',
          // ts-jest 29.4.x's legacy compiler internally hard-codes
          // `moduleResolution: Node10` (see node_modules/ts-jest/dist/legacy/compiler/ts-compiler.js)
          // before merging our override. TypeScript 6.0 errors on `node10` as
          // deprecated. Until ts-jest releases a TS-6-aware version, we opt
          // into the documented `ignoreDeprecations: "6.0"` escape hatch so
          // tests run. This does NOT affect our production tsconfig.json
          // (which uses NodeNext) — it only silences the deprecation in the
          // jest test compile step.
          ignoreDeprecations: '6.0',
        },
      },
    ],
  },
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    // Defensive — `__tests__` doesn't currently contain non-test scaffolding,
    // but if a future contributor adds a helper file under `__tests__`
    // without a `.test.ts` suffix, the file-name patterns above wouldn't
    // catch it. Excluding the whole directory keeps coverage % grounded
    // in production code only. (FIX.md Task 28.)
    '!src/__tests__/**',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  // One-way ratchet. These are the measured `All files` values floored to
  // integers (2026-09-05: statements 95.93, branches 87.16, functions 97.98,
  // lines 95.95 over 25 suites / 1106 tests). `gate-surface.test.ts` asserts
  // that none of them ever falls below that floor. They move UP only: when a run
  // measures higher, raise them; when a run measures lower, the cause is a
  // missing test and that is what gets fixed. Never lower a number and never
  // add a `collectCoverageFrom` exclusion to make a number look better.
  coverageThreshold: {
    global: {
      branches: 87,
      functions: 97,
      lines: 95,
      statements: 95,
    },
  },
  // Exclude the real-browser Vitest suite from the Jest run. The specs under
  // `src/__tests__/browser/` import from `'vitest'` and the built browser entry
  // and are executed by Vitest Browser Mode (`npm run test:browser`), NOT Jest.
  // Without this, Jest's `testMatch` (`**/__tests__/**/*.ts`) would collect them
  // and fail on the `'vitest'` import. `collectCoverageFrom` already excludes
  // `src/__tests__/**`, so browser specs never affect coverage either.
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/src/__tests__/browser/',
  ],
};
