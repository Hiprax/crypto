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
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
};
