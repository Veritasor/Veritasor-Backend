/**
 * Stryker mutation testing configuration.
 *
 * Targets src/services/merkle.ts and src/services/soroban/** for mutation
 * testing. Uses the vitest runner with an initial threshold of 70%.
 * The threshold should be raised to 85% within 30 days as test coverage improves.
 *
 * Run: pnpm run test:mutation
 */
export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  reporters: ["progress", "clear-text", "html"],
  coverageAnalysis: "perTest",
  thresholds: {
    high: 85,
    low: 70,
    break: 70,
  },
  mutate: [
    "src/services/merkle.ts",
    "src/services/merkle/**/*.ts",
    "src/services/soroban/**/*.ts",
  ],
  testFiles: [
    "tests/unit/services/merkle.test.ts",
    "tests/unit/services/soroban/submitAttestation.test.ts",
  ],
  vitest: {
    configFile: "vitest.config.ts",
  },
  timeoutMS: 30000,
  ignoreStatic: false,
  cleanTempDir: "always",
  tsconfigFile: "tsconfig.json",
  tempDirName: ".stryker-tmp",
};
