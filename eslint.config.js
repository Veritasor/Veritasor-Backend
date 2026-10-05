import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'sbom/**'],
  },
  tseslint.configs.base,
  {
    files: ['src/**/*.{ts,js}'],
    rules: {
      // Base config only parses TS without noisy stylistic errors on legacy files
    },
  },
);
