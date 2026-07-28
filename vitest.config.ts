export default {
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts', 'tests/**/*.spec.ts', 'src/**/*.test.ts', 'src/**/*.spec.ts'],
    env: {
      DATABASE_URL: "postgres://localhost:5432/test_db",
      NODE_ENV: "test",
      SOROBAN_CONTRACT_ID:
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
      JWT_SECRET: "test-jwt-secret-key-at-least-thirty-two-characters-long",
      ENCRYPTION_KEY: "01234567890123456789012345678901",
    },
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov", "html"],
      include: ["src/**/*.ts", "src/**/*.js"],
      exclude: ["src/**/*.d.ts", "src/index.ts"],
      reportsDirectory: "coverage",
    },
    server: {
      deps: {
        inline: ["C:"],
      },
    },
  },
};
