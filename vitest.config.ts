import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    env: {
      DATABASE_URL: 'postgres://localhost:5432/test_db',
      NODE_ENV: 'test',
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['src/**/*.ts', 'src/**/*.js'],
      exclude: ['src/**/*.d.ts', 'src/index.ts'],
      reportsDirectory: 'coverage',
    },
  },
})
