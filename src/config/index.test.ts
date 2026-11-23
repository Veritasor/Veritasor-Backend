import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ConfigValidationError } from './index.js';

vi.mock('../app.js', () => ({
  startServer: vi.fn(),
  stopIdempotencySweeper: vi.fn(),
}));
vi.mock('../services/pgbouncerScraper.js', () => ({
  stopPgBouncerScraperIfNeeded: vi.fn(),
}));
vi.mock('../db/client.js', () => ({
  pool: { end: vi.fn() },
}));
vi.mock('../shutdown.js', () => ({
  createShutdownOrchestrator: vi.fn(() => ({ register: vi.fn() })),
}));
vi.mock('../services/revenue/kafkaConsumer.js', () => ({
  createRevenueConsumer: vi.fn(),
}));
vi.mock('../services/metrics/statsdBootstrap.js', () => ({
  stopStatsdDualWriteIfNeeded: vi.fn(),
}));

describe('SECRET_LOADER and SECRET_PROVIDER config & bootstrap validation', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    delete process.env.DATABASE_URL;
    delete process.env.NODE_ENV;
    delete process.env.JWT_SECRET;
    delete process.env.ALLOWED_ORIGINS;
    delete process.env.STELLAR_NETWORK;
    delete process.env.SECRET_LOADER;
    delete process.env.SECRET_PROVIDER;
    delete process.env.SECRET_FILE_PATH;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  async function loadConfig() {
    return await import('./index.js');
  }

  it('throws ConfigValidationError when SECRET_LOADER=env and SECRET_PROVIDER=vault together', async () => {
    process.env.NODE_ENV = 'development';
    process.env.DATABASE_URL = 'postgres://localhost:5432/db';
    process.env.SECRET_LOADER = 'env';
    process.env.SECRET_PROVIDER = 'vault';

    try {
      await loadConfig();
      expect.fail('Expected loadConfig to throw');
    } catch (err: any) {
      expect(err.name).toBe('ConfigValidationError');
      expect(err.message).toMatch(/conflict: both are set and disagree/);
    }
  });

  it('fails bootstrap in production when SECRET_LOADER=file and the file JWT_SECRET is 10 characters', async () => {
    process.env.NODE_ENV = 'production';
    process.env.DATABASE_URL = 'postgres://localhost:5432/db';
    process.env.ALLOWED_ORIGINS = 'https://example.com';
    process.env.SECRET_LOADER = 'file';
    process.env.SECRET_FILE_PATH = '/tmp/test_jwt_secret.json';

    // Mock fs so /tmp/test_jwt_secret.json contains a 10-char JWT_SECRET
    const fs = await import('node:fs/promises');
    await fs.writeFile('/tmp/test_jwt_secret.json', JSON.stringify({ JWT_SECRET: '1234567890' }));

    try {
      const { bootstrap } = await import('../index.js');
      await expect(bootstrap()).rejects.toThrow(
        /JWT_SECRET resolved from secret loader must be at least 32 characters in production/,
      );
    } finally {
      await fs.unlink('/tmp/test_jwt_secret.json').catch(() => {});
    }
  });
});
