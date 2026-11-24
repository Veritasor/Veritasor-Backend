import { afterEach, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

it('refuses to load seeded attestations outside tests', async () => {
  vi.stubEnv('NODE_ENV', 'production');
  await expect(import('../../../src/repositories/attestation.js'))
    .rejects.toThrow('only in tests');
});
