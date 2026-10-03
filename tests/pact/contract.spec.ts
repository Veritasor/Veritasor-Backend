import { PactV3, MatchersV3, SpecificationVersion, Verifier } from '@pact-foundation/pact';
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import path from 'path';
import { Server } from 'http';
import { app } from '../../src/app.js';

const PACT_DIR = path.resolve(__dirname, '../pacts');
const PACT_FILE = 'Veritasor-Frontend-Veritasor-Backend.json';
const PACT_PATH = path.join(PACT_DIR, PACT_FILE);
const PUBLIC_ATTESTATIONS_BASE = '/api/v1/public/attestations';

const mockState = vi.hoisted(() => ({
  attestations: new Map<string, any>(),
}));

vi.mock('../../src/repositories/attestationRepository.js', () => ({
  getById: vi.fn(async (_client: any, id: string) => {
    return mockState.attestations.get(id) ?? null;
  }),
  create: vi.fn(),
  updateStatus: vi.fn(),
  update: vi.fn(),
  getByBusinessAndPeriod: vi.fn(),
  list: vi.fn(),
  createWithConflictCheck: vi.fn(),
  remove: vi.fn(),
  listAll: vi.fn(),
}));

vi.mock('../../src/services/integrations/retryBudget.js', () => ({
  globalOutboundRetryBudget: {
    canRetry: vi.fn(),
    recordRetry: vi.fn(),
    getRetryCount: vi.fn(),
    getRemainingBudget: vi.fn(),
    reset: vi.fn(),
  },
  GlobalRetryBudgetExceededError: class extends Error {
    code = 'GLOBAL_RETRY_BUDGET_EXCEEDED';
    currentRetryCount = 0;
    budgetLimit = 0;
  },
}));

vi.mock('../../src/routes/admin.graphql.js', () => ({
  default: ((_req: any, _res: any, next: any) => {
    next();
  }) as any,
}));

const validAttestation = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  businessId: 'bus_12345',
  period: '2026-Q2',
  merkleRoot: '0xabc123def456',
  txHash: '0xtxhash789012',
  status: 'confirmed' as const,
  version: 1,
  createdAt: new Date('2026-07-29T10:30:00.000Z'),
  updatedAt: new Date('2026-07-29T10:30:00.000Z'),
};

const revokedAttestation = {
  ...validAttestation,
  id: 'revoked123',
  status: 'revoked' as const,
};

function setupHash(hash: string, data: any): void {
  mockState.attestations.set(hash, data);
}
function clearHash(hash: string): void {
  mockState.attestations.delete(hash);
}

describe('Veritasor-Backend Pact Contract', () => {
  let server: Server;
  let PORT: number;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address();
        PORT = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
  });

  it('generates and verifies the pact contract', async () => {
    const provider = new PactV3({
      consumer: 'Veritasor-Frontend',
      provider: 'Veritasor-Backend',
      dir: PACT_DIR,
      spec: SpecificationVersion.SPECIFICATION_VERSION_V2,
    });

    const longHash = 'x'.repeat(513);

    // --- Consumer-side interactions ---
    const interactions: Array<{
      setup: (p: PactV3) => void;
      test: (url: string) => Promise<void>;
    }> = [
      {
        setup: (p) =>
          p
            .given('server is healthy')
            .uponReceiving('a request for the health check')
            .withRequest({ method: 'GET', path: '/api/health' })
            .willRespondWith({
              status: 200,
              headers: { 'Content-Type': 'application/json; charset=utf-8' },
              body: {
                status: MatchersV3.like('ok'),
                service: MatchersV3.like('veritasor-backend'),
                timestamp: MatchersV3.like('2026-07-29T12:15:15.000Z'),
              },
            }),
        test: async (url) => {
          const res = await fetch(`${url}/api/health`);
          expect(res.status).toBe(200);
        },
      },
      {
        setup: (p) =>
          p
            .given('an attestation exists with hash "abc123"')
            .uponReceiving('a request for an attestation by valid hash')
            .withRequest({ method: 'GET', path: `${PUBLIC_ATTESTATIONS_BASE}/abc123` })
            .willRespondWith({
              status: 200,
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Cache-Control': 'public, max-age=60, stale-while-revalidate=60',
                'ETag': '"eyJpZCI6IjU1MGU4NDAwLWUyOWItNDFk"',
                'Last-Modified': 'Wed, 29 Jul 2026 10:30:00 GMT',
                'Age': '0',
              },
              body: {
                status: 'success',
                data: {
                  id: MatchersV3.regex(/^[a-f0-9-]+$/, '550e8400-e29b-41d4-a716-446655440000'),
                  businessId: MatchersV3.like('bus_12345'),
                  period: MatchersV3.like('2026-Q2'),
                  merkleRoot: MatchersV3.like('0xabc123def456'),
                  txHash: MatchersV3.like('0xtxhash789012'),
                  status: 'confirmed',
                  attestedAt: MatchersV3.regex(
                    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
                    '2026-07-29T10:30:00.000Z',
                  ),
                },
              },
            }),
        test: async (url) => {
          const res = await fetch(`${url}${PUBLIC_ATTESTATIONS_BASE}/abc123`);
          expect(res.status).toBe(200);
        },
      },
      {
        setup: (p) =>
          p
            .given('an attestation exists with hash "abc123" and the request has a matching ETag')
            .uponReceiving('a request with matching If-None-Match header')
            .withRequest({
              method: 'GET',
              path: `${PUBLIC_ATTESTATIONS_BASE}/abc123`,
              headers: { 'If-None-Match': '"eyJpZCI6IjU1MGU4NDAwLWUyOWItNDFk"' },
            })
            .willRespondWith({ status: 304 }),
        test: async (url) => {
          const res = await fetch(`${url}${PUBLIC_ATTESTATIONS_BASE}/abc123`, {
            headers: { 'If-None-Match': '"eyJpZCI6IjU1MGU4NDAwLWUyOWItNDFk"' },
          });
          expect(res.status).toBe(304);
        },
      },
      {
        setup: (p) =>
          p
            .given('no attestation exists with hash "nonexistent"')
            .uponReceiving('a request for an attestation by non-existent hash')
            .withRequest({ method: 'GET', path: `${PUBLIC_ATTESTATIONS_BASE}/nonexistent` })
            .willRespondWith({
              status: 404,
              headers: { 'Content-Type': 'application/json; charset=utf-8' },
              body: { status: 'error', code: 'NOT_FOUND', message: 'Attestation not found' },
            }),
        test: async (url) => {
          const res = await fetch(`${url}${PUBLIC_ATTESTATIONS_BASE}/nonexistent`);
          expect(res.status).toBe(404);
        },
      },
      {
        setup: (p) =>
          p
            .given('an attestation exists with hash "revoked123" and status "revoked"')
            .uponReceiving('a request for a revoked attestation')
            .withRequest({ method: 'GET', path: `${PUBLIC_ATTESTATIONS_BASE}/revoked123` })
            .willRespondWith({
              status: 410,
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Cache-Control': 'public, max-age=15, stale-while-revalidate=60',
                'Age': '0',
              },
              body: { status: 'error', code: 'GONE', message: 'Attestation has been revoked' },
            }),
        test: async (url) => {
          const res = await fetch(`${url}${PUBLIC_ATTESTATIONS_BASE}/revoked123`);
          expect(res.status).toBe(410);
        },
      },
      {
        setup: (p) =>
          p
            .given('server is healthy')
            .uponReceiving('a request with a hash exceeding maximum length')
            .withRequest({ method: 'GET', path: `${PUBLIC_ATTESTATIONS_BASE}/${longHash}` })
            .willRespondWith({
              status: 400,
              headers: { 'Content-Type': 'application/json; charset=utf-8' },
              body: {
                status: 'error',
                vrtCode: 'VRT-0002',
                message: 'Invalid attestation identifier',
                timestamp: MatchersV3.like('2026-07-29T12:15:15.000Z'),
              },
            }),
        test: async (url) => {
          const res = await fetch(`${url}${PUBLIC_ATTESTATIONS_BASE}/${longHash}`);
          expect(res.status).toBe(400);
        },
      },
    ];

    // Run each consumer interaction
    for (const interaction of interactions) {
      interaction.setup(provider);
      await provider.executeTest(async (mockServer) => {
        await interaction.test(mockServer.url);
      });
    }

    // --- Provider verification ---
    setupHash('abc123', validAttestation);
    setupHash('revoked123', revokedAttestation);

    const verifier = new Verifier({
      provider: 'Veritasor-Backend',
      providerBaseUrl: `http://localhost:${PORT}`,
      pactUrls: [PACT_PATH],
      stateHandlers: {
        'server is healthy': async () => {
          mockState.attestations.clear();
          setupHash('abc123', validAttestation);
          setupHash('revoked123', revokedAttestation);
        },
        'an attestation exists with hash "abc123"': async () => {
          setupHash('abc123', validAttestation);
        },
        'an attestation exists with hash "abc123" and the request has a matching ETag': async () => {
          setupHash('abc123', validAttestation);
        },
        'no attestation exists with hash "nonexistent"': async () => {
          clearHash('nonexistent');
        },
        'an attestation exists with hash "revoked123" and status "revoked"': async () => {
          setupHash('revoked123', revokedAttestation);
        },
      },
    });

    const result = await verifier.verifyProvider();
    expect(result).toBeDefined();
  }, 30000);
});
