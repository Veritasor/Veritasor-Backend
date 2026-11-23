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

/**
 * Deterministic identity used by the authenticated users + webhook-subscription
 * interactions. The JWT verifier is mocked so the pact file can carry a fixed,
 * non-expiring bearer token instead of a short-lived signed JWT.
 */
const pactAuth = vi.hoisted(() => {
  const userId = 'pact-user-1';
  const email = 'pact.user@example.com';
  const businessId = 'pact-business-1';
  const createdAt = '2026-02-18T09:00:00.000Z';
  const updatedAt = '2026-11-20T15:30:00.000Z';
  return {
    userId,
    email,
    businessId,
    token: 'pact-test-access-token',
    user: {
      id: userId,
      email,
      passwordHash: '$2b$12$pact-secret-hash-that-must-never-leak',
      createdAt: new Date(createdAt),
      updatedAt: new Date(updatedAt),
      role: 'user' as const,
    },
    business: {
      id: businessId,
      userId,
      name: 'Pact Business',
      email,
      industry: null,
      description: null,
      website: null,
      reportingPeriod: 'monthly' as const,
      reportingTimezone: 'UTC',
      lastReminderSentAt: null,
      createdAt,
      updatedAt,
    },
  };
});

/** Webhook subscriptions returned by the mocked repository during verification. */
const webhookState = vi.hoisted(() => ({
  subscriptions: [] as any[],
}));

vi.mock('../../src/utils/jwt.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/utils/jwt.js')>();
  return {
    ...actual,
    verifyToken: vi.fn((token: string) =>
      token === pactAuth.token
        ? { userId: pactAuth.userId, email: pactAuth.email }
        : null,
    ),
  };
});

vi.mock('../../src/repositories/userRepository.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/repositories/userRepository.js')>();
  return {
    ...actual,
    findUserById: vi.fn(async (id: string) =>
      id === pactAuth.userId ? { ...pactAuth.user, createdAt: new Date(pactAuth.user.createdAt), updatedAt: new Date(pactAuth.user.updatedAt) } : null,
    ),
  };
});

vi.mock('../../src/repositories/business.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/repositories/business.js')>();
  return {
    ...actual,
    businessRepository: {
      ...actual.businessRepository,
      getById: vi.fn(async (id: string) =>
        id === pactAuth.businessId ? { ...pactAuth.business } : null,
      ),
    },
  };
});

vi.mock('../../src/repositories/webhookSubscriptionRepository.js', async (importOriginal) => {
  const actual = await importOriginal<
    typeof import('../../src/repositories/webhookSubscriptionRepository.js')
  >();
  return {
    ...actual,
    list: vi.fn(async () => ({ data: webhookState.subscriptions })),
    countByBusiness: vi.fn(async () => webhookState.subscriptions.length),
    create: vi.fn(async (businessId: string, input: any) => ({
      id: 'whsub_pact_created',
      businessId,
      url: input.url,
      secret: input.secret,
      eventFilters: input.eventFilters ?? {},
      enabled: input.enabled ?? true,
      maxPayloadSize: input.maxPayloadSize ?? null,
      secretVersion: 1,
      mtlsConfig: input.mtlsConfig ?? null,
      createdAt: new Date('2026-11-20T10:00:00.000Z'),
      updatedAt: new Date('2026-11-20T10:00:00.000Z'),
    })),
  };
});

vi.mock('../../src/repositories/attestationRepository.js', () => ({
  getById: vi.fn(async (_client: any, id: string) => {
    return mockState.attestations.get(id) ?? null;
  }),
  getByMerkleRoot: vi.fn(async (_client: any, merkleRoot: string) => {
    return mockState.attestations.get(merkleRoot) ?? null;
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

const PACT_WEBHOOK_SECRET = 'pact-webhook-secret-0123456789abcd';
const PACT_WEBHOOK_URL = 'https://example.com/webhooks/pact';

/** Seed a subscription fixture as returned by the repository layer. */
function makeWebhookSubscription(overrides: Record<string, unknown> = {}) {
  return {
    id: 'whsub_pact_1',
    businessId: pactAuth.businessId,
    url: PACT_WEBHOOK_URL,
    secret: PACT_WEBHOOK_SECRET,
    eventFilters: { 'attestation.created': true },
    enabled: true,
    maxPayloadSize: null,
    secretVersion: 1,
    mtlsConfig: null,
    createdAt: new Date('2026-11-20T10:00:00.000Z'),
    updatedAt: new Date('2026-11-20T10:00:00.000Z'),
    ...overrides,
  };
}

const authHeaders = {
  Authorization: `Bearer ${pactAuth.token}`,
};

const businessHeaders = {
  ...authHeaders,
  'x-business-id': pactAuth.businessId,
};

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
                'Cache-Control': 'public, max-age=60, stale-while-revalidate=60, stale-if-error=86400',
                'ETag': '"LHhRKkd446BzEj48D+eXBu90be2WetQXTVwgGKLREPY="',
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
              headers: { 'If-None-Match': '"LHhRKkd446BzEj48D+eXBu90be2WetQXTVwgGKLREPY="' },
            })
            .willRespondWith({ status: 304 }),
        test: async (url) => {
          const res = await fetch(`${url}${PUBLIC_ATTESTATIONS_BASE}/abc123`, {
            headers: { 'If-None-Match': '"LHhRKkd446BzEj48D+eXBu90be2WetQXTVwgGKLREPY="' },
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
                'Cache-Control': 'public, max-age=15, stale-while-revalidate=60, stale-if-error=3600',
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
      {
        setup: (p) =>
          p
            .given('an authenticated user exists')
            .uponReceiving('a request to update the current user profile')
            .withRequest({
              method: 'PATCH',
              path: '/api/users/me',
              headers: { ...authHeaders, 'Content-Type': 'application/json' },
              body: { name: 'Pact User' },
            })
            .willRespondWith({
              status: 200,
              headers: { 'Content-Type': 'application/json; charset=utf-8' },
              body: {
                id: pactAuth.userId,
                email: MatchersV3.like('user@example.com'),
                name: MatchersV3.like('Pact User'),
                profile: MatchersV3.like({}),
              },
            }),
        test: async (url) => {
          const res = await fetch(`${url}/api/users/me`, {
            method: 'PATCH',
            headers: { ...authHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: 'Pact User' }),
          });
          expect(res.status).toBe(200);
        },
      },
      {
        setup: (p) =>
          p
            .given('a business has at least one webhook subscription')
            .uponReceiving('a request to list webhook subscriptions')
            .withRequest({
              method: 'GET',
              path: '/api/v1/webhook-subscriptions',
              headers: businessHeaders,
            })
            .willRespondWith({
              status: 200,
              headers: { 'Content-Type': 'application/json; charset=utf-8' },
              body: {
                status: 'success',
                data: MatchersV3.eachLike({
                  id: 'whsub_pact_1',
                  businessId: pactAuth.businessId,
                  url: PACT_WEBHOOK_URL,
                  eventFilters: { 'attestation.created': true },
                  enabled: true,
                  maxPayloadSize: null,
                  secretVersion: 1,
                  secretLast4: 'abcd',
                  mtlsConfig: null,
                  createdAt: '2026-11-20T10:00:00.000Z',
                  updatedAt: '2026-11-20T10:00:00.000Z',
                }),
              },
            }),
        test: async (url) => {
          const res = await fetch(`${url}/api/v1/webhook-subscriptions`, {
            headers: businessHeaders,
          });
          expect(res.status).toBe(200);
        },
      },
      {
        setup: (p) =>
          p
            .given('a business has room for another webhook subscription')
            .uponReceiving('a request to create a webhook subscription')
            .withRequest({
              method: 'POST',
              path: '/api/v1/webhook-subscriptions',
              headers: { ...businessHeaders, 'Content-Type': 'application/json' },
              body: {
                url: PACT_WEBHOOK_URL,
                secret: PACT_WEBHOOK_SECRET,
                eventFilters: { 'attestation.created': true },
              },
            })
            .willRespondWith({
              status: 201,
              headers: { 'Content-Type': 'application/json; charset=utf-8' },
              body: {
                status: 'success',
                data: MatchersV3.like({
                  id: 'whsub_pact_created',
                  businessId: pactAuth.businessId,
                  url: PACT_WEBHOOK_URL,
                  eventFilters: { 'attestation.created': true },
                  enabled: true,
                  maxPayloadSize: null,
                  secretVersion: 1,
                  secretLast4: 'abcd',
                  mtlsConfig: null,
                  createdAt: '2026-11-20T10:00:00.000Z',
                  updatedAt: '2026-11-20T10:00:00.000Z',
                  secret: PACT_WEBHOOK_SECRET,
                }),
              },
            }),
        test: async (url) => {
          const res = await fetch(`${url}/api/v1/webhook-subscriptions`, {
            method: 'POST',
            headers: { ...businessHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: PACT_WEBHOOK_URL,
              secret: PACT_WEBHOOK_SECRET,
              eventFilters: { 'attestation.created': true },
            }),
          });
          expect(res.status).toBe(201);
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
        'an authenticated user exists': async () => {
          // The user repository mock always resolves the Pact identity.
        },
        'a business has at least one webhook subscription': async () => {
          webhookState.subscriptions = [makeWebhookSubscription()];
        },
        'a business has room for another webhook subscription': async () => {
          webhookState.subscriptions = [];
        },
      },
    });

    const result = await verifier.verifyProvider();
    expect(result).toBeDefined();
  }, 30000);
});
