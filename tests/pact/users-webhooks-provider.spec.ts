/**
 * Pact provider verification for the authenticated users + webhook-subscription
 * routes added for issue #1285.
 *
 * `contract.spec.ts` defines the consumer interactions and regenerates the
 * shared pact file. This spec independently replays the users / webhook
 * interactions from that checked-in pact file against the real Express app,
 * with provider state handlers that seed mocked repositories:
 *
 *   - `userRepository.findUserById` and `businessRepository.getById` are mocked
 *     so the mocked JWT can authenticate without database access.
 *   - `webhookSubscriptionRepository` is mocked so the routes do not need a
 *     PostgreSQL connection.
 *
 * The spec fails if the pact file no longer contains the three interactions,
 * so a lost consumer expectation cannot silently shrink coverage.
 */

import { Verifier } from '@pact-foundation/pact';
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { app } from '../../src/app.js';
import { Server } from 'http';
import path from 'path';
import fs from 'fs';
import os from 'os';

const PACT_FILE = path.resolve(
  __dirname,
  '../pacts/Veritasor-Frontend-Veritasor-Backend.json',
);

const pactAuth = vi.hoisted(() => {
  const userId = 'pact-user-1';
  const email = 'pact.user@example.com';
  const businessId = 'pact-business-1';
  return {
    userId,
    email,
    businessId,
    token: 'pact-test-access-token',
    user: {
      id: userId,
      email,
      passwordHash: '$2b$12$pact-secret-hash-that-must-never-leak',
      createdAt: new Date('2026-02-18T09:00:00.000Z'),
      updatedAt: new Date('2026-11-20T15:30:00.000Z'),
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
      createdAt: '2026-02-18T09:00:00.000Z',
      updatedAt: '2026-11-20T15:30:00.000Z',
    },
  };
});

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
    findUserById: vi.fn(async (id: string) => (id === pactAuth.userId ? { ...pactAuth.user } : null)),
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
      mtlsConfig: null,
      createdAt: new Date('2026-11-20T10:00:00.000Z'),
      updatedAt: new Date('2026-11-20T10:00:00.000Z'),
    })),
  };
});

const WEBHOOK_SECRET = 'pact-webhook-secret-0123456789abcd';

function makeWebhookSubscription(overrides: Record<string, unknown> = {}) {
  return {
    id: 'whsub_pact_1',
    businessId: pactAuth.businessId,
    url: 'https://example.com/webhooks/pact',
    secret: WEBHOOK_SECRET,
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

const AUTH_PATHS = ['/api/users/me', '/api/v1/webhook-subscriptions'];

/** The contract may be rewritten by contract.spec.ts concurrently; retry briefly. */
function readPactFile(): any {
  let lastError: unknown;
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      return JSON.parse(fs.readFileSync(PACT_FILE, 'utf8'));
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

describe('Users + Webhook Subscription Pact Provider Verification', () => {
  let server: Server;
  let tempPactPath: string;

  beforeAll(async () => {
    const pact = readPactFile();
    const interactions = (pact.interactions ?? []).filter((interaction: any) =>
      AUTH_PATHS.some((prefix) => String(interaction.request?.path ?? '').startsWith(prefix)),
    );

    // Guard: the contract must actually contain the interactions this spec covers.
    expect(interactions).toHaveLength(3);

    tempPactPath = path.join(
      os.tmpdir(),
      `veritasor-users-webhooks-${process.pid}-${Date.now()}.pact.json`,
    );
    fs.writeFileSync(tempPactPath, JSON.stringify({ ...pact, interactions }, null, 2));

    await new Promise<void>((resolve) => {
      server = app.listen(0, () => resolve());
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
    if (tempPactPath) {
      fs.rmSync(tempPactPath, { force: true });
    }
  });

  it('verifies the users and webhook-subscription interactions against the app', async () => {
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;

    const verifier = new Verifier({
      provider: 'Veritasor-Backend',
      providerBaseUrl: `http://localhost:${port}`,
      pactUrls: [tempPactPath],
      stateHandlers: {
        'an authenticated user exists': async () => {
          // The user/business repository mocks always resolve the Pact identity.
        },
        'a business has at least one webhook subscription': async () => {
          webhookState.subscriptions = [makeWebhookSubscription()];
        },
        'a business has room for another webhook subscription': async () => {
          webhookState.subscriptions = [];
        },
      },
    });

    await expect(verifier.verifyProvider()).resolves.toBeDefined();
  }, 60000);
});
