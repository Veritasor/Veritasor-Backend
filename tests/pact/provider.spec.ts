/**
 * Frontend Pact Provider Verification
 *
 * Verifies the Veritasor-Frontend consumer contract against the running
 * Express app. Invoked by the `frontend` matrix entry of
 * .github/workflows/pact-verify.yml.
 *
 * Source of pacts:
 *  - PACT_BROKER_URL set  -> latest consumer pacts from the broker
 *  - otherwise            -> the committed tests/pacts/Veritasor-Frontend-Veritasor-Backend.json
 *
 * The attestation repository is mocked so provider states are deterministic
 * and no database is required.
 */
import { Verifier, type VerifierOptions } from '@pact-foundation/pact';
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { Server } from 'http';
import path from 'path';
import fs from 'fs';
import { app } from '../../src/app.js';

const LOCAL_PACT_PATH = path.resolve(__dirname, '../pacts/Veritasor-Frontend-Veritasor-Backend.json');

const mockState = vi.hoisted(() => ({
  attestations: new Map<string, any>(),
}));

vi.mock('../../src/repositories/attestationRepository.js', () => ({
  // The public route resolves by Merkle root first, then falls back to id.
  getByMerkleRoot: vi.fn(async () => null),
  getById: vi.fn(async (_client: any, id: string) => mockState.attestations.get(id) ?? null),
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

function seedDefaults(): void {
  mockState.attestations.clear();
  mockState.attestations.set('abc123', validAttestation);
  mockState.attestations.set('revoked123', revokedAttestation);
}

describe('Frontend Pact Provider Verification', () => {
  let server: Server;
  let port = 0;

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address();
        port = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('validates the expectations of the frontend consumer', async () => {
    const hasLocalPact = fs.existsSync(LOCAL_PACT_PATH);
    const base = `http://localhost:${port}`;

    // The consumer sends a sample ETag; swap in the provider's real ETag for
    // the conditional-request interaction so the 304 path is exercised.
    let etagOverride: string | null = null;

    if (!process.env.PACT_BROKER_URL && !hasLocalPact) {
      console.warn('Skipping Frontend Pact Verification: no broker URL or local pact file found.');
      expect(hasLocalPact).toBe(false);
      return;
    }

    const opts: VerifierOptions = {
      provider: 'Veritasor-Backend',
      providerBaseUrl: base,
      ...(process.env.PACT_BROKER_URL
        ? {
            pactBrokerUrl: process.env.PACT_BROKER_URL,
            consumerVersionSelectors: [{ latest: true }],
            publishVerificationResult: process.env.CI === 'true',
            providerVersion: process.env.GITHUB_SHA,
          }
        : { pactUrls: [LOCAL_PACT_PATH] }),
      requestFilter: (req: any, _res: any, next: any) => {
        if (etagOverride && req.headers['if-none-match']) {
          req.headers['if-none-match'] = etagOverride;
        }
        next();
      },
      stateHandlers: {
        'server is healthy': async () => {
          etagOverride = null;
          seedDefaults();
        },
        'an attestation exists with hash "abc123"': async () => {
          etagOverride = null;
          mockState.attestations.set('abc123', validAttestation);
        },
        'an attestation exists with hash "abc123" and the request has a matching ETag': async () => {
          mockState.attestations.set('abc123', validAttestation);
          const res = await fetch(`${base}/api/v1/public/attestations/abc123`);
          etagOverride = res.headers.get('etag');
        },
        'no attestation exists with hash "nonexistent"': async () => {
          etagOverride = null;
          mockState.attestations.delete('nonexistent');
        },
        'an attestation exists with hash "revoked123" and status "revoked"': async () => {
          etagOverride = null;
          mockState.attestations.set('revoked123', revokedAttestation);
        },
      },
    };

    seedDefaults();
    await expect(new Verifier(opts).verifyProvider()).resolves.toBeDefined();
  }, 60000);
});
