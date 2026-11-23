/**
 * Focused regression coverage for the HMAC signing branch of
 * `publicAttestationsRouter` (issue #948).
 *
 * Evidence: `src/routes/publicAttestations.ts:120` — `if (!ATTESTATION_SIGNING_SECRET) return null;`
 *
 * The pre-existing `publicAttestations.test.ts` only re-derives an HMAC with
 * `crypto` in isolation; it never loads the router with a signing secret
 * configured, so the entire `signPayload()` branch — the early `return null`
 * when the secret is absent *and* the `sha256=<hex>` header when it is present —
 * had no regression protection. A refactor that always signed, never signed, or
 * signed the wrong serialisation would have passed the whole suite.
 *
 * `ATTESTATION_SIGNING_SECRET` is read at module-evaluation time, so each case
 * resets the module registry and (re)loads the router with the env var set to
 * the value under test.
 */
import crypto from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import express, { type Express } from 'express';
import request from 'supertest';

const mockGetById = vi.fn();
const mockGetByMerkleRoot = vi.fn();

vi.mock('../../../src/repositories/attestationRepository.js', () => ({
  getById: mockGetById,
  getByMerkleRoot: mockGetByMerkleRoot,
}));

vi.mock('../../../src/db/client.js', () => ({
  db: { query: vi.fn() },
}));

vi.mock('../../../src/middleware/rateLimiter.js', () => ({
  rateLimiter: () => (_req: unknown, _res: unknown, next: () => void) => next(),
}));

vi.mock('../../../src/metrics.js', () => ({
  etagHitsTotal: { inc: vi.fn() },
}));

const ORIGINAL_SECRET = process.env.ATTESTATION_SIGNING_SECRET;

afterAll(() => {
  if (ORIGINAL_SECRET === undefined) delete process.env.ATTESTATION_SIGNING_SECRET;
  else process.env.ATTESTATION_SIGNING_SECRET = ORIGINAL_SECRET;
});

/** Load a fresh router instance with `ATTESTATION_SIGNING_SECRET` set to `secret`. */
async function buildApp(secret: string | undefined): Promise<Express> {
  vi.resetModules();
  if (secret === undefined) delete process.env.ATTESTATION_SIGNING_SECRET;
  else process.env.ATTESTATION_SIGNING_SECRET = secret;
  const mod = await import('../../../src/routes/publicAttestations.js');
  const app = express();
  app.use('/public/attestations', mod.publicAttestationsRouter);
  return app;
}

function makeAttestation(overrides: Record<string, unknown> = {}) {
  return {
    id: 'att_001',
    businessId: 'biz_001',
    period: '2026-07',
    merkleRoot: 'abc123merkleroot',
    txHash: '0xtx',
    status: 'confirmed',
    createdAt: new Date('2026-07-15T12:00:00Z'),
    updatedAt: new Date('2026-07-15T12:00:00Z'),
    version: 1,
    ...overrides,
  };
}

/** Reproduce the router's sorted-key canonical JSON independently. */
function canonicalJson(attestation: ReturnType<typeof makeAttestation>): string {
  const payload = {
    id: attestation.id,
    businessId: attestation.businessId,
    period: attestation.period,
    merkleRoot: attestation.merkleRoot,
    txHash: attestation.txHash,
    status: attestation.status,
    attestedAt: (attestation.createdAt as Date).toISOString(),
  };
  const sorted = Object.keys(payload)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = payload[key as keyof typeof payload];
      return acc;
    }, {});
  return JSON.stringify(sorted);
}

/** Reproduce the router's HMAC contract independently. */
function expectedSignature(attestation: ReturnType<typeof makeAttestation>, secret: string): string {
  return `sha256=${crypto.createHmac('sha256', secret).update(canonicalJson(attestation)).digest('hex')}`;
}

/** Reproduce the router's strong ETag contract independently. */
function expectedEtag(attestation: ReturnType<typeof makeAttestation>): string {
  return `"${crypto.createHash('sha256').update(canonicalJson(attestation)).digest('base64')}"`;
}

beforeEach(() => {
  mockGetById.mockReset();
  mockGetByMerkleRoot.mockReset();
});

describe('publicAttestationsRouter signing — early-null branch (issue #948)', () => {
  it('omits X-Attestation-Signature when ATTESTATION_SIGNING_SECRET is not configured', async () => {
    const app = await buildApp(undefined);
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());

    const res = await request(app).get('/public/attestations/abc123merkleroot');

    expect(res.status).toBe(200);
    expect(res.headers['x-attestation-signature']).toBeUndefined();
  });

  it('treats an empty-string secret as unconfigured (falsy guard)', async () => {
    const app = await buildApp('');
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());

    const res = await request(app).get('/public/attestations/abc123merkleroot');

    expect(res.status).toBe(200);
    expect(res.headers['x-attestation-signature']).toBeUndefined();
  });
});

describe('publicAttestationsRouter signing — configured branch (issue #948)', () => {
  it('sets an HMAC-SHA256 signature header when a secret is configured', async () => {
    const app = await buildApp('test-signing-secret');
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());

    const res = await request(app).get('/public/attestations/abc123merkleroot');

    expect(res.status).toBe(200);
    expect(res.headers['x-attestation-signature']).toBeDefined();
    expect(res.headers['x-attestation-signature']).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  it('signs the exact canonical (sorted-key) payload, not an ad-hoc serialisation', async () => {
    const secret = 'unit-secret-1';
    const app = await buildApp(secret);
    const attestation = makeAttestation();
    mockGetByMerkleRoot.mockResolvedValue(attestation);

    const res = await request(app).get('/public/attestations/abc123merkleroot');

    expect(res.headers['x-attestation-signature']).toBe(expectedSignature(attestation, secret));
  });

  it('is deterministic regardless of repository key insertion order', async () => {
    const app = await buildApp('order-independent-secret');
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const first = await request(app).get('/public/attestations/abc123merkleroot');

    // Same field values, but the object is constructed with a different key order.
    const reordered = {
      version: 1,
      updatedAt: new Date('2026-07-15T12:00:00Z'),
      createdAt: new Date('2026-07-15T12:00:00Z'),
      status: 'confirmed',
      txHash: '0xtx',
      merkleRoot: 'abc123merkleroot',
      period: '2026-07',
      businessId: 'biz_001',
      id: 'att_001',
    };
    mockGetByMerkleRoot.mockResolvedValue(reordered);
    const second = await request(app).get('/public/attestations/abc123merkleroot');

    expect(second.headers['x-attestation-signature']).toBe(first.headers['x-attestation-signature']);
  });

  it('produces a different signature when a signed field changes', async () => {
    const app = await buildApp('diff-secret');
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation({ id: 'att_001' }));
    const first = await request(app).get('/public/attestations/abc123merkleroot');

    mockGetByMerkleRoot.mockResolvedValue(makeAttestation({ id: 'att_002' }));
    const second = await request(app).get('/public/attestations/abc123merkleroot');

    expect(second.headers['x-attestation-signature']).not.toBe(first.headers['x-attestation-signature']);
  });

  it('does not leak a signature on 304 conditional responses (signing happens only on 200)', async () => {
    const secret = 'conditional-secret';
    const app = await buildApp(secret);
    const attestation = makeAttestation();
    mockGetByMerkleRoot.mockResolvedValue(attestation);

    const res = await request(app)
      .get('/public/attestations/abc123merkleroot')
      .set('If-None-Match', expectedEtag(attestation));

    expect(res.status).toBe(304);
    expect(res.headers['x-attestation-signature']).toBeUndefined();
  });

  it('does not sign 410 Gone (revoked) responses', async () => {
    const app = await buildApp('revoked-secret');
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation({ status: 'revoked' }));

    const res = await request(app).get('/public/attestations/abc123merkleroot');

    expect(res.status).toBe(410);
    expect(res.headers['x-attestation-signature']).toBeUndefined();
  });

  it('does not sign 404 Not Found responses', async () => {
    const app = await buildApp('missing-secret');
    mockGetByMerkleRoot.mockResolvedValue(null);
    mockGetById.mockResolvedValue(null);

    const res = await request(app).get('/public/attestations/nonexistent');

    expect(res.status).toBe(404);
    expect(res.headers['x-attestation-signature']).toBeUndefined();
  });
});
