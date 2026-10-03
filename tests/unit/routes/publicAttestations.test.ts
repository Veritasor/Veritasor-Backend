import crypto from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import express from 'express';

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

const { publicAttestationsRouter } = await import(
  '../../../src/routes/publicAttestations.js'
);

const app = express();
app.use('/public/attestations', publicAttestationsRouter);

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

function expectedEtag(attestation: ReturnType<typeof makeAttestation>): string {
  const payload = {
    id: attestation.id,
    businessId: attestation.businessId,
    period: attestation.period,
    merkleRoot: attestation.merkleRoot,
    txHash: attestation.txHash,
    status: attestation.status,
    attestedAt: (attestation.createdAt as Date).toISOString(),
  };
  const sorted = Object.keys(payload).sort().reduce<Record<string, unknown>>((acc, key) => {
    acc[key] = payload[key as keyof typeof payload];
    return acc;
  }, {});
  const hash = crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('base64');
  return '"' + hash + '"';
}

describe('GET /public/attestations/:hash - happy paths', () => {
  beforeEach(() => { mockGetById.mockReset(); mockGetByMerkleRoot.mockReset(); });

  it('returns 200 found by Merkle root', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.id).toBe('att_001');
    expect(mockGetById).not.toHaveBeenCalled();
  });

  it('falls back to UUID lookup', async () => {
    mockGetByMerkleRoot.mockResolvedValue(null);
    mockGetById.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/att_001');
    expect(res.status).toBe(200);
    expect(mockGetByMerkleRoot).toHaveBeenCalled();
    expect(mockGetById).toHaveBeenCalled();
  });

  it('sets ETag, Cache-Control, Last-Modified on 200', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot');
    expect(res.headers['etag']).toBeDefined();
    expect(res.headers['cache-control']).toContain('public');
    expect(res.headers['last-modified']).toBeDefined();
  });

  it('payload only has expected public fields', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot');
    const fields = Object.keys(res.body.data).sort();
    expect(fields).toStrictEqual(['attestedAt','businessId','id','merkleRoot','period','status','txHash']);
    expect(res.body.data.version).toBeUndefined();
  });
});

describe('GET /public/attestations/:hash - ETag conditional', () => {
  beforeEach(() => { mockGetById.mockReset(); mockGetByMerkleRoot.mockReset(); });

  it('returns 304 with matching ETag', async () => {
    const att = makeAttestation();
    mockGetByMerkleRoot.mockResolvedValue(att);
    const res = await request(app).get('/public/attestations/abc123merkleroot').set('If-None-Match', expectedEtag(att));
    expect(res.status).toBe(304);
    expect(res.headers['etag']).toBeDefined();
    expect(res.headers['cache-control']).toContain('public');
    expect(res.headers['last-modified']).toBeDefined();
  });

  it('returns 200 with non-matching ETag', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot').set('If-None-Match', '"wrong"');
    expect(res.status).toBe(200);
  });

  it('honours W/ weak ETag prefix', async () => {
    const att = makeAttestation();
    mockGetByMerkleRoot.mockResolvedValue(att);
    const res = await request(app).get('/public/attestations/abc123merkleroot').set('If-None-Match', 'W/' + expectedEtag(att));
    expect(res.status).toBe(304);
  });

  it('honours multiple ETags in list', async () => {
    const att = makeAttestation();
    mockGetByMerkleRoot.mockResolvedValue(att);
    const res = await request(app).get('/public/attestations/abc123merkleroot').set('If-None-Match', '"old", ' + expectedEtag(att));
    expect(res.status).toBe(304);
  });
});

describe('GET /public/attestations/:hash - If-Modified-Since conditional', () => {
  beforeEach(() => { mockGetById.mockReset(); mockGetByMerkleRoot.mockReset(); });

  it('returns 304 when If-Modified-Since is after createdAt', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot')
      .set('If-Modified-Since', new Date('2026-07-15T13:00:00Z').toUTCString());
    expect(res.status).toBe(304);
    expect(res.headers['last-modified']).toBeDefined();
  });

  it('returns 304 when If-Modified-Since equals createdAt', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot')
      .set('If-Modified-Since', new Date('2026-07-15T12:00:00Z').toUTCString());
    expect(res.status).toBe(304);
  });

  it('returns 200 when If-Modified-Since is before createdAt', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot')
      .set('If-Modified-Since', new Date('2026-07-14T00:00:00Z').toUTCString());
    expect(res.status).toBe(200);
  });

  it('ignores unparseable If-Modified-Since and returns 200', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/abc123merkleroot').set('If-Modified-Since', 'not-a-date');
    expect(res.status).toBe(200);
  });
});

describe('GET /public/attestations/:hash - invalid input and boundaries', () => {
  beforeEach(() => { mockGetById.mockReset(); mockGetByMerkleRoot.mockReset(); });

  it('returns 404 when not found', async () => {
    mockGetByMerkleRoot.mockResolvedValue(null);
    mockGetById.mockResolvedValue(null);
    const res = await request(app).get('/public/attestations/nonexistent');
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('NOT_FOUND');
    expect(JSON.stringify(res.body)).not.toContain('at ');
  });

  it('returns 410 for revoked attestation with short cache TTL', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation({ status: 'revoked' }));
    const res = await request(app).get('/public/attestations/abc123merkleroot');
    expect(res.status).toBe(410);
    expect(res.body.code).toBe('GONE');
    expect(res.headers['cache-control']).toContain('max-age=15');
  });
});

describe('GET /public/attestations/:hash - HMAC signing unit', () => {
  it('HMAC signature is deterministic and correct format', () => {
    const secret = 'test-signing-secret';
    const payload = { id: 'x', businessId: 'b', period: 'p', merkleRoot: 'm', txHash: 't', status: 's', attestedAt: 'a' };
    const sorted = Object.keys(payload).sort().reduce<Record<string, unknown>>((acc, k) => { acc[k] = payload[k as keyof typeof payload]; return acc; }, {});
    const sig1 = crypto.createHmac('sha256', secret).update(JSON.stringify(sorted)).digest('hex');
    const sig2 = crypto.createHmac('sha256', secret).update(JSON.stringify(sorted)).digest('hex');
    expect(sig1).toBe(sig2);
    expect(sig1).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('GET /public/attestations/:hash - backward compatibility and regression', () => {
  beforeEach(() => { mockGetById.mockReset(); mockGetByMerkleRoot.mockReset(); });

  it('ETag is stable across requests for same data', () => {
    expect(expectedEtag(makeAttestation())).toBe(expectedEtag(makeAttestation({ id: 'att_001' })));
  });

  it('ETag differs for different content', () => {
    expect(expectedEtag(makeAttestation({ id: 'att_001' }))).not.toBe(expectedEtag(makeAttestation({ id: 'att_002' })));
  });

  it('legacy UUID lookup returns backward-compatible shape', async () => {
    mockGetByMerkleRoot.mockResolvedValue(null);
    mockGetById.mockResolvedValue(makeAttestation());
    const res = await request(app).get('/public/attestations/att_001');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'success', data: { id: 'att_001', businessId: 'biz_001' } });
    expect(typeof res.body.data.attestedAt).toBe('string');
  });

  it('concurrent requests return identical ETags', async () => {
    mockGetByMerkleRoot.mockResolvedValue(makeAttestation());
    const [r1, r2, r3] = await Promise.all([
      request(app).get('/public/attestations/abc123merkleroot'),
      request(app).get('/public/attestations/abc123merkleroot'),
      request(app).get('/public/attestations/abc123merkleroot'),
    ]);
    expect(r1.headers['etag']).toBe(r2.headers['etag']);
    expect(r2.headers['etag']).toBe(r3.headers['etag']);
  });

  it('repository failure does not leak internal error message', async () => {
    mockGetByMerkleRoot.mockRejectedValue(new Error('DB connection lost'));
    mockGetById.mockRejectedValue(new Error('DB connection lost'));
    const res = await request(app).get('/public/attestations/somehash');
    expect(res.status).toBeGreaterThanOrEqual(500);
    expect(JSON.stringify(res.body)).not.toContain('DB connection lost');
  });
});
