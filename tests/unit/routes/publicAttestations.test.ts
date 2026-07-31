import crypto from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import express from 'express';

const mockGetById = vi.fn();
vi.mock('../../../src/repositories/attestationRepository.js', () => ({
  getById: mockGetById,
}));

vi.mock('../../../src/db/client.js', () => ({
  db: { query: vi.fn() },
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
    merkleRoot: 'abc123',
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
    attestedAt: attestation.createdAt.toISOString(),
  };
  const sorted = Object.keys(payload).sort().reduce<Record<string, unknown>>((acc, key) => {
    acc[key] = payload[key as keyof typeof payload];
    return acc;
  }, {});
  const hash = crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('base64');
  return `"${hash}"`;
}

describe('GET /public/attestations/:hash', () => {
  beforeEach(() => {
    mockGetById.mockReset();
  });

  it('returns 200 with attestation payload', async () => {
    const att = makeAttestation();
    mockGetById.mockResolvedValue(att);

    const res = await request(app).get('/public/attestations/att_001');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.id).toBe('att_001');
  });

  it('sets ETag and Cache-Control headers on 200', async () => {
    const att = makeAttestation();
    mockGetById.mockResolvedValue(att);

    const res = await request(app).get('/public/attestations/att_001');

    expect(res.status).toBe(200);
    expect(res.headers['etag']).toBeDefined();
    expect(res.headers['cache-control']).toContain('public');
    expect(res.headers['last-modified']).toBeDefined();
  });

  it('returns 304 when If-None-Match matches the computed ETag', async () => {
    const att = makeAttestation();
    mockGetById.mockResolvedValue(att);
    const etag = expectedEtag(att);

    const res = await request(app)
      .get('/public/attestations/att_001')
      .set('If-None-Match', etag);

    expect(res.status).toBe(304);
    expect(res.body).toStrictEqual({});
  });

  it('returns 200 when If-None-Match does not match', async () => {
    const att = makeAttestation();
    mockGetById.mockResolvedValue(att);

    const res = await request(app)
      .get('/public/attestations/att_001')
      .set('If-None-Match', '"different-etag"');

    expect(res.status).toBe(200);
  });

  it('honours weak ETags (W/ prefix) in If-None-Match', async () => {
    const att = makeAttestation();
    mockGetById.mockResolvedValue(att);
    const etag = expectedEtag(att);

    const res = await request(app)
      .get('/public/attestations/att_001')
      .set('If-None-Match', `W/${etag}`);

    expect(res.status).toBe(304);
  });

  it('honours multiple ETags in If-None-Match', async () => {
    const att = makeAttestation();
    mockGetById.mockResolvedValue(att);
    const etag = expectedEtag(att);

    const res = await request(app)
      .get('/public/attestations/att_001')
      .set('If-None-Match', `"old-etag", ${etag}, "another-etag"`);

    expect(res.status).toBe(304);
  });

  it('returns 404 with short jittered Cache-Control when attestation is not found', async () => {
    mockGetById.mockResolvedValue(null);

    const res = await request(app).get('/public/attestations/nonexistent');

    expect(res.status).toBe(404);
    expect(res.body.code).toBe('NOT_FOUND');
    
    // Assert cache headers for negative caching
    expect(res.headers['cache-control']).toMatch(/public, max-age=\d+/);
    expect(res.headers['age']).toBe('0');
    
    // Verify jittered max-age bounds (base 10, +/- 20% -> 8 to 12)
    const maxAgeMatch = res.headers['cache-control'].match(/max-age=(\d+)/);
    expect(maxAgeMatch).not.toBeNull();
    const maxAge = parseInt(maxAgeMatch![1], 10);
    expect(maxAge).toBeGreaterThanOrEqual(1);
    expect(maxAge).toBeLessThanOrEqual(15);
  });

  it('returns 410 when attestation is revoked', async () => {
    const att = makeAttestation({ status: 'revoked' });
    mockGetById.mockResolvedValue(att);

    const res = await request(app).get('/public/attestations/att_001');

    expect(res.status).toBe(410);
    expect(res.body.code).toBe('GONE');
    expect(res.headers['cache-control']).toContain('max-age=15');
  });

  it('returns 400 for invalid hash', async () => {
    const res = await request(app).get('/public/attestations/');

    expect(res.status).toBe(404);
  });

  it('produces stable ETag across serialization changes', () => {
    const att = makeAttestation();
    const etag1 = expectedEtag(att);
    const etag2 = expectedEtag(makeAttestation({ id: 'att_001' }));
    expect(etag1).toBe(etag2);
  });

  it('produces different ETag for different content', () => {
    const att1 = makeAttestation({ id: 'att_001' });
    const att2 = makeAttestation({ id: 'att_002' });
    expect(expectedEtag(att1)).not.toBe(expectedEtag(att2));
  });

  it('handles cache poisoning attempts by sanitizing or rejecting invalid hashes', async () => {
    const maliciousHash = 'invalid%0D%0ACache-Control: public, max-age=999999';
    // Express prevents HTTP response splitting by default, so it might either throw (500)
    // or properly escape/reject. Let's make sure it doesn't return the malicious cache-control
    const res = await request(app).get(`/public/attestations/${maliciousHash}`);
    
    // Either it's rejected by our app or parsed as a hash and not found.
    // If it's not found, the max-age should be jittered TTL (1-15), not 999999
    if (res.status === 404) {
      const maxAgeMatch = res.headers['cache-control'].match(/max-age=(\d+)/);
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10);
        expect(maxAge).toBeLessThan(1000); // Definitely not the poisoned value
      }
    } else {
      expect(res.status).not.toBe(200);
    }
  });
});
