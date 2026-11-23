import { beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import request from 'supertest';

const mocks = vi.hoisted(() => ({
  revokeBatchAttestations: vi.fn(),
  publish: vi.fn(),
}));

vi.mock('../../../src/middleware/permissions.js', () => ({
  requirePermissions: () => (req: any, _res: any, next: () => void) => {
    req.user = { id: 'admin-1' };
    next();
  },
}));

vi.mock('../../../src/services/attestation/revokeBatch.js', () => ({
  revokeBatchAttestations: mocks.revokeBatchAttestations,
}));

vi.mock('../../../src/ws/attestationStream.js', () => ({
  broadcaster: { publish: mocks.publish },
}));

vi.mock('../../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

import adminAttestationsRouter from '../../../src/routes/admin/attestations.js';

const app = express();
app.use(express.json());
app.use('/api/v1/admin', adminAttestationsRouter);
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  res.status(500).json({ error: 'Internal Server Error' });
});

const revokedEntries = [
  { id: 'att-1', businessId: 'biz-a', period: '2026-01' },
  { id: 'att-2', businessId: 'biz-b', period: '2026-02' },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe('POST /api/v1/admin/attestations/revoke-batch', () => {
  it('publishes one attestation.revoked event per revoked attestation, for its business', async () => {
    mocks.revokeBatchAttestations.mockResolvedValue({
      revoked: revokedEntries.map((entry) => entry.id),
      failed: [],
      revokedEntries,
    });

    const res = await request(app)
      .post('/api/v1/admin/attestations/revoke-batch')
      .send({ attestationIds: ['att-1', 'att-2'] });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'Batch revoked successfully', count: 2 });
    expect(mocks.publish).toHaveBeenCalledTimes(2);
    expect(mocks.publish).toHaveBeenNthCalledWith(1, {
      type: 'attestation.revoked',
      businessId: 'biz-a',
      attestationId: 'att-1',
      period: '2026-01',
      timestamp: expect.any(String),
    });
    expect(mocks.publish).toHaveBeenNthCalledWith(2, {
      type: 'attestation.revoked',
      businessId: 'biz-b',
      attestationId: 'att-2',
      period: '2026-02',
      timestamp: expect.any(String),
    });
  });

  it('still returns success when a publish fails', async () => {
    mocks.revokeBatchAttestations.mockResolvedValue({
      revoked: revokedEntries.map((entry) => entry.id),
      failed: [],
      revokedEntries,
    });
    mocks.publish
      .mockImplementationOnce(() => {
        throw new Error('socket server unavailable');
      })
      .mockResolvedValueOnce(undefined);

    const res = await request(app)
      .post('/api/v1/admin/attestations/revoke-batch')
      .send({ attestationIds: ['att-1', 'att-2'] });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'Batch revoked successfully', count: 2 });
    // The failed broadcast does not stop the remaining notifications.
    expect(mocks.publish).toHaveBeenCalledTimes(2);
  });

  it('does not publish for entries the service reports as failed', async () => {
    mocks.revokeBatchAttestations.mockResolvedValue({
      revoked: ['att-1'],
      failed: [{ id: 'att-2', error: 'soroban timeout' }],
      revokedEntries: [revokedEntries[0]],
    });

    const res = await request(app)
      .post('/api/v1/admin/attestations/revoke-batch')
      .send({ attestationIds: ['att-1', 'att-2'] });

    expect(res.status).toBe(200);
    expect(res.body.count).toBe(1);
    expect(mocks.publish).toHaveBeenCalledTimes(1);
    expect(mocks.publish).toHaveBeenCalledWith(
      expect.objectContaining({ attestationId: 'att-1' }),
    );
  });
});
