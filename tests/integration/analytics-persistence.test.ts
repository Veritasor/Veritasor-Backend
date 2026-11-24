import express, { type ErrorRequestHandler } from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { analyticsRouter } from '../../src/routes/analytics.js';
import * as repository from '../../src/repositories/attestationRepository.js';
import { db } from '../../src/db/client.js';

vi.mock('../../src/repositories/attestationRepository.js', () => ({ listPeriods: vi.fn(), listByBusiness: vi.fn() }));
vi.mock('../../src/db/client.js', () => ({ db: {} }));
vi.mock('../../src/utils/logger.js', () => ({ logger: { info: vi.fn(), warn: vi.fn() } }));
vi.mock('../../src/middleware/rateLimiter.js', () => ({
  rateLimiter: () => (_req: express.Request, _res: express.Response, next: express.NextFunction) => next(),
}));
vi.mock('../../src/middleware/requireBusinessAuth.js', () => ({
  requireBusinessAuth: (req: express.Request, _res: express.Response, next: express.NextFunction) => {
    req.business = { id: 'authenticated-business' } as NonNullable<express.Request['business']>;
    next();
  },
}));

const app = express();
app.use('/api/analytics', analyticsRouter);
const errorHandler: ErrorRequestHandler = (_error, _req, res, _next) => {
  res.status(500).json({ error: 'Internal server error' });
};
app.use(errorHandler);

describe('analytics SQL response contracts', () => {
  beforeEach(() => vi.resetAllMocks());

  it('awaits persisted periods and uses the authenticated business', async () => {
    vi.mocked(repository.listPeriods).mockResolvedValue(['2026-02', '2026-01']);
    const response = await request(app).get('/api/analytics/periods?businessId=other');
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ periods: ['2026-02', '2026-01'] });
    expect(repository.listPeriods).toHaveBeenCalledWith(db, 'authenticated-business');
  });

  it('preserves the revenue response shape and timestamp serialization', async () => {
    vi.mocked(repository.listByBusiness).mockResolvedValue([{
      id: 'persisted', businessId: 'authenticated-business', period: '2026-01',
      merkleRoot: 'root', txHash: 'tx', status: 'confirmed', version: 1,
      createdAt: new Date('2026-02-01T00:00:00Z'), updatedAt: new Date('2026-02-01T00:00:00Z'),
    }]);
    const response = await request(app).get('/api/analytics/revenue?period=2026-01');
    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      period: '2026-01', total: 100, net: 95, currency: 'USD',
      breakdown: [{ attestationId: 'persisted', attestedAt: '2026-02-01T00:00:00.000Z' }],
    });
    expect(repository.listByBusiness).toHaveBeenCalledWith(db, 'authenticated-business');
  });

  it('preserves no-data and invalid-query responses', async () => {
    vi.mocked(repository.listByBusiness).mockResolvedValue([]);
    const empty = await request(app).get('/api/analytics/revenue?period=2026-01');
    expect(empty.status).toBe(404);
    expect(empty.body).toEqual({ error: 'No revenue data found for the given period.' });
    vi.mocked(repository.listByBusiness).mockClear();
    const invalid = await request(app).get('/api/analytics/revenue?from=2026-02&to=2026-01');
    expect(invalid.status).toBe(400);
    expect(repository.listByBusiness).not.toHaveBeenCalled();
  });

  it.each(['/periods', '/revenue?period=2026-01'])('forwards rejected DB reads from %s to Express', async path => {
    vi.mocked(repository.listPeriods).mockRejectedValue(new Error('database failed'));
    vi.mocked(repository.listByBusiness).mockRejectedValue(new Error('database failed'));
    const response = await request(app).get(`/api/analytics${path}`);
    expect(response.status).toBe(500);
    expect(response.body).toEqual({ error: 'Internal server error' });
  });
});
