import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';

const mockDlqInstance = vi.hoisted(() => ({
  getEntries: vi.fn(),
  getEntryById: vi.fn(),
  archiveEntry: vi.fn(),
  restoreEntry: vi.fn(),
  archiveOldEntries: vi.fn(),
  getArchiveStats: vi.fn(),
}));

const mockVerifyToken = vi.hoisted(() => vi.fn());
const mockFindUserById = vi.hoisted(() => vi.fn());

vi.mock('../../../src/services/webhooks/deadLetterQueue.js', () => ({
  DeadLetterQueue: vi.fn(function () {
    return mockDlqInstance;
  }),
}));

vi.mock('../../../src/utils/jwt.js', () => ({
  verifyToken: mockVerifyToken,
}));

vi.mock('../../../src/repositories/userRepository.js', () => ({
  findUserById: mockFindUserById,
}));

vi.mock('../../../src/middleware/errorHandler.js', () => ({
  asyncErrorHandler:
    (fn: (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<unknown>) =>
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    },
}));

import dlqRouter from '../../../src/routes/dlqRoutes.js';
import { AppError, ValidationError } from '../../../src/types/errors.js';

const app = express();
app.use(express.json());
app.use('/api/v1/admin/dlq', dlqRouter);
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err instanceof ValidationError) {
    res.status(err.status).json({ error: err.message, code: err.vrtCode, details: err.details });
    return;
  }
  if (err instanceof AppError) {
    res.status(err.status).json({ error: err.message, code: err.vrtCode });
    return;
  }
  res.status(500).json({ error: 'Internal Server Error' });
});

function authAs(role: 'admin' | 'user' | 'business_admin') {
  mockVerifyToken.mockReturnValue({ userId: `${role}_1`, role });
  mockFindUserById.mockResolvedValue({
    id: `${role}_1`,
    email: `${role}@example.com`,
    role,
  });
}

describe('DLQ Admin Routes (/api/v1/admin/dlq)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Authentication & RBAC', () => {
    it('returns 401 when Authorization header is missing', async () => {
      const res = await request(app).get('/api/v1/admin/dlq/entries');
      expect(res.status).toBe(401);
      expect(mockDlqInstance.getEntries).not.toHaveBeenCalled();
    });

    it('returns 401 when bearer token is invalid', async () => {
      mockVerifyToken.mockReturnValue(null);

      const res = await request(app)
        .get('/api/v1/admin/dlq/stats')
        .set('Authorization', 'Bearer invalid-token');

      expect(res.status).toBe(401);
      expect(mockDlqInstance.getArchiveStats).not.toHaveBeenCalled();
    });

    it('returns 403 for non-admin user role on read endpoints', async () => {
      authAs('user');

      const res = await request(app)
        .get('/api/v1/admin/dlq/entries')
        .set('Authorization', 'Bearer user-token');

      expect(res.status).toBe(403);
      expect(mockDlqInstance.getEntries).not.toHaveBeenCalled();
    });

    it('returns 403 for business_admin role on mutating endpoints', async () => {
      authAs('business_admin');

      const res = await request(app)
        .post('/api/v1/admin/dlq/entries/entry-1/restore')
        .set('Authorization', 'Bearer biz-token')
        .send({ restoreToQueue: true });

      expect(res.status).toBe(403);
      expect(mockDlqInstance.restoreEntry).not.toHaveBeenCalled();
    });
  });

  describe('GET /entries', () => {
    it('returns 200 with entries, pagination, and X-Total-Count header', async () => {
      authAs('admin');
      const entries = [{ id: 'dlq-1', type: 'webhook.failed', archived: false }];
      mockDlqInstance.getEntries.mockResolvedValue({ entries, total: 1 });

      const res = await request(app)
        .get('/api/v1/admin/dlq/entries?page=2&pageSize=25&archived=false')
        .set('Authorization', 'Bearer admin-token');

      expect(res.status).toBe(200);
      expect(res.headers['x-total-count']).toBe('1');
      expect(res.body).toEqual({
        success: true,
        data: entries,
        pagination: { page: 2, pageSize: 25, total: 1 },
      });
      expect(mockDlqInstance.getEntries).toHaveBeenCalledWith(
        expect.objectContaining({ page: 2, pageSize: 25, archived: false }),
      );
    });
  });

  describe('GET /entries/:id', () => {
    it('returns 200 for any existing entry id without paging through the list', async () => {
      authAs('admin');
      // A non-newest entry: the old page-1/size-1 lookup could never return it.
      const entry = { id: 42, type: 'stripe.invoice' };
      mockDlqInstance.getEntryById.mockResolvedValue(entry);

      const res = await request(app)
        .get('/api/v1/admin/dlq/entries/42')
        .set('Authorization', 'Bearer admin-token');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, data: entry });
      expect(mockDlqInstance.getEntryById).toHaveBeenCalledTimes(1);
      expect(mockDlqInstance.getEntryById).toHaveBeenCalledWith('42');
      expect(mockDlqInstance.getEntries).not.toHaveBeenCalled();
    });

    it('returns 404 when the id does not exist', async () => {
      authAs('admin');
      mockDlqInstance.getEntryById.mockResolvedValue(null);

      const res = await request(app)
        .get('/api/v1/admin/dlq/entries/999')
        .set('Authorization', 'Bearer admin-token');

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/not found/i);
      expect(mockDlqInstance.getEntries).not.toHaveBeenCalled();
    });

    it('rejects a malformed id before querying the database', async () => {
      authAs('admin');

      const res = await request(app)
        .get('/api/v1/admin/dlq/entries/not-a-number')
        .set('Authorization', 'Bearer admin-token');

      expect(res.status).toBe(400);
      expect(mockDlqInstance.getEntryById).not.toHaveBeenCalled();
      expect(mockDlqInstance.getEntries).not.toHaveBeenCalled();
    });
  });

  describe('POST /entries/:id/archive', () => {
    it('returns 200 with archive location', async () => {
      authAs('admin');
      mockDlqInstance.archiveEntry.mockResolvedValue('s3://bucket/dlq/dlq-1.json');

      const res = await request(app)
        .post('/api/v1/admin/dlq/entries/dlq-1/archive')
        .set('Authorization', 'Bearer admin-token');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        message: 'Entry archived successfully',
        data: { archive_location: 's3://bucket/dlq/dlq-1.json' },
      });
      expect(mockDlqInstance.archiveEntry).toHaveBeenCalledWith('dlq-1');
    });
  });

  describe('POST /entries/:id/restore', () => {
    it('restores entry and forwards restoreToQueue flag', async () => {
      authAs('admin');
      const restored = { id: 'dlq-9', status: 'pending' };
      mockDlqInstance.restoreEntry.mockResolvedValue(restored);

      const res = await request(app)
        .post('/api/v1/admin/dlq/entries/dlq-9/restore')
        .set('Authorization', 'Bearer admin-token')
        .send({ restoreToQueue: true });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        message: 'Entry restored successfully',
        data: restored,
      });
      expect(mockDlqInstance.restoreEntry).toHaveBeenCalledWith('dlq-9', {
        restoreToQueue: true,
      });
    });

    it('routes unexpected errors through errorHandler', async () => {
      authAs('admin');
      mockDlqInstance.restoreEntry.mockRejectedValue(new Error('S3 unavailable'));

      const res = await request(app)
        .post('/api/v1/admin/dlq/entries/dlq-9/restore')
        .set('Authorization', 'Bearer admin-token')
        .send({});

      expect(res.status).toBe(500);
    });
  });

  describe('POST /archive', () => {
    it('triggers archiveOldEntries with parsed options', async () => {
      authAs('admin');
      const archiveResult = { archived: 12, failed: 0 };
      mockDlqInstance.archiveOldEntries.mockResolvedValue(archiveResult);

      const res = await request(app)
        .post('/api/v1/admin/dlq/archive')
        .set('Authorization', 'Bearer admin-token')
        .send({ ttlDays: '30', batchSize: '100' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        success: true,
        message: 'Archive job completed',
        data: archiveResult,
      });
      expect(mockDlqInstance.archiveOldEntries).toHaveBeenCalledWith({
        ttlDays: 30,
        batchSize: 100,
      });
    });
  });

  describe('GET /stats', () => {
    it('returns 200 with archive stats', async () => {
      authAs('admin');
      const stats = { activeCount: 5, archivedCount: 42 };
      mockDlqInstance.getArchiveStats.mockResolvedValue(stats);

      const res = await request(app)
        .get('/api/v1/admin/dlq/stats')
        .set('Authorization', 'Bearer admin-token');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, data: stats });
    });
  });
});
