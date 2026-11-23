import { Router, Request, Response } from 'express';
import { DeadLetterQueue } from '../services/webhooks/deadLetterQueue.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requirePermissions } from '../middleware/permissions.js';
import { IntegrationPermission } from '../types/permissions.js';
import { asyncErrorHandler } from '../middleware/errorHandler.js';
import { NotFoundError } from '../types/errors.js';

const router = Router();
const dlq = new DeadLetterQueue();

// All DLQ admin routes require authentication
router.use(requireAuth);

/**
 * GET /api/v1/admin/dlq/entries
 * Get DLQ entries with pagination
 */
router.get(
  '/entries',
  requirePermissions(IntegrationPermission.ADMIN_READ_STATS),
  asyncErrorHandler(async (req: Request, res: Response) => {
    const { page = 1, pageSize = 50, type, archived, startDate, endDate } = req.query;
    const parsedPage = parseInt(page as string, 10) || 1;
    const parsedPageSize = Math.min(parseInt(pageSize as string, 10) || 50, 200);

    const result = await dlq.getEntries({
      page: parsedPage,
      pageSize: parsedPageSize,
      type: type as string,
      archived: archived !== undefined ? archived === 'true' : undefined,
      startDate: startDate ? new Date(startDate as string) : undefined,
      endDate: endDate ? new Date(endDate as string) : undefined,
    });

    res.setHeader('X-Total-Count', result.total);
    res.setHeader('Access-Control-Expose-Headers', 'X-Total-Count');

    res.json({
      success: true,
      data: result.entries,
      pagination: {
        page: parsedPage,
        pageSize: parsedPageSize,
        total: result.total,
      },
    });
  }),
);

/**
 * GET /api/v1/admin/dlq/entries/:id
 * Get a single DLQ entry
 */
router.get(
  '/entries/:id',
  requirePermissions(IntegrationPermission.ADMIN_READ_STATS),
  asyncErrorHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const result = await dlq.getEntries({ page: 1, pageSize: 1 });
    const entry = result.entries.find(e => e.id === id);

    if (!entry) {
      throw new NotFoundError('DLQ entry not found');
    }

    res.json({
      success: true,
      data: entry,
    });
  }),
);

/**
 * POST /api/v1/admin/dlq/entries/:id/archive
 * Archive a single DLQ entry
 */
router.post(
  '/entries/:id/archive',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  asyncErrorHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const location = await dlq.archiveEntry(id);
    res.json({
      success: true,
      message: 'Entry archived successfully',
      data: { archive_location: location },
    });
  }),
);

/**
 * POST /api/v1/admin/dlq/entries/:id/restore
 * Restore a DLQ entry from archive
 */
router.post(
  '/entries/:id/restore',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  asyncErrorHandler(async (req: Request, res: Response) => {
    const { id } = req.params;
    const { restoreToQueue = false } = req.body ?? {};
    const entry = await dlq.restoreEntry(id, { restoreToQueue });
    res.json({
      success: true,
      message: 'Entry restored successfully',
      data: entry,
    });
  }),
);

/**
 * POST /api/v1/admin/dlq/archive
 * Trigger manual archive job
 */
router.post(
  '/archive',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  asyncErrorHandler(async (req: Request, res: Response) => {
    const { ttlDays, batchSize } = req.body ?? {};
    const result = await dlq.archiveOldEntries({
      ttlDays: ttlDays ? parseInt(ttlDays, 10) : undefined,
      batchSize: batchSize ? parseInt(batchSize, 10) : undefined,
    });
    res.json({
      success: true,
      message: 'Archive job completed',
      data: result,
    });
  }),
);

/**
 * GET /api/v1/admin/dlq/stats
 * Get DLQ statistics
 */
router.get(
  '/stats',
  requirePermissions(IntegrationPermission.ADMIN_READ_STATS),
  asyncErrorHandler(async (_req: Request, res: Response) => {
    const stats = await dlq.getArchiveStats();
    res.json({
      success: true,
      data: stats,
    });
  }),
);

export default router;
