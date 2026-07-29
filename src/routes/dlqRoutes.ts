import { Router, Request, Response } from 'express';
import { DeadLetterQueue } from '../services/webhooks/deadLetterQueue';
import { authMiddleware } from '../middleware/auth';
import { adminMiddleware } from '../middleware/admin';

const router = Router();
const dlq = new DeadLetterQueue();

/**
 * GET /api/dlq/entries
 * Get DLQ entries with pagination
 */
router.get('/entries', authMiddleware, adminMiddleware, async (req: Request, res: Response) => {
  try {
    const { page = 1, pageSize = 50, type, archived, startDate, endDate } = req.query;
    const result = await dlq.getEntries({
      page: parseInt(page as string, 10) || 1,
      pageSize: Math.min(parseInt(pageSize as string, 10) || 50, 200),
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
        page: parseInt(page as string, 10) || 1,
        pageSize: Math.min(parseInt(pageSize as string, 10) || 50, 200),
        total: result.total,
      },
    });
  } catch (error) {
    console.error('Failed to get DLQ entries:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get DLQ entries',
    });
  }
});

/**
 * GET /api/dlq/entries/:id
 * Get a single DLQ entry
 */
router.get('/entries/:id', authMiddleware, adminMiddleware, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const result = await dlq.getEntries({ page: 1, pageSize: 1 });
    const entry = result.entries.find(e => e.id === id);

    if (!entry) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'DLQ entry not found',
      });
    }

    res.json({
      success: true,
      data: entry,
    });
  } catch (error) {
    console.error('Failed to get DLQ entry:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get DLQ entry',
    });
  }
});

/**
 * POST /api/dlq/entries/:id/archive
 * Archive a single DLQ entry
 */
router.post('/entries/:id/archive', authMiddleware, adminMiddleware, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const location = await dlq.archiveEntry(id);
    res.json({
      success: true,
      message: 'Entry archived successfully',
      data: { archive_location: location },
    });
  } catch (error) {
    console.error('Failed to archive DLQ entry:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message || 'Failed to archive DLQ entry',
    });
  }
});

/**
 * POST /api/dlq/entries/:id/restore
 * Restore a DLQ entry from archive
 */
router.post('/entries/:id/restore', authMiddleware, adminMiddleware, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { restoreToQueue = false } = req.body;
    const entry = await dlq.restoreEntry(id, { restoreToQueue });
    res.json({
      success: true,
      message: 'Entry restored successfully',
      data: entry,
    });
  } catch (error) {
    console.error('Failed to restore DLQ entry:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message || 'Failed to restore DLQ entry',
    });
  }
});

/**
 * POST /api/dlq/archive
 * Trigger manual archive job
 */
router.post('/archive', authMiddleware, adminMiddleware, async (req: Request, res: Response) => {
  try {
    const { ttlDays, batchSize } = req.body;
    const result = await dlq.archiveOldEntries({
      ttlDays: ttlDays ? parseInt(ttlDays, 10) : undefined,
      batchSize: batchSize ? parseInt(batchSize, 10) : undefined,
    });
    res.json({
      success: true,
      message: 'Archive job completed',
      data: result,
    });
  } catch (error) {
    console.error('Failed to run archive job:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to run archive job',
    });
  }
});

/**
 * GET /api/dlq/stats
 * Get DLQ statistics
 */
router.get('/stats', authMiddleware, adminMiddleware, async (req: Request, res: Response) => {
  try {
    const stats = await dlq.getArchiveStats();
    res.json({
      success: true,
      data: stats,
    });
  } catch (error) {
    console.error('Failed to get DLQ stats:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get DLQ stats',
    });
  }
});

export default router;
