import { describe, it, expect, beforeEach, vi } from 'vitest';
import { expiredRolePromotionRequestsJob } from '../../../src/jobs/expiredRolePromotionRequests';
import * as repository from '../../../src/repositories/rolePromotionRequestRepository';
import { logger } from '../../../src/utils/logger';

vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
  },
}));

describe('Expired Role Promotion Requests Job', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    repository.clearAllRolePromotionRequests();
  });

  it('should run and log completion', async () => {
    await expiredRolePromotionRequestsJob();
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('Running expired role promotion requests sweeper job'));
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('No expired role promotion requests to mark'));
  });

  it('should log count of expired requests marked', async () => {
    // Create a request
    const request = await repository.createRolePromotionRequest('target-123', 'admin', 'admin-456');
    // Manually expire it
    await repository.updateRolePromotionRequest(request.id, {});
    // Mock sweepExpiredRequests to return count
    vi.spyOn(repository, 'sweepExpiredRequests').mockResolvedValueOnce(1);

    await expiredRolePromotionRequestsJob();
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('Marked 1 expired role promotion requests'));
  });

  it('should log errors if job fails', async () => {
    const testError = new Error('Test job failure');
    vi.spyOn(repository, 'sweepExpiredRequests').mockRejectedValueOnce(testError);

    await expiredRolePromotionRequestsJob();
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('Error running expired role promotion requests job'), testError);
  });
});
