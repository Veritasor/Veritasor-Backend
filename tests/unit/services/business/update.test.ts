import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Request, Response } from 'express';

const businessRepositoryMocks = vi.hoisted(() => ({
  getByUserId: vi.fn(),
  update: vi.fn(),
}));

vi.mock('../../../../src/repositories/business.js', () => ({
  businessRepository: businessRepositoryMocks,
}));

import { updateBusiness } from '../../../../src/services/business/update.js';
import { logger } from '../../../../src/utils/logger.js';

beforeEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

describe('updateBusiness logging', () => {
  it('logs structured error context without the request body', async () => {
    const error = new Error('database unavailable');
    businessRepositoryMocks.getByUserId.mockRejectedValue(error);
    const loggerError = vi.spyOn(logger, 'error').mockImplementation(() => {});

    const request = {
      user: { id: 'user-1', email: 'user@example.com' },
      body: { name: 'Updated business' },
    } as Request;
    const json = vi.fn().mockReturnThis();
    const status = vi.fn().mockReturnValue({ json });
    const response = { status, json } as unknown as Response;

    await updateBusiness(request, response);

    expect(status).toHaveBeenCalledWith(500);
    expect(loggerError).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'business.update.error',
        userId: 'user-1',
        error: 'database unavailable',
        stack: expect.any(String),
      }),
    );
    expect(loggerError.mock.calls[0][0]).not.toHaveProperty('body');
    expect(loggerError.mock.calls[0][0]).not.toHaveProperty('email');
  });
});
