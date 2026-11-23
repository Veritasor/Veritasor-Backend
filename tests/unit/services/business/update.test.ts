import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import { updateBusiness } from '../../../../src/services/business/update.js';
import { businessRepository } from '../../../../src/repositories/business.js';

const AUTHENTICATED_USER = { id: 'user-1', email: 'user@example.com' };

const EXISTING_BUSINESS = {
  id: 'biz-1',
  userId: 'user-1',
  name: 'Acme',
  email: 'user@example.com',
  industry: null,
  description: null,
  website: null,
  countryCode: 'NG',
  reportingPeriod: 'monthly',
  reportingTimezone: 'UTC',
  lastReminderSentAt: null,
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
};

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    user: AUTHENTICATED_USER,
    body: {},
    ...overrides,
  } as Request;
}

function makeRes(): { res: Response; status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn> } {
  const json = vi.fn().mockReturnThis();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json } as unknown as Response;
  return { res, status, json };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('updateBusiness', () => {
  it('normalizes, passes to businessRepository.update, and returns countryCode when provided', async () => {
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(EXISTING_BUSINESS as any);
    const updated = {
      ...EXISTING_BUSINESS,
      name: 'Renamed Corp',
      countryCode: 'NG',
      updatedAt: '2024-01-02T00:00:00Z',
    };
    const updateSpy = vi.spyOn(businessRepository, 'update').mockResolvedValue(updated as any);

    const { res, status, json } = makeRes();
    await updateBusiness(makeReq({ body: { name: 'Renamed Corp', countryCode: 'ng' } }), res);

    expect(updateSpy).toHaveBeenCalledWith(
      'biz-1',
      expect.objectContaining({ name: 'Renamed Corp', countryCode: 'NG' }),
    );
    expect(status).toHaveBeenCalledWith(200);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'Renamed Corp', countryCode: 'NG' }),
    );
  });

  it('updates without countryCode and does not clobber the stored value', async () => {
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(EXISTING_BUSINESS as any);
    const updated = { ...EXISTING_BUSINESS, name: 'Renamed Corp' };
    const updateSpy = vi.spyOn(businessRepository, 'update').mockResolvedValue(updated as any);

    const { res, status, json } = makeRes();
    await updateBusiness(makeReq({ body: { name: 'Renamed Corp' } }), res);

    expect(status).toHaveBeenCalledWith(200);
    const updateData = updateSpy.mock.calls[0][1];
    expect(updateData.name).toBe('Renamed Corp');
    expect(updateData.countryCode).toBeUndefined();
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ name: 'Renamed Corp' }));
  });
});
