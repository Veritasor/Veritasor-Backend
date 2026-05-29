import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import { createBusiness } from '../../../../src/services/business/create.js';
import { businessRepository } from '../../../../src/repositories/business.js';
import { AppError } from '../../../../src/types/errors.js';

const VALID_USER = { id: 'user-1', email: 'user@example.com' };
const EXISTING_BUSINESS = {
  id: 'biz-1',
  userId: 'user-1',
  name: 'Acme',
  email: 'user@example.com',
  industry: null,
  description: null,
  website: null,
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
};

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    user: VALID_USER,
    body: { name: 'Acme Corp' },
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

describe('createBusiness', () => {
  it('returns 409 when a business already exists (fast path)', async () => {
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(EXISTING_BUSINESS as any);
    const createSpy = vi.spyOn(businessRepository, 'create');

    const { res, status, json } = makeRes();
    await createBusiness(makeReq(), res);

    expect(status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'BUSINESS_ALREADY_EXISTS' }),
    );
    expect(createSpy).not.toHaveBeenCalled();
  });

  it('throws AppError on unique constraint violation', async () => {
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(null);
    vi.spyOn(businessRepository, 'create').mockRejectedValue(
      Object.assign(new Error('duplicate key'), {
        code: '23505',
        constraint: 'businesses_user_id_unique_idx',
      }),
    );

    const err = await createBusiness(makeReq(), makeRes().res).catch((e) => e);

    expect(err).toBeInstanceOf(AppError);
    expect(err.status).toBe(409);
    expect(err.code).toBe('BUSINESS_ALREADY_EXISTS');
  });

  it('returns 500 for other unique violations', async () => {
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(null);
    vi.spyOn(businessRepository, 'create').mockRejectedValue(
      Object.assign(new Error('duplicate key'), {
        code: '23505',
        constraint: 'other_unique_idx',
      }),
    );

    const { res, status, json } = makeRes();
    await createBusiness(makeReq(), res);

    expect(status).toHaveBeenCalledWith(500);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'INTERNAL_ERROR' }),
    );
  });
});
