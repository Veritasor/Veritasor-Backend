import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import {
  getMyBusiness,
  getBusinessById,
  listBusinesses,
} from '../../../../src/services/business/get.js';
import { businessRepository } from '../../../../src/repositories/business.js';

const AUTHENTICATED_USER = { id: 'user-1', email: 'user@example.com' };

const BUSINESS = {
  id: 'biz-1',
  userId: 'user-1',
  name: 'Acme',
  email: 'owner@acme.test',
  industry: 'software',
  description: 'Widgets',
  website: 'https://acme.test',
  reportingPeriod: 'monthly',
  reportingTimezone: 'UTC',
  lastReminderSentAt: null,
  createdAt: '2024-01-01T00:00:00.000Z',
  updatedAt: '2024-02-01T00:00:00.000Z',
};

// Only PUBLIC_FIELDS survive getBusinessById / listBusinesses.
const PUBLIC_BUSINESS = {
  id: 'biz-1',
  name: 'Acme',
  industry: 'software',
  description: 'Widgets',
  website: 'https://acme.test',
  createdAt: '2024-01-01T00:00:00.000Z',
};

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    user: AUTHENTICATED_USER,
    params: {},
    query: {},
    ...overrides,
  } as unknown as Request;
}

function makeRes(): {
  res: Response;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn().mockReturnThis();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json } as unknown as Response;
  return { res, status, json };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('getMyBusiness', () => {
  it('returns 200 with the authenticated user\'s business', async () => {
    const getByUserId = vi
      .spyOn(businessRepository, 'getByUserId')
      .mockResolvedValue(BUSINESS as any);

    const { res, status, json } = makeRes();
    await getMyBusiness(makeReq(), res);

    expect(getByUserId).toHaveBeenCalledWith('user-1');
    expect(status).toHaveBeenCalledWith(200);
    expect(json).toHaveBeenCalledWith(BUSINESS);
  });

  it('returns 404 when the authenticated user has no business', async () => {
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(null);

    const { res, status, json } = makeRes();
    await getMyBusiness(makeReq(), res);

    expect(status).toHaveBeenCalledWith(404);
    expect(json).toHaveBeenCalledWith({ error: 'Business not found' });
  });

  it('scopes the lookup to the id carried by the request, not a query value', async () => {
    const getByUserId = vi
      .spyOn(businessRepository, 'getByUserId')
      .mockResolvedValue(null);

    const { res } = makeRes();
    await getMyBusiness(
      makeReq({ user: { id: 'user-42', email: 'other@example.com' }, query: { userId: 'user-1' } }),
      res,
    );

    expect(getByUserId).toHaveBeenCalledWith('user-42');
  });

  it('rejects deterministically when the request has no authenticated user', async () => {
    const getByUserId = vi.spyOn(businessRepository, 'getByUserId');

    const req = makeReq();
    delete (req as any).user;

    await expect(getMyBusiness(req, makeRes().res)).rejects.toThrow(TypeError);
    expect(getByUserId).not.toHaveBeenCalled();
  });

  it('propagates repository failures instead of swallowing them', async () => {
    vi.spyOn(businessRepository, 'getByUserId').mockRejectedValue(
      new Error('database unavailable'),
    );

    const { res, status } = makeRes();
    await expect(getMyBusiness(makeReq(), res)).rejects.toThrow('database unavailable');
    expect(status).not.toHaveBeenCalled();
  });
});

describe('getBusinessById', () => {
  it('returns 200 and only the public projection of the business', async () => {
    const getById = vi
      .spyOn(businessRepository, 'getById')
      .mockResolvedValue(BUSINESS as any);

    const { res, status, json } = makeRes();
    await getBusinessById(makeReq({ params: { id: 'biz-1' } as any }), res);

    expect(getById).toHaveBeenCalledWith('biz-1');
    expect(status).toHaveBeenCalledWith(200);

    const payload = json.mock.calls[0][0];
    expect(payload).toEqual(PUBLIC_BUSINESS);
    // Sensitive / internal fields must never be leaked by the public read.
    expect(payload).not.toHaveProperty('userId');
    expect(payload).not.toHaveProperty('email');
    expect(payload).not.toHaveProperty('updatedAt');
    expect(payload).not.toHaveProperty('reportingTimezone');
    expect(payload).not.toHaveProperty('lastReminderSentAt');
  });

  it('returns 404 when the business does not exist', async () => {
    vi.spyOn(businessRepository, 'getById').mockResolvedValue(null);

    const { res, status, json } = makeRes();
    await getBusinessById(makeReq({ params: { id: 'missing' } as any }), res);

    expect(status).toHaveBeenCalledWith(404);
    expect(json).toHaveBeenCalledWith({ error: 'Business not found' });
  });

  it('treats an empty id as a normal lookup and returns 404 when nothing matches', async () => {
    const getById = vi.spyOn(businessRepository, 'getById').mockResolvedValue(null);

    const { res, status } = makeRes();
    await getBusinessById(makeReq({ params: { id: '' } as any }), res);

    expect(getById).toHaveBeenCalledWith('');
    expect(status).toHaveBeenCalledWith(404);
  });

  it('propagates repository failures', async () => {
    vi.spyOn(businessRepository, 'getById').mockRejectedValue(new Error('boom'));

    await expect(
      getBusinessById(makeReq({ params: { id: 'biz-1' } as any }), makeRes().res),
    ).rejects.toThrow('boom');
  });
});

describe('listBusinesses', () => {
  it('returns 200 with public items and the next cursor', async () => {
    vi.spyOn(businessRepository, 'list').mockResolvedValue({
      items: [BUSINESS as any],
      nextCursor: 'cursor-2',
    });

    const { res, status, json } = makeRes();
    await listBusinesses(makeReq({ query: {} as any }), res);

    expect(status).toHaveBeenCalledWith(200);
    const payload = json.mock.calls[0][0];
    expect(payload).toEqual({ items: [PUBLIC_BUSINESS], nextCursor: 'cursor-2' });
    expect(payload.items[0]).not.toHaveProperty('userId');
    expect(payload.items[0]).not.toHaveProperty('email');
  });

  it('forwards the raw query options to the repository', async () => {
    const list = vi
      .spyOn(businessRepository, 'list')
      .mockResolvedValue({ items: [], nextCursor: undefined });

    const query = {
      limit: '10',
      cursor: 'abc',
      sortBy: 'name',
      sortOrder: 'asc',
      industry: 'fintech',
    };

    const { res } = makeRes();
    await listBusinesses(makeReq({ query: query as any }), res);

    expect(list).toHaveBeenCalledWith({
      limit: '10',
      cursor: 'abc',
      sortBy: 'name',
      sortOrder: 'asc',
      industry: 'fintech',
    });
  });

  it('passes undefined for every option when the query is empty', async () => {
    const list = vi
      .spyOn(businessRepository, 'list')
      .mockResolvedValue({ items: [], nextCursor: undefined });

    const { res } = makeRes();
    await listBusinesses(makeReq({ query: {} as any }), res);

    expect(list).toHaveBeenCalledWith({
      limit: undefined,
      cursor: undefined,
      sortBy: undefined,
      sortOrder: undefined,
      industry: undefined,
    });
  });

  it('returns an empty page with an undefined cursor (empty-result path)', async () => {
    vi.spyOn(businessRepository, 'list').mockResolvedValue({
      items: [],
      nextCursor: undefined,
    });

    const { res, status, json } = makeRes();
    await listBusinesses(makeReq({ query: {} as any }), res);

    expect(status).toHaveBeenCalledWith(200);
    expect(json).toHaveBeenCalledWith({ items: [], nextCursor: undefined });
  });

  it('strips non-public fields from every item, not just the first', async () => {
    const second = {
      ...BUSINESS,
      id: 'biz-2',
      name: 'Globex',
      email: 'hidden@globex.test',
      userId: 'user-2',
      updatedAt: '2024-03-01T00:00:00.000Z',
    };
    vi.spyOn(businessRepository, 'list').mockResolvedValue({
      items: [BUSINESS as any, second as any],
      nextCursor: undefined,
    });

    const { res, json } = makeRes();
    await listBusinesses(makeReq({ query: {} as any }), res);

    const payload = json.mock.calls[0][0];
    expect(payload.items).toHaveLength(2);
    for (const item of payload.items) {
      expect(Object.keys(item).sort()).toEqual(
        ['createdAt', 'description', 'id', 'industry', 'name', 'website'].sort(),
      );
    }
  });

  it('propagates repository failures', async () => {
    vi.spyOn(businessRepository, 'list').mockRejectedValue(new Error('list failed'));

    await expect(
      listBusinesses(makeReq({ query: {} as any }), makeRes().res),
    ).rejects.toThrow('list failed');
  });
});
