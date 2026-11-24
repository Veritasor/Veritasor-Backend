/**
 * Router-level behavior coverage for `src/routes/webhook-subscriptions.ts`.
 *
 * `tests/unit/webhook-subscriptions.test.ts` already covers the Zod schemas and
 * the filter DSL in isolation.  This suite mounts the real router on an Express
 * app and asserts the HTTP contract end-to-end: status codes, the VRT-XXXX
 * error envelope, auth wiring, business scoping, the per-business capacity
 * guard, and the validation boundaries that sit in front of the repository.
 *
 * The subscription and delivery-receipt repositories and the auth middleware
 * are mocked so the suite is hermetic (no database / JWT dependency).
 *
 * @module tests/unit/routes/webhook-subscriptions.router
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';

// Hoisted so the mocked `requireBusinessAuth` middleware and the tests can
// share the business id without module-evaluation ordering issues.
const h = vi.hoisted(() => ({ BUSINESS_ID: 'biz-001' }));

const mockList = vi.fn();
const mockGetById = vi.fn();
const mockCreate = vi.fn();
const mockCountByBusiness = vi.fn();
const mockUpdate = vi.fn();
const mockRemove = vi.fn();
const mockQueryDeliveryReceipts = vi.fn();

// Stand-in for `requireBusinessAuth`: header-driven so a single app can
// exercise both the authorized and unauthorized branches of every route.
vi.mock('../../../src/middleware/requireBusinessAuth.js', () => ({
  requireBusinessAuth: async (
    req: {
      headers: Record<string, string | string[] | undefined>;
      user?: unknown;
      business?: unknown;
    },
    res: { status: (n: number) => { json: (b: unknown) => void } },
    next: () => void,
  ) => {
    const userId = req.headers['x-test-user'];
    if (typeof userId !== 'string' || userId.length === 0) {
      res.status(401).json({ error: 'Missing or invalid authorization header' });
      return;
    }
    req.user = { id: userId, userId, role: 'user' };
    req.business = { id: h.BUSINESS_ID };
    next();
  },
}));

vi.mock('../../../src/repositories/webhookSubscriptionRepository.js', async (importOriginal) => {
  const actual =
    await importOriginal<
      typeof import('../../../src/repositories/webhookSubscriptionRepository.js')
    >();
  return {
    ...actual,
    list: mockList,
    getById: mockGetById,
    create: mockCreate,
    countByBusiness: mockCountByBusiness,
    update: mockUpdate,
    remove: mockRemove,
  };
});

vi.mock('../../../src/repositories/deliveryReceiptRepository.js', () => ({
  queryDeliveryReceipts: mockQueryDeliveryReceipts,
}));

const { webhookSubscriptionsRouter, MAX_PUBLIC_RESPONSE_BODY_LENGTH } = await import(
  '../../../src/routes/webhook-subscriptions.js'
);
const { errorHandler } = await import('../../../src/middleware/errorHandler.js');

const BASE = '/api/v1/webhook-subscriptions';
const BUSINESS_ID = h.BUSINESS_ID;
const VALID_SECRET = 'a-very-long-secret-key-that-is-over-32-chars-long';

const app = express();
app.use(express.json());
app.use(BASE, webhookSubscriptionsRouter);
app.use(errorHandler);

function subscription(overrides: Record<string, unknown> = {}) {
  return {
    id: 'wh-1',
    businessId: BUSINESS_ID,
    url: 'https://example.com/webhook',
    secret: VALID_SECRET,
    eventFilters: {},
    enabled: true,
    maxPayloadSize: null,
    secretVersion: 1,
    mtlsConfig: null,
    createdAt: new Date('2026-07-01T00:00:00Z'),
    updatedAt: new Date('2026-07-01T00:00:00Z'),
    ...overrides,
  };
}

describe('webhookSubscriptionsRouter', () => {
  let errorLog: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    for (const m of [
      mockList,
      mockGetById,
      mockCreate,
      mockCountByBusiness,
      mockUpdate,
      mockRemove,
      mockQueryDeliveryReceipts,
    ]) {
      m.mockReset();
    }
    errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorLog.mockRestore();
  });

  // ── Auth wiring ────────────────────────────────────────────────────────

  const protectedRoutes: Array<[string, () => request.Test]> = [
    ['GET /', () => request(app).get(BASE)],
    ['GET /:id', () => request(app).get(`${BASE}/wh-1`)],
    ['GET /:id/deliveries', () => request(app).get(`${BASE}/wh-1/deliveries`)],
    ['POST /', () => request(app).post(BASE).send({})],
    ['PATCH /:id', () => request(app).patch(`${BASE}/wh-1`).send({})],
    ['DELETE /:id', () => request(app).delete(`${BASE}/wh-1`)],
  ];

  it.each(protectedRoutes)('requires auth on %s', async (_label, call) => {
    const res = await call();

    expect(res.status).toBe(401);
    expect(mockList).not.toHaveBeenCalled();
    expect(mockGetById).not.toHaveBeenCalled();
    expect(mockCreate).not.toHaveBeenCalled();
    expect(mockUpdate).not.toHaveBeenCalled();
    expect(mockRemove).not.toHaveBeenCalled();
    expect(mockQueryDeliveryReceipts).not.toHaveBeenCalled();
  });

  // ── GET / ──────────────────────────────────────────────────────────────

  it('lists subscriptions scoped to the resolved business and coerces the limit', async () => {
    mockList.mockResolvedValue({ data: [subscription()] });

    const res = await request(app).get(`${BASE}?limit=5`).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'success', data: [expect.objectContaining({ id: 'wh-1' })] });
    expect(mockList).toHaveBeenCalledWith(expect.objectContaining({ businessId: BUSINESS_ID, limit: 5 }));
  });

  it('omits nextCursor when the repository has no further page', async () => {
    mockList.mockResolvedValue({ data: [] });

    const res = await request(app).get(BASE).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('nextCursor');
  });

  it('surfaces nextCursor when the repository reports one', async () => {
    mockList.mockResolvedValue({ data: [subscription()], nextCursor: 'wh-2' });

    const res = await request(app).get(BASE).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(res.body.nextCursor).toBe('wh-2');
  });

  it('coerces the enabled filter to a boolean', async () => {
    mockList.mockResolvedValue({ data: [] });

    await request(app).get(`${BASE}?enabled=false`).set('x-test-user', 'u-1');

    expect(mockList).toHaveBeenCalledWith(expect.objectContaining({ enabled: false }));
  });

  it('rejects a limit above the cap with a 400 validation envelope', async () => {
    const res = await request(app).get(`${BASE}?limit=200`).set('x-test-user', 'u-1');

    expect(res.status).toBe(400);
    expect(res.body.vrtCode).toBe('VRT-0002');
    expect(mockList).not.toHaveBeenCalled();
  });

  it('rejects unknown query parameters (strict schema)', async () => {
    const res = await request(app).get(`${BASE}?injected=1`).set('x-test-user', 'u-1');

    expect(res.status).toBe(400);
    expect(res.body.vrtCode).toBe('VRT-0002');
    expect(mockList).not.toHaveBeenCalled();
  });

  // ── GET /:id ───────────────────────────────────────────────────────────

  it('returns a subscription scoped by id and business', async () => {
    mockGetById.mockResolvedValue(subscription({ id: 'wh-9' }));

    const res = await request(app).get(`${BASE}/wh-9`).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe('wh-9');
    expect(mockGetById).toHaveBeenCalledWith('wh-9', BUSINESS_ID);
  });

  it('returns 404 for a subscription outside the caller business', async () => {
    mockGetById.mockResolvedValue(null);

    const res = await request(app).get(`${BASE}/wh-other`).set('x-test-user', 'u-1');

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe('VRT-0004');
    expect(res.body.message).toBe('Webhook subscription not found');
  });

  // ── GET /:id/deliveries ────────────────────────────────────────────────

  function deliveryReceipt(overrides: Record<string, unknown> = {}) {
    return {
      id: 'dr-1',
      deliveryId: 'dv-1',
      attemptNumber: 1,
      subscriptionId: 'wh-1',
      businessId: BUSINESS_ID,
      url: 'https://example.com/webhook',
      statusCode: 200,
      latencyMs: 120,
      signatureVersion: 2,
      signature: 'stored-hmac-signature-must-not-leak',
      responseBody: '{"ok":true}',
      createdAt: '2026-07-02T00:00:00Z',
      ...overrides,
    };
  }

  it('returns paginated receipts scoped to the subscription and business', async () => {
    mockGetById.mockResolvedValue(subscription({ id: 'wh-1' }));
    mockQueryDeliveryReceipts.mockResolvedValue({ data: [deliveryReceipt()], nextCursor: 'dr-2' });

    const res = await request(app).get(`${BASE}/wh-1/deliveries`).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(mockGetById).toHaveBeenCalledWith('wh-1', BUSINESS_ID);
    expect(mockQueryDeliveryReceipts).toHaveBeenCalledTimes(1);
    expect(mockQueryDeliveryReceipts).toHaveBeenCalledWith({
      businessId: BUSINESS_ID,
      subscriptionId: 'wh-1',
      limit: 50,
      cursor: undefined,
    });
    expect(res.body.status).toBe('success');
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0]).toEqual(
      expect.objectContaining({
        id: 'dr-1',
        deliveryId: 'dv-1',
        subscriptionId: 'wh-1',
        businessId: BUSINESS_ID,
        statusCode: 200,
        latencyMs: 120,
        signatureVersion: 2,
        responseBody: '{"ok":true}',
      }),
    );
    expect(res.body.nextCursor).toBe('dr-2');
  });

  it('forwards the validated limit and cursor to the repository', async () => {
    mockGetById.mockResolvedValue(subscription());
    mockQueryDeliveryReceipts.mockResolvedValue({ data: [] });

    const res = await request(app)
      .get(`${BASE}/wh-1/deliveries?limit=5&cursor=abc123`)
      .set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(mockQueryDeliveryReceipts).toHaveBeenCalledWith({
      businessId: BUSINESS_ID,
      subscriptionId: 'wh-1',
      limit: 5,
      cursor: 'abc123',
    });
  });

  it('omits nextCursor when the repository has no further page', async () => {
    mockGetById.mockResolvedValue(subscription());
    mockQueryDeliveryReceipts.mockResolvedValue({ data: [deliveryReceipt()] });

    const res = await request(app).get(`${BASE}/wh-1/deliveries`).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('nextCursor');
  });

  it('rejects invalid limits with a 400 validation envelope before touching the repository', async () => {
    for (const raw of ['0', '-5', '101', '1.5', 'abc', 'NaN', '']) {
      mockGetById.mockReset();
      mockQueryDeliveryReceipts.mockReset();

      const res = await request(app)
        .get(`${BASE}/wh-1/deliveries?limit=${encodeURIComponent(raw)}`)
        .set('x-test-user', 'u-1');

      expect(res.status).toBe(400);
      expect(res.body.vrtCode).toBe('VRT-0002');
      expect(mockGetById).not.toHaveBeenCalled();
      expect(mockQueryDeliveryReceipts).not.toHaveBeenCalled();
    }
  });

  it('rejects unknown query parameters (strict schema)', async () => {
    const res = await request(app)
      .get(`${BASE}/wh-1/deliveries?injected=1`)
      .set('x-test-user', 'u-1');

    expect(res.status).toBe(400);
    expect(res.body.vrtCode).toBe('VRT-0002');
    expect(mockQueryDeliveryReceipts).not.toHaveBeenCalled();
  });

  it('returns 404 and does not query receipts when the subscription is not found', async () => {
    mockGetById.mockResolvedValue(null);

    const res = await request(app).get(`${BASE}/wh-1/deliveries`).set('x-test-user', 'u-1');

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe('VRT-0004');
    expect(res.body.message).toBe('Webhook subscription not found');
    expect(mockQueryDeliveryReceipts).not.toHaveBeenCalled();
  });

  it('returns 404 when the subscription is owned by another business', async () => {
    // The repository lookup is scoped by business; a subscription belonging
    // to another business is not found for this caller's business.
    mockGetById.mockResolvedValue(null);

    const res = await request(app).get(`${BASE}/wh-other/deliveries`).set('x-test-user', 'u-1');

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe('VRT-0004');
    expect(mockGetById).toHaveBeenCalledWith('wh-other', BUSINESS_ID);
    expect(mockQueryDeliveryReceipts).not.toHaveBeenCalled();
  });

  it('omits the stored signature and truncates long response bodies', async () => {
    const longBody = 'x'.repeat(MAX_PUBLIC_RESPONSE_BODY_LENGTH + 150);
    mockGetById.mockResolvedValue(subscription());
    mockQueryDeliveryReceipts.mockResolvedValue({
      data: [deliveryReceipt({ responseBody: longBody })],
    });

    const res = await request(app).get(`${BASE}/wh-1/deliveries`).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    const [item] = res.body.data;
    expect(item).not.toHaveProperty('signature');
    expect(item.signature).toBeUndefined();
    expect(item.responseBody).toBe(longBody.slice(0, MAX_PUBLIC_RESPONSE_BODY_LENGTH));
    expect(item.responseBody.length).toBeLessThanOrEqual(MAX_PUBLIC_RESPONSE_BODY_LENGTH);
  });

  it('handles null response bodies cleanly', async () => {
    mockGetById.mockResolvedValue(subscription());
    mockQueryDeliveryReceipts.mockResolvedValue({
      data: [deliveryReceipt({ responseBody: null })],
    });

    const res = await request(app).get(`${BASE}/wh-1/deliveries`).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    const [item] = res.body.data;
    expect(item).not.toHaveProperty('responseBody');
    expect(item).not.toHaveProperty('signature');
  });

  it('maps a repository failure to a 5xx envelope without leaking internals', async () => {
    mockGetById.mockResolvedValue(subscription());
    mockQueryDeliveryReceipts.mockRejectedValue(new Error('pg: connection to 10.0.0.5 refused'));

    const res = await request(app).get(`${BASE}/wh-1/deliveries`).set('x-test-user', 'u-1');

    expect(res.status).toBe(500);
    expect(res.body.vrtCode).toBe('VRT-9999');
    expect(JSON.stringify(res.body)).not.toContain('10.0.0.5');
  });

  // ── POST / ─────────────────────────────────────────────────────────────

  it('creates a subscription and defaults enabled to true', async () => {
    mockCountByBusiness.mockResolvedValue(0);
    mockCreate.mockImplementation((businessId: string, input: Record<string, unknown>) =>
      subscription({ ...input, businessId, id: 'wh-new' }),
    );

    const res = await request(app)
      .post(BASE)
      .set('x-test-user', 'u-1')
      .send({ url: 'https://example.com/hook', secret: VALID_SECRET });

    expect(res.status).toBe(201);
    expect(res.body.data.id).toBe('wh-new');
    expect(mockCountByBusiness).toHaveBeenCalledWith(BUSINESS_ID);
    expect(mockCreate).toHaveBeenCalledWith(
      BUSINESS_ID,
      expect.objectContaining({ url: 'https://example.com/hook', enabled: true }),
    );
  });

  it('rejects creation at the per-business capacity limit with 409', async () => {
    mockCountByBusiness.mockResolvedValue(10);

    const res = await request(app)
      .post(BASE)
      .set('x-test-user', 'u-1')
      .send({ url: 'https://example.com/hook', secret: VALID_SECRET });

    expect(res.status).toBe(409);
    expect(res.body.vrtCode).toBe('VRT-0005');
    expect(res.body.message).toBe('Maximum of 10 webhook subscriptions allowed per business');
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it('allows creation at one below the capacity limit', async () => {
    mockCountByBusiness.mockResolvedValue(9);
    mockCreate.mockResolvedValue(subscription());

    const res = await request(app)
      .post(BASE)
      .set('x-test-user', 'u-1')
      .send({ url: 'https://example.com/hook', secret: VALID_SECRET });

    expect(res.status).toBe(201);
    expect(mockCreate).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a missing secret', { url: 'https://example.com/hook' }],
    ['a short secret', { url: 'https://example.com/hook', secret: 'short' }],
    ['an invalid url', { url: 'not-a-url', secret: VALID_SECRET }],
    ['a non-https scheme', { url: 'ftp://example.com/hook', secret: VALID_SECRET }],
    ['an unknown field', { url: 'https://example.com/hook', secret: VALID_SECRET, injected: 'x' }],
  ])('rejects creation with %s before touching the repository', async (_label, body) => {
    const res = await request(app).post(BASE).set('x-test-user', 'u-1').send(body);

    expect(res.status).toBe(400);
    expect(res.body.vrtCode).toBe('VRT-0002');
    expect(mockCountByBusiness).not.toHaveBeenCalled();
    expect(mockCreate).not.toHaveBeenCalled();
  });

  // ── PATCH /:id ─────────────────────────────────────────────────────────

  it('updates a subscription and returns the updated record', async () => {
    mockUpdate.mockResolvedValue(subscription({ url: 'https://new.example.com/hook' }));

    const res = await request(app)
      .patch(`${BASE}/wh-1`)
      .set('x-test-user', 'u-1')
      .send({ url: 'https://new.example.com/hook' });

    expect(res.status).toBe(200);
    expect(res.body.data.url).toBe('https://new.example.com/hook');
    expect(mockUpdate).toHaveBeenCalledWith(
      'wh-1',
      BUSINESS_ID,
      expect.objectContaining({ url: 'https://new.example.com/hook' }),
    );
  });

  it('returns 404 when patching a subscription outside the caller business', async () => {
    mockUpdate.mockResolvedValue(null);

    const res = await request(app)
      .patch(`${BASE}/wh-other`)
      .set('x-test-user', 'u-1')
      .send({ enabled: false });

    expect(res.status).toBe(404);
    expect(res.body.message).toBe('Webhook subscription not found');
  });

  it('rejects an invalid partial update with 400 and does not call the repository', async () => {
    const res = await request(app)
      .patch(`${BASE}/wh-1`)
      .set('x-test-user', 'u-1')
      .send({ url: 'javascript:alert(1)' });

    expect(res.status).toBe(400);
    expect(res.body.vrtCode).toBe('VRT-0002');
    expect(mockUpdate).not.toHaveBeenCalled();
  });

  // ── DELETE /:id ────────────────────────────────────────────────────────

  it('deletes a subscription and reports it', async () => {
    mockRemove.mockResolvedValue(true);

    const res = await request(app).delete(`${BASE}/wh-1`).set('x-test-user', 'u-1');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'success', message: 'Webhook subscription deleted' });
    expect(mockRemove).toHaveBeenCalledWith('wh-1', BUSINESS_ID);
  });

  it('returns 404 when deleting a subscription that is not in scope', async () => {
    mockRemove.mockResolvedValue(false);

    const res = await request(app).delete(`${BASE}/wh-other`).set('x-test-user', 'u-1');

    expect(res.status).toBe(404);
    expect(res.body.message).toBe('Webhook subscription not found');
  });

  // ── Failure propagation ────────────────────────────────────────────────

  it('maps a repository failure to a 5xx envelope without leaking internals', async () => {
    mockList.mockRejectedValue(new Error('pg: connection to 10.0.0.5 refused'));

    const res = await request(app).get(BASE).set('x-test-user', 'u-1');

    expect(res.status).toBe(500);
    expect(res.body.vrtCode).toBe('VRT-9999');
    expect(JSON.stringify(res.body)).not.toContain('10.0.0.5');
  });
});
