import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const {
  lookupMock,
  requestMock,
  createDeliveryReceiptMock,
  saveDeadLetterMock,
} = vi.hoisted(() => ({
  lookupMock: vi.fn(),
  requestMock: vi.fn(),
  createDeliveryReceiptMock: vi.fn().mockResolvedValue(undefined),
  saveDeadLetterMock: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('node:dns/promises', () => ({ lookup: (...args: unknown[]) => lookupMock(...args) }));
vi.mock('https', () => ({ request: (...args: unknown[]) => requestMock(...args) }));
vi.mock('../../../utils/secret-loader.js', () => ({ secretLoader: { get: vi.fn() } }));
vi.mock('../../../repositories/auditLogRepository.js', () => ({ createAuditLog: vi.fn() }));
vi.mock('../../../repositories/deliveryReceiptRepository.js', () => ({
  createDeliveryReceipt: (...args: unknown[]) => createDeliveryReceiptMock(...args),
}));
vi.mock('../deadLetterQueue.js', () => ({
  saveDeadLetter: (...args: unknown[]) => saveDeadLetterMock(...args),
}));

import { sendWebhookDelivery, WebhookSubscription } from '../dispatcher.js';

const subscription: WebhookSubscription = {
  id: 'sub-retry-1',
  businessId: 'biz-retry-1',
  url: 'https://hooks.example.com/webhook',
  secret: 'test-secret-key-32-chars-minimum',
};

function mockHttpResponse(statusCode: number, body = '') {
  return (
    _url: unknown,
    _options: unknown,
    callback: (r: EventEmitter & { statusCode: number; setEncoding: (s: string) => void }) => void,
  ) => {
    const req = new EventEmitter() as EventEmitter & {
      end: (b: string) => void;
      destroy: (err: Error) => void;
    };
    req.end = () => {
      const res = new EventEmitter() as EventEmitter & {
        statusCode: number;
        setEncoding: (s: string) => void;
      };
      res.statusCode = statusCode;
      res.setEncoding = () => {};
      callback(res);
      if (body) res.emit('data', body);
      res.emit('end');
    };
    req.destroy = (err) => req.emit('error', err);
    return req;
  };
}

function mockNetworkError(message = 'ECONNRESET') {
  return () => {
    const req = new EventEmitter() as EventEmitter & {
      end: (b: string) => void;
      destroy: (err: Error) => void;
    };
    req.end = () => {
      const err = new Error(message) as Error & { code: string };
      err.code = 'ECONNRESET';
      req.emit('error', err);
    };
    req.destroy = (err) => req.emit('error', err);
    return req;
  };
}

describe('webhook dispatcher bounded retries and DLQ', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    lookupMock.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
  });

  afterEach(() => {
    vi.useRealTimers();
    delete process.env.WEBHOOK_DELIVERY_MAX_ATTEMPTS;
    delete process.env.WEBHOOK_DELIVERY_BASE_DELAY_MS;
  });

  it('retries transient 5xx failure then succeeds and records multiple receipts', async () => {
    requestMock
      .mockImplementationOnce(mockHttpResponse(503, 'Service Unavailable'))
      .mockImplementationOnce(mockHttpResponse(200, 'OK'));

    const deliveryPromise = sendWebhookDelivery({
      subscription,
      payload: { event: 'attestation.created', id: 'att-1' },
      maxAttempts: 3,
      baseDelayMs: 100,
    });

    await vi.runAllTimersAsync();
    const result = await deliveryPromise;

    expect(result.statusCode).toBe(200);
    expect(result.attempt).toBe(2);
    expect(requestMock).toHaveBeenCalledTimes(2);
    expect(createDeliveryReceiptMock).toHaveBeenCalledTimes(2);
    expect(createDeliveryReceiptMock.mock.calls[0][0]).toMatchObject({
      attemptNumber: 1,
      statusCode: 503,
      subscriptionId: subscription.id,
      businessId: subscription.businessId,
    });
    expect(createDeliveryReceiptMock.mock.calls[1][0]).toMatchObject({
      attemptNumber: 2,
      statusCode: 200,
      subscriptionId: subscription.id,
      businessId: subscription.businessId,
    });
    expect(saveDeadLetterMock).not.toHaveBeenCalled();
  });

  it('retries network errors, 408, and 429 responses', async () => {
    requestMock
      .mockImplementationOnce(mockNetworkError())
      .mockImplementationOnce(mockHttpResponse(408, 'Request Timeout'))
      .mockImplementationOnce(mockHttpResponse(429, 'Too Many Requests'))
      .mockImplementationOnce(mockHttpResponse(200, 'OK'));

    const deliveryPromise = sendWebhookDelivery({
      subscription,
      payload: { event: 'attestation.updated' },
      maxAttempts: 4,
      baseDelayMs: 50,
    });

    await vi.runAllTimersAsync();
    const result = await deliveryPromise;

    expect(result.statusCode).toBe(200);
    expect(result.attempt).toBe(4);
    expect(createDeliveryReceiptMock).toHaveBeenCalledTimes(4);
    expect(saveDeadLetterMock).not.toHaveBeenCalled();
  });

  it('enqueues payload into DLQ after exhausting maxAttempts', async () => {
    requestMock
      .mockImplementationOnce(mockHttpResponse(500, 'err1'))
      .mockImplementationOnce(mockHttpResponse(502, 'err2'))
      .mockImplementationOnce(mockHttpResponse(503, 'err3'));

    const payload = { event: 'attestation.revoked', id: 'att-99' };
    const deliveryPromise = sendWebhookDelivery({
      subscription,
      payload,
      maxAttempts: 3,
      baseDelayMs: 100,
    });

    await vi.runAllTimersAsync();
    const result = await deliveryPromise;

    expect(result.statusCode).toBe(503);
    expect(result.attempt).toBe(3);
    expect(createDeliveryReceiptMock).toHaveBeenCalledTimes(3);
    expect(saveDeadLetterMock).toHaveBeenCalledTimes(1);
    expect(saveDeadLetterMock).toHaveBeenCalledWith(
      'webhook',
      result.deliveryId,
      expect.objectContaining({
        subscriptionId: subscription.id,
        businessId: subscription.businessId,
        url: subscription.url,
        payload,
      }),
      expect.objectContaining({ code: 'HTTP_503' }),
      3,
    );
  });

  it('does not retry non-408/429 4xx responses and does not enqueue to DLQ', async () => {
    requestMock.mockImplementationOnce(mockHttpResponse(400, 'Bad Request'));

    const result = await sendWebhookDelivery({
      subscription,
      payload: { event: 'attestation.created' },
      maxAttempts: 3,
      baseDelayMs: 100,
    });

    expect(result.statusCode).toBe(400);
    expect(result.attempt).toBe(1);
    expect(requestMock).toHaveBeenCalledTimes(1);
    expect(createDeliveryReceiptMock).toHaveBeenCalledTimes(1);
    expect(saveDeadLetterMock).not.toHaveBeenCalled();
  });

  it('respects configurable WEBHOOK_DELIVERY_MAX_ATTEMPTS env var', async () => {
    process.env.WEBHOOK_DELIVERY_MAX_ATTEMPTS = '2';
    process.env.WEBHOOK_DELIVERY_BASE_DELAY_MS = '25';

    requestMock
      .mockImplementationOnce(mockHttpResponse(500, 'err1'))
      .mockImplementationOnce(mockHttpResponse(500, 'err2'));

    const deliveryPromise = sendWebhookDelivery({
      subscription,
      payload: { event: 'test' },
    });

    await vi.runAllTimersAsync();
    const result = await deliveryPromise;

    expect(result.attempt).toBe(2);
    expect(requestMock).toHaveBeenCalledTimes(2);
    expect(saveDeadLetterMock).toHaveBeenCalledWith(
      'webhook',
      result.deliveryId,
      expect.objectContaining({
        subscriptionId: subscription.id,
        businessId: subscription.businessId,
      }),
      expect.objectContaining({ code: 'HTTP_500' }),
      2,
    );
  });
});
