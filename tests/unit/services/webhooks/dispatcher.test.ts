import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { createHmac } from 'node:crypto';

const mocks = vi.hoisted(() => ({
  secretLoaderGet: vi.fn(),
  createAuditLog: vi.fn(),
  createDeliveryReceipt: vi.fn(),
  lookup: vi.fn(),
  request: vi.fn(),
  X509Certificate: vi.fn(function () {
    return { validTo: '' };
  }),
}));

vi.mock('node:dns/promises', () => ({ lookup: mocks.lookup }));

vi.mock('node:https', () => {
  class MockAgent {
    options: Record<string, unknown>;
    constructor(options: Record<string, unknown>) {
      this.options = options;
    }
  }
  return { request: mocks.request, Agent: MockAgent };
});

vi.mock('https', () => {
  class MockAgent {
    options: Record<string, unknown>;
    constructor(options: Record<string, unknown>) {
      this.options = options;
    }
  }
  return { request: mocks.request, Agent: MockAgent };
});

vi.mock('crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('crypto')>();
  return {
    ...actual,
    default: { ...actual, X509Certificate: mocks.X509Certificate },
  };
});

vi.mock('../../../../src/utils/secret-loader.js', () => ({
  secretLoader: { get: mocks.secretLoaderGet },
}));

vi.mock('../../../../src/repositories/auditLogRepository.js', () => ({
  createAuditLog: mocks.createAuditLog,
}));

vi.mock('../../../../src/repositories/deliveryReceiptRepository.js', () => ({
  createDeliveryReceipt: mocks.createDeliveryReceipt,
}));

import {
  sendWebhookDelivery,
  signAndPrepareDelivery,
  verifyWebhookSignature,
  type WebhookSubscription,
} from '../../../../src/services/webhooks/dispatcher.js';

const payload = { event: 'test.created', id: 'att-1' };
const NOW = Date.UTC(2026, 10, 24, 12, 0, 0);

function subscription(overrides: Partial<WebhookSubscription> = {}): WebhookSubscription {
  return {
    id: '1',
    businessId: 'b1',
    url: 'https://example.com/hook',
    secret: 'new-secret',
    secretVersion: 2,
    ...overrides,
  };
}

function installHttpMock(status = 200): void {
  mocks.request.mockImplementation(
    (_url: unknown, _options: unknown, callback: (res: EventEmitter & { statusCode?: number }) => void) => {
      const req = new EventEmitter() as EventEmitter & {
        write: (chunk: string) => void;
        end: (chunk?: string) => void;
      };
      req.write = vi.fn();
      req.end = vi.fn(() => {
        const res = new EventEmitter() as EventEmitter & {
          statusCode?: number;
          setEncoding: (encoding: string) => void;
        };
        res.statusCode = status;
        res.setEncoding = vi.fn();
        callback(res);
        queueMicrotask(() => {
          res.emit('data', 'OK');
          res.emit('end');
        });
      });
      return req;
    },
  );
}

function signedData(headers: Record<string, string>): string {
  return `${headers['X-Veritasor-Delivery-Id']}.${headers['X-Veritasor-Attempt']}.${headers['X-Veritasor-Timestamp']}.${JSON.stringify(payload)}`;
}

describe('webhook dispatcher signature rotation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    mocks.lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    installHttpMock();
    mocks.createAuditLog.mockResolvedValue(true);
    mocks.createDeliveryReceipt.mockResolvedValue(true);
    mocks.secretLoaderGet.mockResolvedValue('mock-secret-value');
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('signs with both secrets during the rotation grace window and both verify', () => {
    const { headers } = signAndPrepareDelivery(
      payload,
      subscription({
        previousSecret: 'old-secret',
        previousSecretVersion: 1,
        previousSecretExpiresAt: new Date(NOW + 300_000),
      }),
      2,
    );

    const data = signedData(headers);
    expect(headers['X-Veritasor-Signature']).toBe(
      createHmac('sha256', 'new-secret').update(data).digest('hex'),
    );
    expect(headers['X-Veritasor-Previous-Signature']).toBe(
      createHmac('sha256', 'old-secret').update(data).digest('hex'),
    );
    expect(headers['X-Veritasor-Signature-Version']).toBe('2');
    expect(headers['X-Veritasor-Previous-Signature-Version']).toBe('1');
    expect(
      verifyWebhookSignature({
        payload: JSON.stringify(payload),
        headers,
        secret: 'new-secret',
      }),
    ).toBe(true);
    expect(
      verifyWebhookSignature({
        payload: JSON.stringify(payload),
        headers: {
          ...headers,
          'X-Veritasor-Signature': headers['X-Veritasor-Previous-Signature'],
        },
        secret: 'old-secret',
      }),
    ).toBe(true);
  });

  it('stops signing with the previous secret after its expiry', () => {
    const { headers } = signAndPrepareDelivery(
      payload,
      subscription({
        previousSecret: 'old-secret',
        previousSecretVersion: 1,
        previousSecretExpiresAt: new Date(NOW - 1_000),
      }),
    );

    expect(headers).not.toHaveProperty('X-Veritasor-Previous-Signature');
    expect(headers).not.toHaveProperty('X-Veritasor-Previous-Signature-Version');
    expect(
      verifyWebhookSignature({
        payload: JSON.stringify(payload),
        headers,
        secret: 'old-secret',
      }),
    ).toBe(false);
    expect(
      verifyWebhookSignature({
        payload: JSON.stringify(payload),
        headers,
        secret: 'new-secret',
      }),
    ).toBe(true);
  });

  it('reports the current secret version in the delivery receipt and headers', async () => {
    const sub = subscription({
      previousSecret: 'old-secret',
      previousSecretVersion: 1,
      previousSecretExpiresAt: new Date(NOW + 300_000),
    });

    const result = await sendWebhookDelivery({ subscription: sub, payload });

    expect(result.signatureVersion).toBe(2);
    expect(mocks.createDeliveryReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ signatureVersion: 2 }),
    );
    expect(mocks.request).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        headers: expect.objectContaining({
          'X-Veritasor-Previous-Signature': expect.any(String),
        }),
      }),
      expect.any(Function),
    );
  });

  it('does not consult the secret loader for non-mTLS deliveries', async () => {
    await sendWebhookDelivery({ subscription: subscription(), payload });

    expect(mocks.secretLoaderGet).not.toHaveBeenCalled();
    expect(mocks.createDeliveryReceipt).toHaveBeenCalledTimes(1);
  });

  it('rejects an expired client certificate before dispatching', async () => {
    mocks.X509Certificate.mockImplementation(function () {
      return { validTo: new Date(NOW - 86_400_000).toISOString() };
    });

    const sub = subscription({
      id: '3',
      mtlsConfig: {
        clientCertSecretId: 'cert-123',
        clientKeySecretId: 'key-123',
        caPinSecretId: 'ca-123',
      },
    });

    await expect(sendWebhookDelivery({ subscription: sub, payload })).rejects.toThrow(
      /Client certificate for subscription 3 expired/,
    );

    expect(mocks.request).not.toHaveBeenCalled();
    expect(mocks.createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'webhook_delivery_rejected',
        metadata: expect.objectContaining({ reason: 'MTLS_CERT_EXPIRED' }),
      }),
    );
  });
});
