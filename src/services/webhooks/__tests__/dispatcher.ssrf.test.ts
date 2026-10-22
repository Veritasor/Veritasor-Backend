import { EventEmitter } from 'node:events';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { lookupMock, requestMock } = vi.hoisted(() => ({ lookupMock: vi.fn(), requestMock: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup: (...args: unknown[]) => lookupMock(...args) }));
vi.mock('https', () => ({ request: (...args: unknown[]) => requestMock(...args) }));
vi.mock('../../../utils/secret-loader.js', () => ({ secretLoader: { get: vi.fn() } }));
vi.mock('../../../repositories/auditLogRepository.js', () => ({ createAuditLog: vi.fn() }));
vi.mock('../../../repositories/deliveryReceiptRepository.js', () => ({ createDeliveryReceipt: vi.fn() }));

import { sendWebhookDelivery } from '../dispatcher.js';

describe('webhook dispatcher SSRF protection', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('refuses a hostname when DNS resolves to loopback without sending a request', async () => {
    lookupMock.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    const result = await sendWebhookDelivery({
      subscription: { id: 's', businessId: 'b', url: 'https://hooks.example.com/x', secret: 'secret' },
      payload: { event: 'test' },
    });
    expect(result.statusCode).toBe(0);
    expect(requestMock).not.toHaveBeenCalled();
  });

  it('records a redirect response without following its Location', async () => {
    lookupMock.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
    requestMock.mockImplementation((_url: unknown, _options: unknown, callback: (r: EventEmitter & { statusCode: number; setEncoding: (s: string) => void }) => void) => {
      const request = new EventEmitter() as EventEmitter & { end: (body: string) => void; destroy: (err: Error) => void };
      request.end = () => {
        const response = new EventEmitter() as EventEmitter & { statusCode: number; setEncoding: (s: string) => void };
        response.statusCode = 302;
        response.setEncoding = () => {};
        callback(response);
        response.emit('data', 'redirect');
        response.emit('end');
      };
      request.destroy = (err) => request.emit('error', err);
      return request;
    });
    const result = await sendWebhookDelivery({
      subscription: { id: 's', businessId: 'b', url: 'https://hooks.example.com/x', secret: 'secret' },
      payload: { event: 'test' },
    });
    expect(result.statusCode).toBe(302);
    expect(requestMock).toHaveBeenCalledTimes(1);
  });
});
