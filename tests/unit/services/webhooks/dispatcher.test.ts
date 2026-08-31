import { sendWebhookDelivery, WebhookSubscription } from '../../../../src/services/webhooks/dispatcher';
import { secretLoader } from '../../../../src/utils/secret-loader';
import { createAuditLog } from '../../../../src/repositories/auditLogRepository';
import { createDeliveryReceipt } from '../../../../src/repositories/deliveryReceiptRepository';
import * as crypto from 'crypto';
import fetch from 'node-fetch';

jest.mock('node-fetch');

jest.mock('../../../../src/utils/secret-loader', () => ({
  secretLoader: {
    get: jest.fn()
  }
}));

jest.mock('../../../../src/repositories/auditLogRepository', () => ({
  createAuditLog: jest.fn().mockResolvedValue(true)
}));

jest.mock('../../../../src/repositories/deliveryReceiptRepository', () => ({
  createDeliveryReceipt: jest.fn().mockResolvedValue(true)
}));

jest.mock('crypto', () => {
  const original = jest.requireActual('crypto');
  return {
    ...original,
    X509Certificate: jest.fn(),
  };
});

describe('Webhook Dispatcher', () => {
  const mockPayload = { event: 'test.created' };
  
  beforeEach(() => {
    jest.clearAllMocks();
    (fetch as unknown as jest.Mock).mockResolvedValue({ 
      ok: true, 
      status: 200,
      text: jest.fn().mockResolvedValue('OK') 
    });
  });

  it('should deliver standard webhooks without mTLS', async () => {
    const sub: WebhookSubscription = { 
      id: '1', 
      businessId: 'b1',
      url: 'https://example.com/hook', 
      secret: 'test-secret'
    };
    
    await sendWebhookDelivery({ subscription: sub, payload: mockPayload });
    
    expect(secretLoader.get).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledWith('https://example.com/hook', expect.objectContaining({
      agent: undefined
    }));
    expect(createDeliveryReceipt).toHaveBeenCalled();
  });

  it('should deliver mTLS webhooks with valid pinned certs', async () => {
    const sub: WebhookSubscription = { 
      id: '2', 
      businessId: 'b2',
      url: 'https://secure.example.com/hook', 
      secret: 'test-secret',
      mtlsConfig: {
        clientCertSecretId: 'cert-123',
        clientKeySecretId: 'key-123',
        caPinSecretId: 'ca-123'
      } 
    };

    (secretLoader.get as jest.Mock)
      .mockResolvedValueOnce('mock-cert')
      .mockResolvedValueOnce('mock-key')
      .mockResolvedValueOnce('mock-ca');

    (crypto.X509Certificate as jest.Mock).mockImplementation(() => ({
      validTo: new Date(Date.now() + 86400000).toISOString() // +1 day
    }));

    await sendWebhookDelivery({ subscription: sub, payload: mockPayload });

    expect(secretLoader.get).toHaveBeenCalledTimes(3);
    
    const fetchCallArg = (fetch as unknown as jest.Mock).mock.calls[0][1];
    expect(fetchCallArg.agent).toBeDefined();
    expect(fetchCallArg.agent.options.cert).toBe('mock-cert');
    expect(fetchCallArg.agent.options.ca).toBe('mock-ca');
    expect(fetchCallArg.agent.options.rejectUnauthorized).toBe(true);
  });

  it('should reject delivery if client certificate has expired', async () => {
    const sub: WebhookSubscription = { 
      id: '3', 
      businessId: 'b3',
      url: 'https://secure.example.com/hook', 
      secret: 'test-secret',
      mtlsConfig: {
        clientCertSecretId: 'cert-123',
        clientKeySecretId: 'key-123',
        caPinSecretId: 'ca-123'
      } 
    };

    (secretLoader.get as jest.Mock).mockResolvedValue('mock-pem');

    (crypto.X509Certificate as jest.Mock).mockImplementation(() => ({
      validTo: new Date(Date.now() - 86400000).toISOString() // -1 day
    }));

    await expect(sendWebhookDelivery({ subscription: sub, payload: mockPayload }))
      .rejects
      .toThrow(/Client certificate for subscription 3 expired/);

    expect(fetch).not.toHaveBeenCalled();
    
    expect(createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      action: 'webhook_delivery_rejected',
      metadata: expect.objectContaining({
        reason: 'MTLS_CERT_EXPIRED'
      })
    }));
  });
});