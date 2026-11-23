/**
 * Focused coverage for the security-sensitive webhook signing-secret storage
 * path in `src/repositories/webhookSubscriptionRepository.ts`.
 *
 * The database and secret loader are mocked so the suite can observe exactly
 * what is handed to PostgreSQL, without requiring a live database or secret
 * provider.
 *
 * @module tests/unit/repositories/webhookSubscriptionRepository
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { mockDbQuery, mockSecretLoaderGet } = vi.hoisted(() => ({
  mockDbQuery: vi.fn(),
  mockSecretLoaderGet: vi.fn(),
}));

vi.mock('../../../src/db/client.js', () => ({
  db: { query: mockDbQuery },
}));

vi.mock('../../../src/utils/secret-loader.js', () => ({
  secretLoader: { get: mockSecretLoaderGet },
}));

import {
  create,
  decryptStoredSecret,
  encryptStoredSecret,
  getById,
  getSigningSecret,
  toPublicSubscription,
  update,
  type WebhookSubscription,
} from '../../../src/repositories/webhookSubscriptionRepository.js';

const BUSINESS_ID = 'biz-webhook-encryption';
const PLAINTEXT_SECRET = `whsec_${'a'.repeat(48)}`;
const ROTATED_SECRET = `whsec_${'b'.repeat(48)}`;
const LEGACY_PLAINTEXT_SECRET = `legacy_whsec_${'c'.repeat(40)}`;
const ENCRYPTION_KEY = 'loader-provided-webhook-encryption-key-0123456789';
const ENV_ENCRYPTION_KEY = 'environment-webhook-encryption-key-0123456789';
const SHORT_KEY = 'short-webhook-key';
const WEBHOOK_URL = 'https://example.com/webhook';

const ORIGINAL_ENCRYPTION_KEY = process.env.WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY;

function rowWithSecret(
  secret: string,
  secretVersion = 1,
): Record<string, unknown> {
  return {
    id: 'wh-1',
    business_id: BUSINESS_ID,
    url: WEBHOOK_URL,
    secret,
    event_filters: { 'attestation.created': true },
    enabled: true,
    max_payload_size: null,
    secret_version: secretVersion,
    mtls_config: null,
    created_at: '2026-10-21T00:00:00.000Z',
    updated_at: '2026-10-21T00:00:00.000Z',
  };
}

function useEnvironmentKey(key: string): void {
  process.env.WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY = key;
  mockSecretLoaderGet.mockImplementation(() => {
    throw new Error('secretLoader must not be consulted when the env key is valid');
  });
}

function useLoaderKey(key: string): void {
  delete process.env.WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY;
  mockSecretLoaderGet.mockReturnValue(key);
}

/** Store whatever the repository passes as the INSERT secret parameter. */
function mockInsertEchoingStoredSecret(): void {
  mockDbQuery.mockImplementation(async (_sql: string, params: unknown[]) => ({
    rows: [rowWithSecret(params[2] as string)],
    rowCount: 1,
  }));
}

function firstQueryParams(): unknown[] {
  expect(mockDbQuery).toHaveBeenCalled();
  return mockDbQuery.mock.calls[0]?.[1] as unknown[];
}

describe('webhookSubscriptionRepository secret encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY;
    mockSecretLoaderGet.mockImplementation(() => {
      throw new Error('Secret not found: WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY');
    });
    mockDbQuery.mockResolvedValue({ rows: [], rowCount: 0 });
  });

  afterEach(() => {
    if (ORIGINAL_ENCRYPTION_KEY === undefined) {
      delete process.env.WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY;
    } else {
      process.env.WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY = ORIGINAL_ENCRYPTION_KEY;
    }
  });

  describe('create()', () => {
    it('writes an encrypted value, never the raw secret, when a 32+ char key is set', async () => {
      useEnvironmentKey(ENV_ENCRYPTION_KEY);
      mockInsertEchoingStoredSecret();

      const created = await create(BUSINESS_ID, {
        url: WEBHOOK_URL,
        secret: PLAINTEXT_SECRET,
        enabled: true,
      });

      const [sql] = mockDbQuery.mock.calls[0] as [string, unknown[]];
      const storedSecret = firstQueryParams()[2] as string;

      expect(sql).toContain('INSERT INTO webhook_subscriptions');
      expect(storedSecret).toMatch(/^enc:v1:[^:]+:[^:]+$/);
      expect(storedSecret).not.toBe(PLAINTEXT_SECRET);
      expect(storedSecret).not.toContain(PLAINTEXT_SECRET);
      expect(created.url).toBe(WEBHOOK_URL);
      expect(mockSecretLoaderGet).not.toHaveBeenCalled();
    });

    it('round-trips the stored ciphertext back to the plaintext secret', async () => {
      useLoaderKey(ENCRYPTION_KEY);
      mockInsertEchoingStoredSecret();

      const created = await create(BUSINESS_ID, {
        url: WEBHOOK_URL,
        secret: PLAINTEXT_SECRET,
        enabled: true,
      });

      const storedSecret = firstQueryParams()[2] as string;

      expect(mockSecretLoaderGet).toHaveBeenCalledWith(
        'WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY',
      );
      expect(storedSecret).not.toBe(PLAINTEXT_SECRET);
      expect(decryptStoredSecret(storedSecret)).toBe(PLAINTEXT_SECRET);
      expect(created.secret).toBe(PLAINTEXT_SECRET);
    });

    it('keeps the legacy plaintext format when the configured key is shorter than 32 chars', async () => {
      useEnvironmentKey(SHORT_KEY);
      mockInsertEchoingStoredSecret();

      const created = await create(BUSINESS_ID, {
        url: WEBHOOK_URL,
        secret: PLAINTEXT_SECRET,
        enabled: true,
      });

      const storedSecret = firstQueryParams()[2] as string;

      expect(storedSecret).toBe(PLAINTEXT_SECRET);
      expect(decryptStoredSecret(storedSecret)).toBe(PLAINTEXT_SECRET);
      expect(created.secret).toBe(PLAINTEXT_SECRET);
    });

    it('ignores a short key supplied by the secret loader as well', () => {
      useLoaderKey(SHORT_KEY);

      expect(encryptStoredSecret(PLAINTEXT_SECRET)).toBe(PLAINTEXT_SECRET);
      expect(decryptStoredSecret(PLAINTEXT_SECRET)).toBe(PLAINTEXT_SECRET);
    });
  });

  describe('update()', () => {
    it('encrypts a rotated secret and stores it instead of the raw value', async () => {
      useLoaderKey(ENCRYPTION_KEY);
      mockDbQuery.mockImplementation(async (_sql: string, params: unknown[]) => ({
        rows: [rowWithSecret(params[0] as string, 2)],
        rowCount: 1,
      }));

      const updated = await update('wh-1', BUSINESS_ID, { secret: ROTATED_SECRET });

      const [sql, params] = mockDbQuery.mock.calls[0] as [string, unknown[]];
      const storedSecret = params[0] as string;

      expect(sql).toContain('UPDATE webhook_subscriptions');
      expect(sql).toContain('secret_version = secret_version + 1');
      expect(storedSecret).not.toBe(ROTATED_SECRET);
      expect(storedSecret).not.toContain(ROTATED_SECRET);
      expect(decryptStoredSecret(storedSecret)).toBe(ROTATED_SECRET);
      expect(updated?.secret).toBe(ROTATED_SECRET);
      expect(updated?.secretVersion).toBe(2);
    });
  });

  describe('legacy plaintext rows', () => {
    it('remain readable through getById() and getSigningSecret() when a key is configured', async () => {
      useEnvironmentKey(ENV_ENCRYPTION_KEY);
      mockDbQuery.mockResolvedValue({
        rows: [rowWithSecret(LEGACY_PLAINTEXT_SECRET)],
        rowCount: 1,
      });

      const subscription = await getById('wh-1', BUSINESS_ID);
      const signingSecret = await getSigningSecret('wh-1', BUSINESS_ID);

      expect(decryptStoredSecret(LEGACY_PLAINTEXT_SECRET)).toBe(
        LEGACY_PLAINTEXT_SECRET,
      );
      expect(subscription?.secret).toBe(LEGACY_PLAINTEXT_SECRET);
      expect(signingSecret).toBe(LEGACY_PLAINTEXT_SECRET);
    });
  });

  describe('toPublicSubscription()', () => {
    it('exposes only secretLast4 and never the secret itself', () => {
      const subscription: WebhookSubscription = {
        id: 'wh-1',
        businessId: BUSINESS_ID,
        url: WEBHOOK_URL,
        secret: PLAINTEXT_SECRET,
        eventFilters: { 'attestation.created': true },
        enabled: true,
        maxPayloadSize: 4096,
        secretVersion: 3,
        mtlsConfig: null,
        createdAt: new Date('2026-10-21T00:00:00.000Z'),
        updatedAt: new Date('2026-10-22T00:00:00.000Z'),
      };

      const publicSubscription = toPublicSubscription(subscription);

      expect(Object.keys(publicSubscription)).not.toContain('secret');
      expect(Object.keys(publicSubscription)).toContain('secretLast4');
      expect(publicSubscription.secretLast4).toBe(PLAINTEXT_SECRET.slice(-4));
      expect(JSON.stringify(publicSubscription)).not.toContain(PLAINTEXT_SECRET);
      expect(publicSubscription).toEqual({
        id: subscription.id,
        businessId: subscription.businessId,
        url: subscription.url,
        eventFilters: subscription.eventFilters,
        enabled: subscription.enabled,
        maxPayloadSize: subscription.maxPayloadSize,
        secretVersion: subscription.secretVersion,
        secretLast4: PLAINTEXT_SECRET.slice(-4),
        mtlsConfig: subscription.mtlsConfig,
        createdAt: subscription.createdAt,
        updatedAt: subscription.updatedAt,
      });
    });

    it('reports no last four digits when the secret is empty', () => {
      const subscription: WebhookSubscription = {
        id: 'wh-1',
        businessId: BUSINESS_ID,
        url: WEBHOOK_URL,
        secret: '',
        eventFilters: {},
        enabled: true,
        maxPayloadSize: null,
        secretVersion: 1,
        mtlsConfig: null,
        createdAt: new Date('2026-10-21T00:00:00.000Z'),
        updatedAt: new Date('2026-10-21T00:00:00.000Z'),
      };

      expect(toPublicSubscription(subscription).secretLast4).toBeNull();
    });
  });
});
