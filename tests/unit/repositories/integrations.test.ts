/**
 * Dedicated behavior coverage for `src/repositories/integrations.ts`.
 *
 * `integrationRepository` is an in-memory store for `ConnectedIntegration`
 * records: it owns id/createdAt generation, the (user, provider) and
 * (business, provider) uniqueness lookups, per-user / per-business listing and
 * deletion. These tests pin that contract, including the negative paths
 * (unknown ids, mismatched provider pairs) and the state transitions the
 * surrounding services rely on.
 *
 * The module keeps a single module-level store, so every test derives fresh
 * user/business ids to stay independent of the others.
 *
 * @module tests/unit/repositories/integrations
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import integrationRepositoryDefault, {
  integrationRepository,
} from '../../../src/repositories/integrations.js';
import type { ConnectedIntegration } from '../../../src/repositories/integrations.js';

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function ids() {
  return {
    userId: `user-${randomUUID()}`,
    businessId: `biz-${randomUUID()}`,
  };
}

function create(
  overrides: Partial<Omit<ConnectedIntegration, 'id' | 'createdAt'>> = {},
): ConnectedIntegration {
  const { userId, businessId } = ids();
  return integrationRepository.create({
    provider: 'stripe',
    userId,
    businessId,
    meta: {},
    ...overrides,
  });
}

describe('integrations repository - module shape', () => {
  it('exposes the same instance as the default and named export', () => {
    expect(integrationRepositoryDefault).toBe(integrationRepository);
  });

  it('exposes the create/find/list/delete surface', () => {
    expect(typeof integrationRepository.create).toBe('function');
    expect(typeof integrationRepository.findById).toBe('function');
    expect(typeof integrationRepository.findByUserAndProvider).toBe('function');
    expect(typeof integrationRepository.findByBusinessAndProvider).toBe('function');
    expect(typeof integrationRepository.listByUser).toBe('function');
    expect(typeof integrationRepository.listByBusiness).toBe('function');
    expect(typeof integrationRepository.deleteById).toBe('function');
  });
});

describe('integrations repository - create', () => {
  it('generates a UUID id and an ISO-8601 createdAt', () => {
    const rec = create();

    expect(rec.id).toMatch(UUID_V4_RE);
    expect(Number.isNaN(Date.parse(rec.createdAt))).toBe(false);
    expect(new Date(rec.createdAt).toISOString()).toBe(rec.createdAt);
  });

  it('echoes every caller-supplied field and makes the record immediately findable', () => {
    const { userId, businessId } = ids();
    const meta = { installedAt: '2026-01-02T03:04:05Z', scopes: ['read'] };

    const rec = integrationRepository.create({ provider: 'shopify', userId, businessId, meta });

    expect(rec).toMatchObject({ provider: 'shopify', userId, businessId, meta });
    expect(integrationRepository.findById(rec.id)).toBe(rec);
  });

  it('keeps the caller meta object by reference (no defensive copy)', () => {
    const meta: Record<string, unknown> = { region: 'eu-west-1' };
    const rec = create({ meta });

    expect(rec.meta).toBe(meta);

    meta.region = 'us-east-1';
    expect(integrationRepository.findById(rec.id)!.meta.region).toBe('us-east-1');
  });

  it('issues unique ids for otherwise identical payloads', () => {
    const { userId, businessId } = ids();

    const a = integrationRepository.create({ provider: 'stripe', userId, businessId, meta: {} });
    const b = integrationRepository.create({ provider: 'stripe', userId, businessId, meta: {} });

    expect(a.id).not.toBe(b.id);
    expect(integrationRepository.findById(a.id)).not.toBeNull();
    expect(integrationRepository.findById(b.id)).not.toBeNull();
  });
});

describe('integrations repository - findById', () => {
  it('returns null for an unknown id and after the record is deleted', () => {
    expect(integrationRepository.findById(`missing-${randomUUID()}`)).toBeNull();

    const rec = create();
    expect(integrationRepository.findById(rec.id)).toBe(rec);

    expect(integrationRepository.deleteById(rec.id)).toBe(true);
    expect(integrationRepository.findById(rec.id)).toBeNull();
  });

  it('treats an empty-string id as unknown rather than throwing', () => {
    expect(integrationRepository.findById('')).toBeNull();
  });
});

describe('integrations repository - provider lookups', () => {
  it('requires both the user and the provider to match', () => {
    const { userId, businessId } = ids();
    const rec = integrationRepository.create({
      provider: 'stripe',
      userId,
      businessId,
      meta: {},
    });

    expect(integrationRepository.findByUserAndProvider(userId, 'stripe')).toBe(rec);
    expect(integrationRepository.findByUserAndProvider(userId, 'paypal')).toBeNull();
    expect(integrationRepository.findByUserAndProvider(`other-${userId}`, 'stripe')).toBeNull();
    expect(integrationRepository.findByUserAndProvider('', 'stripe')).toBeNull();
  });

  it('requires both the business and the provider to match', () => {
    const { userId, businessId } = ids();
    const rec = integrationRepository.create({
      provider: 'shopify',
      userId,
      businessId,
      meta: {},
    });

    expect(integrationRepository.findByBusinessAndProvider(businessId, 'shopify')).toBe(rec);
    expect(integrationRepository.findByBusinessAndProvider(businessId, 'stripe')).toBeNull();
    expect(integrationRepository.findByBusinessAndProvider(`other-${businessId}`, 'shopify')).toBeNull();
  });

  it('is case-sensitive on the provider value', () => {
    const { userId, businessId } = ids();
    integrationRepository.create({ provider: 'Stripe', userId, businessId, meta: {} });

    expect(integrationRepository.findByUserAndProvider(userId, 'stripe')).toBeNull();
    expect(integrationRepository.findByUserAndProvider(userId, 'Stripe')).not.toBeNull();
  });

  it('resolves the first record when a user connects the same provider twice', () => {
    const { userId, businessId } = ids();
    const first = integrationRepository.create({ provider: 'stripe', userId, businessId, meta: {} });
    const second = integrationRepository.create({ provider: 'stripe', userId, businessId, meta: {} });

    expect(second.id).not.toBe(first.id);
    expect(integrationRepository.findByUserAndProvider(userId, 'stripe')).toBe(first);
  });
});

describe('integrations repository - listing', () => {
  it('filters by user and preserves insertion order', () => {
    const { userId, businessId } = ids();
    const other = ids();

    const a = integrationRepository.create({ provider: 'stripe', userId, businessId, meta: {} });
    const b = integrationRepository.create({ provider: 'shopify', userId, businessId, meta: {} });
    integrationRepository.create({ provider: 'stripe', userId: other.userId, businessId: other.businessId, meta: {} });

    expect(integrationRepository.listByUser(userId).map((r) => r.id)).toEqual([a.id, b.id]);
    expect(integrationRepository.listByUser(`unknown-${userId}`)).toEqual([]);
  });

  it('filters by business, including businesses that share a user', () => {
    const { userId } = ids();
    const bizOne = `biz-${randomUUID()}`;
    const bizTwo = `biz-${randomUUID()}`;

    const a = integrationRepository.create({ provider: 'stripe', userId, businessId: bizOne, meta: {} });
    integrationRepository.create({ provider: 'stripe', userId, businessId: bizTwo, meta: {} });

    expect(integrationRepository.listByBusiness(bizOne).map((r) => r.id)).toEqual([a.id]);
    expect(integrationRepository.listByBusiness(bizTwo)).toHaveLength(1);
    expect(integrationRepository.listByBusiness(`unknown-${bizOne}`)).toEqual([]);
  });

  it('returns a fresh array so callers cannot mutate the store', () => {
    const rec = create();
    const listing = integrationRepository.listByUser(rec.userId);

    listing.length = 0;

    expect(integrationRepository.listByUser(rec.userId)).toHaveLength(1);
  });
});

describe('integrations repository - deleteById', () => {
  it('reports false for unknown ids and leaves the store untouched', () => {
    const rec = create();
    const before = integrationRepository.listByUser(rec.userId).length;

    expect(integrationRepository.deleteById(`missing-${randomUUID()}`)).toBe(false);
    expect(integrationRepository.listByUser(rec.userId)).toHaveLength(before);
  });

  it('removes only the addressed record and is idempotent', () => {
    const { userId, businessId } = ids();
    const a = integrationRepository.create({ provider: 'stripe', userId, businessId, meta: {} });
    const b = integrationRepository.create({ provider: 'shopify', userId, businessId, meta: {} });

    expect(integrationRepository.deleteById(a.id)).toBe(true);
    expect(integrationRepository.deleteById(a.id)).toBe(false);

    expect(integrationRepository.listByUser(userId).map((r) => r.id)).toEqual([b.id]);
    expect(integrationRepository.findById(b.id)).toBe(b);
  });

  it('drops the record from both the user and business views', () => {
    const rec = create();

    expect(integrationRepository.listByBusiness(rec.businessId)).toHaveLength(1);
    integrationRepository.deleteById(rec.id);

    expect(integrationRepository.listByBusiness(rec.businessId)).toEqual([]);
    expect(integrationRepository.listByUser(rec.userId)).toEqual([]);
    expect(integrationRepository.findByUserAndProvider(rec.userId, rec.provider)).toBeNull();
    expect(integrationRepository.findByBusinessAndProvider(rec.businessId, rec.provider)).toBeNull();
  });
});
