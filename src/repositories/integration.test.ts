import { beforeEach, describe, expect, it } from 'vitest';

import {
  clearAll,
  create,
  deleteById,
  getById,
  listByBusinessId,
  listByUserId,
  update,
  type CreateIntegrationData,
} from './integration.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function makeData(overrides: Partial<CreateIntegrationData> = {}): CreateIntegrationData {
  return {
    userId: 'user-1',
    businessId: 'biz-1',
    provider: 'stripe',
    externalId: 'acct_123',
    token: { access: 'tok_1' },
    metadata: { scope: 'read' },
    ...overrides,
  };
}

beforeEach(() => {
  clearAll();
});

describe('integration repository — create', () => {
  it('assigns a UUID id and matching createdAt/updatedAt timestamps', async () => {
    const created = await create(makeData());

    expect(created.id).toMatch(UUID_V4);
    expect(created.createdAt).toBe(created.updatedAt);
    expect(Date.parse(created.createdAt)).not.toBeNaN();
  });

  it('persists every CreateIntegrationData field', async () => {
    const created = await create(makeData());

    expect(created.userId).toBe('user-1');
    expect(created.businessId).toBe('biz-1');
    expect(created.provider).toBe('stripe');
    expect(created.externalId).toBe('acct_123');
    expect(created.token).toEqual({ access: 'tok_1' });
    expect(created.metadata).toEqual({ scope: 'read' });
  });

  it('gives each created record a distinct id', async () => {
    const a = await create(makeData());
    const b = await create(makeData());

    expect(a.id).not.toBe(b.id);
  });

  it('deep-clones the input token/metadata so later caller mutation cannot leak in', async () => {
    const data = makeData({ token: { nested: { access: 'tok' } } });
    const created = await create(data);

    (data.token.nested as { access: string }).access = 'mutated';
    data.metadata.extra = true;

    const stored = await getById(created.id);
    expect(stored?.token).toEqual({ nested: { access: 'tok' } });
    expect(stored?.metadata).toEqual({ scope: 'read' });
  });

  it('returns a copy, not the stored reference', async () => {
    const created = await create(makeData());

    (created.metadata as { scope: string }).scope = 'mutated';

    const stored = await getById(created.id);
    expect(stored?.metadata).toEqual({ scope: 'read' });
  });

  it('accepts empty token and metadata objects', async () => {
    const created = await create(makeData({ token: {}, metadata: {} }));

    expect(created.token).toEqual({});
    expect(created.metadata).toEqual({});
  });
});

describe('integration repository — getById', () => {
  it('returns null for an unknown id', async () => {
    expect(await getById('does-not-exist')).toBeNull();
  });

  it('returns null for an empty id', async () => {
    expect(await getById('')).toBeNull();
  });

  it('returns the record for a known id, as a deep clone', async () => {
    const created = await create(makeData({ token: { nested: { access: 'tok' } } }));

    const first = await getById(created.id);
    const second = await getById(created.id);

    expect(first).toEqual(created);
    expect(first).not.toBe(second);
    (first!.token.nested as { access: string }).access = 'mutated';
    expect((await getById(created.id))?.token).toEqual({ nested: { access: 'tok' } });
  });
});

describe('integration repository — list queries', () => {
  it('returns [] for a user with no integrations', async () => {
    await create(makeData());
    expect(await listByUserId('nobody')).toEqual([]);
  });

  it('returns only the matching user’s integrations', async () => {
    const a = await create(makeData({ userId: 'user-a' }));
    const b = await create(makeData({ userId: 'user-b' }));

    const list = await listByUserId('user-a');

    expect(list).toHaveLength(1);
    expect(list[0].id).toBe(a.id);
    expect(list.some((i) => i.id === b.id)).toBe(false);
  });

  it('returns [] for a business with no integrations', async () => {
    await create(makeData());
    expect(await listByBusinessId('nobody')).toEqual([]);
  });

  it('returns only the matching business’s integrations', async () => {
    const a = await create(makeData({ businessId: 'biz-a' }));
    const b = await create(makeData({ businessId: 'biz-b' }));
    const c = await create(makeData({ businessId: 'biz-a' }));

    const list = await listByBusinessId('biz-a');

    expect(list.map((i) => i.id).sort()).toEqual([a.id, c.id].sort());
    expect(list.some((i) => i.id === b.id)).toBe(false);
  });

  it('hands out clones from list queries (mutations do not leak back)', async () => {
    const created = await create(makeData({ metadata: { scope: 'read' } }));

    const [fromList] = await listByUserId('user-1');
    (fromList.metadata as { scope: string }).scope = 'mutated';

    expect((await getById(created.id))?.metadata).toEqual({ scope: 'read' });
  });
});

describe('integration repository — update', () => {
  it('updates token only when metadata is omitted', async () => {
    const created = await create(makeData({ token: { access: 'old' }, metadata: { scope: 'read' } }));

    const updated = await update('biz-1', created.id, { token: { access: 'new' } });

    expect(updated?.token).toEqual({ access: 'new' });
    expect(updated?.metadata).toEqual({ scope: 'read' });
  });

  it('updates metadata only when token is omitted', async () => {
    const created = await create(makeData({ token: { access: 'old' }, metadata: { scope: 'read' } }));

    const updated = await update('biz-1', created.id, { metadata: { scope: 'write' } });

    expect(updated?.token).toEqual({ access: 'old' });
    expect(updated?.metadata).toEqual({ scope: 'write' });
  });

  it('replaces token/metadata rather than merging them', async () => {
    const created = await create(makeData({ token: { access: 'old', refresh: 'r' } }));

    const updated = await update('biz-1', created.id, { token: { access: 'new' } });

    expect(updated?.token).toEqual({ access: 'new' });
    expect(updated?.token.refresh).toBeUndefined();
  });

  it('advances updatedAt but never createdAt', async () => {
    const created = await create(makeData());
    await new Promise((resolve) => setTimeout(resolve, 5));

    const updated = await update('biz-1', created.id, { metadata: { scope: 'write' } });

    expect(updated?.createdAt).toBe(created.createdAt);
    expect(Date.parse(updated!.updatedAt)).toBeGreaterThanOrEqual(Date.parse(created.updatedAt));
  });

  it('returns null and leaves the record untouched for a mismatched business (cross-tenant)', async () => {
    const created = await create(makeData({ businessId: 'biz-1', token: { access: 'old' } }));

    const result = await update('biz-other', created.id, { token: { access: 'hacked' } });

    expect(result).toBeNull();
    expect((await getById(created.id))?.token).toEqual({ access: 'old' });
  });

  it('returns null for an unknown id', async () => {
    expect(await update('biz-1', 'missing', { metadata: {} })).toBeNull();
  });

  it('is a no-op on token/metadata when given an empty patch', async () => {
    const created = await create(makeData({ token: { access: 'old' }, metadata: { scope: 'read' } }));

    const updated = await update('biz-1', created.id, {});

    expect(updated?.token).toEqual({ access: 'old' });
    expect(updated?.metadata).toEqual({ scope: 'read' });
  });

  it('returns a clone so the caller cannot mutate stored state', async () => {
    const created = await create(makeData());

    const updated = await update('biz-1', created.id, { metadata: { scope: 'write' } });
    (updated!.metadata as { scope: string }).scope = 'mutated';

    expect((await getById(created.id))?.metadata).toEqual({ scope: 'write' });
  });
});

describe('integration repository — deleteById', () => {
  it('deletes a record within the owning business and reports true', async () => {
    const created = await create(makeData({ businessId: 'biz-1' }));

    expect(await deleteById('biz-1', created.id)).toBe(true);
    expect(await getById(created.id)).toBeNull();
    expect(await listByBusinessId('biz-1')).toEqual([]);
  });

  it('refuses to delete across tenant boundaries and leaves the record intact', async () => {
    const created = await create(makeData({ businessId: 'biz-1' }));

    expect(await deleteById('biz-other', created.id)).toBe(false);
    expect(await getById(created.id)).not.toBeNull();
  });

  it('returns false for an unknown id', async () => {
    expect(await deleteById('biz-1', 'missing')).toBe(false);
  });

  it('is idempotent: the second delete of the same id reports false', async () => {
    const created = await create(makeData());

    expect(await deleteById('biz-1', created.id)).toBe(true);
    expect(await deleteById('biz-1', created.id)).toBe(false);
  });
});

describe('integration repository — clearing', () => {
  it('clearAll empties every index', async () => {
    await create(makeData({ userId: 'user-a', businessId: 'biz-a' }));
    await create(makeData({ userId: 'user-b', businessId: 'biz-b' }));

    clearAll();

    expect(await listByUserId('user-a')).toEqual([]);
    expect(await listByBusinessId('biz-b')).toEqual([]);
  });
});
