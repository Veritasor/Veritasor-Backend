import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dbQuery = vi.hoisted(() => vi.fn());

vi.mock('../../../../src/db/client.js', () => ({
  db: { query: dbQuery },
}));

import { resolveBusinessIdForUser } from '../../../../src/services/business/resolveBusiness.js';

const USER_ID = 'user-1';

beforeEach(() => {
  dbQuery.mockReset();
});

afterEach(() => {
  dbQuery.mockReset();
});

describe('resolveBusinessIdForUser', () => {
  it('returns the business id from the matching row', async () => {
    dbQuery.mockResolvedValue({ rows: [{ id: 'biz-123' }] });

    await expect(resolveBusinessIdForUser(USER_ID)).resolves.toBe('biz-123');

    expect(dbQuery).toHaveBeenCalledTimes(1);
  });

  it('returns null when no rows match the user', async () => {
    dbQuery.mockResolvedValue({ rows: [] });

    await expect(resolveBusinessIdForUser(USER_ID)).resolves.toBeNull();

    expect(dbQuery).toHaveBeenCalledTimes(1);
  });

  it('uses a bind parameter and deterministic ordering', async () => {
    dbQuery.mockResolvedValue({ rows: [{ id: 'biz-123' }] });

    await resolveBusinessIdForUser(USER_ID);

    expect(dbQuery).toHaveBeenCalledTimes(1);

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]];

    expect(sql).toContain('$1');
    expect(sql).not.toContain(USER_ID);
    expect(params).toEqual([USER_ID]);

    const normalizedSql = sql.replace(/\s+/g, ' ').trim().toUpperCase();
    expect(normalizedSql).toContain('ORDER BY CREATED_AT ASC, ID ASC');
  });

  it('propagates database errors', async () => {
    dbQuery.mockRejectedValue(new Error('connection lost'));

    await expect(resolveBusinessIdForUser(USER_ID)).rejects.toThrow('connection lost');
  });
});
