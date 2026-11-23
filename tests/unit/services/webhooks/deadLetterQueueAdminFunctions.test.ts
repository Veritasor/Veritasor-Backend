import { beforeEach, describe, expect, it, vi } from 'vitest';
import fc from 'fast-check';

vi.mock('../../../../src/db/client.js', () => ({
  db: {
    query: vi.fn(),
  },
}));

import { db } from '../../../../src/db/client.js';
import {
  computePayloadHash,
  deleteDeadLetter,
  getDeadLetter,
  isQuarantined,
  listDeadLetterShards,
  listQuarantinedLetters,
  purgeQuarantinedLetter,
  releaseQuarantinedLetter,
} from '../../../../src/services/webhooks/deadLetterQueue.js';

describe('dead-letter admin functions', () => {
  const mockQuery = vi.mocked(db.query);

  beforeEach(() => {
    mockQuery.mockReset();
  });

  it('hashes JSON payloads deterministically regardless of recursively shuffled keys', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.string(), { minLength: 1, maxLength: 8 }),
        fc.array(fc.jsonValue(), { minLength: 1, maxLength: 8 }),
        (keys, values) => {
          const entries = keys.map((key, index) => [key, values[index % values.length]] as const);
          const originalOrder = Object.fromEntries(entries);
          const shuffledOrder = Object.fromEntries([...entries].reverse());

          expect(computePayloadHash(originalOrder)).toBe(computePayloadHash(shuffledOrder));
        },
      ),
    );
  });

  it('gets a dead letter by provider and event ID and returns null when absent', async () => {
    const row = {
      id: 12,
      provider: 'razorpay',
      event_id: 'evt_12',
      payload_hash: 'hash',
      error_code: 'Failure',
      attempt_count: 2,
      integration: 'razorpay',
      created_at: new Date(),
      updated_at: new Date(),
    };
    mockQuery.mockResolvedValueOnce({ rows: [row], rowCount: 1 } as never);

    await expect(getDeadLetter('razorpay', 'evt_12')).resolves.toEqual(row);
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('FROM webhook_dead_letters'),
      ['razorpay', 'evt_12'],
    );

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as never);
    await expect(getDeadLetter('razorpay', 'missing')).resolves.toBeNull();
  });

  it('deletes a dead letter with parameterized provider and event ID', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 } as never);

    await deleteDeadLetter('razorpay', 'evt_12');

    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('DELETE FROM webhook_dead_letters'),
      ['razorpay', 'evt_12'],
    );
  });

  it('checks only active quarantine entries', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ exists: true }], rowCount: 1 } as never);
    await expect(isQuarantined('razorpay', 'evt_12')).resolves.toBe(true);
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('released_at IS NULL'),
      ['razorpay', 'evt_12'],
    );

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as never);
    await expect(isQuarantined('razorpay', 'released')).resolves.toBe(false);
  });

  it('lists active quarantines with optional parameterized filters', async () => {
    const rows = [{ provider: 'razorpay', event_id: 'evt_12', integration: 'payments' }];
    mockQuery.mockResolvedValueOnce({ rows, rowCount: 1 } as never);

    await expect(listQuarantinedLetters('razorpay', 'payments')).resolves.toEqual(rows);
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('provider = $1 AND integration = $2'),
      ['razorpay', 'payments'],
    );

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as never);
    await expect(listQuarantinedLetters()).resolves.toEqual([]);
    expect(mockQuery).toHaveBeenLastCalledWith(
      expect.stringContaining('released_at IS NULL'),
      [],
    );
  });

  it('releases an active quarantine once and returns false for already released or missing rows', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 4 }], rowCount: 1 } as never);

    await expect(releaseQuarantinedLetter('razorpay', 'evt_12', 'admin-1')).resolves.toBe(true);
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('released_by = $3'),
      ['razorpay', 'evt_12', 'admin-1'],
    );

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as never);
    await expect(releaseQuarantinedLetter('razorpay', 'evt_12', 'admin-1')).resolves.toBe(false);
  });

  it('purges a quarantine entry and returns false when no row matches', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 4 }], rowCount: 1 } as never);

    await expect(purgeQuarantinedLetter('razorpay', 'evt_12')).resolves.toBe(true);
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('DELETE FROM webhook_quarantine'),
      ['razorpay', 'evt_12'],
    );

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as never);
    await expect(purgeQuarantinedLetter('razorpay', 'missing')).resolves.toBe(false);
  });

  it('lists dead-letter shards with grouped counts', async () => {
    const rows = [{ integration: 'razorpay', count: 2 }];
    mockQuery.mockResolvedValueOnce({ rows, rowCount: 1 } as never);

    await expect(listDeadLetterShards()).resolves.toEqual(rows);
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('GROUP BY integration'),
    );
  });
});
