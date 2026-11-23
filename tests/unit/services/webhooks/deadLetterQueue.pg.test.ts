import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../../../src/db/client.js', () => ({ db: { query: vi.fn() } }))

import { db } from '../../../../src/db/client.js'
import { DeadLetterQueue, saveDeadLetter } from '../../../../src/services/webhooks/deadLetterQueue.js'

describe('dead-letter PostgreSQL access', () => {
  const query = vi.mocked(db.query)

  beforeEach(() => query.mockReset())

  it('persists an event with one parameterized incrementing upsert', async () => {
    query.mockResolvedValue({ rows: [], rowCount: 1 } as any)
    const payload = { event: 'payment.failed' }

    await saveDeadLetter('razorpay', 'evt-1', payload, new Error('failed'), 3)

    expect(query).toHaveBeenCalledTimes(1)
    const [sql, params] = query.mock.calls[0]
    expect(sql).toContain('INSERT INTO webhook_dead_letters')
    expect(sql).toContain('ON CONFLICT (provider, event_id) DO UPDATE')
    expect(sql).toContain('attempt_count = webhook_dead_letters.attempt_count + EXCLUDED.attempt_count')
    expect(sql).toContain('error_code = EXCLUDED.error_code')
    expect(sql).toContain('updated_at = NOW()')
    expect(params).toEqual(['razorpay', 'evt-1', expect.any(String), 'Error', 3])
  })

  it('paginates DLQ entries using the requested page and page size', async () => {
    const row = { id: 11, provider: 'razorpay', event_id: 'evt-11' }
    query
      .mockResolvedValueOnce({ rows: [{ total: '25' }], rowCount: 1 } as any)
      .mockResolvedValueOnce({ rows: [row], rowCount: 1 } as any)

    const result = await new DeadLetterQueue().getEntries({ page: 2, pageSize: 10 })

    expect(result).toEqual({ entries: [row], total: 25 })
    expect(query.mock.calls[0][0]).toContain('COUNT(*)')
    expect(query.mock.calls[1][0]).toContain('ORDER BY created_at DESC LIMIT $1 OFFSET $2')
    expect(query.mock.calls[1][1]).toEqual([10, 10])
  })
})
