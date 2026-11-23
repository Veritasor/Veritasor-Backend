import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  revenueSnapshotRepository,
  type RevenueSnapshot,
  type RevenueSnapshotInput,
} from '../../../src/repositories/revenueSnapshotRepository.js'

const { mockDb } = vi.hoisted(() => ({
  mockDb: {
    query: vi.fn(),
  },
}))

vi.mock('../../../src/db/client.js', () => ({ db: mockDb }))

const INPUT: RevenueSnapshotInput = {
  businessId: 'biz-1',
  period: '2025-11',
  totalRevenue: 1234.56,
  netRevenue: 1170.79,
  currency: 'USD',
}

const MAPPED: RevenueSnapshot = {
  id: 'snap-1',
  businessId: 'biz-1',
  period: '2025-11',
  totalRevenue: 1234.56,
  netRevenue: 1170.79,
  currency: 'USD',
  createdAt: '2025-12-01T00:00:00.000Z',
}

/** Build a raw `revenue_snapshots` row (snake_case columns, NUMERIC as string). */
function makeRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'snap-1',
    business_id: 'biz-1',
    period: '2025-11',
    total_revenue: '1234.56',
    net_revenue: '1170.79',
    currency: 'USD',
    created_at: '2025-12-01T00:00:00.000Z',
    ...overrides,
  }
}

describe('revenueSnapshotRepository', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('upsert', () => {
    it('issues a parameterized INSERT ... ON CONFLICT ... RETURNING and maps the row to camelCase', async () => {
      mockDb.query.mockResolvedValue({ rows: [makeRow()] })

      const snapshot = await revenueSnapshotRepository.upsert(INPUT)

      expect(mockDb.query).toHaveBeenCalledTimes(1)
      const [sql, params] = mockDb.query.mock.calls[0] as [string, unknown[]]

      expect(sql).toContain(
        'INSERT INTO revenue_snapshots (business_id, period, total_revenue, net_revenue, currency)',
      )
      expect(sql).toContain('VALUES ($1, $2, $3, $4, $5)')
      expect(sql).toContain('ON CONFLICT (business_id, period)')
      expect(sql).toMatch(/DO UPDATE SET\s+total_revenue = EXCLUDED\.total_revenue/)
      expect(sql).toMatch(/net_revenue = EXCLUDED\.net_revenue/)
      expect(sql).toMatch(/currency = EXCLUDED\.currency/)
      expect(sql).toContain('RETURNING *')

      expect(params).toEqual(['biz-1', '2025-11', 1234.56, 1170.79, 'USD'])

      // Values are bound parameters — they must not appear in the SQL text.
      expect(sql).not.toContain('biz-1')
      expect(sql).not.toContain('2025-11')
      expect(sql).not.toContain('1234.56')

      expect(snapshot).toEqual(MAPPED)
    })

    it('throws when the statement returns no rows', async () => {
      mockDb.query.mockResolvedValue({ rows: [] })

      await expect(revenueSnapshotRepository.upsert(INPUT)).rejects.toThrow(/no rows returned/)
    })

    it('coerces NUMERIC columns (string from pg) to numbers', async () => {
      mockDb.query.mockResolvedValue({ rows: [makeRow({ total_revenue: '0', net_revenue: '0' })] })

      const snapshot = await revenueSnapshotRepository.upsert(INPUT)

      expect(snapshot.totalRevenue).toBe(0)
      expect(snapshot.netRevenue).toBe(0)
    })
  })

  describe('listByBusinessAndRange', () => {
    it('issues a parameterized WHERE business_id = $1 AND period >= $2 AND period <= $3 with ORDER BY', async () => {
      mockDb.query.mockResolvedValue({ rows: [makeRow(), makeRow({ id: 'snap-2', period: '2025-12' })] })

      const snapshots = await revenueSnapshotRepository.listByBusinessAndRange('biz-1', '2025-11', '2025-12')

      expect(mockDb.query).toHaveBeenCalledTimes(1)
      const [sql, params] = mockDb.query.mock.calls[0] as [string, unknown[]]

      expect(sql).toContain('FROM revenue_snapshots')
      expect(sql).toMatch(/WHERE business_id = \$1/)
      expect(sql).toMatch(/AND period >= \$2/)
      expect(sql).toMatch(/AND period <= \$3/)
      expect(sql).toMatch(/ORDER BY/)

      expect(params).toEqual(['biz-1', '2025-11', '2025-12'])

      // Values are bound parameters — they must not appear in the SQL text.
      expect(sql).not.toContain('biz-1')
      expect(sql).not.toContain('2025-11')
      expect(sql).not.toContain('2025-12')

      expect(snapshots).toHaveLength(2)
      expect(snapshots[0]).toEqual(MAPPED)
      expect(snapshots[1]).toEqual({ ...MAPPED, id: 'snap-2', period: '2025-12' })
    })

    it('returns an empty array when no rows match the window', async () => {
      mockDb.query.mockResolvedValue({ rows: [] })

      const snapshots = await revenueSnapshotRepository.listByBusinessAndRange('biz-1', '2025-11', '2025-12')

      expect(snapshots).toEqual([])
    })
  })
})
