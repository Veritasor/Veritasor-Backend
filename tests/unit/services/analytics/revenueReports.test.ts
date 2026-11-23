import { beforeEach, describe, expect, it, vi } from 'vitest'

const { listByBusinessAndRange } = vi.hoisted(() => ({ listByBusinessAndRange: vi.fn() }))

vi.mock('../../../../src/repositories/revenueSnapshotRepository.js', () => ({
  revenueSnapshotRepository: { listByBusinessAndRange },
}))

import { getRevenueReport, TimeWindowError } from '../../../../src/services/analytics/revenueReports.js'
import type { RevenueSnapshot } from '../../../../src/repositories/revenueSnapshotRepository.js'

/** Snapshot rows as they would be read back from `revenue_snapshots`. */
const snapshots: RevenueSnapshot[] = [
  { id: 'snap_oct', businessId: 'biz_1', period: '2025-10', totalRevenue: 1000, netRevenue: 950, currency: 'USD', createdAt: '2025-11-01T00:00:00.000Z' },
  { id: 'snap_nov', businessId: 'biz_1', period: '2025-11', totalRevenue: 1200, netRevenue: 1140, currency: 'USD', createdAt: '2025-12-01T00:00:00.000Z' },
  { id: 'snap_dec', businessId: 'biz_1', period: '2025-12', totalRevenue: 1300, netRevenue: 1235, currency: 'USD', createdAt: '2026-01-01T00:00:00.000Z' },
  { id: 'snap_other_business', businessId: 'biz_2', period: '2025-11', totalRevenue: 99999, netRevenue: 99999, currency: 'USD', createdAt: '2025-12-02T00:00:00.000Z' },
]

describe('revenueReports', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    // Emulate the repository contract: filter by business and inclusive period window.
    listByBusinessAndRange.mockImplementation(
      (businessId: string, start: string, end: string) =>
        Promise.resolve(
          snapshots.filter(
            (snapshot) => snapshot.businessId === businessId && snapshot.period >= start && snapshot.period <= end,
          ),
        ),
    )
  })

  describe('TimeWindowError', () => {
    it('exposes a stable name and code while preserving the message', () => {
      const error = new TimeWindowError('invalid window')

      expect(error).toBeInstanceOf(Error)
      expect(error.name).toBe('TimeWindowError')
      expect(error.code).toBe('INVALID_TIME_WINDOW')
      expect(error.message).toBe('invalid window')
    })
  })

  describe('getRevenueReport', () => {
    it('reads the window from revenueSnapshotRepository and aggregates the snapshot rows', async () => {
      const report = await getRevenueReport('biz_1', '2025-11')

      expect(report).toEqual({
        period: '2025-11',
        total: 1200,
        net: 1140,
        currency: 'USD',
        breakdown: [{ attestationId: 'snap_nov', attestedAt: '2025-12-01T00:00:00.000Z' }],
      })
      expect(listByBusinessAndRange).toHaveBeenCalledWith('biz_1', '2025-11', '2025-11')
    })

    it('returns an inclusive range report without including another business', async () => {
      listByBusinessAndRange.mockResolvedValue([
        snapshots.find((s) => s.id === 'snap_nov')!,
        snapshots.find((s) => s.id === 'snap_dec')!,
      ])

      expect(await getRevenueReport('biz_1', undefined, '2025-11', '2025-12')).toEqual({
        period: '2025-11 to 2025-12',
        total: 2500,
        net: 2375,
        currency: 'USD',
        breakdown: [
          { attestationId: 'snap_nov', attestedAt: '2025-12-01T00:00:00.000Z' },
          { attestationId: 'snap_dec', attestedAt: '2026-01-01T00:00:00.000Z' },
        ],
      })
      expect(listByBusinessAndRange).toHaveBeenCalledWith('biz_1', '2025-11', '2025-12')
    })

    it('accepts the 24 month maximum range and rejects a 25 month range', async () => {
      listByBusinessAndRange.mockResolvedValue([])
      expect(await getRevenueReport('biz_1', undefined, '2024-01', '2025-12')).toBeNull()
      await expect(getRevenueReport('biz_1', undefined, '2024-01', '2026-01'))
        .rejects.toThrow(/25 months exceeds the maximum allowed window of 24 months/)
    })

    it('returns null when no snapshot rows exist for the window', async () => {
      listByBusinessAndRange.mockResolvedValue([])
      await expect(getRevenueReport('biz_1', '2026-01')).resolves.toBeNull()
    })

    it.each([
      ['missing query mode', () => getRevenueReport('biz_1'), /Provide either/],
      ['malformed period', () => getRevenueReport('biz_1', '2025/11'), /YYYY-MM/],
      ['invalid from month', () => getRevenueReport('biz_1', undefined, '2025-13', '2025-12'), /YYYY-MM/],
      ['invalid to format', () => getRevenueReport('biz_1', undefined, '2025-11', '2025-1'), /exactly 7 characters/],
      ['incomplete range', () => getRevenueReport('biz_1', undefined, '2025-11'), /Provide either/],
      ['reversed range', () => getRevenueReport('biz_1', undefined, '2025-12', '2025-11'), /must not be later/],
    ])('throws TimeWindowError for %s', async (_case, invoke, message) => {
      await expect(invoke()).rejects.toThrow(TimeWindowError)
      await expect(invoke()).rejects.toThrow(message)
    })
  })
})
