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

    // -----------------------------------------------------------------------
    // from > to: exact boundary
    // -----------------------------------------------------------------------

    it('throws TimeWindowError when from is one month after to', () => {
      expect(() => getRevenueReport('biz_1', undefined, '2025-06', '2025-05')).toThrow(TimeWindowError)
      expect(() => getRevenueReport('biz_1', undefined, '2025-06', '2025-05')).toThrow(
        /"from" \(2025-06\) must not be later than "to" \(2025-05\)/,
      )
    })

    it('throws TimeWindowError when from is one year after to', () => {
      expect(() => getRevenueReport('biz_1', undefined, '2026-01', '2025-01')).toThrow(TimeWindowError)
      expect(() => getRevenueReport('biz_1', undefined, '2026-01', '2025-01')).toThrow(
        /"from" \(2026-01\) must not be later than "to" \(2025-01\)/,
      )
    })

    // -----------------------------------------------------------------------
    // from === to: single-month range
    // -----------------------------------------------------------------------

    it('accepts a range where from equals to (one-month window)', () => {
      expect(getRevenueReport('biz_1', undefined, '2025-11', '2025-11')).toEqual({
        period: '2025-11 to 2025-11',
        total: 100,
        net: 95,
        currency: 'USD',
        breakdown: [{ attestationId: 'att_nov', attestedAt: '2025-12-01T00:00:00.000Z' }],
      })
    })

    // -----------------------------------------------------------------------
    // Max window boundaries
    // -----------------------------------------------------------------------

    it('rejects a window of exactly 25 months with the count in the message', () => {
      listByBusiness.mockReturnValue([])
      expect(() => getRevenueReport('biz_1', undefined, '2023-12', '2025-12')).toThrow(TimeWindowError)
      expect(() => getRevenueReport('biz_1', undefined, '2023-12', '2025-12')).toThrow(
        /25 months exceeds the maximum allowed window of 24 months/,
      )
    })

    it('rejects a window of 36 months with the correct count in the message', () => {
      listByBusiness.mockReturnValue([])
      expect(() => getRevenueReport('biz_1', undefined, '2023-01', '2025-12')).toThrow(TimeWindowError)
      expect(() => getRevenueReport('biz_1', undefined, '2023-01', '2025-12')).toThrow(
        /36 months exceeds the maximum allowed window of 24 months/,
      )
    })

    // -----------------------------------------------------------------------
    // No-data paths returning null
    // -----------------------------------------------------------------------

    it('returns null for a period that has no matching attestations in a mock returning no records', () => {
      listByBusiness.mockReturnValue([])
      expect(getRevenueReport('biz_1', '2025-11')).toBeNull()
    })

    it('returns null for a range that spans real months but has no matching attestations', () => {
      listByBusiness.mockReturnValue([])
      expect(getRevenueReport('biz_1', undefined, '2020-01', '2020-12')).toBeNull()
    })

    it('returns null when the period predates all attestations', () => {
      expect(getRevenueReport('biz_1', '2024-01')).toBeNull()
    })

    // -----------------------------------------------------------------------
    // Month-boundary UTC cases
    // -----------------------------------------------------------------------

    it('correctly includes an attestation on the first day of the from-month', () => {
      // att_oct has period '2025-10'; range starts at 2025-10
      expect(getRevenueReport('biz_1', undefined, '2025-10', '2025-10')).toEqual({
        period: '2025-10 to 2025-10',
        total: 100,
        net: 95,
        currency: 'USD',
        breakdown: [{ attestationId: 'att_oct', attestedAt: '2025-11-01T00:00:00.000Z' }],
      })
    })

    it('correctly includes an attestation on the last month of the to-month', () => {
      // att_dec has period '2025-12'; range ends at 2025-12
      expect(getRevenueReport('biz_1', undefined, '2025-12', '2025-12')).toEqual({
        period: '2025-12 to 2025-12',
        total: 100,
        net: 95,
        currency: 'USD',
        breakdown: [{ attestationId: 'att_dec', attestedAt: '2026-01-01T00:00:00.000Z' }],
      })
    })

    it('excludes attestations that fall outside the from/to range on exact boundaries', () => {
      // Only 2025-11 should be included, not 2025-10 or 2025-12
      const result = getRevenueReport('biz_1', undefined, '2025-11', '2025-11')
      expect(result?.breakdown).toHaveLength(1)
      expect(result?.breakdown[0].attestationId).toBe('att_nov')
    })

    it('handles year-rollover month boundaries correctly (Dec to Jan)', () => {
      listByBusiness.mockReturnValue([
        { id: 'att_jan', businessId: 'biz_1', period: '2026-01', attestedAt: '2026-02-01T00:00:00.000Z' },
      ])
      expect(getRevenueReport('biz_1', undefined, '2025-12', '2026-01')).toEqual({
        period: '2025-12 to 2026-01',
        total: 100,
        net: 95,
        currency: 'USD',
        breakdown: [{ attestationId: 'att_jan', attestedAt: '2026-02-01T00:00:00.000Z' }],
      })
    })

    // -----------------------------------------------------------------------
    // Breakdown ordering and totals for multi-attestation periods
    // -----------------------------------------------------------------------

    it('aggregates multiple attestations in the same period with correct total and net', () => {
      listByBusiness.mockReturnValue([
        { id: 'att_nov_1', businessId: 'biz_1', period: '2025-11', attestedAt: '2025-11-10T00:00:00.000Z' },
        { id: 'att_nov_2', businessId: 'biz_1', period: '2025-11', attestedAt: '2025-11-20T00:00:00.000Z' },
        { id: 'att_nov_3', businessId: 'biz_1', period: '2025-11', attestedAt: '2025-11-30T00:00:00.000Z' },
      ])
      const result = getRevenueReport('biz_1', '2025-11')
      expect(result).not.toBeNull()
      expect(result!.total).toBe(300)       // 3 × 100
      expect(result!.net).toBe(285)         // Math.round(300 * 0.95)
      expect(result!.currency).toBe('USD')
      expect(result!.breakdown).toHaveLength(3)
    })

    it('preserves the repository-returned order in the breakdown array', () => {
      listByBusiness.mockReturnValue([
        { id: 'att_z', businessId: 'biz_1', period: '2025-11', attestedAt: '2025-11-30T00:00:00.000Z' },
        { id: 'att_a', businessId: 'biz_1', period: '2025-11', attestedAt: '2025-11-01T00:00:00.000Z' },
      ])
      const result = getRevenueReport('biz_1', '2025-11')
      expect(result!.breakdown[0].attestationId).toBe('att_z')
      expect(result!.breakdown[1].attestationId).toBe('att_a')
    })

    it('computes total and net correctly for a range spanning multiple months with multiple attestations', () => {
      listByBusiness.mockReturnValue([
        { id: 'att_1', businessId: 'biz_1', period: '2025-10', attestedAt: '2025-10-15T00:00:00.000Z' },
        { id: 'att_2', businessId: 'biz_1', period: '2025-10', attestedAt: '2025-10-20T00:00:00.000Z' },
        { id: 'att_3', businessId: 'biz_1', period: '2025-11', attestedAt: '2025-11-05T00:00:00.000Z' },
      ])
      const result = getRevenueReport('biz_1', undefined, '2025-10', '2025-11')
      expect(result).not.toBeNull()
      expect(result!.total).toBe(300)
      expect(result!.net).toBe(285)
      expect(result!.breakdown).toHaveLength(3)
      expect(result!.period).toBe('2025-10 to 2025-11')
    })

    it('breakdown includes attestedAt exactly as stored without mutation', () => {
      const isoTs = '2025-11-15T12:34:56.789Z'
      listByBusiness.mockReturnValue([
        { id: 'att_precise', businessId: 'biz_1', period: '2025-11', attestedAt: isoTs },
      ])
      const result = getRevenueReport('biz_1', '2025-11')
      expect(result!.breakdown[0].attestedAt).toBe(isoTs)
    })

    // -----------------------------------------------------------------------
    // Non-UTC timezone: service uses string comparison for period filtering,
    // so TZ should have no effect on report output.
    // -----------------------------------------------------------------------

    it('produces identical results regardless of the process TZ (UTC vs America/New_York)', () => {
      const originalTz = process.env.TZ

      listByBusiness.mockReturnValue(records.filter((r) => r.businessId === 'biz_1'))
      process.env.TZ = 'UTC'
      const utcResult = getRevenueReport('biz_1', undefined, '2025-11', '2025-12')

      listByBusiness.mockReturnValue(records.filter((r) => r.businessId === 'biz_1'))
      process.env.TZ = 'America/New_York'
      const nyResult = getRevenueReport('biz_1', undefined, '2025-11', '2025-12')

      process.env.TZ = originalTz

      expect(utcResult).toEqual(nyResult)
    })

    it('produces identical results regardless of the process TZ (UTC vs Asia/Tokyo)', () => {
      const originalTz = process.env.TZ

      listByBusiness.mockReturnValue(records.filter((r) => r.businessId === 'biz_1'))
      process.env.TZ = 'UTC'
      const utcResult = getRevenueReport('biz_1', '2025-11')

      listByBusiness.mockReturnValue(records.filter((r) => r.businessId === 'biz_1'))
      process.env.TZ = 'Asia/Tokyo'
      const tokyoResult = getRevenueReport('biz_1', '2025-11')

      process.env.TZ = originalTz

      expect(utcResult).toEqual(tokyoResult)
    })

    // -----------------------------------------------------------------------
    // Invalid date inputs via schema rejection
    // -----------------------------------------------------------------------

    it('throws TimeWindowError for a period with single-digit month (schema rejects before service)', () => {
      expect(() => getRevenueReport('biz_1', '2025-9')).toThrow(TimeWindowError)
    })

    it('throws TimeWindowError for a period with an out-of-range year (schema rejects year < 2020)', () => {
      expect(() => getRevenueReport('biz_1', '2019-01')).toThrow(TimeWindowError)
    })

    it('throws TimeWindowError for a period with an out-of-range year (schema rejects year > 2105)', () => {
      expect(() => getRevenueReport('biz_1', '2106-01')).toThrow(TimeWindowError)
    })

    it('throws TimeWindowError for a from date with invalid day separator', () => {
      expect(() => getRevenueReport('biz_1', undefined, '2025.11', '2025-12')).toThrow(TimeWindowError)
    })

    it('throws TimeWindowError when both period and from/to are supplied simultaneously', () => {
      // Schema-level refine: period + range is not allowed
      expect(() => getRevenueReport('biz_1', '2025-11', '2025-11', '2025-12')).toThrow(TimeWindowError)
    })
  })
})
