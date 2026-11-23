import { beforeEach, describe, expect, it, vi } from 'vitest'

const { listByBusiness } = vi.hoisted(() => ({ listByBusiness: vi.fn() }))

vi.mock('../../../../src/repositories/attestationRepository.js', () => ({
  listByBusiness,
}))

vi.mock('../../../../src/db/client.js', () => ({ db: {} }))
import { db } from '../../../../src/db/client.js'

import { getRevenueReport, TimeWindowError } from '../../../../src/services/analytics/revenueReports.js'

const records = [
  { id: 'att_oct', businessId: 'biz_1', period: '2025-10', createdAt: new Date('2025-11-01T00:00:00.000Z') },
  { id: 'att_nov', businessId: 'biz_1', period: '2025-11', createdAt: new Date('2025-12-01T00:00:00.000Z') },
  { id: 'att_dec', businessId: 'biz_1', period: '2025-12', createdAt: new Date('2026-01-01T00:00:00.000Z') },
  { id: 'att_other_business', businessId: 'biz_2', period: '2025-11', createdAt: new Date('2025-12-02T00:00:00.000Z') },
]

describe('revenueReports', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    listByBusiness.mockResolvedValue(records.filter((record) => record.businessId === 'biz_1'))
  })

  describe('TimeWindowError', () => {
    it('exposes a stable name and code while preserving the message', async () => {
      const error = new TimeWindowError('invalid window')

      expect(error).toBeInstanceOf(Error)
      expect(error.name).toBe('TimeWindowError')
      expect(error.code).toBe('INVALID_TIME_WINDOW')
      expect(error.message).toBe('invalid window')
    })
  })

  describe('getRevenueReport', () => {
    it('returns the selected single period and calculated report fields', async () => {
      expect(await getRevenueReport('biz_1', '2025-11')).toEqual({
        period: '2025-11',
        total: 100,
        net: 95,
        currency: 'USD',
        breakdown: [{ attestationId: 'att_nov', attestedAt: '2025-12-01T00:00:00.000Z' }],
      })
      expect(listByBusiness).toHaveBeenCalledWith(db, 'biz_1')
    })

    it('returns an inclusive range report without including another business', async () => {
      listByBusiness.mockResolvedValue(records.filter((record) => record.businessId === 'biz_1'))

      expect(await getRevenueReport('biz_1', undefined, '2025-11', '2025-12')).toEqual({
        period: '2025-11 to 2025-12',
        total: 200,
        net: 190,
        currency: 'USD',
        breakdown: [
          { attestationId: 'att_nov', attestedAt: '2025-12-01T00:00:00.000Z' },
          { attestationId: 'att_dec', attestedAt: '2026-01-01T00:00:00.000Z' },
        ],
      })
    })

    it('accepts the 24 month maximum range and rejects a 25 month range', async () => {
      listByBusiness.mockResolvedValue([])
      expect(await getRevenueReport('biz_1', undefined, '2024-01', '2025-12')).toBeNull()
      await expect(getRevenueReport('biz_1', undefined, '2024-01', '2026-01'))
        .rejects.toThrow(/25 months exceeds the maximum allowed window of 24 months/)
    })

    it('returns null when no attestations match', async () => {
      expect(await getRevenueReport('biz_1', '2026-01')).toBeNull()
    })

    it.each([
      ['missing query mode', () => getRevenueReport('biz_1'), /Provide either/],
      ['malformed period', () => getRevenueReport('biz_1', '2025/11'), /Must be a valid YYYY-MM month string/],
      ['invalid from month', () => getRevenueReport('biz_1', undefined, '2025-13', '2025-12'), /month must be between 01 and 12/],
      ['invalid to format', () => getRevenueReport('biz_1', undefined, '2025-11', '2025-1'), /Period string must be exactly 7 characters/],
      ['incomplete range', () => getRevenueReport('biz_1', undefined, '2025-11'), /Provide either/],
      ['reversed range', () => getRevenueReport('biz_1', undefined, '2025-12', '2025-11'), /must not be later/],
    ])('throws TimeWindowError for %s', async (_case, invoke, message) => {
      await expect(invoke()).rejects.toThrow(TimeWindowError)
      await expect(invoke()).rejects.toThrow(message)
      expect(listByBusiness).not.toHaveBeenCalled()
    })
  })
})
