import { beforeEach, describe, expect, it, vi } from 'vitest'

const { listByBusiness } = vi.hoisted(() => ({ listByBusiness: vi.fn() }))

vi.mock('../../../../src/repositories/attestation.js', () => ({
  attestationRepository: { listByBusiness },
}))

import { getRevenueReport, TimeWindowError } from '../../../../src/services/analytics/revenueReports.js'

const records = [
  { id: 'att_oct', businessId: 'biz_1', period: '2025-10', attestedAt: '2025-11-01T00:00:00.000Z' },
  { id: 'att_nov', businessId: 'biz_1', period: '2025-11', attestedAt: '2025-12-01T00:00:00.000Z' },
  { id: 'att_dec', businessId: 'biz_1', period: '2025-12', attestedAt: '2026-01-01T00:00:00.000Z' },
  { id: 'att_other_business', businessId: 'biz_2', period: '2025-11', attestedAt: '2025-12-02T00:00:00.000Z' },
]

describe('revenueReports', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    listByBusiness.mockReturnValue(records.filter((record) => record.businessId === 'biz_1'))
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
    it('returns the selected single period and calculated report fields', () => {
      expect(getRevenueReport('biz_1', '2025-11')).toEqual({
        period: '2025-11',
        total: 100,
        net: 95,
        currency: 'USD',
        breakdown: [{ attestationId: 'att_nov', attestedAt: '2025-12-01T00:00:00.000Z' }],
      })
      expect(listByBusiness).toHaveBeenCalledWith('biz_1')
    })

    it('returns an inclusive range report without including another business', () => {
      listByBusiness.mockReturnValue(records.filter((record) => record.businessId === 'biz_1'))

      expect(getRevenueReport('biz_1', undefined, '2025-11', '2025-12')).toEqual({
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

    it('accepts the 24 month maximum range and rejects a 25 month range', () => {
      listByBusiness.mockReturnValue([])
      expect(getRevenueReport('biz_1', undefined, '2024-01', '2025-12')).toBeNull()
      expect(() => getRevenueReport('biz_1', undefined, '2024-01', '2026-01'))
        .toThrow(/25 months exceeds the maximum allowed window of 24 months/)
    })

    it('returns null when no attestations match', () => {
      expect(getRevenueReport('biz_1', '2026-01')).toBeNull()
    })

    it.each([
      ['missing query mode', () => getRevenueReport('biz_1'), /Provide either/],
      ['malformed period', () => getRevenueReport('biz_1', '2025/11'), /Invalid format for "period"/],
      ['invalid from month', () => getRevenueReport('biz_1', undefined, '2025-13', '2025-12'), /Invalid month for "from"/],
      ['invalid to format', () => getRevenueReport('biz_1', undefined, '2025-11', '2025-1'), /Invalid format for "to"/],
      ['incomplete range', () => getRevenueReport('biz_1', undefined, '2025-11'), /Provide either/],
      ['reversed range', () => getRevenueReport('biz_1', undefined, '2025-12', '2025-11'), /must not be later/],
    ])('throws TimeWindowError for %s', (_case, invoke, message) => {
      expect(invoke).toThrow(TimeWindowError)
      expect(invoke).toThrow(message)
    })
  })
})
