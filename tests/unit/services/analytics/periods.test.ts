import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../../../src/repositories/attestation.js', () => ({
  attestationRepository: { listByBusiness: vi.fn() },
}))

import {
  currentPeriod,
  dateToPeriod,
  isTimestampInPeriod,
  parsePeriodToBounds,
  PeriodParseError,
} from '../../../../src/services/analytics/periods.js'

const DAY_MS = 24 * 60 * 60 * 1000

/** Convert an ISO instant to Unix epoch seconds. */
const toSeconds = (iso: string): number => Math.floor(new Date(iso).getTime() / 1000)

/** Assert that parsing `value` throws a PeriodParseError with code INVALID_PERIOD. */
const expectParseError = (value: string): void => {
  let caught: unknown
  try {
    parsePeriodToBounds(value)
  } catch (error) {
    caught = error
  }
  expect(caught).toBeInstanceOf(PeriodParseError)
  expect((caught as PeriodParseError).code).toBe('INVALID_PERIOD')
}

describe('periods', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  describe('parsePeriodToBounds', () => {
    it('rolls over to the next year at December end', () => {
      const { start, end } = parsePeriodToBounds('2025-12')
      expect(start.toISOString()).toBe('2025-12-01T00:00:00.000Z')
      expect(end.toISOString()).toBe('2026-01-01T00:00:00.000Z')
    })

    it('computes mid-year month boundaries', () => {
      const { start, end } = parsePeriodToBounds('2025-07')
      expect(start.toISOString()).toBe('2025-07-01T00:00:00.000Z')
      expect(end.toISOString()).toBe('2025-08-01T00:00:00.000Z')
    })

    it('returns a full 29-day span for leap-year February 2024', () => {
      const { start, end } = parsePeriodToBounds('2024-02')
      expect(start.toISOString()).toBe('2024-02-01T00:00:00.000Z')
      expect(end.toISOString()).toBe('2024-03-01T00:00:00.000Z')
      expect(end.getTime() - start.getTime()).toBe(29 * DAY_MS)
    })

    it('returns a 28-day span for non-leap-year February 2023', () => {
      const { start, end } = parsePeriodToBounds('2023-02')
      expect(start.toISOString()).toBe('2023-02-01T00:00:00.000Z')
      expect(end.toISOString()).toBe('2023-03-01T00:00:00.000Z')
      expect(end.getTime() - start.getTime()).toBe(28 * DAY_MS)
    })

    it('rolls the boundary into the next year for December 2024', () => {
      const { start, end } = parsePeriodToBounds('2024-12')
      expect(start.toISOString()).toBe('2024-12-01T00:00:00.000Z')
      expect(end.toISOString()).toBe('2025-01-01T00:00:00.000Z')
    })

    it.each(['2025-13', '2025-00', '25-01', ''])(
      'throws PeriodParseError for invalid input %j',
      (value) => {
        expectParseError(value)
      },
    )
  })

  describe('isTimestampInPeriod', () => {
    const period = '2025-12'
    const start = toSeconds('2025-12-01T00:00:00.000Z')
    const end = toSeconds('2026-01-01T00:00:00.000Z')

    it('includes the exact start timestamp (inclusive)', () => {
      expect(isTimestampInPeriod(start, period)).toBe(true)
    })

    it('excludes the second before the start', () => {
      expect(isTimestampInPeriod(start - 1, period)).toBe(false)
    })

    it('includes the second before the end', () => {
      expect(isTimestampInPeriod(end - 1, period)).toBe(true)
    })

    it('excludes the exact end timestamp (exclusive)', () => {
      expect(isTimestampInPeriod(end, period)).toBe(false)
    })
  })

  describe('dateToPeriod', () => {
    it('zero-pads single-digit months near UTC midnight', () => {
      expect(dateToPeriod(new Date('2025-01-01T00:00:00.000Z'))).toBe('2025-01')
      expect(dateToPeriod(new Date('2025-09-30T23:59:59.000Z'))).toBe('2025-09')
    })

    it('formats double-digit months cleanly', () => {
      expect(dateToPeriod(new Date('2025-10-01T00:00:00.000Z'))).toBe('2025-10')
      expect(dateToPeriod(new Date('2025-12-31T23:59:59.000Z'))).toBe('2025-12')
    })
  })

  describe('currentPeriod', () => {
    it('returns the UTC period at the end of the year (2025-12-31)', () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2025-12-31T23:59:59Z'))
      expect(currentPeriod()).toBe('2025-12')
    })

    it('rolls over to 2026-01 at UTC midnight', () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
      expect(currentPeriod()).toBe('2026-01')
    })
  })
})
