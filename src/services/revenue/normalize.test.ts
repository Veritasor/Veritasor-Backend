import { afterEach, describe, expect, it, vi } from 'vitest'
import { normalizeRevenueEntry } from './normalize.js'
import type { NormalizedRevenue, RawRevenueInput } from './normalize.js'

function raw(overrides: Partial<RawRevenueInput> = {}): RawRevenueInput {
  return {
    id: 'revenue-1',
    amount: 12.5,
    currency: 'usd',
    date: '2025-04-10T12:30:00.000Z',
    source: 'stripe',
    ...overrides,
  }
}

describe('normalizeRevenueEntry', () => {
  it('maps RawRevenueInput to the complete NormalizedRevenue contract', () => {
    const result: NormalizedRevenue = normalizeRevenueEntry(raw())

    expect(result).toEqual({
      id: 'revenue-1',
      amount: 12.5,
      currency: 'USD',
      date: '2025-04-10T12:30:00.000Z',
      type: 'payment',
      source: 'stripe',
    })
    expect(Object.keys(result).sort()).toEqual(['amount', 'currency', 'date', 'id', 'source', 'type'])
  })

  it.each([
    [-0.01, 'refund'],
    [0, 'payment'],
    [0.01, 'payment'],
  ] as const)('classifies amount %s as %s', (amount, type) => {
    expect(normalizeRevenueEntry(raw({ amount })).type).toBe(type)
    expect(normalizeRevenueEntry(raw({ amount })).amount).toBe(amount)
  })

  it('uppercases a supplied currency and defaults an empty currency to USD', () => {
    expect(normalizeRevenueEntry(raw({ currency: 'eUr' })).currency).toBe('EUR')
    expect(normalizeRevenueEntry(raw({ currency: '' })).currency).toBe('USD')
  })

  it('converts Unix seconds and preserves the epoch boundary', () => {
    expect(normalizeRevenueEntry(raw({ date: 1_700_000_000 })).date).toBe('2023-11-14T22:13:20.000Z')
    expect(normalizeRevenueEntry(raw({ date: 0 })).date).toBe('1970-01-01T00:00:00.000Z')
  })

  it('uses the current time for invalid, empty, or missing dates', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-02-03T04:05:06.789Z'))

    const expectedDate = '2026-02-03T04:05:06.789Z'
    expect(normalizeRevenueEntry(raw({ date: 'not-a-date' })).date).toBe(expectedDate)
    expect(normalizeRevenueEntry(raw({ date: '' })).date).toBe(expectedDate)
    expect(normalizeRevenueEntry(raw({ date: undefined })).date).toBe(expectedDate)
  })

  it('defaults missing and empty sources to unknown', () => {
    const { source: _source, ...inputWithoutSource } = raw()

    expect(normalizeRevenueEntry(inputWithoutSource).source).toBe('unknown')
    expect(normalizeRevenueEntry(raw({ source: '' })).source).toBe('unknown')
  })

  it('preserves the raw input and ignores fields outside the normalized contract', () => {
    const input = raw({ providerPayload: { event: 'captured' } })
    const snapshot = structuredClone(input)

    const result = normalizeRevenueEntry(input)

    expect(input).toEqual(snapshot)
    expect(result).not.toHaveProperty('providerPayload')
  })
})

afterEach(() => {
  vi.useRealTimers()
})