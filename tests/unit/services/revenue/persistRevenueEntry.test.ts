import { beforeEach, describe, expect, it, vi } from 'vitest'
import { metricsRegistry } from '../../../../src/metrics.js'
import type { NormalizedRevenue } from '../../../../src/services/revenue/normalize.js'

const { mockUpsert } = vi.hoisted(() => ({ mockUpsert: vi.fn() }))

vi.mock('../../../../src/repositories/revenueEntryRepository.js', () => ({
  revenueEntryRepository: { upsert: mockUpsert },
}))

import { persistRevenueEntry } from '../../../../src/services/revenue/persistRevenueEntry.js'

const entry: NormalizedRevenue = {
  id: 'erp-tx-002',
  amount: -25,
  currency: 'usd',
  date: '2024-03-02T00:00:00.000Z',
  type: 'refund',
  source: 'stripe',
}

async function outcomeValue(outcome: string): Promise<number> {
  const metrics = await metricsRegistry.getMetricsAsJSON()
  const metric = metrics.find(
    (candidate) => candidate.name === 'kafka_revenue_entries_total',
  )
  const sample = metric?.values.find(
    (value) => value.labels.outcome === outcome,
  )
  return Number(sample?.value ?? 0)
}

describe('persistRevenueEntry', () => {
  beforeEach(() => {
    metricsRegistry.resetMetrics()
    mockUpsert.mockReset()
  })

  it('counts a new entry as inserted', async () => {
    mockUpsert.mockResolvedValue({ entry: null, inserted: true })

    await expect(persistRevenueEntry(entry)).resolves.toBeUndefined()

    expect(mockUpsert).toHaveBeenCalledWith(entry)
    expect(await outcomeValue('inserted')).toBe(1)
    expect(await outcomeValue('duplicate')).toBe(0)
  })

  it('counts a redelivered entry as a duplicate without re-inserting', async () => {
    mockUpsert
      .mockResolvedValueOnce({ entry: null, inserted: true })
      .mockResolvedValueOnce({ entry: null, inserted: false })

    await persistRevenueEntry(entry)
    await persistRevenueEntry(entry)

    expect(mockUpsert).toHaveBeenCalledTimes(2)
    expect(await outcomeValue('inserted')).toBe(1)
    expect(await outcomeValue('duplicate')).toBe(1)
  })

  it('counts a failure and rethrows so the consumer can use the DLT', async () => {
    mockUpsert.mockRejectedValue(new Error('db unavailable'))

    await expect(persistRevenueEntry(entry)).rejects.toThrow('db unavailable')

    expect(await outcomeValue('failed')).toBe(1)
  })
})
