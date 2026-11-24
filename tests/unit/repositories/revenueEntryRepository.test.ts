import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { NormalizedRevenue } from '../../../src/services/revenue/normalize.js'

const { mockQuery } = vi.hoisted(() => ({ mockQuery: vi.fn() }))

vi.mock('../../../src/db/client.js', () => ({
  db: { query: mockQuery },
}))

import { revenueEntryRepository } from '../../../src/repositories/revenueEntryRepository.js'

const entry: NormalizedRevenue = {
  id: 'erp-tx-001',
  amount: 500,
  currency: 'EUR',
  date: '2024-03-01T00:00:00.000Z',
  type: 'payment',
  source: 'sap-erp',
}

function storedRow(input: NormalizedRevenue) {
  return {
    id: 'row-1',
    entry_id: input.id,
    source: input.source,
    amount: String(input.amount),
    currency: input.currency,
    entry_type: input.type,
    event_at: input.date,
    created_at: '2026-11-24T00:00:00.000Z',
    updated_at: '2026-11-24T00:00:00.000Z',
  }
}

describe('revenueEntryRepository', () => {
  beforeEach(() => {
    mockQuery.mockReset()
  })

  it('inserts a normalized entry with parameterized SQL', async () => {
    mockQuery.mockResolvedValue({ rows: [storedRow(entry)], rowCount: 1 })

    const result = await revenueEntryRepository.upsert(entry)

    const [sql, params] = mockQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain('INSERT INTO revenue_entries')
    expect(sql).toContain('ON CONFLICT (source, entry_id) DO NOTHING')
    expect(params).toEqual([
      'erp-tx-001',
      'sap-erp',
      500,
      'EUR',
      'payment',
      '2024-03-01T00:00:00.000Z',
    ])
    expect(result.inserted).toBe(true)
    expect(result.entry).toMatchObject({
      entryId: 'erp-tx-001',
      source: 'sap-erp',
      amount: 500,
      currency: 'EUR',
      type: 'payment',
      date: '2024-03-01T00:00:00.000Z',
    })
  })

  it('stores one row when the same source and external id is delivered twice', async () => {
    const rows = new Map<string, ReturnType<typeof storedRow>>()
    mockQuery.mockImplementation(async (sql: string, params: unknown[]) => {
      if (sql.includes('INSERT INTO revenue_entries')) {
        const key = `${String(params[1])}|${String(params[0])}`
        if (rows.has(key)) return { rows: [], rowCount: 0 }
        const row = storedRow({
          ...entry,
          id: String(params[0]),
          source: String(params[1]),
        })
        rows.set(key, row)
        return { rows: [row], rowCount: 1 }
      }
      return { rows: [], rowCount: 0 }
    })

    const first = await revenueEntryRepository.upsert(entry)
    const second = await revenueEntryRepository.upsert(entry)

    expect(first.inserted).toBe(true)
    expect(second.inserted).toBe(false)
    expect(second.entry).toBeNull()
    expect(rows.size).toBe(1)
  })

  it('finds a stored entry by source and external id', async () => {
    mockQuery.mockResolvedValue({ rows: [storedRow(entry)], rowCount: 1 })

    const found = await revenueEntryRepository.findBySourceAndId('sap-erp', 'erp-tx-001')

    expect(mockQuery).toHaveBeenCalledWith(
      'SELECT * FROM revenue_entries WHERE source = $1 AND entry_id = $2',
      ['sap-erp', 'erp-tx-001'],
    )
    expect(found?.entryId).toBe('erp-tx-001')
  })
})
