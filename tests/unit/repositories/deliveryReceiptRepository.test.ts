/**
 * Focused coverage for delivery-receipt keyset pagination.
 *
 * db.query is mocked; the in-memory helper interprets the same cursor tuple
 * the repository sends to Postgres so page traversal is exercised end to end.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

const dbQuery = vi.hoisted(() => vi.fn())

vi.mock('../../../src/db/client.js', () => ({
  db: { query: dbQuery },
}))

import { queryDeliveryReceipts } from '../../../src/repositories/deliveryReceiptRepository.js'
import { decodeCursor, encodeCursor } from '../../../src/utils/pagination.js'

interface ReceiptRow {
  id: string
  delivery_id: string
  attempt_number: number
  subscription_id: string
  business_id: string
  url: string
  status_code: number
  latency_ms: number
  signature_version: number
  signature: string
  response_body: string | null
  created_at: string
}

const TS_NEW = '2026-01-02T00:00:00.000Z'
const TS_TIE = '2026-01-01T00:00:00.000Z'
const TS_OLD = '2025-12-31T00:00:00.000Z'

function row(id: string, createdAt: string, overrides: Partial<ReceiptRow> = {}): ReceiptRow {
  return {
    id,
    delivery_id: 'delivery-1',
    attempt_number: 1,
    subscription_id: 'subscription-1',
    business_id: 'business-1',
    url: 'https://example.test/webhook',
    status_code: 200,
    latency_ms: 42,
    signature_version: 1,
    signature: 'sha256=abc',
    response_body: null,
    created_at: createdAt,
    ...overrides,
  }
}

/** Minimal Postgres stand-in for (created_at, id) keyset filtering. */
function useKeysetDatabase(rows: ReceiptRow[]) {
  dbQuery.mockImplementation(async (...args: unknown[]) => {
    const sql = args[0] as string
    const params = args[1] as unknown[]
    const fetchLimit = params[params.length - 1] as number
    let matching = [...rows]

    if (sql.includes('((created_at, id) < ')) {
      const cursorValue = params[params.length - 3] as string
      const cursorId = params[params.length - 2] as string
      matching = matching.filter(
        (candidate) =>
          candidate.created_at < cursorValue ||
          (candidate.created_at === cursorValue && candidate.id < cursorId),
      )
    }

    return { rows: matching.slice(0, fetchLimit) }
  })
}

describe('queryDeliveryReceipts', () => {
  beforeEach(() => {
    dbQuery.mockReset()
  })

  it('fetches limit+1 filtered rows and encodes (created_at, id) as nextCursor', async () => {
    dbQuery.mockResolvedValue({
      rows: [row('r-3', TS_NEW), row('r-2', TS_TIE), row('r-1', TS_OLD)],
    })

    const result = await queryDeliveryReceipts({
      businessId: 'business-1',
      deliveryId: 'delivery-1',
      subscriptionId: 'subscription-1',
      limit: 2,
    })

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain('WHERE business_id = $1 AND delivery_id = $2 AND subscription_id = $3')
    expect(sql).toContain('ORDER BY created_at DESC, id DESC LIMIT $4')
    expect(params).toEqual(['business-1', 'delivery-1', 'subscription-1', 3])

    expect(result.data.map((receipt) => receipt.id)).toEqual(['r-3', 'r-2'])
    expect(decodeCursor(result.nextCursor!)).toEqual({ value: TS_TIE, id: 'r-2' })
    expect(result.nextCursor).toBe(encodeCursor({ value: TS_TIE, id: 'r-2' }))
  })

  it('applies the decoded cursor as a tuple comparison with the same ordering', async () => {
    const cursor = encodeCursor({ value: TS_TIE, id: 'r-2' })
    dbQuery.mockResolvedValue({ rows: [row('r-1', TS_OLD)] })

    await queryDeliveryReceipts({ businessId: 'business-1', cursor, limit: 2 })

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain(
      'WHERE business_id = $1 AND ((created_at, id) < ($2, $3)) ORDER BY created_at DESC, id DESC LIMIT $4',
    )
    expect(params).toEqual(['business-1', TS_TIE, 'r-2', 3])
  })

  it('following nextCursor yields distinct, ordered pages including timestamp ties', async () => {
    useKeysetDatabase([
      row('c', TS_TIE),
      row('b', TS_TIE),
      row('a', TS_TIE),
      row('older', TS_OLD),
    ])

    const pages: string[][] = []
    let cursor: string | undefined

    for (let page = 0; page < 5; page += 1) {
      const result = await queryDeliveryReceipts({ limit: 2, cursor })
      pages.push(result.data.map((receipt) => receipt.id))
      cursor = result.nextCursor
      if (!cursor) break
    }

    expect(pages).toEqual([['c', 'b'], ['a', 'older']])
    expect(new Set(pages.flat()).size).toBe(4)
    expect(dbQuery).toHaveBeenCalledTimes(2)
  })

  it('omits nextCursor when there are exactly limit rows to avoid a trailing empty page', async () => {
    dbQuery.mockResolvedValue({ rows: [row('r-2', TS_TIE), row('r-1', TS_OLD)] })

    const result = await queryDeliveryReceipts({ limit: 2 })

    expect(result.data.map((receipt) => receipt.id)).toEqual(['r-2', 'r-1'])
    expect(result.nextCursor).toBeUndefined()
    expect(dbQuery.mock.calls[0][1]).toEqual([3])
  })

  it.each([
    ['non-base64', '%%%not-base64%%%'],
    ['malformed JSON', Buffer.from('{broken').toString('base64')],
    ['missing id', Buffer.from(JSON.stringify({ value: TS_TIE })).toString('base64')],
    ['empty id', encodeCursor({ value: TS_TIE, id: '' })],
    ['non-date value', encodeCursor({ value: 'not-a-timestamp', id: 'r-1' })],
  ])('ignores a %s cursor', async (_label, cursor) => {
    dbQuery.mockResolvedValue({ rows: [] })

    const result = await queryDeliveryReceipts({ cursor, limit: 5 })

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).not.toContain('(created_at, id)')
    expect(params).toEqual([6])
    expect(result.data).toEqual([])
    expect(result.nextCursor).toBeUndefined()
  })

  it.each([
    ['default', undefined, 50],
    ['zero', 0, 1],
    ['negative', -4, 1],
    ['above max', 1000, 100],
    ['NaN', Number.NaN, 50],
    ['fractional', 2.9, 2],
  ])('clamps a %s limit before fetching', async (_label, limit, expectedLimit) => {
    dbQuery.mockResolvedValue({ rows: [] })

    await queryDeliveryReceipts({ limit })

    expect(dbQuery.mock.calls[0][1]).toEqual([expectedLimit + 1])
  })
})
