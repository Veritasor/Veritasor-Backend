/**
 * Revenue Entry Repository
 *
 * Data access for normalized revenue entries received from Kafka. Entries are
 * immutable: a redelivered message with the same (source, entry_id) pair must
 * not create a second row.
 *
 * All SQL is parameterized and rows are mapped from snake_case to camelCase.
 */

import { db } from '../db/client.js'
import type { NormalizedRevenue } from '../services/revenue/normalize.js'

export type RevenueEntry = {
  id: string
  entryId: string
  source: string
  amount: number
  currency: string
  type: 'payment' | 'refund'
  date: string
  createdAt: string
  updatedAt: string
}

export type RevenueEntryUpsertResult = {
  entry: RevenueEntry | null
  inserted: boolean
}

type RevenueEntryRow = {
  id: string
  entry_id: string
  source: string
  amount: number | string
  currency: string
  entry_type: 'payment' | 'refund'
  event_at: string
  created_at: string
  updated_at: string
}

function toNumber(value: number | string): number {
  const num = typeof value === 'string' ? Number(value) : value
  return Number.isFinite(num) ? num : 0
}

function mapRow(row: RevenueEntryRow): RevenueEntry {
  return {
    id: row.id,
    entryId: row.entry_id,
    source: row.source,
    amount: toNumber(row.amount),
    currency: row.currency,
    type: row.entry_type,
    date: new Date(row.event_at).toISOString(),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

export const revenueEntryRepository = {
  /**
   * Insert a normalized entry, or no-op when the same source/external id was
   * already stored. `inserted` lets callers distinguish new rows from replays.
   */
  async upsert(entry: NormalizedRevenue): Promise<RevenueEntryUpsertResult> {
    const sql = `
      INSERT INTO revenue_entries (entry_id, source, amount, currency, entry_type, event_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (source, entry_id) DO NOTHING
      RETURNING *
    `

    const result = await db.query<RevenueEntryRow>(sql, [
      entry.id,
      entry.source,
      entry.amount,
      entry.currency,
      entry.type,
      entry.date,
    ])

    if (result.rows.length === 0) {
      return { entry: null, inserted: false }
    }

    return { entry: mapRow(result.rows[0]), inserted: true }
  },

  /** Look up a stored entry by its natural key. */
  async findBySourceAndId(
    source: string,
    entryId: string,
  ): Promise<RevenueEntry | null> {
    const result = await db.query<RevenueEntryRow>(
      'SELECT * FROM revenue_entries WHERE source = $1 AND entry_id = $2',
      [source, entryId],
    )

    return result.rows.length > 0 ? mapRow(result.rows[0]) : null
  },
}
