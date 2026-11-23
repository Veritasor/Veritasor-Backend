/**
 * Revenue Snapshot Repository
 *
 * Data access layer for the `revenue_snapshots` table (caching/analytics).
 * The table is defined by migration `002_create_revenue_snapshots_table.sql`:
 *
 *   revenue_snapshots (
 *     id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *     business_id   TEXT NOT NULL,
 *     period        TEXT NOT NULL,
 *     total_revenue NUMERIC NOT NULL,
 *     net_revenue   NUMERIC NOT NULL,
 *     currency      TEXT NOT NULL,
 *     created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
 *   )
 *
 * Conventions:
 *  - All SQL is parameterized ($1, $2, ...). Identifiers and values are never
 *    interpolated into the query text.
 *  - Rows are mapped from snake_case (DB) to camelCase (domain).
 *  - NUMERIC columns arrive as strings from `pg`; they are coerced to numbers
 *    on the way out.
 *  - The conflict target for `upsert` is the business-scoped period
 *    (`business_id`, `period`), the natural key of a snapshot.
 */

import { db } from '../db/client.js'

/** Domain representation of a `revenue_snapshots` row. */
export type RevenueSnapshot = {
  /** Snapshot primary key (UUID). */
  id: string
  /** Authenticated business identifier the snapshot belongs to. */
  businessId: string
  /** Billing period of the snapshot (e.g. YYYY-MM). */
  period: string
  /** Gross revenue for the period. */
  totalRevenue: number
  /** Net revenue after fees for the period. */
  netRevenue: number
  /** ISO 4217 currency code. */
  currency: string
  /** Timestamp of when the snapshot was written. */
  createdAt: string
}

/** Input accepted by {@link revenueSnapshotRepository.upsert}. */
export type RevenueSnapshotInput = {
  businessId: string
  period: string
  totalRevenue: number
  netRevenue: number
  currency: string
}

/** Raw database row (snake_case columns; NUMERIC as string). */
type RevenueSnapshotRow = {
  id: string
  business_id: string
  period: string
  total_revenue: number | string
  net_revenue: number | string
  currency: string
  created_at: string
}

/** Coerce a NUMERIC column value (string from `pg`, or number) to a number. */
function toNumber(value: number | string): number {
  const num = typeof value === 'string' ? Number(value) : value
  return Number.isFinite(num) ? num : 0
}

/** Map a raw database row to the domain shape. */
function mapRowToSnapshot(row: RevenueSnapshotRow): RevenueSnapshot {
  return {
    id: row.id,
    businessId: row.business_id,
    period: row.period,
    totalRevenue: toNumber(row.total_revenue),
    netRevenue: toNumber(row.net_revenue),
    currency: row.currency,
    createdAt: row.created_at,
  }
}

export const revenueSnapshotRepository = {
  /**
   * Insert a revenue snapshot, or refresh the existing row for the same
   * (business_id, period) via ON CONFLICT. Returns the persisted row.
   *
   * @param input - Business-scoped snapshot values to write.
   * @returns The persisted snapshot row (camelCase).
   * @throws Error if the statement returns no rows.
   */
  async upsert(input: RevenueSnapshotInput): Promise<RevenueSnapshot> {
    const sql = `
      INSERT INTO revenue_snapshots (business_id, period, total_revenue, net_revenue, currency)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (business_id, period)
      DO UPDATE SET
        total_revenue = EXCLUDED.total_revenue,
        net_revenue = EXCLUDED.net_revenue,
        currency = EXCLUDED.currency
      RETURNING *
    `

    const result = await db.query<RevenueSnapshotRow>(sql, [
      input.businessId,
      input.period,
      input.totalRevenue,
      input.netRevenue,
      input.currency,
    ])

    if (result.rows.length === 0) {
      throw new Error('Failed to upsert revenue snapshot: no rows returned')
    }

    return mapRowToSnapshot(result.rows[0])
  },

  /**
   * List snapshots for a business whose period falls in the inclusive
   * [start, end] window (both are YYYY-MM strings; `period >= start` and
   * `period <= end` mirror the string comparison the report service used).
   *
   * Results are ordered oldest-first (period, then created_at).
   *
   * @param businessId - Authenticated business identifier (tenant scope).
   * @param start      - Inclusive window start (YYYY-MM).
   * @param end        - Inclusive window end (YYYY-MM).
   * @returns Snapshots for the business within the window, oldest first.
   */
  async listByBusinessAndRange(
    businessId: string,
    start: string,
    end: string,
  ): Promise<RevenueSnapshot[]> {
    const sql = `
      SELECT * FROM revenue_snapshots
      WHERE business_id = $1
        AND period >= $2
        AND period <= $3
      ORDER BY period ASC, created_at ASC
    `

    const result = await db.query<RevenueSnapshotRow>(sql, [businessId, start, end])
    return result.rows.map(mapRowToSnapshot)
  },
}
