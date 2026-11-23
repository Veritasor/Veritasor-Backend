import crypto from 'crypto'
import { db } from '../db/client.js'
import { decodeCursor, encodeCursor } from '../utils/pagination.js'

export type ReportingPeriod = 'weekly' | 'monthly'

export interface Business {
  id: string
  userId: string
  name: string
  email: string
  industry?: string | null
  description?: string | null
  website?: string | null
  /** Calendar granularity for attestation reminder alignment. Defaults to 'monthly'. */
  reportingPeriod: ReportingPeriod
  /** IANA timezone for computing period boundaries, e.g. 'America/New_York'. Defaults to 'UTC'. */
  reportingTimezone: string
  /** ISO-8601 timestamp of the last time a reminder was sent. Null if never sent. */
  lastReminderSentAt: string | null
  createdAt: string
  updatedAt: string
}

export type CreateBusinessData = {
  userId: string
  name: string
  email: string
  industry?: string | null
  description?: string | null
  website?: string | null
  reportingPeriod?: ReportingPeriod
  reportingTimezone?: string
}

export type UpdateBusinessData = Partial<Omit<CreateBusinessData, 'userId'>>

// In-memory storage for businesses
const businesses: Map<string, Business> = new Map()

export async function create(data: CreateBusinessData): Promise<Business> {
  const now = new Date().toISOString()
  const business: Business = {
    id: crypto.randomUUID(),
    userId: data.userId,
    name: data.name,
    email: data.email,
    industry: data.industry ?? null,
    description: data.description ?? null,
    website: data.website ?? null,
    reportingPeriod: data.reportingPeriod ?? 'monthly',
    reportingTimezone: data.reportingTimezone ?? 'UTC',
    lastReminderSentAt: null,
    createdAt: now,
    updatedAt: now,
  }

  businesses.set(business.id, business)
  return { ...business }
}

export async function getById(id: string): Promise<Business | null> {
  const business = businesses.get(id)
  return business ? { ...business } : null
}

export async function getByIds(ids: readonly string[]): Promise<(Business | Error)[]> {
  return ids.map(id => {
    const business = businesses.get(id)
    return business ? { ...business } : new Error(`Business not found: ${id}`)
  })
}

export async function getByUserId(userId: string): Promise<Business | null> {
  for (const business of businesses.values()) {
    if (business.userId === userId) {
      return { ...business }
    }
  }
  return null
}

export async function getAll(): Promise<Business[]> {
  return Array.from(businesses.values()).map(b => ({ ...b }))
}

export interface BusinessListOptions {
  limit: number;
  cursor?: string;
  sortBy: 'createdAt' | 'name';
  sortOrder: 'asc' | 'desc';
  industry?: string;
}

export interface PaginatedBusinessResult {
  items: Business[];
  nextCursor?: string;
}

/** Raw row shape returned by the `businesses` table (snake_case columns). */
interface BusinessRow {
  id: string
  user_id: string
  name: string
  email: string
  industry: string | null
  description: string | null
  website: string | null
  reporting_period?: string | null
  reporting_timezone?: string | null
  last_reminder_sent_at?: string | Date | null
  created_at: string | Date
  updated_at: string | Date
}

/** Convert a timestamp column (Date or string) to an ISO-8601 string. */
function toIso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : String(value)
}

/**
 * Narrow a DB `reporting_period` value to the ReportingPeriod union.
 * The DB CHECK constraint only permits 'weekly' | 'monthly'; any other
 * value (defensive) falls back to the documented default 'monthly'.
 */
function toReportingPeriod(value: string | null | undefined): ReportingPeriod {
  return value === 'weekly' ? 'weekly' : 'monthly'
}

/** Map a snake_case DB row to the public camelCase `Business` shape. */
function toBusiness(row: BusinessRow): Business {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    email: row.email,
    industry: row.industry ?? null,
    description: row.description ?? null,
    website: row.website ?? null,
    reportingPeriod: toReportingPeriod(row.reporting_period),
    reportingTimezone: row.reporting_timezone ?? 'UTC',
    lastReminderSentAt: row.last_reminder_sent_at ? toIso(row.last_reminder_sent_at) : null,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  }
}

export async function list(options: BusinessListOptions): Promise<PaginatedBusinessResult> {
  const { limit, cursor, sortBy, sortOrder, industry } = options;
  
  const sortColumn = sortBy === 'createdAt' ? 'created_at' : 'name';
  const op = sortOrder === 'asc' ? '>' : '<';
  
  const values: unknown[] = [];
  const conditions: string[] = [];
  
  if (industry !== undefined) {
    values.push(industry);
    conditions.push(`industry = $${values.length}`);
  }
  
  if (cursor) {
    const decoded = decodeCursor(cursor)
    if (decoded) {
      values.push(decoded.value)
      values.push(decoded.id)
      const valIdx = values.length - 1
      const idIdx = values.length
      conditions.push(`(${sortColumn}, id) ${op} ($${valIdx}, $${idIdx})`)
    }
  }
  
  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const orderClause = `ORDER BY ${sortColumn} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}, id ${sortOrder === 'asc' ? 'ASC' : 'DESC'}`;
  
  values.push(limit + 1);
  const limitIdx = values.length;
  
  const result = await db.query<BusinessRow>(
    `
      SELECT id, user_id, name, email, industry, description, website,
             reporting_period, reporting_timezone, last_reminder_sent_at,
             created_at, updated_at
      FROM businesses
      ${whereClause}
      ${orderClause}
      LIMIT $${limitIdx}
    `,
    values
  );
  
  const hasMore = result.rows.length > limit;
  const rowsToReturn = hasMore ? result.rows.slice(0, limit) : result.rows;
  const items = rowsToReturn.map(toBusiness);
  
  let nextCursor: string | undefined;
  if (hasMore) {
    const lastItem = items[items.length - 1]
    const sortValue = sortBy === 'createdAt' ? lastItem.createdAt : lastItem.name
    nextCursor = encodeCursor({ value: sortValue, id: lastItem.id })
  }
  
  return { items, nextCursor };
}

export async function update(id: string, data: UpdateBusinessData): Promise<Business | null> {
  const business = businesses.get(id)
  if (!business) return null

  if (data.name !== undefined) business.name = data.name
  if (data.industry !== undefined) business.industry = data.industry
  if (data.description !== undefined) business.description = data.description
  if (data.website !== undefined) business.website = data.website
  
  business.updatedAt = new Date().toISOString()
  return { ...business }
}

/**
 * Clear all businesses from storage (for testing purposes)
 */
export function clearAll(): void {
  businesses.clear()
}

/**
 * Persist the last reminder sent timestamp for a business.
 * Returns false if the business was not found.
 */
export async function setLastReminderSentAt(id: string, sentAt: string): Promise<boolean> {
  const business = businesses.get(id)
  if (!business) return false
  business.lastReminderSentAt = sentAt
  business.updatedAt = new Date().toISOString()
  return true
}

export const businessRepository = {
  create,
  getById,
  getByIds,
  getByUserId,
  getAll,
  list,
  update,
  setLastReminderSentAt,
  findById: getById,
  findByUserId: getByUserId,
  clearAll,
}
