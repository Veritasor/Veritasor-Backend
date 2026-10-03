export type PaginationParams = {
  page: number
  limit: number
  offset: number
}

/**
 * Parse query params and return limit/offset for DB queries.
 * Accepts `{page, limit}` from req.query and applies sane defaults and caps.
 */
export function getPagination(query?: { page?: string | number; limit?: string | number }): PaginationParams {
  const rawPage = query?.page ?? 1
  const rawLimit = query?.limit ?? 20

  const page = Math.max(1, Number(rawPage) || 1)
  const limit = Math.min(100, Math.max(1, Number(rawLimit) || 20))
  const offset = (page - 1) * limit

  return { page, limit, offset }
}

// ---------------------------------------------------------------------------
// Keyset (cursor) pagination helpers
//
// The cursor is the base64 encoding of a JSON payload `{ value, id }` where
// `value` is the sort key of the last item on the previous page and `id` is
// that item's primary key (a stable tiebreaker for equal sort values).
// ---------------------------------------------------------------------------

export type CursorPayload = {
  value: string
  id: string
}

/**
 * Encode a cursor payload as a URL-safe opaque string.
 * Deterministic: the same payload always yields the same cursor.
 */
export function encodeCursor(payload: CursorPayload): string {
  return Buffer.from(JSON.stringify({ value: payload.value, id: payload.id }), 'utf8').toString('base64')
}

/**
 * Decode a cursor string produced by {@link encodeCursor}.
 *
 * Returns `null` for undefined/empty cursors (meaning "first page") and for
 * any cursor that is malformed or decodes to a payload without string
 * `value` and `id` fields. Never throws, so callers can treat `null` as
 * "ignore the cursor" or as their own invalid-cursor error.
 */
export function decodeCursor(cursor?: string | null): CursorPayload | null {
  if (cursor === undefined || cursor === null || cursor === '') return null
  try {
    const parsed: unknown = JSON.parse(Buffer.from(cursor, 'base64').toString('utf8'))
    if (typeof parsed !== 'object' || parsed === null) return null
    const { value, id } = parsed as Record<string, unknown>
    if (typeof value !== 'string' || typeof id !== 'string') return null
    return { value, id }
  } catch {
    return null
  }
}
