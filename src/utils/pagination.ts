export type PaginationParams = {
  page: number
  limit: number
  offset: number
}

/**
 * Parse query params and return limit/offset for DB queries.
 * Accepts `{ page, limit }` from req.query and applies sane defaults and caps.
 */
export function getPagination(query?: { page?: string | number; limit?: string | number }): PaginationParams {
  const rawPage = query?.page ?? 1
  const rawLimit = query?.limit ?? 20

  const page = Math.max(1, Number(rawPage) || 1)
  const limit = Math.min(100, Math.max(1, Number(rawLimit) || 20))
  const offset = (page - 1) * limit

  return { page, limit, offset }
}

/**
 * Format a paginated response payload.
 * Returns an object containing `data`, `total`, `page`, and `limit`.
 */
export function formatPaginatedResponse<T>(data: T[], total: number, page: number, limit: number) {
  return {
    data,
    total,
    page,
    limit,
    totalPages: Math.max(1, Math.ceil(total / limit)),
  }
}

export default { getPagination, formatPaginatedResponse }
