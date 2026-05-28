/**
 * Parse query params and return limit/offset for DB queries.
 * Accepts `{ page, limit }` from req.query and applies sane defaults and caps.
 */
export function getPagination(query) {
    const rawPage = query?.page ?? 1;
    const rawLimit = query?.limit ?? 20;
    const page = Math.max(1, Number(rawPage) || 1);
    const limit = Math.min(100, Math.max(1, Number(rawLimit) || 20));
    const offset = (page - 1) * limit;
    return { page, limit, offset };
}
/**
 * Format a paginated response payload.
 * Returns an object containing `data`, `total`, `page`, and `limit`.
 */
export function formatPaginatedResponse(data, total, page, limit) {
    return {
        data,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit) || 0,
    };
}
export default { getPagination, formatPaginatedResponse };
