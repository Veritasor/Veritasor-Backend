import { db } from "../../db/client.js";
import { NotFoundError } from "../types/errors.js";

/**
 * Resolve the business ID for a given user ID.
 *
 * Queries the businesses table to find the business associated with
 * the authenticated user. Returns null when no business is found.
 */
export async function resolveBusinessIdForUser(
  userId: string,
): Promise<string | null> {
  const result = await db.query(
    "SELECT id FROM businesses WHERE user_id = $1 LIMIT 1",
    [userId],
  );
  if (result.rows.length === 0) return null;
  return (result.rows[0] as Record<string, unknown>).id as string;
}
