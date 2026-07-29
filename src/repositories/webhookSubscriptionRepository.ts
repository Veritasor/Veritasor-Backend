import { db } from "../db/client.js";
import type {
  EventFilters,
  CreateWebhookSubscriptionInput,
  UpdateWebhookSubscriptionInput,
  ListWebhookSubscriptionsQuery,
} from "../schemas/webhookSubscription.js";

export interface WebhookSubscription {
  id: string;
  businessId: string;
  url: string;
  secret: string;
  eventFilters: EventFilters;
  enabled: boolean;
  maxPayloadSize: number | null;
  secretVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

function mapRow(row: Record<string, unknown>): WebhookSubscription {
  return {
    id: row.id as string,
    businessId: row.business_id as string,
    url: row.url as string,
    secret: row.secret as string,
    eventFilters: (row.event_filters as EventFilters) ?? {},
    enabled: (row.enabled as boolean) ?? true,
    maxPayloadSize: (row.max_payload_size as number) ?? null,
    secretVersion: (row.secret_version as number) ?? 1,
    createdAt: new Date(row.created_at as string),
    updatedAt: new Date(row.updated_at as string),
  };
}

/**
 * Create a new webhook subscription.
 */
export async function create(
  businessId: string,
  input: CreateWebhookSubscriptionInput,
): Promise<WebhookSubscription> {
  const eventFilters = input.eventFilters ?? {};
  const result = await db.query(
    `INSERT INTO webhook_subscriptions
       (business_id, url, secret, event_filters, enabled, max_payload_size)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [
      businessId,
      input.url,
      input.secret,
      JSON.stringify(eventFilters),
      input.enabled ?? true,
      input.maxPayloadSize ?? null,
    ],
  );
  return mapRow(result.rows[0] as Record<string, unknown>);
}

/**
 * Get a webhook subscription by ID, scoped to a business.
 */
export async function getById(
  id: string,
  businessId: string,
): Promise<WebhookSubscription | null> {
  const result = await db.query(
    "SELECT * FROM webhook_subscriptions WHERE id = $1 AND business_id = $2",
    [id, businessId],
  );
  if (result.rows.length === 0) return null;
  return mapRow(result.rows[0] as Record<string, unknown>);
}

/**
 * List webhook subscriptions with optional filters and cursor pagination.
 */
export async function list(
  query: ListWebhookSubscriptionsQuery,
): Promise<{ data: WebhookSubscription[]; nextCursor?: string }> {
  const conditions: string[] = [];
  const params: (string | boolean | number)[] = [];
  let paramIndex = 1;

  if (query.businessId) {
    conditions.push(`business_id = $${paramIndex++}`);
    params.push(query.businessId);
  }
  if (query.enabled !== undefined) {
    conditions.push(`enabled = $${paramIndex++}`);
    params.push(query.enabled);
  }

  // Cursor-based pagination: filter rows after the cursor ID
  if (query.cursor) {
    conditions.push(`id > $${paramIndex++}`);
    params.push(query.cursor);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = Math.min(query.limit ?? 20, 100);

  const result = await db.query(
    `SELECT * FROM webhook_subscriptions ${where} ORDER BY id ASC LIMIT $${paramIndex++}`,
    [...params, limit],
  );

  const subscriptions = (result.rows as Record<string, unknown>[]).map(mapRow);
  const nextCursor =
    subscriptions.length === limit
      ? subscriptions[subscriptions.length - 1].id
      : undefined;

  return { data: subscriptions, nextCursor };
}

/**
 * Count subscriptions for a business (for capacity enforcement).
 */
export async function countByBusiness(businessId: string): Promise<number> {
  const result = await db.query(
    "SELECT COUNT(*)::int AS count FROM webhook_subscriptions WHERE business_id = $1",
    [businessId],
  );
  return (result.rows[0] as Record<string, unknown>).count as number;
}

/**
 * Update an existing webhook subscription.
 */
export async function update(
  id: string,
  businessId: string,
  input: UpdateWebhookSubscriptionInput,
): Promise<WebhookSubscription | null> {
  const fields: string[] = [];
  const values: (string | boolean | number)[] = [];
  let placeholderIndex = 1;
  let secretChanged = false;

  if (input.url !== undefined) {
    fields.push(`url = $${placeholderIndex++}`);
    values.push(input.url);
  }
  if (input.secret !== undefined) {
    fields.push(`secret = $${placeholderIndex++}`);
    values.push(input.secret);
    secretChanged = true;
  }
  if (input.eventFilters !== undefined) {
    fields.push(`event_filters = $${placeholderIndex++}`);
    values.push(JSON.stringify(input.eventFilters));
  }
  if (input.enabled !== undefined) {
    fields.push(`enabled = $${placeholderIndex++}`);
    values.push(input.enabled);
  }
  if (input.maxPayloadSize !== undefined) {
    fields.push(`max_payload_size = $${placeholderIndex++}`);
    values.push(input.maxPayloadSize);
  }

  // Auto-increment secret version on secret rotation
  if (secretChanged) {
    fields.push(`secret_version = secret_version + 1`);
  }

  if (fields.length === 0) {
    return getById(id, businessId);
  }

  fields.push(`updated_at = now()`);
  values.push(id);
  values.push(businessId);

  const result = await db.query(
    `UPDATE webhook_subscriptions
     SET ${fields.join(", ")}
     WHERE id = $${placeholderIndex++} AND business_id = $${placeholderIndex++}
     RETURNING *`,
    values,
  );

  if (result.rows.length === 0) return null;
  return mapRow(result.rows[0] as Record<string, unknown>);
}

/**
 * Delete a webhook subscription.
 */
export async function remove(
  id: string,
  businessId: string,
): Promise<boolean> {
  const result = await db.query(
    "DELETE FROM webhook_subscriptions WHERE id = $1 AND business_id = $2",
    [id, businessId],
  );
  return (result.rowCount ?? 0) > 0;
}
