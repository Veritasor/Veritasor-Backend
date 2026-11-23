import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { db } from "../db/client.js";
import type {
  EventFilters,
  CreateWebhookSubscriptionInput,
  UpdateWebhookSubscriptionInput,
  ListWebhookSubscriptionsQuery,
} from "../schemas/webhookSubscription.js";
import { secretLoader } from "../utils/secret-loader.js";

export interface WebhookMTLSConfig {
  clientCertSecretId: string;
  clientKeySecretId: string;
  caPinSecretId: string;
}

export interface WebhookSubscription {
  id: string;
  businessId: string;
  url: string;
  secret: string;
  eventFilters: EventFilters;
  enabled: boolean;
  maxPayloadSize: number | null;
  secretVersion: number;
  mtlsConfig: WebhookMTLSConfig | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface PublicWebhookSubscription {
  id: string;
  businessId: string;
  url: string;
  eventFilters: EventFilters;
  enabled: boolean;
  maxPayloadSize: number | null;
  secretVersion: number;
  secretLast4: string | null;
  mtlsConfig: WebhookMTLSConfig | null;
  createdAt: Date;
  updatedAt: Date;
}

const WEBHOOK_SECRET_ENCRYPTION_KEY = "WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY";

// Webhook signing secrets are encrypted at rest using the app's secret loader.
// Existing plaintext rows are still readable via decryptStoredSecret() and are re-encrypted
// on the next create/update write. If no encryption key is configured, the app keeps the
// legacy plaintext format until deployment wiring adds WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY.
function getWebhookSecretEncryptionKey(): string | null {
  const keyFromEnv = process.env.WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY?.trim();
  if (keyFromEnv && keyFromEnv.length >= 32) return keyFromEnv;

  try {
    const keyFromSecretLoader = secretLoader.get(WEBHOOK_SECRET_ENCRYPTION_KEY)?.trim();
    if (keyFromSecretLoader && keyFromSecretLoader.length >= 32) {
      return keyFromSecretLoader;
    }
  } catch {
    // Fall through to plaintext storage when no encryption key is configured.
  }

  return null;
}

function deriveEncryptionKey(keyMaterial: string): Buffer {
  return createHash("sha256").update(keyMaterial).digest();
}

export function encryptStoredSecret(secret: string): string {
  const encryptionKey = getWebhookSecretEncryptionKey();
  if (!encryptionKey) {
    return secret;
  }

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveEncryptionKey(encryptionKey), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `enc:v1:${iv.toString("base64")}:${Buffer.concat([ciphertext, authTag]).toString("base64")}`;
}

export function decryptStoredSecret(secret: string): string {
  if (!secret.startsWith("enc:v1:")) {
    return secret;
  }

  const encryptionKey = getWebhookSecretEncryptionKey();
  if (!encryptionKey) {
    return secret;
  }

  const [, , ivB64, payloadB64] = secret.split(":");
  if (!ivB64 || !payloadB64) {
    return secret;
  }

  const iv = Buffer.from(ivB64, "base64");
  const payload = Buffer.from(payloadB64, "base64");
  const authTag = payload.subarray(payload.length - 16);
  const ciphertext = payload.subarray(0, payload.length - 16);

  const decipher = createDecipheriv("aes-256-gcm", deriveEncryptionKey(encryptionKey), iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

export function toPublicSubscription(subscription: WebhookSubscription): PublicWebhookSubscription {
  return {
    id: subscription.id,
    businessId: subscription.businessId,
    url: subscription.url,
    eventFilters: subscription.eventFilters,
    enabled: subscription.enabled,
    maxPayloadSize: subscription.maxPayloadSize,
    secretVersion: subscription.secretVersion,
    secretLast4: subscription.secret ? subscription.secret.slice(-4) || null : null,
    mtlsConfig: subscription.mtlsConfig,
    createdAt: subscription.createdAt,
    updatedAt: subscription.updatedAt,
  };
}

function mapRow(row: Record<string, unknown>): WebhookSubscription {
  return {
    id: row.id as string,
    businessId: row.business_id as string,
    url: row.url as string,
    secret: decryptStoredSecret((row.secret as string) ?? ""),
    eventFilters: (row.event_filters as EventFilters) ?? {},
    enabled: (row.enabled as boolean) ?? true,
    maxPayloadSize: (row.max_payload_size as number) ?? null,
    secretVersion: (row.secret_version as number) ?? 1,
    mtlsConfig: (row.mtls_config as WebhookMTLSConfig) ?? null,
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
  const secret = encryptStoredSecret(input.secret);

  const result = await db.query(
    `INSERT INTO webhook_subscriptions
       (business_id, url, secret, event_filters, enabled, max_payload_size, mtls_config)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [
      businessId,
      input.url,
      secret,
      JSON.stringify(eventFilters),
      input.enabled ?? true,
      input.maxPayloadSize ?? null,
      input.mtlsConfig ? JSON.stringify(input.mtlsConfig) : null,
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
  const values: (string | boolean | number | null)[] = [];
  let placeholderIndex = 1;
  let secretChanged = false;

  if (input.url !== undefined) {
    fields.push(`url = $${placeholderIndex++}`);
    values.push(input.url);
  }
  if (input.secret !== undefined) {
    fields.push(`secret = $${placeholderIndex++}`);
    values.push(encryptStoredSecret(input.secret));
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
  if (input.mtlsConfig !== undefined) {
    fields.push(`mtls_config = $${placeholderIndex++}`);
    values.push(input.mtlsConfig ? JSON.stringify(input.mtlsConfig) : null);
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
 * Return the plaintext signing secret for server-side use such as dispatch.
 * The repository decrypts the stored value when encryption is enabled.
 */
export async function getSigningSecret(
  id: string,
  businessId: string,
): Promise<string | null> {
  const result = await db.query(
    "SELECT secret FROM webhook_subscriptions WHERE id = $1 AND business_id = $2",
    [id, businessId],
  );

  if (result.rows.length === 0) {
    return null;
  }

  return decryptStoredSecret((result.rows[0].secret as string) ?? "");
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