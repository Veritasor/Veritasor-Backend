import { db } from "../db/client.js";

export interface DeliveryReceipt {
  id: string;
  deliveryId: string;
  attemptNumber: number;
  subscriptionId: string;
  businessId: string;
  url: string;
  statusCode: number;
  latencyMs: number;
  signatureVersion: number;
  signature: string;
  responseBody?: string;
  createdAt: string;
}

export interface CreateDeliveryReceiptInput {
  deliveryId: string;
  attemptNumber: number;
  subscriptionId: string;
  businessId: string;
  url: string;
  statusCode: number;
  latencyMs: number;
  signatureVersion: number;
  signature: string;
  responseBody?: string;
}

export interface DeliveryReceiptQuery {
  businessId?: string;
  deliveryId?: string;
  subscriptionId?: string;
  limit?: number;
  cursor?: string;
}

function mapRow(row: Record<string, unknown>): DeliveryReceipt {
  return {
    id: row.id as string,
    deliveryId: row.delivery_id as string,
    attemptNumber: row.attempt_number as number,
    subscriptionId: row.subscription_id as string,
    businessId: row.business_id as string,
    url: row.url as string,
    statusCode: row.status_code as number,
    latencyMs: row.latency_ms as number,
    signatureVersion: row.signature_version as number,
    signature: row.signature as string,
    responseBody: (row.response_body as string) ?? undefined,
    createdAt: row.created_at as string,
  };
}

export async function createDeliveryReceipt(input: CreateDeliveryReceiptInput): Promise<DeliveryReceipt> {
  const result = await db.query(
    `INSERT INTO delivery_receipts (
      delivery_id, attempt_number, subscription_id, business_id, url,
      status_code, latency_ms, signature_version, signature, response_body
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    RETURNING *`,
    [
      input.deliveryId,
      input.attemptNumber,
      input.subscriptionId,
      input.businessId,
      input.url,
      input.statusCode,
      input.latencyMs,
      input.signatureVersion,
      input.signature,
      input.responseBody ?? null,
    ],
  );
  return mapRow(result.rows[0] as Record<string, unknown>);
}

export async function queryDeliveryReceipts(query: DeliveryReceiptQuery): Promise<{ data: DeliveryReceipt[]; nextCursor?: string }> {
  const conditions: string[] = [];
  const params: (string | number)[] = [];
  let paramIndex = 1;

  if (query.businessId) {
    conditions.push(`business_id = $${paramIndex++}`);
    params.push(query.businessId);
  }
  if (query.deliveryId) {
    conditions.push(`delivery_id = $${paramIndex++}`);
    params.push(query.deliveryId);
  }
  if (query.subscriptionId) {
    conditions.push(`subscription_id = $${paramIndex++}`);
    params.push(query.subscriptionId);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = Math.min(query.limit ?? 50, 100);

  const result = await db.query(
    `SELECT * FROM delivery_receipts ${where} ORDER BY created_at DESC LIMIT $${paramIndex++}`,
    [...params, limit],
  );

  const receipts = (result.rows as Record<string, unknown>[]).map(mapRow);
  const nextCursor = receipts.length === limit ? receipts[receipts.length - 1].id : undefined;

  return { data: receipts, nextCursor };
}

export async function getDeliveryReceiptsByDeliveryId(deliveryId: string): Promise<DeliveryReceipt[]> {
  const result = await db.query(
    "SELECT * FROM delivery_receipts WHERE delivery_id = $1 ORDER BY attempt_number ASC",
    [deliveryId],
  );
  return (result.rows as Record<string, unknown>[]).map(mapRow);
}
