import crypto from "crypto";
import { staleWebhookDeliveries } from "../../metrics.js";
import { createAuditLog } from "../../repositories/auditLogRepository.js";

export class WebhookPayloadTooLargeError extends Error {
  public readonly code = 'PAYLOAD_TOO_LARGE';
  public readonly statusCode = 413;
  constructor(message: string) {
    super(message);
    this.name = 'WebhookPayloadTooLargeError';
  }
}

export interface WebhookSubscription {
  id: string;
  businessId: string;
  url: string;
  secret: string;
  maxPayloadSize?: number;
  /** Monotonically increasing version of the webhook secret, used for rotation tracking. */
  secretVersion?: number;
}

export interface WebhookDeliveryReceipt {
  delivery_id: string;
  attempt: number;
  signature: string;
  timestamp: string;
}

/**
 * Signs the outbound payload and constructs a verifiable delivery receipt
 */
export function signAndPrepareDelivery(
  payload: object,
  subscription: WebhookSubscription,
  attempt: number = 1
): { headers: Record<string, string>; receipt: WebhookDeliveryReceipt } {
  const serializedPayload = JSON.stringify(payload);
  
  if (subscription.maxPayloadSize !== undefined) {
    const payloadSize = Buffer.byteLength(serializedPayload, 'utf8');
    if (payloadSize > subscription.maxPayloadSize) {
      createAuditLog({
        userId: subscription.businessId,
        action: 'webhook_delivery_rejected',
        resource: 'webhook_subscription',
        resourceId: subscription.id,
        metadata: {
          reason: 'PAYLOAD_TOO_LARGE',
          payloadSize,
          maxPayloadSize: subscription.maxPayloadSize,
        }
      }).catch(err => console.error('Failed to write audit log', err));
      
      throw new WebhookPayloadTooLargeError(`Webhook payload size (${payloadSize} bytes) exceeds maximum allowed size (${subscription.maxPayloadSize} bytes)`);
    }
  }

  const deliveryId = crypto.randomUUID();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  
  // Compute standard HMAC-SHA256 signature over the payload with the business subscription secret
  const signature = crypto
    .createHmac("sha256", subscription.secret)
    .update(`${deliveryId}.${attempt}.${timestamp}.${serializedPayload}`)
    .digest("hex");

  const headers = {
    "Content-Type": "application/json",
    "X-Veritasor-Delivery-Id": deliveryId,
    "X-Veritasor-Attempt": attempt.toString(),
    "X-Veritasor-Timestamp": timestamp,
    "X-Veritasor-Signature": signature,
  };

  const receipt: WebhookDeliveryReceipt = {
    delivery_id: deliveryId,
    attempt,
    signature,
    timestamp,
  };

  return { headers, receipt };
}

export interface VerifyWebhookOptions {
  payload: string;
  headers: Record<string, string | string[] | undefined>;
  secret: string;
  toleranceMs?: number; // default 5 minutes
}

/**
 * Verifies the signature of an incoming webhook delivery.
 * 
 * Verification Recipe for Consumers:
 * 1. Extract the following headers from the incoming request:
 *    - X-Veritasor-Delivery-Id
 *    - X-Veritasor-Attempt
 *    - X-Veritasor-Timestamp
 *    - X-Veritasor-Signature
 * 2. Verify that the timestamp is within a reasonable tolerance (e.g., 5 minutes) of the current time.
 *    - Reject if Math.abs(current_time_unix - timestamp) > tolerance_seconds.
 *    - This protects against replay attacks.
 * 3. Construct the signature payload as a string:
 *    `${deliveryId}.${attempt}.${timestamp}.${rawBody}`
 * 4. Compute an HMAC-SHA256 signature using your webhook secret over the payload.
 * 5. Compare the computed signature to the `X-Veritasor-Signature` header using a constant-time string comparison.
 * 6. To protect against reorder attacks across delivery attempts, track the highest `attempt` seen for a given `deliveryId`.
 */
export function verifyWebhookSignature(options: VerifyWebhookOptions): boolean {
  const { payload, headers, secret, toleranceMs = 5 * 60 * 1000 } = options;

  const getHeader = (name: string) => headers[name] ?? headers[name.toLowerCase()];
  
  const deliveryId = getHeader("X-Veritasor-Delivery-Id");
  const attemptHeader = getHeader("X-Veritasor-Attempt");
  const timestampHeader = getHeader("X-Veritasor-Timestamp");
  const signatureHeader = getHeader("X-Veritasor-Signature");

  if (!deliveryId || !attemptHeader || !timestampHeader || !signatureHeader) {
    return false;
  }

  const deliveryIdStr = Array.isArray(deliveryId) ? deliveryId[0] : deliveryId;
  const attemptStr = Array.isArray(attemptHeader) ? attemptHeader[0] : attemptHeader;
  const timestampStr = Array.isArray(timestampHeader) ? timestampHeader[0] : timestampHeader;
  const signatureStr = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;

  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp)) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);
  const toleranceSeconds = Math.floor(toleranceMs / 1000);
  
  if (Math.abs(now - timestamp) > toleranceSeconds) {
    staleWebhookDeliveries.inc();
    return false;
  }

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(`${deliveryIdStr}.${attemptStr}.${timestampStr}.${payload}`)
    .digest("hex");

  const expectedBuffer = Buffer.from(expectedSignature, "hex");
  
  let providedBuffer: Buffer;
  try {
    providedBuffer = Buffer.from(signatureStr, "hex");
  } catch {
    return false;
  }

  if (expectedBuffer.length !== providedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
}