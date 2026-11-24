import crypto from "crypto";
import * as https from "https";
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isBlockedAddress, isValidWebhookUrl } from '../../schemas/webhookSubscription.js';
import { secretLoader } from "../../utils/secret-loader.js";
import { staleWebhookDeliveries } from "../../metrics.js";
import { createAuditLog } from "../../repositories/auditLogRepository.js";
import { createDeliveryReceipt } from "../../repositories/deliveryReceiptRepository.js";
import { evaluateEventFilter } from "../../schemas/webhookSubscription.js";
import { logger } from "../../utils/logger.js";

export class WebhookPayloadTooLargeError extends Error {
  public readonly code = 'PAYLOAD_TOO_LARGE';
  public readonly statusCode = 413;
  constructor(message: string) {
    super(message);
    this.name = 'WebhookPayloadTooLargeError';
  }
}

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
  maxPayloadSize?: number;
  /** Monotonically increasing version of the webhook secret, used for rotation tracking. */
  secretVersion?: number;
  /** Previous secret kept verifiable during a rotation grace window. */
  previousSecret?: string | null;
  /** Version of the previous secret. */
  previousSecretVersion?: number | null;
  /** Expiry of the rotation grace window. */
  previousSecretExpiresAt?: Date | string | null;
  /** Per-event filter DSL. Maps event types to boolean or filter objects. */
  eventFilters?: Record<string, boolean | Record<string, string>>;
  mtlsConfig?: WebhookMTLSConfig | null;
}

export interface WebhookDeliveryReceipt {
  delivery_id: string;
  attempt: number;
  signature: string;
  timestamp: string;
}

function computeSignature(
  secret: string,
  deliveryId: string,
  attempt: number | string,
  timestamp: string,
  serializedPayload: string,
): string {
  return crypto
    .createHmac("sha256", secret)
    .update(`${deliveryId}.${attempt}.${timestamp}.${serializedPayload}`)
    .digest("hex");
}

function previousSecretUsable(
  subscription: WebhookSubscription,
  now: number,
): boolean {
  if (!subscription.previousSecret || !subscription.previousSecretExpiresAt) {
    return false;
  }

  const expiresAt = new Date(subscription.previousSecretExpiresAt).getTime();
  return Number.isFinite(expiresAt) && expiresAt > now;
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
  
  if (subscription.maxPayloadSize !== undefined && subscription.maxPayloadSize !== null) {
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
      }).catch(error => logger.error(
        { event: 'webhook_audit_log_write_failed', error },
        'Failed to write audit log',
      ));
      
      throw new WebhookPayloadTooLargeError(`Webhook payload size (${payloadSize} bytes) exceeds maximum allowed size (${subscription.maxPayloadSize} bytes)`);
    }
  }

  const deliveryId = crypto.randomUUID();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  
  const now = Date.now();
  const signature = computeSignature(
    subscription.secret,
    deliveryId,
    attempt,
    timestamp,
    serializedPayload,
  );

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Veritasor-Delivery-Id": deliveryId,
    "X-Veritasor-Attempt": attempt.toString(),
    "X-Veritasor-Timestamp": timestamp,
    "X-Veritasor-Signature": signature,
    "X-Veritasor-Signature-Alg": "hmac-sha256",
    "X-Veritasor-Signature-Version": String(subscription.secretVersion ?? 1),
  };

  if (previousSecretUsable(subscription, now)) {
    headers["X-Veritasor-Previous-Signature"] = computeSignature(
      subscription.previousSecret as string,
      deliveryId,
      attempt,
      timestamp,
      serializedPayload,
    );
    headers["X-Veritasor-Previous-Signature-Version"] = String(
      subscription.previousSecretVersion ?? (subscription.secretVersion ?? 1) - 1,
    );
  }

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
  previousSecret?: string | null;
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
  const {
    payload,
    headers,
    secret,
    previousSecret,
    toleranceMs = 5 * 60 * 1000,
  } = options;

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

  let providedBuffer: Buffer;
  try {
    providedBuffer = Buffer.from(signatureStr, "hex");
  } catch {
    return false;
  }

  const secrets = [secret, ...(previousSecret ? [previousSecret] : [])];
  for (const candidate of secrets) {
    const expectedBuffer = Buffer.from(
      computeSignature(
        candidate,
        deliveryIdStr,
        attemptStr,
        timestampStr,
        payload,
      ),
      "hex",
    );
    if (
      expectedBuffer.length === providedBuffer.length &&
      crypto.timingSafeEqual(expectedBuffer, providedBuffer)
    ) {
      return true;
    }
  }

  return false;
}

export interface SendWebhookDeliveryOptions {
  subscription: WebhookSubscription;
  payload: object;
  attempt?: number;
}

export interface SendWebhookDeliveryResult {
  deliveryId: string;
  attempt: number;
  statusCode: number;
  latencyMs: number;
  signature: string;
  signatureVersion: number;
  responseBody?: string;
}

/**
 * Evaluate whether an event should be delivered to a subscription
 * based on its event-filters DSL.
 *
 * When no filters are configured, all events are delivered.
 * Otherwise the first matching rule (exact → most-specific single-segment
 * wildcard → recursive) determines delivery.
 */
export function shouldDeliverEvent(
  eventType: string,
  eventPayload: Record<string, unknown>,
  subscription: WebhookSubscription,
): boolean {
  return evaluateEventFilter(
    eventType,
    eventPayload,
    subscription.eventFilters ?? {},
  );
}

export async function sendWebhookDelivery(options: SendWebhookDeliveryOptions): Promise<SendWebhookDeliveryResult> {
  const { subscription, payload, attempt = 1 } = options;

  const { headers, receipt } = signAndPrepareDelivery(payload, subscription, attempt);

  const url = subscription.url;
  const serializedPayload = JSON.stringify(payload);
  
  let agent: https.Agent | undefined;

  if (subscription.mtlsConfig) {
    const [clientCert, clientKey, caPin] = await Promise.all([
      secretLoader.get(subscription.mtlsConfig.clientCertSecretId),
      secretLoader.get(subscription.mtlsConfig.clientKeySecretId),
      secretLoader.get(subscription.mtlsConfig.caPinSecretId),
    ]);

    const cert = new crypto.X509Certificate(clientCert);
    const now = new Date();
    const validTo = new Date(cert.validTo);

    if (now > validTo) {
      createAuditLog({
        userId: subscription.businessId,
        action: 'webhook_delivery_rejected',
        resource: 'webhook_subscription',
        resourceId: subscription.id,
        metadata: {
          reason: 'MTLS_CERT_EXPIRED',
          validTo: validTo.toISOString(),
        }
      }).catch(error => logger.error(
        { event: 'webhook_audit_log_write_failed', error },
        'Failed to write audit log',
      ));

      throw new Error(`Client certificate for subscription ${subscription.id} expired on ${validTo.toISOString()}`);
    }

    agent = new https.Agent({
      cert: clientCert,
      key: clientKey,
      ca: caPin,
      rejectUnauthorized: true,
      keepAlive: true,
    });
  }

  const startedAt = Date.now();

  let statusCode = 0;
  let responseBody: string | undefined;

  try {
    if (!isValidWebhookUrl(url) || !url.startsWith('https://')) throw new Error('Webhook URL is not allowed');
    const parsed = new URL(url);
    const records = isIP(parsed.hostname.replace(/^\[|\]$/g, ''))
      ? [{ address: parsed.hostname.replace(/^\[|\]$/g, ''), family: isIP(parsed.hostname.replace(/^\[|\]$/g, '')) }]
      : await lookup(parsed.hostname, { all: true, verbatim: true });
    if (!records.length || records.some((record) => isBlockedAddress(record.address))) throw new Error('Webhook host resolves to a restricted address');
    const vetted = records[0];
    const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const request = https.request(parsed, {
        method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
        agent, timeout: 10_000,
        lookup: ((_hostname: string, options: any, callback: any) => {
          if (options?.all) callback(null, records);
          else callback(null, vetted.address, vetted.family);
        }) as any,
      }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => { if (body.length < 2048) body += chunk.slice(0, 2048 - body.length); });
        response.on('end', () => resolve({ status: response.statusCode ?? 0, body }));
      });
      request.on('timeout', () => request.destroy(new Error('Webhook request timed out')));
      request.on('error', reject);
      request.end(serializedPayload);
    });
    statusCode = result.status;
    responseBody = result.body;
  } catch (error) {
    statusCode = 0;
    responseBody = error instanceof Error ? error.message : "Unknown networking error";
  }

  const latencyMs = Date.now() - startedAt;

  await createDeliveryReceipt({
    deliveryId: receipt.delivery_id,
    attemptNumber: attempt,
    subscriptionId: subscription.id,
    businessId: subscription.businessId,
    url,
    statusCode,
    latencyMs,
    signatureVersion: subscription.secretVersion ?? 1,
    signature: receipt.signature,
    responseBody,
  });

  return {
    deliveryId: receipt.delivery_id,
    attempt,
    statusCode,
    latencyMs,
    signature: receipt.signature,
    signatureVersion: subscription.secretVersion ?? 1,
    responseBody,
  };
}
