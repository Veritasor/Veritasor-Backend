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
import { BackoffError, DEFAULT_BACKOFF_OPTIONS, withBackoff } from "../../utils/backoff.js";
import { saveDeadLetter } from "./deadLetterQueue.js";

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

export interface SendWebhookDeliveryOptions {
  subscription: WebhookSubscription;
  payload: object;
  attempt?: number;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
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

function parsePositiveIntEnv(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function isRetryableStatusCode(statusCode: number): boolean {
  return statusCode === 0 || statusCode === 408 || statusCode === 429 || (statusCode >= 500 && statusCode < 600);
}

class WebhookAttemptError extends Error {
  public readonly code: string;
  public readonly result: SendWebhookDeliveryResult;
  public readonly retryable: boolean;

  constructor(result: SendWebhookDeliveryResult, retryable: boolean, cause?: unknown) {
    const code =
      result.statusCode > 0
        ? `HTTP_${result.statusCode}`
        : cause instanceof Error && "code" in cause && typeof (cause as { code?: unknown }).code === "string"
          ? (cause as { code: string }).code
          : "NETWORK_ERROR";
    super(result.responseBody || `Webhook delivery failed with status ${result.statusCode}`);
    this.name = "WebhookAttemptError";
    this.code = code;
    this.result = result;
    this.retryable = retryable;
  }
}

export async function sendWebhookDelivery(options: SendWebhookDeliveryOptions): Promise<SendWebhookDeliveryResult> {
  const {
    subscription,
    payload,
    attempt = 1,
    maxAttempts = parsePositiveIntEnv(
      process.env.WEBHOOK_DELIVERY_MAX_ATTEMPTS,
      DEFAULT_BACKOFF_OPTIONS.maxAttempts,
    ),
    baseDelayMs = parsePositiveIntEnv(
      process.env.WEBHOOK_DELIVERY_BASE_DELAY_MS,
      DEFAULT_BACKOFF_OPTIONS.baseDelayMs,
    ),
    maxDelayMs = parsePositiveIntEnv(
      process.env.WEBHOOK_DELIVERY_MAX_DELAY_MS,
      DEFAULT_BACKOFF_OPTIONS.maxDelayMs,
    ),
  } = options;

  const url = subscription.url;
  const serializedPayload = JSON.stringify(payload);

  // Validate payload size before any network / mTLS work.
  signAndPrepareDelivery(payload, subscription, attempt);

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
      }).catch(err => console.error('Failed to write audit log', err));

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

  let lastResult: SendWebhookDeliveryResult | undefined;

  try {
    return await withBackoff(
      async (retryIndex) => {
        const attemptNumber = attempt + retryIndex - 1;
        const { headers, receipt } = signAndPrepareDelivery(payload, subscription, attemptNumber);
        const startedAt = Date.now();

        let statusCode = 0;
        let responseBody: string | undefined;
        let ssrfBlocked = false;
        let networkError: unknown;

        try {
          if (!isValidWebhookUrl(url) || !url.startsWith('https://')) {
            ssrfBlocked = true;
            throw new Error('Webhook URL is not allowed');
          }
          const parsed = new URL(url);
          const records = isIP(parsed.hostname.replace(/^\[|\]$/g, ''))
            ? [{ address: parsed.hostname.replace(/^\[|\]$/g, ''), family: isIP(parsed.hostname.replace(/^\[|\]$/g, '')) }]
            : await lookup(parsed.hostname, { all: true, verbatim: true });
          if (!records.length || records.some((record) => isBlockedAddress(record.address))) {
            ssrfBlocked = true;
            throw new Error('Webhook host resolves to a restricted address');
          }
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
          networkError = error;
          statusCode = 0;
          responseBody = error instanceof Error ? error.message : "Unknown networking error";
        }

        const latencyMs = Date.now() - startedAt;

        await createDeliveryReceipt({
          deliveryId: receipt.delivery_id,
          attemptNumber,
          subscriptionId: subscription.id,
          businessId: subscription.businessId,
          url,
          statusCode,
          latencyMs,
          signatureVersion: 1,
          signature: receipt.signature,
          responseBody,
        });

        const attemptResult: SendWebhookDeliveryResult = {
          deliveryId: receipt.delivery_id,
          attempt: attemptNumber,
          statusCode,
          latencyMs,
          signature: receipt.signature,
          signatureVersion: 1,
          responseBody,
        };
        lastResult = attemptResult;

        if (!ssrfBlocked && isRetryableStatusCode(statusCode)) {
          throw new WebhookAttemptError(attemptResult, true, networkError);
        }

        return attemptResult;
      },
      {
        baseDelayMs,
        maxDelayMs,
        maxAttempts,
        shouldRetry: (error) => error instanceof WebhookAttemptError && error.retryable,
      },
    );
  } catch (error) {
    const attemptError =
      error instanceof BackoffError && error.cause instanceof WebhookAttemptError
        ? error.cause
        : error instanceof WebhookAttemptError
          ? error
          : undefined;

    if (attemptError && lastResult) {
      await saveDeadLetter(
        'webhook',
        lastResult.deliveryId,
        {
          subscriptionId: subscription.id,
          businessId: subscription.businessId,
          url: subscription.url,
          payload,
        },
        attemptError,
        error instanceof BackoffError ? error.attemptCount : maxAttempts,
      );
      return lastResult;
    }

    throw error;
  }
}
