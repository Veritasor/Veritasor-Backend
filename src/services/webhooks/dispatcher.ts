import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";

export interface WebhookSubscription {
  id: string;
  businessId: string;
  url: string;
  secret: string;
  algo?: WebhookAlgorithm | string;
}

export interface WebhookDeliveryReceipt {
  delivery_id: string;
  attempt: number;
  signature: string;
  algo: string;
  timestamp: string;
}

export enum WebhookCircuitBreakerState {
  CLOSED = "closed",
  OPEN = "open",
  HALF_OPEN = "half_open",
}

interface PersistedWebhookCircuitBreakerState {
  endpointKey: string;
  state: WebhookCircuitBreakerState;
  failureCount: number;
  openedAt: number;
  halfOpenProbeCount: number;
}

interface WebhookCircuitBreakerPersistence {
  load(): Record<string, PersistedWebhookCircuitBreakerState>;
  save(states: Record<string, PersistedWebhookCircuitBreakerState>): void;
}

export interface WebhookEndpointCircuitBreakerOptions {
  endpointKey: string;
  failureThreshold?: number;
  cooldownMs?: number;
  halfOpenMaxProbes?: number;
  now?: () => number;
  persistence?: WebhookCircuitBreakerPersistence;
}

const DEFAULT_FAILURE_THRESHOLD = 5;
const DEFAULT_COOLDOWN_MS = 30_000;
const DEFAULT_HALF_OPEN_MAX_PROBES = 1;
const MIN_FAILURE_THRESHOLD = 1;
const MAX_FAILURE_THRESHOLD = 50;
const MIN_COOLDOWN_MS = 1_000;
const MAX_COOLDOWN_MS = 300_000;
const MIN_HALF_OPEN_MAX_PROBES = 1;
const MAX_HALF_OPEN_MAX_PROBES = 10;
const BREAKER_STATE_FILE_ENV = "WEBHOOK_CIRCUIT_BREAKER_STATE_FILE";
const DEFAULT_BREAKER_STATE_FILE = path.join(os.tmpdir(), "veritasor-webhook-breakers.json");

function normalizeEndpointKey(endpointKey: string): string {
  return endpointKey.trim();
}

function validatePositiveInteger(value: number, min: number, max: number, name: string): number {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }

  return value;
}

class FileWebhookCircuitBreakerPersistence implements WebhookCircuitBreakerPersistence {
  constructor(private readonly filePath: string) {}

  load(): Record<string, PersistedWebhookCircuitBreakerState> {
    try {
      if (!fs.existsSync(this.filePath)) {
        return {};
      }

      const raw = fs.readFileSync(this.filePath, "utf8").trim();
      if (!raw) {
        return {};
      }

      const parsed = JSON.parse(raw) as Record<string, PersistedWebhookCircuitBreakerState> | PersistedWebhookCircuitBreakerState;
      if (parsed && typeof parsed === "object" && "endpointKey" in parsed) {
        return { [parsed.endpointKey]: parsed };
      }

      return parsed as Record<string, PersistedWebhookCircuitBreakerState>;
    } catch {
      return {};
    }
  }

  save(states: Record<string, PersistedWebhookCircuitBreakerState>): void {
    const directory = path.dirname(this.filePath);
    fs.mkdirSync(directory, { recursive: true });

    const tempFilePath = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tempFilePath, JSON.stringify(states, null, 2));
    fs.renameSync(tempFilePath, this.filePath);
  }
}

function createDefaultPersistence(): WebhookCircuitBreakerPersistence {
  const configuredPath = process.env[BREAKER_STATE_FILE_ENV]?.trim();
  return new FileWebhookCircuitBreakerPersistence(configuredPath ?? DEFAULT_BREAKER_STATE_FILE);
}

/**
 * Per-endpoint circuit breaker for webhook delivery.
 *
 * It opens after repeated failures, enters half-open probing after a cooldown window,
 * and only allows a bounded number of probes before returning to a closed state.
 * State is persisted to disk so a restarted process can preserve breaker behavior.
 */
export class WebhookEndpointCircuitBreaker {
  private state: WebhookCircuitBreakerState;
  private failureCount = 0;
  private openedAt = 0;
  private halfOpenProbeCount = 0;
  private readonly endpointKey: string;
  private readonly failureThreshold: number;
  private readonly cooldownMs: number;
  private readonly halfOpenMaxProbes: number;
  private readonly now: () => number;
  private readonly persistence?: WebhookCircuitBreakerPersistence;

  constructor(options: WebhookEndpointCircuitBreakerOptions) {
    this.endpointKey = normalizeEndpointKey(options.endpointKey);
    this.failureThreshold = validatePositiveInteger(
      options.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD,
      MIN_FAILURE_THRESHOLD,
      MAX_FAILURE_THRESHOLD,
      "failureThreshold",
    );
    this.cooldownMs = validatePositiveInteger(
      options.cooldownMs ?? DEFAULT_COOLDOWN_MS,
      MIN_COOLDOWN_MS,
      MAX_COOLDOWN_MS,
      "cooldownMs",
    );
    this.halfOpenMaxProbes = validatePositiveInteger(
      options.halfOpenMaxProbes ?? DEFAULT_HALF_OPEN_MAX_PROBES,
      MIN_HALF_OPEN_MAX_PROBES,
      MAX_HALF_OPEN_MAX_PROBES,
      "halfOpenMaxProbes",
    );
    this.now = options.now ?? (() => Date.now());
    this.persistence = options.persistence ?? createDefaultPersistence();

    const persistedStates = this.persistence.load();
    const persistedState = persistedStates[this.endpointKey];
    if (persistedState) {
      this.state = persistedState.state;
      this.failureCount = persistedState.failureCount;
      this.openedAt = persistedState.openedAt;
      this.halfOpenProbeCount = persistedState.halfOpenProbeCount;
    } else {
      this.state = WebhookCircuitBreakerState.CLOSED;
      this.failureCount = 0;
      this.openedAt = 0;
      this.halfOpenProbeCount = 0;
    }

    if (this.state === WebhookCircuitBreakerState.OPEN && this.isCooldownElapsed()) {
      this.transitionTo(WebhookCircuitBreakerState.HALF_OPEN);
      this.halfOpenProbeCount = 0;
    }

    this.persist();
  }

  /** Returns whether the endpoint is currently allowed to attempt delivery. */
  canAttempt(): boolean {
    if (this.state === WebhookCircuitBreakerState.OPEN) {
      if (!this.isCooldownElapsed()) {
        return false;
      }

      this.transitionTo(WebhookCircuitBreakerState.HALF_OPEN);
      this.halfOpenProbeCount = 0;
      this.persist();
      return true;
    }

    if (this.state === WebhookCircuitBreakerState.HALF_OPEN) {
      if (this.halfOpenProbeCount >= this.halfOpenMaxProbes) {
        return false;
      }

      this.halfOpenProbeCount += 1;
      this.persist();
      return true;
    }

    return true;
  }

  /** Records a successful delivery and closes the breaker if it was probing. */
  recordSuccess(): void {
    if (this.state === WebhookCircuitBreakerState.HALF_OPEN) {
      this.transitionTo(WebhookCircuitBreakerState.CLOSED);
    }

    this.failureCount = 0;
    this.halfOpenProbeCount = 0;
    this.persist();
  }

  /** Records a failed delivery and opens the breaker when the threshold is reached. */
  recordFailure(): void {
    if (this.state === WebhookCircuitBreakerState.HALF_OPEN) {
      this.transitionTo(WebhookCircuitBreakerState.OPEN);
      this.openedAt = this.now();
      this.failureCount = this.failureThreshold;
      this.halfOpenProbeCount = 0;
      this.persist();
      return;
    }

    if (this.state === WebhookCircuitBreakerState.OPEN) {
      this.openedAt = this.now();
      this.persist();
      return;
    }

    this.failureCount += 1;
    if (this.failureCount >= this.failureThreshold) {
      this.transitionTo(WebhookCircuitBreakerState.OPEN);
      this.openedAt = this.now();
      this.halfOpenProbeCount = 0;
    }

    this.persist();
  }

  getState(): WebhookCircuitBreakerState {
    return this.state;
  }

  getEndpointKey(): string {
    return this.endpointKey;
  }

  private isCooldownElapsed(): boolean {
    return this.now() - this.openedAt >= this.cooldownMs;
  }

  private transitionTo(nextState: WebhookCircuitBreakerState): void {
    this.state = nextState;
  }

  private persist(): void {
    if (!this.persistence) {
      return;
    }

    const persistedStates = this.persistence.load();
    persistedStates[this.endpointKey] = this.snapshot();
    this.persistence.save(persistedStates);
  }

  private snapshot(): PersistedWebhookCircuitBreakerState {
    return {
      endpointKey: this.endpointKey,
      state: this.state,
      failureCount: this.failureCount,
      openedAt: this.openedAt,
      halfOpenProbeCount: this.halfOpenProbeCount,
    };
  }
}

const webhookBreakerRegistry = new Map<string, WebhookEndpointCircuitBreaker>();

/**
 * Returns a breaker for the supplied endpoint key, reusing the same instance for the process lifetime.
 */
export function getWebhookEndpointCircuitBreaker(
  endpointKey: string,
  options?: Partial<WebhookEndpointCircuitBreakerOptions>,
): WebhookEndpointCircuitBreaker {
  const normalizedEndpointKey = normalizeEndpointKey(endpointKey);
  const existingBreaker = webhookBreakerRegistry.get(normalizedEndpointKey);
  if (existingBreaker) {
    return existingBreaker;
  }

  const breaker = new WebhookEndpointCircuitBreaker({
    endpointKey: normalizedEndpointKey,
    ...options,
  });
  webhookBreakerRegistry.set(normalizedEndpointKey, breaker);
  return breaker;
}

/**
 * Derives a stable endpoint identifier from the subscription URL.
 */
export function getEndpointKeyFromSubscription(subscription: Pick<WebhookSubscription, "url">): string {
  try {
    const parsedUrl = new URL(subscription.url);
    return `${parsedUrl.origin}${parsedUrl.pathname}`;
  } catch {
    return subscription.url;
  }
}

/**
 * Signs the outbound payload and constructs a verifiable delivery receipt.
 * Supports algorithm negotiation (HMAC-SHA256 and Ed25519) per subscription.
 */
export function signAndPrepareDelivery(
  payload: object,
  subscription: WebhookSubscription,
  attempt: number = 1,
): { headers: Record<string, string>; receipt: WebhookDeliveryReceipt } {
  const deliveryId = crypto.randomUUID();
  const serializedPayload = JSON.stringify(payload);

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
    "X-Veritasor-Signature-Alg": normalizedAlgo,
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