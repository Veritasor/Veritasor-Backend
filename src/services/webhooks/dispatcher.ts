import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";

export interface WebhookSubscription {
  id: string;
  businessId: string;
  url: string;
  secret: string;
}

export interface WebhookDeliveryReceipt {
  delivery_id: string;
  attempt: number;
  signature: string;
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
  load(): PersistedWebhookCircuitBreakerState | null;
  save(state: PersistedWebhookCircuitBreakerState): void;
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

  load(): PersistedWebhookCircuitBreakerState | null {
    try {
      if (!fs.existsSync(this.filePath)) {
        return null;
      }

      const raw = fs.readFileSync(this.filePath, "utf8").trim();
      if (!raw) {
        return null;
      }

      return JSON.parse(raw) as PersistedWebhookCircuitBreakerState;
    } catch {
      return null;
    }
  }

  save(state: PersistedWebhookCircuitBreakerState): void {
    const directory = path.dirname(this.filePath);
    fs.mkdirSync(directory, { recursive: true });

    const tempFilePath = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tempFilePath, JSON.stringify(state, null, 2));
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

    const persistedState = this.persistence.load();
    if (persistedState && persistedState.endpointKey === this.endpointKey) {
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
    this.persistence?.save(this.snapshot());
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
 * Signs the outbound payload and constructs a verifiable delivery receipt
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
    .update(`${deliveryId}.${attempt}.${serializedPayload}`)
    .digest("hex");

  const headers = {
    "Content-Type": "application/json",
    "X-Veritasor-Delivery-Id": deliveryId,
    "X-Veritasor-Attempt": attempt.toString(),
    "X-Veritasor-Signature": signature,
  };

  const receipt: WebhookDeliveryReceipt = {
    delivery_id: deliveryId,
    attempt,
    signature,
    timestamp: new Date().toISOString(),
  };

  return { headers, receipt };
}