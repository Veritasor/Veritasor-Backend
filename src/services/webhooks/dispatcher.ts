import crypto from "crypto";

export type WebhookAlgorithm = "hmac-sha256" | "ed25519";

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

/**
 * Signs the outbound payload and constructs a verifiable delivery receipt.
 * Supports algorithm negotiation (HMAC-SHA256 and Ed25519) per subscription.
 */
export function signAndPrepareDelivery(
  payload: object,
  subscription: WebhookSubscription,
  attempt: number = 1
): { headers: Record<string, string>; receipt: WebhookDeliveryReceipt } {
  const deliveryId = crypto.randomUUID();
  const serializedPayload = JSON.stringify(payload);
  const dataToSign = `${deliveryId}.${attempt}.${serializedPayload}`;

  const rawAlgo = subscription.algo || "hmac-sha256";
  const algo = rawAlgo.toLowerCase();

  let signature: string;
  let normalizedAlgo: string;

  if (algo === "hmac-sha256" || algo === "hmac" || algo === "sha256") {
    normalizedAlgo = "hmac-sha256";
    signature = crypto
      .createHmac("sha256", subscription.secret)
      .update(dataToSign)
      .digest("hex");
  } else if (algo === "ed25519") {
    normalizedAlgo = "ed25519";
    try {
      let key: crypto.KeyObject | string = subscription.secret;
      if (typeof subscription.secret === "string" && !subscription.secret.includes("-----BEGIN")) {
        try {
          key = crypto.createPrivateKey(subscription.secret);
        } catch {
          key = crypto.createPrivateKey({
            key: Buffer.from(subscription.secret, "utf8"),
            format: "pem",
            type: "pkcs8"
          });
        }
      }
      signature = crypto.sign(null, Buffer.from(dataToSign), key).toString("hex");
    } catch (err: any) {
      signature = crypto.sign(null, Buffer.from(dataToSign), subscription.secret).toString("hex");
    }
  } else {
    throw new Error(`Unsupported webhook signature algorithm: ${subscription.algo}`);
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Veritasor-Delivery-Id": deliveryId,
    "X-Veritasor-Attempt": attempt.toString(),
    "X-Veritasor-Signature": signature,
    "X-Veritasor-Signature-Alg": normalizedAlgo,
  };

  const receipt: WebhookDeliveryReceipt = {
    delivery_id: deliveryId,
    attempt,
    signature,
    algo: normalizedAlgo,
    timestamp: new Date().toISOString(),
  };

  return { headers, receipt };
}

/**
 * Helper utility to verify webhook signatures using either HMAC-SHA256 or Ed25519
 */
export function verifyWebhookSignature(
  payload: object,
  deliveryId: string,
  attempt: number,
  signature: string,
  secretOrPublicKey: string,
  algo: string = "hmac-sha256"
): boolean {
  const serializedPayload = JSON.stringify(payload);
  const dataToSign = `${deliveryId}.${attempt}.${serializedPayload}`;
  const normalizedAlgo = algo.toLowerCase();

  if (normalizedAlgo === "hmac-sha256" || normalizedAlgo === "hmac" || normalizedAlgo === "sha256") {
    const expected = crypto
      .createHmac("sha256", secretOrPublicKey)
      .update(dataToSign)
      .digest("hex");
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } else if (normalizedAlgo === "ed25519") {
    return crypto.verify(
      null,
      Buffer.from(dataToSign),
      secretOrPublicKey,
      Buffer.from(signature, "hex")
    );
  } else {
    throw new Error(`Unsupported webhook signature algorithm: ${algo}`);
  }
}

export const DEFAULT_EWMA_HALF_LIFE_SECONDS = 300; // 5 minutes default half-life

/**
 * Exponentially Weighted Moving Average (EWMA) decay counter.
 * Emphasizes recent failures over historical noise with configurable half-life.
 * Clock skew safe: Prevents negative time elapsed calculation if system clock drifts backwards.
 */
export class EWMADecayCounter {
  private value: number = 0;
  private lastTimestamp: number;
  private halfLifeSeconds: number;

  constructor(halfLifeSeconds: number = DEFAULT_EWMA_HALF_LIFE_SECONDS, initialTimestamp: number = Date.now()) {
    this.halfLifeSeconds = halfLifeSeconds > 0 ? halfLifeSeconds : DEFAULT_EWMA_HALF_LIFE_SECONDS;
    this.lastTimestamp = initialTimestamp;
  }

  /**
   * Calculates current value decayed up to timestamp without adding new weight.
   * Clamps delta to >= 0 to protect against clock skew.
   */
  public getValue(now: number = Date.now()): number {
    if (this.value === 0) return 0;
    const deltaMs = Math.max(0, now - this.lastTimestamp);
    const deltaSeconds = deltaMs / 1000;
    const decayFactor = Math.pow(2, -deltaSeconds / this.halfLifeSeconds);
    return this.value * decayFactor;
  }

  /**
   * Adds an event weight to the counter at the given timestamp after applying decay.
   * Clock skew protection ensures lastTimestamp does not drift backwards.
   */
  public add(weight: number = 1, timestamp: number = Date.now()): number {
    const currentDecayed = this.getValue(timestamp);
    this.value = currentDecayed + weight;
    this.lastTimestamp = Math.max(this.lastTimestamp, timestamp);
    return this.value;
  }

  /**
   * Decay current score without adding any weight (e.g. on successful webhook attempt).
   */
  public decay(timestamp: number = Date.now()): number {
    this.value = this.getValue(timestamp);
    this.lastTimestamp = Math.max(this.lastTimestamp, timestamp);
    return this.value;
  }

  public setHalfLife(halfLifeSeconds: number): void {
    if (halfLifeSeconds > 0) {
      const now = Date.now();
      this.value = this.getValue(now);
      this.lastTimestamp = now;
      this.halfLifeSeconds = halfLifeSeconds;
    }
  }

  public getHalfLife(): number {
    return this.halfLifeSeconds;
  }

  public reset(timestamp: number = Date.now()): void {
    this.value = 0;
    this.lastTimestamp = timestamp;
  }
}

import { webhookDeliveryFailureEWMAScore } from "../../metrics.js";

let globalHalfLifeSeconds = DEFAULT_EWMA_HALF_LIFE_SECONDS;
const ewmaCounters = new Map<string, { counter: EWMADecayCounter; businessId: string; algo: string }>();

export function setGlobalEWMADecayHalfLife(seconds: number): void {
  if (seconds > 0) {
    globalHalfLifeSeconds = seconds;
    for (const entry of ewmaCounters.values()) {
      entry.counter.setHalfLife(seconds);
    }
  }
}

export function getGlobalEWMADecayHalfLife(): number {
  return globalHalfLifeSeconds;
}

export function clearWebhookEWMACounters(): void {
  ewmaCounters.clear();
  try {
    webhookDeliveryFailureEWMAScore.reset();
  } catch {
    // metrics safety fallback
  }
}

export function recordWebhookFailure(
  subscription: WebhookSubscription,
  weight: number = 1,
  timestamp: number = Date.now()
): number {
  let entry = ewmaCounters.get(subscription.id);
  if (!entry) {
    entry = {
      counter: new EWMADecayCounter(globalHalfLifeSeconds, timestamp),
      businessId: subscription.businessId || "unknown",
      algo: (subscription.algo || "hmac-sha256").toLowerCase(),
    };
    ewmaCounters.set(subscription.id, entry);
  }
  const score = entry.counter.add(weight, timestamp);
  try {
    webhookDeliveryFailureEWMAScore
      .labels(subscription.id, entry.businessId, entry.algo)
      .set(score);
  } catch {
    // metrics safety fallback
  }
  return score;
}

export function recordWebhookSuccess(
  subscription: WebhookSubscription,
  timestamp: number = Date.now()
): number {
  let entry = ewmaCounters.get(subscription.id);
  if (!entry) {
    entry = {
      counter: new EWMADecayCounter(globalHalfLifeSeconds, timestamp),
      businessId: subscription.businessId || "unknown",
      algo: (subscription.algo || "hmac-sha256").toLowerCase(),
    };
    ewmaCounters.set(subscription.id, entry);
  }
  const score = entry.counter.decay(timestamp);
  try {
    webhookDeliveryFailureEWMAScore
      .labels(subscription.id, entry.businessId, entry.algo)
      .set(score);
  } catch {
    // metrics safety fallback
  }
  return score;
}

export function getWebhookEWMAScore(
  subscriptionId: string,
  timestamp: number = Date.now()
): number {
  const entry = ewmaCounters.get(subscriptionId);
  if (!entry) return 0;
  return entry.counter.getValue(timestamp);
}