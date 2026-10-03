import { describe, it, expect, beforeEach } from "vitest";
import {
  EWMADecayCounter,
  DEFAULT_EWMA_HALF_LIFE_SECONDS,
  recordWebhookFailure,
  recordWebhookSuccess,
  getWebhookEWMAScore,
  setGlobalEWMADecayHalfLife,
  getGlobalEWMADecayHalfLife,
  clearWebhookEWMACounters,
  WebhookSubscription,
} from "../../src/services/webhooks/dispatcher.js";
import { webhookDeliveryFailureEWMAScore, metricsRegistry } from "../../src/metrics.js";

describe("Webhook EWMA Failure Decay Counter & Metrics Matrix", () => {
  const mockSub: WebhookSubscription = {
    id: "sub-ewma-101",
    businessId: "biz-test-001",
    url: "https://test.client/webhook",
    secret: "test-secret-key-32b-length-required-mock",
    algo: "hmac-sha256",
  };

  beforeEach(() => {
    clearWebhookEWMACounters();
    setGlobalEWMADecayHalfLife(DEFAULT_EWMA_HALF_LIFE_SECONDS);
  });

  describe("EWMADecayCounter Unit Math & Clock Skew Resilience", () => {
    it("initializes with default half-life and zero initial value", () => {
      const now = 1_000_000;
      const counter = new EWMADecayCounter(300, now);
      expect(counter.getHalfLife()).toBe(300);
      expect(counter.getValue(now)).toBe(0);
    });

    it("accrues failure weight and decays correctly over one half-life", () => {
      const startTime = 1_000_000;
      const counter = new EWMADecayCounter(300, startTime); // half-life 300 seconds

      // Add 1 failure at startTime
      counter.add(1, startTime);
      expect(counter.getValue(startTime)).toBe(1);

      // Exactly 300 seconds (300,000 ms) later, value should decay to exactly 0.5
      const halfLifeLater = startTime + 300 * 1000;
      expect(counter.getValue(halfLifeLater)).toBeCloseTo(0.5, 6);

      // 600 seconds (2 half-lives) later, value should decay to 0.25
      const twoHalfLivesLater = startTime + 600 * 1000;
      expect(counter.getValue(twoHalfLivesLater)).toBeCloseTo(0.25, 6);
    });

    it("handles custom configurable half-life", () => {
      const startTime = 1_000_000;
      const counter = new EWMADecayCounter(60, startTime); // 60s half-life
      expect(counter.getHalfLife()).toBe(60);

      counter.add(2, startTime);
      expect(counter.getValue(startTime)).toBe(2);

      // 60 seconds later (1 half-life) -> value should be 1.0
      expect(counter.getValue(startTime + 60 * 1000)).toBeCloseTo(1.0, 6);

      // Update half-life dynamically
      counter.setHalfLife(120);
      expect(counter.getHalfLife()).toBe(120);
    });

    it("handles clock skew gracefully when timestamp is in the past (clock backwards drift)", () => {
      const now = 1_000_000;
      const counter = new EWMADecayCounter(300, now);
      counter.add(10, now);

      // Clock drift backwards into the past (50 seconds earlier)
      const pastSkewedTimestamp = now - 50 * 1000;
      
      // getValue should clamp delta to 0 and return un-inflated value 10
      expect(counter.getValue(pastSkewedTimestamp)).toBe(10);

      // Adding weight at past skewed timestamp should not move lastTimestamp backward or blow up decay
      const newScore = counter.add(1, pastSkewedTimestamp);
      expect(newScore).toBe(11);
      expect(counter.getValue(now)).toBe(11);
    });

    it("resets counter to zero", () => {
      const now = 1_000_000;
      const counter = new EWMADecayCounter(300, now);
      counter.add(5, now);
      expect(counter.getValue(now)).toBe(5);

      counter.reset(now + 1000);
      expect(counter.getValue(now + 1000)).toBe(0);
    });
  });

  describe("Global Webhook EWMA Dispatcher Integration", () => {
    it("records webhook failure and updates Prometheus metric gauge", async () => {
      const now = Date.now();
      const score1 = recordWebhookFailure(mockSub, 1, now);
      expect(score1).toBe(1);

      expect(getWebhookEWMAScore(mockSub.id, now)).toBe(1);

      // Check Prometheus registry output
      const metricsText = await metricsRegistry.metrics();
      expect(metricsText).toContain("webhook_delivery_failure_ewma_score");
      expect(metricsText).toContain(`subscription_id="${mockSub.id}"`);
      expect(metricsText).toContain(`business_id="${mockSub.businessId}"`);
    });

    it("decays score on successful webhook delivery", () => {
      const startTime = 1_000_000;
      recordWebhookFailure(mockSub, 4, startTime);
      expect(getWebhookEWMAScore(mockSub.id, startTime)).toBe(4);

      // 300 seconds later, record success
      const successTime = startTime + 300 * 1000;
      const scoreAfterSuccess = recordWebhookSuccess(mockSub, successTime);
      expect(scoreAfterSuccess).toBeCloseTo(2, 5);
      expect(getWebhookEWMAScore(mockSub.id, successTime)).toBeCloseTo(2, 5);
    });

    it("allows configuring global half-life", () => {
      setGlobalEWMADecayHalfLife(120);
      expect(getGlobalEWMADecayHalfLife()).toBe(120);

      const now = 1_000_000;
      recordWebhookFailure(mockSub, 2, now);
      expect(getWebhookEWMAScore(mockSub.id, now + 120 * 1000)).toBeCloseTo(1, 5);
    });

    it("returns 0 for non-existent subscription score query", () => {
      expect(getWebhookEWMAScore("non-existent-sub")).toBe(0);
    });
  });
});
