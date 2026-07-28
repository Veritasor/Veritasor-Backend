import { describe, it, expect, vi } from "vitest";
import {
  signAndPrepareDelivery,
  WebhookSubscription,
  WebhookCircuitBreakerState,
  WebhookEndpointCircuitBreaker,
} from "../../src/services/webhooks/dispatcher";

describe("Business Fan-out Webhooks Dispatch Verification Matrix", () => {
  const mockSubscription: WebhookSubscription = {
    id: "sub-123",
    businessId: "biz-456",
    url: "https://client.site/webhook",
    secret: "super-secret-crypto-signing-key-string-padding-32b",
  };

  const mockEvent = { event: "attestation.created", root: "0xhash" };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-28T00:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("constructs a signature receipt conforming to structured parameters", () => {
    const { headers, receipt } = signAndPrepareDelivery(mockEvent, mockSubscription, 1);

    expect(headers["X-Veritasor-Signature"]).toBeDefined();
    expect(headers["X-Veritasor-Timestamp"]).toBeDefined();
    expect(receipt).toMatchObject({
      delivery_id: expect.any(String),
      attempt: 1,
      signature: headers["X-Veritasor-Signature"],
      timestamp: headers["X-Veritasor-Timestamp"],
    });
  });

  it("opens after repeated failures and blocks delivery until the cooldown elapses", () => {
    const now = vi.fn(() => 0);
    const breaker = new WebhookEndpointCircuitBreaker({
      endpointKey: "webhook-endpoint-1",
      failureThreshold: 2,
      cooldownMs: 1000,
      halfOpenMaxProbes: 1,
      now,
    });

    expect(breaker.canAttempt()).toBe(true);
    breaker.recordFailure();
    expect(breaker.canAttempt()).toBe(true);
    breaker.recordFailure();

    expect(breaker.getState()).toBe(WebhookCircuitBreakerState.OPEN);
    expect(breaker.canAttempt()).toBe(false);

    now.mockReturnValue(1500);
    expect(breaker.canAttempt()).toBe(true);
  });

  it("allows one probe in half-open mode and closes on success", () => {
    const now = vi.fn(() => 0);
    const breaker = new WebhookEndpointCircuitBreaker({
      endpointKey: "webhook-endpoint-2",
      failureThreshold: 1,
      cooldownMs: 1000,
      halfOpenMaxProbes: 1,
      now,
    });

    breaker.recordFailure();
    expect(breaker.getState()).toBe(WebhookCircuitBreakerState.OPEN);

    now.mockReturnValue(1500);
    expect(breaker.canAttempt()).toBe(true);
    breaker.recordSuccess();

    expect(breaker.getState()).toBe(WebhookCircuitBreakerState.CLOSED);
    expect(breaker.canAttempt()).toBe(true);
  });

  it("persists breaker state across instances for the same endpoint", () => {
    const storage = new Map<string, unknown>();
    const persistence = {
      load: () => Object.fromEntries(storage.entries()),
      save: (states: Record<string, unknown>) => {
        storage.clear();
        Object.entries(states).forEach(([key, value]) => storage.set(key, value));
      },
    };

    const breaker = new WebhookEndpointCircuitBreaker({
      endpointKey: "persisted-endpoint",
      failureThreshold: 1,
      cooldownMs: 1000,
      halfOpenMaxProbes: 1,
      persistence: persistence as never,
    });

    breaker.recordFailure();

    const restoredBreaker = new WebhookEndpointCircuitBreaker({
      endpointKey: "persisted-endpoint",
      failureThreshold: 1,
      cooldownMs: 1000,
      halfOpenMaxProbes: 1,
      persistence: persistence as never,
    });

    expect(restoredBreaker.getState()).toBe(WebhookCircuitBreakerState.OPEN);
    expect(restoredBreaker.canAttempt()).toBe(false);
  });
});