import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { signAndPrepareDelivery, verifyWebhookSignature, WebhookSubscription } from "../../src/services/webhooks/dispatcher";

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

  it("verifies a valid signature successfully", () => {
    const { headers } = signAndPrepareDelivery(mockEvent, mockSubscription, 1);
    
    const isValid = verifyWebhookSignature({
      payload: JSON.stringify(mockEvent),
      headers,
      secret: mockSubscription.secret,
    });

    expect(isValid).toBe(true);
  });

  it("rejects an invalid signature", () => {
    const { headers } = signAndPrepareDelivery(mockEvent, mockSubscription, 1);
    
    // Modify signature
    headers["X-Veritasor-Signature"] = "deadbeef" + headers["X-Veritasor-Signature"].substring(8);
    
    const isValid = verifyWebhookSignature({
      payload: JSON.stringify(mockEvent),
      headers,
      secret: mockSubscription.secret,
    });

    expect(isValid).toBe(false);
  });

  it("rejects a stale delivery outside the configurable freshness window", () => {
    const { headers } = signAndPrepareDelivery(mockEvent, mockSubscription, 1);
    
    // Advance time by 6 minutes (beyond default 5 min tolerance)
    vi.advanceTimersByTime(6 * 60 * 1000);
    
    const isValid = verifyWebhookSignature({
      payload: JSON.stringify(mockEvent),
      headers,
      secret: mockSubscription.secret,
    });

    expect(isValid).toBe(false);
  });

  it("accepts a delivery within the configurable freshness window", () => {
    const { headers } = signAndPrepareDelivery(mockEvent, mockSubscription, 1);
    
    // Advance time by 4 minutes (within default 5 min tolerance)
    vi.advanceTimersByTime(4 * 60 * 1000);
    
    const isValid = verifyWebhookSignature({
      payload: JSON.stringify(mockEvent),
      headers,
      secret: mockSubscription.secret,
    });

    expect(isValid).toBe(true);
  });

  it("prevents reorder attacks by requiring attempt tracking (implicit via distinct signatures)", () => {
    const attempt1 = signAndPrepareDelivery(mockEvent, mockSubscription, 1);
    const attempt2 = signAndPrepareDelivery(mockEvent, mockSubscription, 2);
    
    // The signatures must be different
    expect(attempt1.headers["X-Veritasor-Signature"]).not.toEqual(attempt2.headers["X-Veritasor-Signature"]);
    
    // If an attacker sends attempt 1 headers but changes the attempt number to 2, signature verification should fail
    const forgedHeaders = { ...attempt1.headers, "X-Veritasor-Attempt": "2" };
    
    const isValid = verifyWebhookSignature({
      payload: JSON.stringify(mockEvent),
      headers: forgedHeaders,
      secret: mockSubscription.secret,
    });

    expect(isValid).toBe(false);
  });
});