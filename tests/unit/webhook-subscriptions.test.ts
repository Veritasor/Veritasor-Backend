import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { eventFiltersSchema, evaluateEventFilter, createWebhookSubscriptionSchema, updateWebhookSubscriptionSchema, listWebhookSubscriptionsQuerySchema } from "../../src/schemas/webhookSubscription.js";

describe("eventFiltersSchema", () => {
  it("accepts an empty object", () => {
    const result = eventFiltersSchema.safeParse({});
    expect(result.success).toBe(true);
    expect(result.data).toEqual({});
  });

  it("defaults to empty object when omitted", () => {
    const result = eventFiltersSchema.safeParse(undefined);
    expect(result.success).toBe(true);
    expect(result.data).toEqual({});
  });

  it("accepts boolean filter values", () => {
    const result = eventFiltersSchema.safeParse({
      "attestation.created": true,
      "attestation.updated": false,
    });
    expect(result.success).toBe(true);
    expect(result.data).toEqual({
      "attestation.created": true,
      "attestation.updated": false,
    });
  });

  it("accepts object filter values with string fields", () => {
    const result = eventFiltersSchema.safeParse({
      "attestation.updated": { status: "completed" },
    });
    expect(result.success).toBe(true);
    expect(result.data?.["attestation.updated"]).toEqual({ status: "completed" });
  });

  it("accepts wildcard event types", () => {
    const result = eventFiltersSchema.safeParse({
      "attestation.*": true,
      "**": { env: "production" },
    });
    expect(result.success).toBe(true);
  });

  it("rejects invalid event-type characters", () => {
    const result = eventFiltersSchema.safeParse({
      "bad<script>": true,
    });
    expect(result.success).toBe(false);
  });

  it("rejects event types starting with a dot", () => {
    const result = eventFiltersSchema.safeParse({
      ".attestation": true,
    });
    expect(result.success).toBe(false);
  });

  it("rejects more than MAX_FILTER_RULES entries", () => {
    const filters: Record<string, boolean> = {};
    for (let i = 0; i < 51; i++) {
      filters[`event.${i}`] = true;
    }
    const result = eventFiltersSchema.safeParse(filters);
    expect(result.success).toBe(false);
  });

  it("rejects deeply nested filter objects", () => {
    const nested: Record<string, unknown> = { a: { b: { c: { d: { e: { f: "too deep" } } } } } };
    const result = eventFiltersSchema.safeParse({
      "test.event": nested,
    });
    expect(result.success).toBe(false);
  });
});

describe("evaluateEventFilter", () => {
  it("returns true when no filters are configured", () => {
    expect(evaluateEventFilter("attestation.created", {}, {})).toBe(true);
  });

  it("matches exact event type with boolean filter", () => {
    expect(
      evaluateEventFilter("attestation.created", {}, {
        "attestation.created": true,
        "attestation.updated": false,
      }),
    ).toBe(true);

    expect(
      evaluateEventFilter("attestation.updated", {}, {
        "attestation.created": true,
        "attestation.updated": false,
      }),
    ).toBe(false);
  });

  it("matches exact event type with object filter", () => {
    expect(
      evaluateEventFilter(
        "attestation.updated",
        { status: "completed" },
        { "attestation.updated": { status: "completed" } },
      ),
    ).toBe(true);

    expect(
      evaluateEventFilter(
        "attestation.updated",
        { status: "pending" },
        { "attestation.updated": { status: "completed" } },
      ),
    ).toBe(false);
  });

  it("matches segment-level wildcard", () => {
    expect(
      evaluateEventFilter("attestation.created", {}, {
        "attestation.*": true,
      }),
    ).toBe(true);

    expect(
      evaluateEventFilter("attestation.updated", { status: "completed" }, {
        "attestation.*": { status: "completed" },
      }),
    ).toBe(true);

    expect(
      evaluateEventFilter("attestation.updated", { status: "pending" }, {
        "attestation.*": { status: "completed" },
      }),
    ).toBe(false);
  });

  it("matches recursive wildcard (**)", () => {
    expect(
      evaluateEventFilter("anything.here.works", {}, { "**": true }),
    ).toBe(true);

    expect(
      evaluateEventFilter("anything", { env: "production" }, {
        "**": { env: "production" },
      }),
    ).toBe(true);

    expect(
      evaluateEventFilter("anything", { env: "staging" }, {
        "**": { env: "production" },
      }),
    ).toBe(false);
  });

  it("defaults to true when no rule matches", () => {
    expect(
      evaluateEventFilter("unknown.event", {}, {
        "attestation.created": false,
      }),
    ).toBe(true);
  });

  it("exact match takes precedence over wildcards", () => {
    expect(
      evaluateEventFilter("attestation.created", {}, {
        "attestation.created": false,
        "attestation.*": true,
        "**": true,
      }),
    ).toBe(false);
  });

  it("resolves nested payload fields via dot-notation", () => {
    const payload = { data: { status: "completed", id: "123" } };
    expect(
      evaluateEventFilter("order.shipped", payload, {
        "order.shipped": { "data.status": "completed" },
      }),
    ).toBe(true);

    expect(
      evaluateEventFilter("order.shipped", payload, {
        "order.shipped": { "data.status": "pending" },
      }),
    ).toBe(false);
  });
});

describe("createWebhookSubscriptionSchema", () => {
  it("accepts a valid subscription", () => {
    const result = createWebhookSubscriptionSchema.safeParse({
      url: "https://example.com/webhook",
      secret: "a-very-long-secret-key-that-is-over-32-chars-long",
    });
    expect(result.success).toBe(true);
    expect(result.data?.url).toBe("https://example.com/webhook");
    expect(result.data?.enabled).toBe(true); // default
  });

  it("accepts optional event filters and maxPayloadSize", () => {
    const result = createWebhookSubscriptionSchema.safeParse({
      url: "https://example.com/webhook",
      secret: "a-very-long-secret-key-that-is-over-32-chars-long",
      eventFilters: { "attestation.created": true },
      maxPayloadSize: 102400,
      enabled: false,
    });
    expect(result.success).toBe(true);
    expect(result.data?.enabled).toBe(false);
    expect(result.data?.maxPayloadSize).toBe(102400);
  });

  it("rejects a short secret", () => {
    const result = createWebhookSubscriptionSchema.safeParse({
      url: "https://example.com/webhook",
      secret: "short",
    });
    expect(result.success).toBe(false);
  });

  it("rejects invalid URLs", () => {
    const result = createWebhookSubscriptionSchema.safeParse({
      url: "not-a-url",
      secret: "a-very-long-secret-key-that-is-over-32-chars-long",
    });
    expect(result.success).toBe(false);
  });

  it("rejects javascript: scheme URLs", () => {
    const result = createWebhookSubscriptionSchema.safeParse({
      url: "javascript:alert(1)",
      secret: "a-very-long-secret-key-that-is-over-32-chars-long",
    });
    expect(result.success).toBe(false);
  });

  it("rejects extra unknown fields", () => {
    const result = createWebhookSubscriptionSchema.safeParse({
      url: "https://example.com/webhook",
      secret: "a-very-long-secret-key-that-is-over-32-chars-long",
      injectedField: "bad",
    });
    expect(result.success).toBe(false);
  });
});

describe("updateWebhookSubscriptionSchema", () => {
  it("accepts partial updates", () => {
    const result = updateWebhookSubscriptionSchema.safeParse({
      url: "https://new.example.com/webhook",
    });
    expect(result.success).toBe(true);
    expect(result.data?.url).toBe("https://new.example.com/webhook");
  });

  it("accepts an empty object", () => {
    const result = updateWebhookSubscriptionSchema.safeParse({});
    expect(result.success).toBe(true);
  });

  it("rejects invalid URLs in partial update", () => {
    const result = updateWebhookSubscriptionSchema.safeParse({
      url: "ftp://bad.example.com",
    });
    expect(result.success).toBe(false);
  });
});

describe("listWebhookSubscriptionsQuerySchema", () => {
  it("defaults limit to 20", () => {
    const result = listWebhookSubscriptionsQuerySchema.safeParse({});
    expect(result.success).toBe(true);
    expect(result.data?.limit).toBe(20);
  });

  it("coerces string limit to number", () => {
    const result = listWebhookSubscriptionsQuerySchema.safeParse({ limit: "5" });
    expect(result.success).toBe(true);
    expect(result.data?.limit).toBe(5);
  });

  it("caps limit at 100", () => {
    const result = listWebhookSubscriptionsQuerySchema.safeParse({ limit: 200 });
    expect(result.success).toBe(false);
  });

  it("accepts businessId filter", () => {
    const result = listWebhookSubscriptionsQuerySchema.safeParse({
      businessId: "biz-123",
    });
    expect(result.success).toBe(true);
    expect(result.data?.businessId).toBe("biz-123");
  });

  it("accepts enabled filter as boolean string", () => {
    const result = listWebhookSubscriptionsQuerySchema.safeParse({
      enabled: "true",
    });
    expect(result.success).toBe(true);
    expect(result.data?.enabled).toBe(true);
  });
});
