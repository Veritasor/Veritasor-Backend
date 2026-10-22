import { describe, expect, it } from "vitest";
import { shouldDeliverEvent } from "../../services/webhooks/dispatcher.js";
import {
  createWebhookSubscriptionSchema,
  evaluateEventFilter,
  type EventFilters,
} from "../webhookSubscription.js";

const cases: {
  name: string;
  eventType: string;
  filters: EventFilters;
  expected: boolean;
}[] = [
  {
    name: "prefers a specific wildcard over the bare wildcard",
    eventType: "attestation.created",
    filters: { "*": false, "attestation.*": true },
    expected: true,
  },
  {
    name: "does not let a single wildcard consume multiple segments",
    eventType: "a.b.c",
    filters: { "a.*": true, "**": false },
    expected: false,
  },
  {
    name: "prefers a wildcard in the last segment",
    eventType: "a.b.c",
    filters: { "*.b.c": false, "a.*.c": false, "a.b.*": true },
    expected: true,
  },
  {
    name: "falls through to the default when segment counts differ",
    eventType: "a.b.c",
    filters: { "a.*": true },
    expected: true,
  },
  {
    name: "matches one segment with a bare wildcard",
    eventType: "a",
    filters: { "*": true },
    expected: true,
  },
  {
    name: "uses the recursive wildcard when a single wildcard does not match",
    eventType: "a.b",
    filters: { "*": true, "**": false },
    expected: false,
  },
  {
    name: "does not let a bare wildcard match a multi-segment event",
    eventType: "a.b",
    filters: { "*": false },
    expected: true,
  },
  {
    name: "prefers an exact rule over the recursive wildcard",
    eventType: "a.b",
    filters: { "**": true, "a.b": false },
    expected: false,
  },
];

describe("event filter precedence", () => {
  it.each(cases)("$name", ({ eventType, filters, expected }) => {
    const schemaResult = evaluateEventFilter(eventType, {}, filters);
    const dispatcherResult = shouldDeliverEvent(eventType, {}, {
      id: "subscription",
      businessId: "business",
      url: "https://example.com/webhook",
      secret: "secret",
      eventFilters: filters,
    });

    expect(schemaResult).toBe(expected);
    expect(dispatcherResult).toBe(expected);
    expect(dispatcherResult).toBe(schemaResult);
  });
});

describe("webhook event filter pattern validation", () => {
  const subscription = {
    url: "https://example.com/webhook",
    secret: "s".repeat(32),
  };

  it.each(["a..b", "a.**.b", "a.**", "a*b"])(
    "rejects malformed pattern %s",
    (pattern) => {
      const result = createWebhookSubscriptionSchema.safeParse({
        ...subscription,
        eventFilters: { [pattern]: true },
      });

      expect(result.success).toBe(false);
    },
  );

  it("accepts a standalone recursive wildcard", () => {
    const result = createWebhookSubscriptionSchema.safeParse({
      ...subscription,
      eventFilters: { "**": true },
    });

    expect(result.success).toBe(true);
  });
});
