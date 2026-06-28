/**
 * Tests for the OTel span PII sanitizer.
 *
 * Coverage targets:
 *  - isDenylisted: key matching, case-insensitivity
 *  - sanitizeAttributes: denylisted key replacement, pass-through of safe keys,
 *    undefined / empty input, nested objects, arrays
 *  - SanitizingSpanExporter: attributes, span events, span links, shutdown/forceFlush
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  REDACTED_VALUE,
  DENYLIST,
  isDenylisted,
  sanitizeAttributes,
  SanitizingSpanExporter,
} from "../../../src/tracing/sanitizer.js";
import type { ReadableSpan } from "@opentelemetry/sdk-trace-base";
import type { ExportResult } from "@opentelemetry/core";
import type { Attributes } from "@opentelemetry/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Construct a minimal ReadableSpan stub. Only the fields touched by the
 * sanitizer need to be populated; the rest stay as empty no-ops so we don't
 * have to recreate the full SDK type.
 */
function makeSpan(
  overrides: Partial<ReadableSpan> = {},
): ReadableSpan {
  return {
    name: "test-span",
    kind: 0,
    spanContext: () => ({
      traceId: "abc123",
      spanId: "def456",
      traceFlags: 1,
    }),
    startTime: [0, 0],
    endTime: [0, 0],
    status: { code: 0 },
    attributes: {},
    links: [],
    events: [],
    duration: [0, 0],
    ended: true,
    resource: {} as never,
    instrumentationLibrary: { name: "test" },
    instrumentationScope: { name: "test" },
    droppedAttributesCount: 0,
    droppedEventsCount: 0,
    droppedLinksCount: 0,
    parentSpanId: undefined,
    ...overrides,
  } as unknown as ReadableSpan;
}

/**
 * Build a fake SpanExporter whose `export` method can be inspected.
 */
function makeInnerExporter() {
  const exportedBatches: ReadableSpan[][] = [];
  let shutdownCalled = false;
  let forceFlushCalled = false;

  return {
    export(spans: ReadableSpan[], cb: (r: ExportResult) => void) {
      exportedBatches.push(spans);
      cb({ code: 0 });
    },
    async shutdown() {
      shutdownCalled = true;
    },
    async forceFlush() {
      forceFlushCalled = true;
    },
    exportedBatches,
    get shutdownCalled() {
      return shutdownCalled;
    },
    get forceFlushCalled() {
      return forceFlushCalled;
    },
  };
}

// ---------------------------------------------------------------------------
// DENYLIST membership
// ---------------------------------------------------------------------------

describe("DENYLIST", () => {
  it("contains expected PII-sensitive key categories", () => {
    // Auth
    expect(DENYLIST.has("email")).toBe(true);
    expect(DENYLIST.has("token")).toBe(true);
    expect(DENYLIST.has("password")).toBe(true);
    expect(DENYLIST.has("access_token")).toBe(true);
    expect(DENYLIST.has("refresh_token")).toBe(true);
    expect(DENYLIST.has("api_key")).toBe(true);
    expect(DENYLIST.has("secret")).toBe(true);
    // Financial
    expect(DENYLIST.has("revenue")).toBe(true);
    expect(DENYLIST.has("amount")).toBe(true);
    expect(DENYLIST.has("revenue_amount")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isDenylisted
// ---------------------------------------------------------------------------

describe("isDenylisted", () => {
  it("returns true for exact-match keys", () => {
    expect(isDenylisted("email")).toBe(true);
    expect(isDenylisted("token")).toBe(true);
    expect(isDenylisted("revenue")).toBe(true);
  });

  it("is case-insensitive", () => {
    expect(isDenylisted("Email")).toBe(true);
    expect(isDenylisted("TOKEN")).toBe(true);
    expect(isDenylisted("Revenue_Amount")).toBe(true);
    expect(isDenylisted("User.Email")).toBe(true);
    expect(isDenylisted("PASSWORD")).toBe(true);
  });

  it("returns false for safe keys", () => {
    expect(isDenylisted("http.request.method")).toBe(false);
    expect(isDenylisted("url.path")).toBe(false);
    expect(isDenylisted("rpc.system")).toBe(false);
    expect(isDenylisted("soroban.rpc.attempt")).toBe(false);
    expect(isDenylisted("veritasor.correlation_id")).toBe(false);
    expect(isDenylisted("http.response.status_code")).toBe(false);
  });

  it("handles empty string without throwing", () => {
    expect(isDenylisted("")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sanitizeAttributes
// ---------------------------------------------------------------------------

describe("sanitizeAttributes", () => {
  it("returns undefined unchanged", () => {
    expect(sanitizeAttributes(undefined)).toBeUndefined();
  });

  it("returns an empty object unchanged", () => {
    expect(sanitizeAttributes({})).toEqual({});
  });

  it("replaces a single denylisted key with the redaction sentinel", () => {
    const result = sanitizeAttributes({ email: "user@example.com" });
    expect(result).toEqual({ email: REDACTED_VALUE });
  });

  it("passes through non-denylisted keys verbatim", () => {
    const attrs: Attributes = {
      "http.request.method": "GET",
      "url.path": "/api/v1/health",
      "http.response.status_code": 200,
    };
    expect(sanitizeAttributes(attrs)).toEqual(attrs);
  });

  it("redacts multiple denylisted keys in the same attribute map", () => {
    const result = sanitizeAttributes({
      "http.request.method": "POST",
      email: "a@b.com",
      token: "tok_live_secret",
      revenue: 999.99,
      "url.path": "/checkout",
    });
    expect(result).toEqual({
      "http.request.method": "POST",
      email: REDACTED_VALUE,
      token: REDACTED_VALUE,
      revenue: REDACTED_VALUE,
      "url.path": "/checkout",
    });
  });

  it("recurses into nested object values and redacts denylisted sub-keys", () => {
    const result = sanitizeAttributes({
      "nested.object": { email: "leak@example.com", safe: "ok" } as never,
    });
    expect((result!["nested.object"] as Record<string, unknown>).email).toBe(
      REDACTED_VALUE,
    );
    expect((result!["nested.object"] as Record<string, unknown>).safe).toBe(
      "ok",
    );
  });

  it("recurses into arrays within attribute values", () => {
    const result = sanitizeAttributes({
      // A hypothetical multi-value attribute stored as an array of objects
      items: [
        { email: "x@y.com", name: "Alice" },
        { email: "z@w.com", name: "Bob" },
      ] as never,
    });
    const items = result!["items"] as Array<Record<string, unknown>>;
    expect(items[0].email).toBe(REDACTED_VALUE);
    expect(items[0].name).toBe("Alice");
    expect(items[1].email).toBe(REDACTED_VALUE);
  });

  it("does not mutate the original attributes object", () => {
    const original: Attributes = { email: "secret@domain.com", safe: "val" };
    const copy = { ...original };
    sanitizeAttributes(original);
    expect(original).toEqual(copy);
  });

  it("handles null attribute values without throwing", () => {
    const result = sanitizeAttributes({ safe: null as never });
    expect(result).toEqual({ safe: null });
  });
});

// ---------------------------------------------------------------------------
// SanitizingSpanExporter — attributes
// ---------------------------------------------------------------------------

describe("SanitizingSpanExporter (attributes)", () => {
  it("strips denylisted attribute keys before forwarding spans", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const span = makeSpan({
      attributes: {
        "http.request.method": "POST",
        email: "admin@example.com",
        token: "sk-live-abc123",
        "url.path": "/api/v1/attestations",
      },
    });

    exporter.export([span], () => {});

    const forwarded = inner.exportedBatches[0][0];
    expect(forwarded.attributes["email"]).toBe(REDACTED_VALUE);
    expect(forwarded.attributes["token"]).toBe(REDACTED_VALUE);
    expect(forwarded.attributes["http.request.method"]).toBe("POST");
    expect(forwarded.attributes["url.path"]).toBe("/api/v1/attestations");
  });

  it("does not mutate the original span's attribute map", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const originalAttrs = {
      email: "should-not-be-touched@example.com",
      safe: "ok",
    };
    const span = makeSpan({ attributes: { ...originalAttrs } });
    exporter.export([span], () => {});

    // Original span attributes should be untouched by the exporter
    expect(span.attributes["email"]).toBe(originalAttrs.email);
  });

  it("passes spans with no PII through unchanged", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const attrs: Attributes = {
      "rpc.system": "soroban",
      "rpc.method": "simulateTransaction",
      "soroban.rpc.attempt": 1,
    };
    const span = makeSpan({ attributes: { ...attrs } });
    exporter.export([span], () => {});

    expect(inner.exportedBatches[0][0].attributes).toEqual(attrs);
  });

  it("handles an empty span batch without error", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);
    expect(() => exporter.export([], () => {})).not.toThrow();
    expect(inner.exportedBatches[0]).toEqual([]);
  });

  it("redacts revenue amounts from span attributes", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const span = makeSpan({
      attributes: {
        revenue_amount: 12345.67,
        "rpc.method": "submitAttestation",
      },
    });
    exporter.export([span], () => {});

    const forwarded = inner.exportedBatches[0][0];
    expect(forwarded.attributes["revenue_amount"]).toBe(REDACTED_VALUE);
    expect(forwarded.attributes["rpc.method"]).toBe("submitAttestation");
  });
});

// ---------------------------------------------------------------------------
// SanitizingSpanExporter — span events
// ---------------------------------------------------------------------------

describe("SanitizingSpanExporter (span events)", () => {
  it("redacts denylisted keys from span event attributes", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const span = makeSpan({
      events: [
        {
          name: "user.login",
          attributes: { email: "user@example.com", success: true },
          time: [0, 0],
          droppedAttributesCount: 0,
        },
      ],
    });

    exporter.export([span], () => {});

    const event = inner.exportedBatches[0][0].events[0];
    expect(event.attributes!["email"]).toBe(REDACTED_VALUE);
    expect(event.attributes!["success"]).toBe(true);
  });

  it("handles events with no attributes", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const span = makeSpan({
      events: [
        {
          name: "something.happened",
          time: [0, 0],
          droppedAttributesCount: 0,
        },
      ],
    });

    expect(() => exporter.export([span], () => {})).not.toThrow();
    expect(inner.exportedBatches[0][0].events[0].attributes).toBeUndefined();
  });

  it("preserves event name and time after sanitization", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const span = makeSpan({
      events: [
        {
          name: "my-event",
          attributes: { token: "secret" },
          time: [1234, 5678],
          droppedAttributesCount: 0,
        },
      ],
    });

    exporter.export([span], () => {});

    const event = inner.exportedBatches[0][0].events[0];
    expect(event.name).toBe("my-event");
    expect(event.time).toEqual([1234, 5678]);
    expect(event.attributes!["token"]).toBe(REDACTED_VALUE);
  });
});

// ---------------------------------------------------------------------------
// SanitizingSpanExporter — span links
// ---------------------------------------------------------------------------

describe("SanitizingSpanExporter (span links)", () => {
  it("redacts denylisted keys from span link attributes", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const span = makeSpan({
      links: [
        {
          context: {
            traceId: "trace1",
            spanId: "span1",
            traceFlags: 1,
          },
          attributes: {
            "link.reason": "parent-call",
            email: "leak@domain.com",
            amount: 500,
          },
          droppedAttributesCount: 0,
        },
      ],
    });

    exporter.export([span], () => {});

    const link = inner.exportedBatches[0][0].links[0];
    expect(link.attributes!["email"]).toBe(REDACTED_VALUE);
    expect(link.attributes!["amount"]).toBe(REDACTED_VALUE);
    expect(link.attributes!["link.reason"]).toBe("parent-call");
    // Ensure the span context itself is preserved
    expect(link.context.traceId).toBe("trace1");
  });

  it("handles links with no attributes", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const span = makeSpan({
      links: [
        {
          context: { traceId: "t", spanId: "s", traceFlags: 1 },
          droppedAttributesCount: 0,
        },
      ],
    });

    expect(() => exporter.export([span], () => {})).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// SanitizingSpanExporter — lifecycle
// ---------------------------------------------------------------------------

describe("SanitizingSpanExporter (lifecycle)", () => {
  it("forwards shutdown to the inner exporter", async () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);
    await exporter.shutdown();
    expect(inner.shutdownCalled).toBe(true);
  });

  it("forwards forceFlush to the inner exporter when present", async () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);
    await exporter.forceFlush?.();
    expect(inner.forceFlushCalled).toBe(true);
  });

  it("resolves forceFlush gracefully when inner exporter lacks the method", async () => {
    const inner = makeInnerExporter();
    // Remove optional forceFlush to simulate a basic exporter
    (inner as Partial<typeof inner>).forceFlush = undefined;
    const exporter = new SanitizingSpanExporter(inner);
    await expect(exporter.forceFlush?.()).resolves.toBeUndefined();
  });

  it("forwards the export callback result from the inner exporter", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);
    const cb = vi.fn();

    exporter.export([makeSpan()], cb);

    expect(cb).toHaveBeenCalledTimes(1);
    expect(cb).toHaveBeenCalledWith({ code: 0 });
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("SanitizingSpanExporter (edge cases)", () => {
  it("handles spans with no attributes object", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);
    const span = makeSpan({ attributes: undefined });
    expect(() => exporter.export([span], () => {})).not.toThrow();
  });

  it("processes a large batch of spans efficiently", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);

    const spans = Array.from({ length: 500 }, (_, i) =>
      makeSpan({
        attributes: {
          "span.index": i,
          email: `user${i}@example.com`,
          "http.method": "GET",
        },
      }),
    );

    exporter.export(spans, () => {});

    const forwarded = inner.exportedBatches[0];
    expect(forwarded).toHaveLength(500);

    for (const s of forwarded) {
      expect(s.attributes["email"]).toBe(REDACTED_VALUE);
      expect(s.attributes["http.method"]).toBe("GET");
    }
  });

  it("does not redact values whose key is a safe prefix of a denylisted key", () => {
    // "emailer" is NOT "email" — prefix-only should not match
    expect(isDenylisted("emailer")).toBe(false);
    expect(isDenylisted("tokenizer")).toBe(false);
  });
});
