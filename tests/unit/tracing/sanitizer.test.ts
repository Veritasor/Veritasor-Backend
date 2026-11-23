import { describe, it, expect, vi } from "vitest";
import type { ReadableSpan, SpanExporter } from "@opentelemetry/sdk-trace-base";
import {
  DENYLIST,
  REDACTED_VALUE,
  SanitizingSpanExporter,
  isDenylisted,
  sanitizeAttributes,
} from "../../../src/tracing/sanitizer.js";

function makeSpan(overrides: Partial<ReadableSpan> = {}): ReadableSpan {
  return {
    name: "test-span",
    kind: 0,
    spanContext: () => ({
      traceId: "00000000000000000000000000000001",
      spanId: "0000000000000001",
      traceFlags: 1,
    }),
    startTime: [1000, 0],
    endTime: [1001, 0],
    status: { code: 0 },
    attributes: {},
    links: [],
    events: [],
    duration: [1, 0],
    ended: true,
    resource: {} as ReadableSpan["resource"],
    instrumentationScope: { name: "test" },
    droppedAttributesCount: 0,
    droppedEventsCount: 0,
    droppedLinksCount: 0,
    ...overrides,
  };
}

describe("tracing/sanitizer", () => {
  describe("isDenylisted & DENYLIST", () => {
    it("matches every key in DENYLIST case-insensitively", () => {
      for (const key of DENYLIST) {
        expect(isDenylisted(key)).toBe(true);
        expect(isDenylisted(key.toUpperCase())).toBe(true);
      }
    });

    it("detects mixed-case auth, credential, financial, and identity keys", () => {
      expect(isDenylisted("User.Email")).toBe(true);
      expect(isDenylisted("HTTP.REQUEST.HEADER.AUTHORIZATION")).toBe(true);
      expect(isDenylisted("Http.Response.Header.Set-Cookie")).toBe(true);
      expect(isDenylisted("Access_Token")).toBe(true);
      expect(isDenylisted("X-Api-Key")).toBe(true);
      expect(isDenylisted("X-Auth-Token")).toBe(true);
      expect(isDenylisted("Transaction_Amount")).toBe(true);
      expect(isDenylisted("Customer_Id")).toBe(true);
    });

    it("returns false for non-sensitive attribute keys", () => {
      expect(isDenylisted("http.method")).toBe(false);
      expect(isDenylisted("http.status_code")).toBe(false);
      expect(isDenylisted("service.name")).toBe(false);
      expect(isDenylisted("db.system")).toBe(false);
    });
  });

  describe("sanitizeAttributes", () => {
    it("returns undefined when attrs is undefined", () => {
      expect(sanitizeAttributes(undefined)).toBeUndefined();
    });

    it("redacts auth, cookie, email, token, financial, and identity attributes", () => {
      const attrs = {
        "http.request.header.authorization": "Bearer secret-jwt",
        "http.response.header.set-cookie": "session=abc123; HttpOnly",
        "user.email": "alice@example.com",
        email: "alice@example.com",
        "enduser.email": "alice@example.com",
        token: "tok_123",
        access_token: "acc_123",
        refresh_token: "ref_123",
        api_key: "key_123",
        apikey: "key_456",
        secret: "s3cr3t",
        password: "hunter2",
        reset_token: "rst_123",
        code: "123456",
        revenue: 1000,
        revenue_amount: 500,
        amount: 42.5,
        gross_revenue: 1200,
        net_revenue: 900,
        transaction_amount: 75,
        "user.id": "u-1",
        user_id: "u-2",
        account_id: "a-1",
        customer_id: "c-1",
        jwt: "eyJhbGciOiJIUzI1NiJ9.e30.sig",
        bearer: "tok",
        "x-api-key": "xak",
        "x-auth-token": "xat",
      };

      const cleaned = sanitizeAttributes(attrs)!;
      for (const key of Object.keys(attrs)) {
        expect(cleaned[key]).toBe(REDACTED_VALUE);
      }
    });

    it("preserves non-sensitive attributes and non-string primitives untouched", () => {
      const attrs = {
        "http.method": "POST",
        "http.status_code": 201,
        "http.retry": false,
        "http.route": "/api/v1/attestations",
        tags: ["alpha", "beta"],
        counts: [1, 2, 3],
      };

      const cleaned = sanitizeAttributes(attrs);
      expect(cleaned).toEqual(attrs);
      expect(cleaned).not.toBe(attrs);
    });

    it("recursively redacts denylisted keys inside nested objects and arrays", () => {
      const attrs = {
        payload: {
          safeField: "ok",
          count: 3,
          nullable: null,
          missing: undefined,
          email: "nested@example.com",
          nested: {
            Authorization: undefined,
            "x-api-key": "secret-key",
            token: "tok_nested",
          },
        },
        items: [
          { password: "p1", label: "first" },
          { amount: 99, label: "second" },
        ],
      } as unknown as Record<string, any>;

      const cleaned = sanitizeAttributes(attrs) as Record<string, any>;
      expect(cleaned.payload.safeField).toBe("ok");
      expect(cleaned.payload.count).toBe(3);
      expect(cleaned.payload.nullable).toBeNull();
      expect(cleaned.payload.missing).toBeUndefined();
      expect(cleaned.payload.email).toBe(REDACTED_VALUE);
      expect(cleaned.payload.nested["x-api-key"]).toBe(REDACTED_VALUE);
      expect(cleaned.payload.nested.token).toBe(REDACTED_VALUE);
      expect(cleaned.items).toEqual([
        { password: REDACTED_VALUE, label: "first" },
        { amount: REDACTED_VALUE, label: "second" },
      ]);
      // Original object must not be mutated
      expect(attrs.payload.email).toBe("nested@example.com");
    });
  });

  describe("SanitizingSpanExporter", () => {
    it("sanitizes span attributes, events, and links without mutating original spans", () => {
      const exportedSpans: ReadableSpan[] = [];
      const inner: SpanExporter = {
        export: vi.fn((spans, cb) => {
          exportedSpans.push(...spans);
          cb({ code: 0 });
        }),
        shutdown: vi.fn().mockResolvedValue(undefined),
        forceFlush: vi.fn().mockResolvedValue(undefined),
      };

      const originalSpan = makeSpan({
        attributes: {
          "http.method": "GET",
          "http.request.header.authorization": "Bearer abc",
          "user.email": "bob@example.com",
        },
        events: [
          {
            name: "auth.check",
            time: [1000, 500],
            attributes: {
              token: "secret-tok",
              "event.outcome": "success",
            },
          },
        ],
        links: [
          {
            context: {
              traceId: "00000000000000000000000000000002",
              spanId: "0000000000000002",
              traceFlags: 1,
            },
            attributes: {
              user_id: "user-42",
              "link.type": "parent",
            },
          },
        ],
      });

      const exporter = new SanitizingSpanExporter(inner);
      const callback = vi.fn();
      exporter.export([originalSpan], callback);

      expect(inner.export).toHaveBeenCalledTimes(1);
      expect(callback).toHaveBeenCalledWith({ code: 0 });

      const [sanitized] = exportedSpans;
      expect(sanitized.attributes).toEqual({
        "http.method": "GET",
        "http.request.header.authorization": REDACTED_VALUE,
        "user.email": REDACTED_VALUE,
      });
      expect(sanitized.events[0].attributes).toEqual({
        token: REDACTED_VALUE,
        "event.outcome": "success",
      });
      expect(sanitized.links[0].attributes).toEqual({
        user_id: REDACTED_VALUE,
        "link.type": "parent",
      });

      // Original span must remain untouched
      expect(originalSpan.attributes["user.email"]).toBe("bob@example.com");
      expect(originalSpan.events[0].attributes?.token).toBe("secret-tok");
      expect(originalSpan.links[0].attributes?.user_id).toBe("user-42");
    });

    it("forwards shutdown and forceFlush (and handles missing forceFlush)", async () => {
      const innerWithFlush: SpanExporter = {
        export: vi.fn(),
        shutdown: vi.fn().mockResolvedValue(undefined),
        forceFlush: vi.fn().mockResolvedValue(undefined),
      };
      const exporter1 = new SanitizingSpanExporter(innerWithFlush);
      await exporter1.forceFlush?.();
      await exporter1.shutdown();
      expect(innerWithFlush.forceFlush).toHaveBeenCalledTimes(1);
      expect(innerWithFlush.shutdown).toHaveBeenCalledTimes(1);

      const innerWithoutFlush: SpanExporter = {
        export: vi.fn(),
        shutdown: vi.fn().mockResolvedValue(undefined),
      };
      const exporter2 = new SanitizingSpanExporter(innerWithoutFlush);
      await expect(exporter2.forceFlush?.()).resolves.toBeUndefined();
    });
  });
});
