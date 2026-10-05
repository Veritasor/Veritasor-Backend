/**
 * Invariant / boundary coverage for the OTel span PII sanitizer.
 *
 * `tests/unit/tracing/sanitizer.test.ts` already exercises the happy paths of
 * `sanitizeAttributes` and `SanitizingSpanExporter`. This suite pins the parts
 * of `src/tracing/sanitizer.ts` that a future edit is most likely to break
 * silently:
 *
 *  - the exact `REDACTED_VALUE` sentinel and the normalisation invariant of
 *    `DENYLIST` (every stored key must already be lower-case, otherwise
 *    `isDenylisted` can never reach it);
 *  - the full denylist contract (every declared category/key is reachable);
 *  - `isDenylisted` boundary inputs (whitespace, case, prefixes, unicode);
 *  - deep recursion through nested objects/arrays and the guarantee that
 *    redacting a nested key never corrupts safe siblings or the input object.
 */
import { describe, it, expect } from "vitest";
import {
  REDACTED_VALUE,
  DENYLIST,
  isDenylisted,
  sanitizeAttributes,
  SanitizingSpanExporter,
} from "../../../src/tracing/sanitizer.js";
import type { ReadableSpan } from "@opentelemetry/sdk-trace-base";
import type { ExportResult } from "@opentelemetry/core";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSpan(overrides: Partial<ReadableSpan> = {}): ReadableSpan {
  return {
    name: "test-span",
    kind: 0,
    spanContext: () => ({ traceId: "abc", spanId: "def", traceFlags: 1 }),
    startTime: [0, 0],
    endTime: [0, 0],
    status: { code: 0 },
    attributes: {},
    links: [],
    events: [],
    duration: [0, 0],
    ended: true,
    resource: {} as never,
    instrumentationScope: { name: "test" },
    droppedAttributesCount: 0,
    droppedEventsCount: 0,
    droppedLinksCount: 0,
    parentSpanId: undefined,
    ...overrides,
  } as unknown as ReadableSpan;
}

function makeInnerExporter() {
  const exportedBatches: ReadableSpan[][] = [];
  return {
    export(spans: ReadableSpan[], cb: (r: ExportResult) => void) {
      exportedBatches.push(spans);
      cb({ code: 0 });
    },
    async shutdown() {},
    async forceFlush() {},
    exportedBatches,
  };
}

// ---------------------------------------------------------------------------
// REDACTED_VALUE
// ---------------------------------------------------------------------------

describe("REDACTED_VALUE", () => {
  it("is the documented, non-empty sentinel", () => {
    expect(REDACTED_VALUE).toBe("[REDACTED]");
    expect(REDACTED_VALUE.length).toBeGreaterThan(0);
  });

  it("is used verbatim for both top-level and nested redactions", () => {
    const top = sanitizeAttributes({ email: "a@b.com" });
    expect(top!["email"]).toBe(REDACTED_VALUE);

    const nested = sanitizeAttributes({
      "nested.blob": { token: "secret" } as never,
    });
    expect((nested!["nested.blob"] as Record<string, unknown>).token).toBe(
      REDACTED_VALUE,
    );
  });
});

// ---------------------------------------------------------------------------
// DENYLIST
// ---------------------------------------------------------------------------

describe("DENYLIST", () => {
  // The exact expected set. Keeping this list explicit means an accidental
  // deletion or a typo in `sanitizer.ts` fails the suite instead of silently
  // un-redacting a field.
  const EXPECTED = [
    // Auth / credential fields
    "user.email", "email", "enduser.email",
    "http.request.header.authorization", "http.response.header.set-cookie",
    "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
    "password", "reset_token", "code",
    // Revenue / financial data
    "revenue", "revenue_amount", "amount", "gross_revenue", "net_revenue",
    "transaction_amount",
    // Identity
    "user.id", "user_id", "account_id", "customer_id",
    // Raw token values
    "jwt", "bearer", "x-api-key", "x-auth-token",
  ];

  it("contains every declared PII key", () => {
    for (const key of EXPECTED) {
      expect(DENYLIST.has(key), `DENYLIST is missing "${key}"`).toBe(true);
    }
  });

  it("has no unexpected additions", () => {
    expect([...DENYLIST].sort()).toEqual([...EXPECTED].sort());
  });

  it("stores every key lower-cased and trimmed (normalisation invariant)", () => {
    for (const key of DENYLIST) {
      expect(key, `"${key}" is unreachable via isDenylisted`).toBe(key.toLowerCase());
      expect(key.trim()).toBe(key);
      expect(key.length).toBeGreaterThan(0);
    }
  });

  it("rejects every stored key case-insensitively through isDenylisted", () => {
    for (const key of DENYLIST) {
      expect(isDenylisted(key)).toBe(true);
      expect(isDenylisted(key.toUpperCase())).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// isDenylisted — boundary inputs
// ---------------------------------------------------------------------------

describe("isDenylisted (boundary inputs)", () => {
  it("does not trim whitespace around a key", () => {
    expect(isDenylisted(" email")).toBe(false);
    expect(isDenylisted("email ")).toBe(false);
    expect(isDenylisted("\temail")).toBe(false);
    expect(isDenylisted("\nTOKEN")).toBe(false);
  });

  it("does not match substrings or prefixes", () => {
    expect(isDenylisted("email_address")).toBe(false);
    expect(isDenylisted("my_token")).toBe(false);
    expect(isDenylisted("revenue_total")).toBe(false);
    expect(isDenylisted("user.id.")).toBe(false);
  });

  it("matches the newly guarded token headers case-insensitively", () => {
    expect(isDenylisted("x-api-key")).toBe(true);
    expect(isDenylisted("X-API-KEY")).toBe(true);
    expect(isDenylisted("x-auth-token")).toBe(true);
    expect(isDenylisted("JWT")).toBe(true);
    expect(isDenylisted("Bearer")).toBe(true);
  });

  it("treats non-string coercible keys deterministically", () => {
    // The signature is `string`, but defensive callers/mocks exist. `Set.has`
    // is strict, so a non-lower-cased lookup still falls back to the lowercased
    // query and therefore still matches.
    expect(isDenylisted("EMAIL".toLowerCase())).toBe(true);
    expect(isDenylisted("" as string)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sanitizeAttributes — deep recursion / boundary inputs
// ---------------------------------------------------------------------------

describe("sanitizeAttributes (deep recursion)", () => {
  it("redacts denylisted keys two levels deep and preserves safe siblings", () => {
    const result = sanitizeAttributes({
      outer: {
        inner: { email: "deep@example.com", safe: 1 },
        keep: "ok",
      } as never,
      "http.method": "POST",
    });
    const outer = result!["outer"] as Record<string, any>;
    expect(outer.inner.email).toBe(REDACTED_VALUE);
    expect(outer.inner.safe).toBe(1);
    expect(outer.keep).toBe("ok");
    expect(result!["http.method"]).toBe("POST");
  });

  it("redacts denylisted keys inside objects nested inside arrays", () => {
    const result = sanitizeAttributes({
      batch: [
        { meta: { token: "t1" }, id: "a" },
        { meta: { token: "t2" }, id: "b" },
      ] as never,
    });
    const batch = result!["batch"] as Array<Record<string, any>>;
    expect(batch[0].meta.token).toBe(REDACTED_VALUE);
    expect(batch[1].meta.token).toBe(REDACTED_VALUE);
    expect(batch[0].id).toBe("a");
    expect(batch[1].id).toBe("b");
  });

  it("replaces the whole value when a denylisted key maps to an object", () => {
    // A denylisted *key* wins over recursion: the entire nested value is
    // replaced, so nothing inside it can leak.
    const result = sanitizeAttributes({
      token: { nested: "leak" } as never,
    });
    expect(result!["token"]).toBe(REDACTED_VALUE);
  });

  it("does not mutate deep structures in the input", () => {
    const original = {
      outer: { inner: { email: "deep@example.com", safe: 1 } },
      "http.method": "POST",
    };
    const snapshot = JSON.parse(JSON.stringify(original));
    sanitizeAttributes(original as never);
    expect(original).toEqual(snapshot);
    expect(original.outer.inner.email).toBe("deep@example.com");
  });

  it("passes bigint-valued safe keys through untouched", () => {
    const result = sanitizeAttributes({ "soroban.ledger": 42n as never });
    expect(result!["soroban.ledger"]).toBe(42n);
  });

  it("returns undefined for undefined and an empty object for {}", () => {
    expect(sanitizeAttributes(undefined)).toBeUndefined();
    expect(sanitizeAttributes({})).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// SanitizingSpanExporter — deep attributes survive the round trip
// ---------------------------------------------------------------------------

describe("SanitizingSpanExporter (deep attribute redaction)", () => {
  it("redacts nested span attributes without dropping safe values", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);
    const span = makeSpan({
      attributes: {
        "business.blob": { email: "leak@example.com", tier: "gold" } as never,
        "rpc.method": "submitAttestation",
      },
    });

    exporter.export([span], () => {});

    const forwarded = inner.exportedBatches[0][0];
    const blob = forwarded.attributes["business.blob"] as Record<string, unknown>;
    expect(blob.email).toBe(REDACTED_VALUE);
    expect(blob.tier).toBe("gold");
    expect(forwarded.attributes["rpc.method"]).toBe("submitAttestation");
  });

  it("redacts nested event attributes", () => {
    const inner = makeInnerExporter();
    const exporter = new SanitizingSpanExporter(inner);
    const span = makeSpan({
      events: [
        {
          name: "checkout",
          attributes: { payload: { token: "t", ok: true } as never },
          time: [0, 0],
          droppedAttributesCount: 0,
        },
      ],
    });

    exporter.export([span], () => {});

    const ev = inner.exportedBatches[0][0].events[0];
    const payload = ev.attributes!["payload"] as Record<string, unknown>;
    expect(payload.token).toBe(REDACTED_VALUE);
    expect(payload.ok).toBe(true);
  });
});
