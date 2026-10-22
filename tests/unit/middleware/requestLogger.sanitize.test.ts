/**
 * Focused regression suite for `sanitizeCorrelationId` and the correlation-id
 * failure paths in `src/middleware/requestLogger.ts`.
 *
 * Scope (issue #917 — CorrelatedRequest failure handling):
 *  - `src/middleware/requestLogger.ts:48` — `return undefined` when the inbound
 *    header value is not a string (missing header, repeated headers, objects).
 *  - `src/middleware/requestLogger.ts:53` — `return undefined` when the inbound
 *    value fails the `CORRELATION_ID_PATTERN` charset/length check.
 *
 * The neighbouring normal paths are covered too so a silent behaviour change in
 * either direction (accepting junk, or rejecting valid ids) fails loudly:
 *  - length boundaries of the 8..128 pattern,
 *  - the accepted charset, the legacy `x-request-id` fallback and its precedence,
 *  - `res.locals` propagation and the generated-UUID fallback,
 *  - redaction of sensitive query parameters in the emitted request log.
 */

import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  REDACTED_HEADERS,
  REDACTED_QUERY_PARAMS,
  requestLogger,
  sanitizeCorrelationId,
} from "../../../src/middleware/requestLogger.js";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Probe app that echoes the correlation id plus the values stored on res.locals. */
function createProbeApp() {
  const app = express();
  app.use(requestLogger);
  app.get("/probe", (req, res) => {
    res.json({
      correlationId: (req as express.Request & { correlationId: string }).correlationId,
      localsRequestId: res.locals.requestId,
      localsCorrelationId: res.locals.correlationId,
      receivedBody: req.body,
    });
  });
  return app;
}

function parseJsonLogs(spy: ReturnType<typeof vi.spyOn>) {
  return spy.mock.calls.map(([line]) => JSON.parse(String(line)) as Record<string, any>);
}

function requestLog(spy: ReturnType<typeof vi.spyOn>) {
  const entry = parseJsonLogs(spy).find((line) => line.type === "request");
  if (!entry) throw new Error("no request log entry was emitted");
  return entry;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sanitizeCorrelationId — non-string inbound values (failure path 1)", () => {
  it("returns undefined for every non-string primitive", () => {
    for (const value of [undefined, null, 42, 0, true, false, 1n, Symbol("cid")]) {
      expect(sanitizeCorrelationId(value)).toBeUndefined();
    }
  });

  it("returns undefined for plain objects and Maps", () => {
    expect(sanitizeCorrelationId({})).toBeUndefined();
    expect(sanitizeCorrelationId({ toString: () => "trace-123456" })).toBeUndefined();
    expect(sanitizeCorrelationId(new Map())).toBeUndefined();
  });

  it("returns undefined for an empty repeated-header array", () => {
    expect(sanitizeCorrelationId([])).toBeUndefined();
  });

  it("uses the first value of a repeated-header array (Express gives string[])", () => {
    expect(sanitizeCorrelationId(["trace-123456", "trace-654321"])).toBe("trace-123456");
  });

  it("returns undefined when the first repeated-header value itself is invalid", () => {
    expect(sanitizeCorrelationId(["bad id", "trace-123456"])).toBeUndefined();
  });

  it("returns undefined when the first repeated-header value is not a string", () => {
    expect(sanitizeCorrelationId([42, "trace-123456"])).toBeUndefined();
  });

  it("does not coerce non-string values into a usable id", () => {
    const hostile = {
      toString: () => "trace-123456",
      valueOf: () => "trace-123456",
      length: 12,
    };
    expect(sanitizeCorrelationId(hostile)).toBeUndefined();
  });
});

describe("sanitizeCorrelationId — length boundaries", () => {
  it("rejects ids shorter than 8 characters", () => {
    expect(sanitizeCorrelationId("")).toBeUndefined();
    expect(sanitizeCorrelationId("a")).toBeUndefined();
    expect(sanitizeCorrelationId("a".repeat(7))).toBeUndefined();
  });

  it("accepts ids of exactly 8 characters (lower bound)", () => {
    expect(sanitizeCorrelationId("a".repeat(8))).toBe("a".repeat(8));
  });

  it("accepts ids of exactly 128 characters (upper bound)", () => {
    const max = "a".repeat(128);
    expect(sanitizeCorrelationId(max)).toBe(max);
  });

  it("rejects ids longer than 128 characters", () => {
    expect(sanitizeCorrelationId("a".repeat(129))).toBeUndefined();
  });

  it("applies the length limit after trimming", () => {
    expect(sanitizeCorrelationId(`  ${"a".repeat(8)}  `)).toBe("a".repeat(8));
    expect(sanitizeCorrelationId(`  ${"a".repeat(129)}  `)).toBeUndefined();
  });
});

describe("sanitizeCorrelationId — accepted charset", () => {
  it("accepts every allowed character class", () => {
    const allowed = "abcABC018._:/=@-";
    expect(allowed.length).toBeGreaterThanOrEqual(8);
    expect(sanitizeCorrelationId(allowed)).toBe(allowed);
  });

  it("accepts realistic uuid, w3c traceparent and vendor ids", () => {
    const samples = [
      "123e4567-e89b-12d3-a456-426614174000",
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "trace_id=abc-123",
      "req@edge-1.2.3/4",
    ];
    for (const sample of samples) {
      expect(sanitizeCorrelationId(sample)).toBe(sample);
    }
  });

  it("rejects every character outside the allow-list (header-injection surface)", () => {
    const rejected = [
      "bad id 123",
      "quoted\"id",
      "semi;colon",
      "amp&ersand",
      "percent%id",
      "hash#id",
      "paren(thesis)",
      "plus+sign",
      "comma,id",
      "bang!id",
      "dollar$id",
      "star*id",
      "back\\slash",
      "pipe|id",
      "caret^id",
      "tilde~id",
      "bracket[id]",
      "brace{id}",
      "question?id",
      "less<than",
      "greater>than",
      "apostrophe'id",
      "back`tick",
      "new\nline",
      "carriage\rreturn",
      "tab\tid",
      "null\u0000byte",
      "unit\u001fsep",
    ];
    for (const candidate of rejected) {
      expect(sanitizeCorrelationId(candidate)).toBeUndefined();
    }
  });
});

describe("requestLogger — legacy header fallback and precedence", () => {
  it("falls back to the legacy x-request-id header when x-correlation-id is absent", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await request(createProbeApp())
      .get("/probe")
      .set("x-request-id", "legacy-trace-1")
      .expect(200);

    expect(res.headers["x-correlation-id"]).toBe("legacy-trace-1");
    expect(res.headers["x-request-id"]).toBe("legacy-trace-1");
    expect(res.body.correlationId).toBe("legacy-trace-1");
    expect(requestLog(consoleSpy).correlationId).toBe("legacy-trace-1");
  });

  it("prefers x-correlation-id over a valid legacy x-request-id", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await request(createProbeApp())
      .get("/probe")
      .set("x-correlation-id", "primary-trace-1")
      .set("x-request-id", "legacy-trace-1")
      .expect(200);

    expect(res.body.correlationId).toBe("primary-trace-1");
    expect(res.headers["x-request-id"]).toBe("primary-trace-1");
    expect(JSON.stringify(parseJsonLogs(consoleSpy))).not.toContain("legacy-trace-1");
  });

  it("ignores an invalid x-correlation-id in favour of a valid legacy header", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await request(createProbeApp())
      .get("/probe")
      .set("x-correlation-id", "bad id 123")
      .set("x-request-id", "legacy-trace-2")
      .expect(200);

    expect(res.body.correlationId).toBe("legacy-trace-2");
    const logs = JSON.stringify(parseJsonLogs(consoleSpy));
    expect(logs).not.toContain("bad id 123");
  });

  it("generates a UUID when both inbound headers are invalid", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await request(createProbeApp())
      .get("/probe")
      .set("x-correlation-id", "short")
      .set("x-request-id", "also short")
      .expect(200);

    expect(res.headers["x-correlation-id"]).toMatch(UUID_V4);
    expect(JSON.stringify(parseJsonLogs(consoleSpy))).not.toContain("also short");
  });

  it("stores the resolved id on res.locals for downstream middleware", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await request(createProbeApp())
      .get("/probe")
      .set("x-correlation-id", "locals-trace-1")
      .expect(200);

    expect(res.body.localsRequestId).toBe("locals-trace-1");
    expect(res.body.localsCorrelationId).toBe("locals-trace-1");
  });

  it("sanitizes (trims) the accepted inbound id before propagating it", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await request(createProbeApp())
      .get("/probe")
      .set("x-correlation-id", "  padded-trace-1  ")
      .expect(200);

    expect(res.body.correlationId).toBe("padded-trace-1");
    expect(res.headers["x-correlation-id"]).toBe("padded-trace-1");
  });
});

describe("requestLogger — log redaction invariants", () => {
  it("redacts sensitive query parameters before logging", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await request(createProbeApp())
      .get("/probe?token=q-secret&access_token=at-secret&api_key=ak-secret&page=2&businessId=biz_1")
      .set("x-correlation-id", "redact-trace-1")
      .expect(200);

    const entry = requestLog(consoleSpy);
    expect(entry.query).toMatchObject({
      token: "[REDACTED]",
      access_token: "[REDACTED]",
      api_key: "[REDACTED]",
      page: "2",
      businessId: "biz_1",
    });

    const serialized = JSON.stringify(parseJsonLogs(consoleSpy));
    for (const secret of ["q-secret", "at-secret", "ak-secret"]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("redacts sensitive query parameters case-insensitively", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await request(createProbeApp())
      .get("/probe?TOKEN=upper-secret&PASSWORD=pw-secret")
      .set("x-correlation-id", "redact-trace-2")
      .expect(200);

    const serialized = JSON.stringify(parseJsonLogs(consoleSpy));
    expect(serialized).not.toContain("upper-secret");
    expect(serialized).not.toContain("pw-secret");
    expect(requestLog(consoleSpy).query).toMatchObject({
      TOKEN: "[REDACTED]",
      PASSWORD: "[REDACTED]",
    });
  });

  it("never logs request bodies or authentication headers", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await request(createProbeApp())
      .get("/probe")
      .set("authorization", "Bearer body-secret-token")
      .set("cookie", "session=cookie-secret")
      .set("x-correlation-id", "redact-trace-3")
      .expect(200);

    const logs = parseJsonLogs(consoleSpy);
    const serialized = JSON.stringify(logs);
    expect(serialized).not.toContain("body-secret-token");
    expect(serialized).not.toContain("cookie-secret");
    expect(requestLog(consoleSpy)).not.toHaveProperty("body");
    expect(requestLog(consoleSpy)).not.toHaveProperty("headers");
  });

  it("keeps the operator-facing redaction lists in contract with the middleware", () => {
    for (const header of ["authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"]) {
      expect(REDACTED_HEADERS.has(header)).toBe(true);
    }
    for (const param of ["token", "access_token", "refresh_token", "api_key", "secret", "password"]) {
      expect(REDACTED_QUERY_PARAMS.has(param)).toBe(true);
    }
  });
});
