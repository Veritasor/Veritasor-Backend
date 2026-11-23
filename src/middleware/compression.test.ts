import { describe, it, expect, vi } from "vitest";
import zlib from "node:zlib";
import { compressionMiddleware, disableCompression, selectEncoding } from "./compression.js";
import type { CompressionOptions } from "./compression.js";

/**
 * Regression + boundary suite for the compression middleware's failure / empty
 * result paths.
 *
 * Named evidence from the issue:
 *   - `src/middleware/compression.ts:102` → `if (!acceptEncoding) return null;`
 *   - `src/middleware/compression.ts:126` → `return null;`
 *
 * `selectEncoding` is the single decision point for "should this response be
 * encoded at all". Both `null` returns mean "send the body uncompressed", so
 * every downstream guard is asserted against a real response object here rather
 * than in isolation.
 */

function toBuffer(chunk: unknown, encoding?: BufferEncoding): Buffer {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (typeof chunk === "string") return Buffer.from(chunk, encoding ?? "utf8");
  if (chunk instanceof Uint8Array) return Buffer.from(chunk);
  return Buffer.from(String(chunk), encoding ?? "utf8");
}

interface FakeRes {
  statusCode: number;
  body?: Buffer;
  headers: Map<string, string | string[]>;
  getHeader(name: string): string | string[] | undefined;
  setHeader(name: string, value: string | string[] | number): void;
  removeHeader(name: string): void;
  vary(field: string): void;
  write: (chunk: unknown, ...rest: unknown[]) => boolean;
  end: (chunk?: unknown, ...rest: unknown[]) => FakeRes;
}

/**
 * Minimal Express-like response. The middleware swaps `write`/`end`, so the
 * originals here record the final body exactly like a real socket would.
 */
function createRes(init: { statusCode?: number; headers?: Record<string, string | string[]> } = {}): FakeRes {
  const headers = new Map<string, string | string[]>();
  for (const [key, value] of Object.entries(init.headers ?? {})) {
    headers.set(key.toLowerCase(), value);
  }

  const res: FakeRes = {
    statusCode: init.statusCode ?? 200,
    body: undefined,
    headers,
    getHeader(name) {
      return headers.get(name.toLowerCase());
    },
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value as string | string[]);
    },
    removeHeader(name) {
      headers.delete(name.toLowerCase());
    },
    vary(field) {
      const current = headers.get("vary");
      headers.set("vary", current ? `${current}, ${field}` : field);
    },
    // Replacements below are the pre-middleware "socket" implementation.
    write: () => true,
    end: () => res,
  };

  res.write = (chunk, ...rest) => {
    if (chunk == null) return true;
    const encoding = typeof rest[0] === "string" ? (rest[0] as BufferEncoding) : undefined;
    res.body = Buffer.concat([res.body ?? Buffer.alloc(0), toBuffer(chunk, encoding)]);
    return true;
  };

  res.end = (chunk, ...rest) => {
    if (typeof chunk === "function") return res;
    if (chunk != null) {
      const encoding = typeof rest[0] === "string" ? (rest[0] as BufferEncoding) : undefined;
      res.body = Buffer.concat([res.body ?? Buffer.alloc(0), toBuffer(chunk, encoding)]);
    }
    return res;
  };

  return res;
}

interface RunOptions {
  /** Omit entirely to simulate a client that sends no Accept-Encoding header. */
  acceptEncoding?: string;
  body?: string | Buffer;
  contentType?: string;
  statusCode?: number;
  headers?: Record<string, string | string[]>;
  options?: CompressionOptions;
  /** Runs after the middleware installs its overrides and before `end`. */
  beforeEnd?: (res: FakeRes) => void;
}

function run(options: RunOptions = {}) {
  const req: { headers: Record<string, unknown> } = { headers: {} };
  if (options.acceptEncoding !== undefined) {
    req.headers["accept-encoding"] = options.acceptEncoding;
  }

  const res = createRes({ statusCode: options.statusCode, headers: options.headers });
  if (options.contentType !== undefined) res.setHeader("Content-Type", options.contentType);

  const next = vi.fn();
  compressionMiddleware(options.options)(req as never, res as never, next);

  if (options.beforeEnd) options.beforeEnd(res);
  res.end(options.body ?? "");

  return { req, res, next };
}

const BIG_BODY = JSON.stringify({ status: "ok", filler: "x".repeat(4096) });

// ── selectEncoding: the `return null` branches ─────────────────────────────

describe("selectEncoding - empty / failure results", () => {
  it("returns null when Accept-Encoding is absent (line 102 guard)", () => {
    expect(selectEncoding(undefined)).toBeNull();
  });

  it("returns null when Accept-Encoding is the empty string", () => {
    expect(selectEncoding("")).toBeNull();
  });

  it("returns null when the client only advertises identity", () => {
    expect(selectEncoding("identity")).toBeNull();
  });

  it("returns null when every supported encoding is disabled with q=0 (line 126)", () => {
    expect(selectEncoding("gzip;q=0, br;q=0, zstd;q=0")).toBeNull();
  });

  it("returns null when a disabled wildcard is the only remaining entry", () => {
    expect(selectEncoding("gzip;q=0, *;q=0")).toBeNull();
  });

  it("returns null for a header made only of separators/whitespace", () => {
    expect(selectEncoding(" , , ")).toBeNull();
  });

  it("returns null when only unknown encodings are advertised", () => {
    expect(selectEncoding("deflate, exi")).toBeNull();
  });
});

describe("selectEncoding - neighbouring normal path", () => {
  it("prefers zstd over brotli over gzip", () => {
    expect(selectEncoding("gzip, br, zstd")).toBe("zstd");
  });

  it("prefers brotli when zstd is not advertised", () => {
    expect(selectEncoding("gzip, br")).toBe("br");
  });

  it("falls back to gzip when it is the only supported encoding", () => {
    expect(selectEncoding("gzip")).toBe("gzip");
  });

  it("treats a positive wildcard as support for otherwise-unlisted encodings", () => {
    expect(selectEncoding("*")).toBe("zstd");
  });

  it("treats encoding names case-insensitively", () => {
    expect(selectEncoding("GZIP")).toBe("gzip");
  });

  it("ignores malformed q-values and keeps the default q=1", () => {
    expect(selectEncoding("gzip;q=abc")).toBe("gzip");
  });

  it("honours fractional q-values when ranking candidates", () => {
    expect(selectEncoding("br;q=0.5, gzip;q=0.9")).toBe("br");
  });

  it("skips empty segments without losing later entries", () => {
    expect(selectEncoding(" , , gzip")).toBe("gzip");
  });

  it("rejects an encoding explicitly disabled with q=0 even if listed first", () => {
    expect(selectEncoding("zstd;q=0, gzip")).toBe("gzip");
  });
});

// ── compressionMiddleware: fallback to the uncompressed body ───────────────

describe("compressionMiddleware - uncompressed fallback paths", () => {
  it("calls next() and sends the raw body when the client sends no Accept-Encoding", () => {
    const { res, next } = run({ body: BIG_BODY, contentType: "application/json" });

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.body?.toString("utf8")).toBe(BIG_BODY);
    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    // The body is still eligible for compression, so the representation does
    // vary on Accept-Encoding — a shared cache must key on the header even for
    // this identity response.
    expect(res.getHeader("vary")).toBe("Accept-Encoding");
  });

  it("does not advertise Vary for a response that is not eligible anyway", () => {
    const { res } = run({ body: BIG_BODY, contentType: "image/png" });
    expect(res.getHeader("vary")).toBeUndefined();
  });

  it("sends the raw body when the client advertises only unsupported encodings", () => {
    const { res } = run({
      acceptEncoding: "identity",
      body: BIG_BODY,
      contentType: "application/json",
    });

    expect(res.body?.toString("utf8")).toBe(BIG_BODY);
    expect(res.getHeader("Content-Encoding")).toBeUndefined();
  });

  it("does not compress bodies below the default threshold", () => {
    const { res } = run({ acceptEncoding: "gzip", body: "{}", contentType: "application/json" });
    expect(res.body?.toString("utf8")).toBe("{}");
    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    expect(res.getHeader("vary")).toBeUndefined();
  });

  it("does not compress when Content-Encoding is already set (no double encoding)", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { "Content-Encoding": "br" },
    });

    expect(res.getHeader("Content-Encoding")).toBe("br");
    expect(res.body?.toString("utf8")).toBe(BIG_BODY);
    expect(res.getHeader("vary")).toBeUndefined();
  });

  it("does not compress 204 No Content responses", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      statusCode: 204,
    });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    expect(res.body?.toString("utf8")).toBe(BIG_BODY);
  });

  it("does not compress 304 Not Modified responses", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      statusCode: 304,
    });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
  });

  it("honours Cache-Control: no-transform", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { "Cache-Control": "public, no-transform" },
    });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    expect(res.body?.toString("utf8")).toBe(BIG_BODY);
  });

  it("skips compressible-looking but non-compressible content types", () => {
    const { res } = run({ acceptEncoding: "gzip", body: BIG_BODY, contentType: "image/png" });
    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    expect(res.getHeader("vary")).toBeUndefined();
  });

  it("respects a custom threshold option", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: "hello world!",
      contentType: "text/plain",
      options: { threshold: 1_000 },
    });
    expect(res.getHeader("Content-Encoding")).toBeUndefined();
  });

  it("falls back to the raw body when disableCompression opts the response out", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      beforeEnd: (r) => disableCompression(r as never),
    });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    expect(res.body?.toString("utf8")).toBe(BIG_BODY);
  });
});

describe("compressionMiddleware - BREACH guard rejects cookies and CSRF tokens", () => {
  it("never compresses a response that sets a session cookie", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { "Set-Cookie": "session=abc123; Path=/; HttpOnly" },
    });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    expect(res.body?.toString("utf8")).toBe(BIG_BODY);
  });

  it("detects a session cookie anywhere in a multi-cookie Set-Cookie array", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { "Set-Cookie": ["theme=dark; Path=/", "connect.sid=s%3Axyz; HttpOnly"] },
    });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
  });

  it("compresses an unrelated cookie that is not a configured session cookie", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { "Set-Cookie": "theme=dark; Path=/" },
    });

    expect(res.getHeader("Content-Encoding")).toBe("gzip");
  });

  it("honours a custom sessionCookieNames option", () => {
    const blocked = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { "Set-Cookie": "x-app-session=1" },
      options: { sessionCookieNames: ["x-app-session"] },
    });
    expect(blocked.res.getHeader("Content-Encoding")).toBeUndefined();

    const allowed = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { "Set-Cookie": "session=1" },
      options: { sessionCookieNames: ["x-app-session"] },
    });
    expect(allowed.res.getHeader("Content-Encoding")).toBe("gzip");
  });

  it("never compresses a JSON body that carries a CSRF token field", () => {
    const body = JSON.stringify({ csrf_token: "secret", filler: "x".repeat(4096) });
    const { res } = run({ acceptEncoding: "gzip", body, contentType: "application/json" });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
    expect(res.body?.toString("utf8")).toBe(body);
  });

  it("honours a custom csrfFieldNames option", () => {
    const body = JSON.stringify({ "x-anti-forgery": "secret", filler: "x".repeat(4096) });
    const { res } = run({
      acceptEncoding: "gzip",
      body,
      contentType: "application/json",
      options: { csrfFieldNames: ["x-anti-forgery"] },
    });

    expect(res.getHeader("Content-Encoding")).toBeUndefined();
  });
});

// ── compressionMiddleware: normal path + boundaries ────────────────────────

describe("compressionMiddleware - successful compression", () => {
  it("gzips an eligible response and round-trips the payload", () => {
    const { res } = run({ acceptEncoding: "gzip", body: BIG_BODY, contentType: "application/json" });

    expect(res.getHeader("Content-Encoding")).toBe("gzip");
    expect(Number(res.getHeader("Content-Length"))).toBe(res.body?.length);
    expect(zlib.gunzipSync(res.body as Buffer).toString("utf8")).toBe(BIG_BODY);
    expect(res.getHeader("vary")).toBe("Accept-Encoding");
  });

  it("uses brotli when the client prefers it over gzip", () => {
    const { res } = run({ acceptEncoding: "br, gzip", body: BIG_BODY, contentType: "application/json" });

    expect(res.getHeader("Content-Encoding")).toBe("br");
    expect(zlib.brotliDecompressSync(res.body as Buffer).toString("utf8")).toBe(BIG_BODY);
  });

  it("selects zstd when the client advertises it", () => {
    const { res } = run({ acceptEncoding: "zstd, br, gzip", body: BIG_BODY, contentType: "application/json" });

    expect(res.getHeader("Content-Encoding")).toBe("zstd");
    expect((res.body as Buffer).length).toBeLessThan(Buffer.byteLength(BIG_BODY));
    // Regression: the zstd branch used to throw inside `compressSync`, which the
    // middleware swallowed, so a zstd-capable client silently received an
    // unencoded body. The payload must now round-trip through a real codec.
    expect(zlib.zstdDecompressSync(res.body as Buffer).toString("utf8")).toBe(BIG_BODY);
  });

  it("appends Accept-Encoding to a pre-existing Vary header", () => {
    const { res } = run({
      acceptEncoding: "gzip",
      body: BIG_BODY,
      contentType: "application/json",
      headers: { Vary: "Origin" },
    });

    expect(res.getHeader("vary")).toBe("Origin, Accept-Encoding");
  });

  it("compresses a payload at exactly the configured threshold", () => {
    const body = "y".repeat(64);
    const { res } = run({
      acceptEncoding: "gzip",
      body,
      contentType: "text/plain",
      options: { threshold: 64 },
    });

    expect(res.getHeader("Content-Encoding")).toBe("gzip");
    expect(zlib.gunzipSync(res.body as Buffer).toString("utf8")).toBe(body);
  });

  it("compresses a streamed response assembled from write() + end()", () => {
    const part1 = "a".repeat(2048);
    const part2 = "b".repeat(2048);

    const req = { headers: { "accept-encoding": "gzip" } };
    const res = createRes();
    res.setHeader("Content-Type", "application/json");
    const next = vi.fn();
    compressionMiddleware()(req as never, res as never, next);

    res.write(part1);
    res.write(part2);
    res.end();

    expect(res.getHeader("Content-Encoding")).toBe("gzip");
    expect(zlib.gunzipSync(res.body as Buffer).toString("utf8")).toBe(part1 + part2);
  });
});
