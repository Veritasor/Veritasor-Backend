/**
 * Focused behavior coverage for `createCorsMiddleware`
 * (src/middleware/cors.ts).
 *
 * `tests/unit/cors.test.ts` covers `getAllowedOrigins()` and
 * `tests/integration/cors.test.ts` covers the observable HTTP headers produced
 * by a real Express stack.  Neither exercises the middleware factory itself, so
 * this suite drives the CORS options delegate that `createCorsMiddleware()`
 * hands to the `cors` package:
 *
 * - the factory contract (one delegate argument, returned middleware identity)
 * - the shared preflight/header options taken from config
 * - no-Origin requests (non-browser / same-origin)
 * - wildcard mode, including the forced `credentials: false`
 * - allowlist match, near-miss rejection, and cross-origin attack shapes
 * - structured `cors_rejected` logging on every rejection
 *
 * The `cors` package is mocked so the delegate can be invoked directly and every
 * branch decision is observable without HTTP.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const corsMock = vi.hoisted(() =>
  vi.fn(() => {
    // Stand-in for the real express middleware returned by `cors()`.
    return function corsMiddleware() {};
  }),
);

vi.mock("cors", () => ({ default: corsMock }));

type CorsOptions = Record<string, unknown>;
type Delegate = (
  req: unknown,
  callback: (err: unknown, options?: CorsOptions) => void,
) => void;

const ALLOWED = "https://app.veritasor.com";
const ALSO_ALLOWED = "https://admin.veritasor.com";

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.resetModules();
  corsMock.mockClear();
  process.env.DATABASE_URL = "postgres://localhost:5432/test_db";
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
  delete process.env.ALLOWED_ORIGINS;
  delete process.env.NODE_ENV;
});

/** Import the module with the current env, then run the factory and grab the delegate. */
async function loadMiddleware() {
  const mod = (await import("../../src/middleware/cors.js")) as unknown as {
    createCorsMiddleware: () => unknown;
  };
  const middleware = mod.createCorsMiddleware();
  const delegate = corsMock.mock.calls.at(-1)?.[0] as Delegate | undefined;
  if (!delegate) throw new Error("createCorsMiddleware did not call cors()");
  return { middleware, delegate };
}

/** Invoke the delegate with the given request headers and resolve its callback payload. */
function invoke(
  delegate: Delegate,
  headers: Record<string, string | string[] | undefined> = {},
) {
  return new Promise<{ err: unknown; options: CorsOptions }>((resolve) => {
    delegate({ headers }, (err, options) => {
      resolve({ err, options: options ?? {} });
    });
  });
}

function rejectedLog() {
  const raw = warnSpy.mock.calls
    .map((call) => call[0])
    .find((arg): arg is string => typeof arg === "string");
  return raw ? (JSON.parse(raw) as CorsOptions) : undefined;
}

async function loadAllowlistMode() {
  process.env.NODE_ENV = "production";
  process.env.ALLOWED_ORIGINS = `${ALLOWED},${ALSO_ALLOWED}`;
  return loadMiddleware();
}

async function loadWildcardMode() {
  process.env.NODE_ENV = "development";
  delete process.env.ALLOWED_ORIGINS;
  return loadMiddleware();
}

describe("createCorsMiddleware — factory contract", () => {
  it("calls cors() exactly once with a single delegate function", async () => {
    await loadAllowlistMode();

    expect(corsMock).toHaveBeenCalledTimes(1);
    expect(corsMock.mock.calls[0]).toHaveLength(1);
    expect(typeof corsMock.mock.calls[0][0]).toBe("function");
  });

  it("returns the middleware produced by cors() unchanged", async () => {
    const { middleware } = await loadAllowlistMode();

    expect(middleware).toBe(corsMock.mock.results[0].value);
  });

  it("builds an independent delegate per factory call", async () => {
    const first = await loadMiddleware();
    const second = await loadMiddleware();

    expect(first.delegate).not.toBe(second.delegate);
  });
});

describe("createCorsMiddleware — shared options", () => {
  it("forwards the cached preflight and header configuration", async () => {
    const { delegate } = await loadAllowlistMode();

    const { options } = await invoke(delegate, { origin: ALLOWED });

    expect(options.maxAge).toBe(86_400);
    expect(options.allowedHeaders).toEqual([
      "Content-Type",
      "Authorization",
      "X-Request-ID",
      "Idempotency-Key",
    ]);
    expect(options.exposedHeaders).toEqual(["X-Request-ID"]);
    expect(options.methods).toEqual([
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ]);
  });

  it("never reports an error through the delegate callback", async () => {
    const allowlist = await loadAllowlistMode();
    const wildcard = await loadWildcardMode();

    for (const { delegate } of [allowlist, wildcard]) {
      for (const headers of [
        {},
        { origin: ALLOWED },
        { origin: "https://evil.example.com" },
      ]) {
        const { err } = await invoke(delegate, headers);
        expect(err).toBeNull();
      }
    }
  });
});

describe("createCorsMiddleware — no Origin header", () => {
  it("allows a request without an Origin header with credentials", async () => {
    const { delegate } = await loadAllowlistMode();

    const { options } = await invoke(delegate, {});

    expect(options.origin).toBe(true);
    expect(options.credentials).toBe(true);
  });

  it("treats an empty Origin header as a non-browser request", async () => {
    const { delegate } = await loadAllowlistMode();

    const { options } = await invoke(delegate, { origin: "" });

    expect(options.origin).toBe(true);
    expect(options.credentials).toBe(true);
    expect(rejectedLog()).toBeUndefined();
  });
});

describe("createCorsMiddleware — wildcard mode", () => {
  it("reflects any origin and forces credentials off", async () => {
    const { delegate } = await loadWildcardMode();

    const { options } = await invoke(delegate, {
      origin: "http://localhost:5173",
    });

    // config.cors.credentials is `true`; the middleware must still force it off
    // because a reflected wildcard origin cannot be combined with credentials.
    expect(options.credentials).toBe(false);
    expect(options.origin).toBe(true);
  });

  it("does not log rejections in wildcard mode", async () => {
    const { delegate } = await loadWildcardMode();

    await invoke(delegate, { origin: "https://evil.example.com" });

    expect(rejectedLog()).toBeUndefined();
  });
});

describe("createCorsMiddleware — allowlist mode", () => {
  it("reflects an allowed origin with credentials", async () => {
    const { delegate } = await loadAllowlistMode();

    const allowedFirst = await invoke(delegate, { origin: ALLOWED });
    expect(allowedFirst.options.origin).toBe(true);
    expect(allowedFirst.options.credentials).toBe(true);

    const allowedSecond = await invoke(delegate, { origin: ALSO_ALLOWED });
    expect(allowedSecond.options.origin).toBe(true);

    expect(rejectedLog()).toBeUndefined();
  });

  it("rejects an origin that is not on the allowlist and logs it", async () => {
    const { delegate } = await loadAllowlistMode();

    const blocked = "https://evil.example.com";
    const { options } = await invoke(delegate, { origin: blocked });

    expect(options.origin).toBe(false);
    const log = rejectedLog();
    expect(log?.type).toBe("cors_rejected");
    expect(log?.origin).toBe(blocked);
  });

  it.each([
    ["trailing slash", `${ALLOWED}/`],
    ["uppercase scheme/host", "HTTPS://APP.VERITASOR.COM"],
    ["suffix attack", `${ALLOWED}.evil.example.com`],
    ["prefix attack", `https://evil.example.com?next=${ALLOWED}`],
    ["subdomain", "https://evil.app.veritasor.com"],
    ["opaque origin", "null"],
  ])("rejects a near-miss origin (%s)", async (_label, origin) => {
    const { delegate } = await loadAllowlistMode();

    const { options } = await invoke(delegate, { origin });

    expect(options.origin).toBe(false);
    expect(rejectedLog()?.origin).toBe(origin);
  });

  it("rejects a duplicated Origin header", async () => {
    const { delegate } = await loadAllowlistMode();

    const { options } = await invoke(delegate, {
      origin: [ALLOWED, "https://evil.example.com"],
    });

    expect(options.origin).toBe(false);
    expect(rejectedLog()).toBeDefined();
  });

  it("does not log allowed origins", async () => {
    const { delegate } = await loadAllowlistMode();

    await invoke(delegate, { origin: ALLOWED });

    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("rejects everything when the allowlist is empty", async () => {
    process.env.NODE_ENV = "production";
    process.env.ALLOWED_ORIGINS = ",";
    const { delegate } = await loadMiddleware();

    const { options } = await invoke(delegate, { origin: ALLOWED });

    expect(options.origin).toBe(false);
    expect(rejectedLog()?.origin).toBe(ALLOWED);
  });
});
