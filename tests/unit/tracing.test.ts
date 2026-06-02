import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const spans: FakeSpan[] = [];
const extractMock = vi.fn((ctx: Record<string, unknown>) => ({
  ...ctx,
  extracted: true,
}));

class FakeSpan {
  public attributes: Record<string, unknown>;
  public exceptions: unknown[] = [];
  public status: unknown;
  public ended = false;

  constructor(
    public readonly name: string,
    options: { attributes?: Record<string, unknown> },
  ) {
    this.attributes = { ...(options.attributes ?? {}) };
  }

  setAttribute(key: string, value: unknown) {
    this.attributes[key] = value;
  }

  recordException(error: unknown) {
    this.exceptions.push(error);
  }

  setStatus(status: unknown) {
    this.status = status;
  }

  end() {
    this.ended = true;
  }
}

vi.mock("@opentelemetry/api", () => ({
  SpanKind: {
    SERVER: "server",
    CLIENT: "client",
  },
  SpanStatusCode: {
    OK: "ok",
    ERROR: "error",
  },
  context: {
    active: () => ({}),
    with: (_ctx: unknown, callback: () => unknown) => callback(),
  },
  propagation: {
    extract: extractMock,
  },
  trace: {
    getTracer: () => ({
      startActiveSpan: (
        name: string,
        options: { attributes?: Record<string, unknown> },
        callback: (span: FakeSpan) => unknown,
      ) => {
        const span = new FakeSpan(name, options);
        spans.push(span);
        return callback(span);
      },
    }),
  },
}));

describe("OpenTelemetry tracing helpers", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    spans.length = 0;
    extractMock.mockClear();
    process.env = { ...originalEnv };
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.env = { ...originalEnv };
  });

  it("keeps tracing disabled when OTEL_EXPORTER_OTLP_ENDPOINT is unset", async () => {
    const { isOpenTelemetryEnabled, traceSorobanRpcAttempt } = await import(
      "../../src/tracing.js"
    );
    const execute = vi.fn(async () => "ok");

    await expect(traceSorobanRpcAttempt("sendTransaction", 1, execute)).resolves.toBe(
      "ok",
    );

    expect(isOpenTelemetryEnabled()).toBe(false);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(spans).toHaveLength(0);
  });

  it("records Soroban attempt errors without leaking exception messages", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318/v1/traces";
    const { traceSorobanRpcAttempt } = await import("../../src/tracing.js");

    await expect(
      traceSorobanRpcAttempt("simulateTransaction", 2, async () => {
        throw new Error("token=secret-value");
      }),
    ).rejects.toThrow("token=secret-value");

    expect(spans).toHaveLength(1);
    expect(spans[0].name).toBe("soroban.rpc simulateTransaction");
    expect(spans[0].attributes).toMatchObject({
      "rpc.system": "soroban",
      "rpc.method": "simulateTransaction",
      "soroban.rpc.attempt": 2,
      "error.type": "Error",
    });
    expect(JSON.stringify(spans[0].exceptions)).toContain("redacted");
    expect(JSON.stringify(spans[0].exceptions)).not.toContain("secret-value");
    expect(spans[0].ended).toBe(true);
  });

  it("creates request spans from safe HTTP attributes only", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318/v1/traces";
    const { startHttpRequestSpan } = await import("../../src/tracing.js");
    const req = {
      headers: {
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        authorization: "Bearer secret",
      },
      method: "POST",
      path: "/api/v1/attestations",
      ip: "127.0.0.1",
      query: {
        token: "secret",
      },
      route: {
        path: "/api/v1/attestations",
      },
    };
    const res = Object.assign(new EventEmitter(), {
      statusCode: 201,
      once: EventEmitter.prototype.once,
    });
    const next = vi.fn();

    startHttpRequestSpan(req as never, res as never, "corr-12345678", next);
    res.emit("finish");

    expect(next).toHaveBeenCalledTimes(1);
    expect(extractMock).toHaveBeenCalledTimes(1);
    expect(spans).toHaveLength(1);
    expect(spans[0].attributes).toMatchObject({
      "http.request.method": "POST",
      "http.route": "/api/v1/attestations",
      "http.response.status_code": 201,
      "url.path": "/api/v1/attestations",
      "veritasor.correlation_id": "corr-12345678",
    });
    expect(JSON.stringify(spans[0].attributes)).not.toContain("secret");
    expect(spans[0].ended).toBe(true);
  });
});
