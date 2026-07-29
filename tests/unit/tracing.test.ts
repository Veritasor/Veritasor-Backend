import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const spans: FakeSpan[] = [];
const extractMock = vi.fn((ctx: Record<string, unknown>) => ({
  ...ctx,
  extracted: true,
}));

// Mock @grpc/grpc-js for gRPC mTLS tests
vi.mock("@grpc/grpc-js", () => ({
  credentials: {
    createSsl: vi.fn(
      (_rootCert?: Buffer, _privateKey?: Buffer, _certChain?: Buffer) => ({
        _isSecure: true,
        _mtlsMocked: true,
      }),
    ),
  },
}));

// Mock OTLP gRPC exporter modules
vi.mock("@opentelemetry/exporter-trace-otlp-grpc", () => ({
  OTLPTraceExporter: class MockGrpcTraceExporter {
    constructor(opts: Record<string, unknown>) {
      mockExporterCalls.push({ type: "trace-grpc", opts });
    }
  },
}));

vi.mock("@opentelemetry/exporter-logs-otlp-grpc", () => ({
  OTLPLogExporter: class MockGrpcLogExporter {
    constructor(opts: Record<string, unknown>) {
      mockExporterCalls.push({ type: "log-grpc", opts });
    }
  },
}));

const mockExporterCalls: Array<{ type: string; opts: Record<string, unknown> }> = [];

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

vi.mock("@opentelemetry/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@opentelemetry/api")>();
  return {
    ...actual,
    createContextKey: vi.fn().mockReturnValue("mocked-context-key"),
    context: {
      ...actual.context,
      active: () => ({}),
      with: (_ctx: unknown, callback: () => unknown) => callback(),
    },
    propagation: {
      ...actual.propagation,
      extract: extractMock,
      getBaggage: vi.fn(),
      setBaggage: vi.fn((ctx) => ctx),
      createBaggage: vi.fn(() => ({
        getEntry: vi.fn(),
        setEntry: vi.fn().mockReturnThis(),
        removeEntry: vi.fn().mockReturnThis(),
      })),
    },
    trace: {
      ...actual.trace,
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
  };
});

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
    mockExporterCalls.length = 0;
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
      "retry.attempt": 2,
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

  it("propagates tenant.id from baggage into span attributes", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318/v1/traces";
    const api = await import("@opentelemetry/api");
    const { startHttpRequestSpan } = await import("../../src/tracing.js");

    const mockBaggage = {
      getEntry: vi.fn((key) => {
        if (key === "tenant.id") return { value: "tenant-123" };
        return undefined;
      }),
      setEntry: vi.fn().mockReturnThis(),
      removeEntry: vi.fn().mockReturnThis(),
    };
    
    vi.mocked(api.propagation.getBaggage).mockReturnValue(mockBaggage as any);
    
    const req = {
      headers: {},
      method: "GET",
      path: "/api/v1/tenant-test",
      ip: "127.0.0.1",
      query: {},
    };
    const res = Object.assign(new EventEmitter(), {
      statusCode: 200,
      once: EventEmitter.prototype.once,
    });
    const next = vi.fn();

    startHttpRequestSpan(req as never, res as never, "corr-test", next);
    res.emit("finish");

    expect(spans).toHaveLength(1);
    expect(spans[0].attributes["tenant.id"]).toBe("tenant-123");
  });
});

describe("OTLP exporter protocol selection", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    delete process.env.OTEL_EXPORTER_PROTOCOL;
    delete process.env.OTEL_GRPC_MTLS_ENABLED;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.env = { ...originalEnv };
  });

  it("getExporterProtocol defaults to http", async () => {
    const { getExporterProtocol } = await import("../../src/tracing.js");
    expect(getExporterProtocol()).toBe("http");
  });

  it("getExporterProtocol returns grpc when OTEL_EXPORTER_PROTOCOL=grpc", async () => {
    process.env.OTEL_EXPORTER_PROTOCOL = "grpc";
    const { getExporterProtocol } = await import("../../src/tracing.js");
    expect(getExporterProtocol()).toBe("grpc");
  });

  it("getExporterProtocol treats unknown values as http", async () => {
    process.env.OTEL_EXPORTER_PROTOCOL = "unknown";
    const { getExporterProtocol } = await import("../../src/tracing.js");
    expect(getExporterProtocol()).toBe("http");
  });

  it("getExporterProtocol is case-insensitive", async () => {
    process.env.OTEL_EXPORTER_PROTOCOL = "GRPC";
    const { getExporterProtocol } = await import("../../src/tracing.js");
    expect(getExporterProtocol()).toBe("grpc");
  });

  it("isGrpcMtlsEnabled defaults to false", async () => {
    const { isGrpcMtlsEnabled } = await import("../../src/tracing.js");
    expect(isGrpcMtlsEnabled()).toBe(false);
  });

  it("isGrpcMtlsEnabled returns true when OTEL_GRPC_MTLS_ENABLED=true", async () => {
    process.env.OTEL_GRPC_MTLS_ENABLED = "true";
    const { isGrpcMtlsEnabled } = await import("../../src/tracing.js");
    expect(isGrpcMtlsEnabled()).toBe(true);
  });

  it("isGrpcMtlsEnabled supports multiple truthy values", async () => {
    for (const val of ["true", "1", "yes", "on"]) {
      process.env.OTEL_GRPC_MTLS_ENABLED = val;
      // Re-import to pick up new env value
      vi.resetModules();
      const { isGrpcMtlsEnabled } = await import("../../src/tracing.js");
      expect(isGrpcMtlsEnabled()).toBe(true);
    }
  });
});
