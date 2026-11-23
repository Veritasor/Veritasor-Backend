/**
 * Exporter selection coverage for `initializeOpenTelemetry`.
 *
 * Each environment configuration must load only the transport it needs, wire
 * the expected endpoint, and leave the SDK in the same lifecycle state the
 * pre-refactor implementation produced. The exporter packages are mocked so
 * the test observes which constructors were used rather than opening sockets.
 */
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const observed = vi.hoisted(() => ({
  traceHttpOptions: [] as Array<Record<string, unknown>>,
  traceGrpcOptions: [] as Array<Record<string, unknown>>,
  logHttpOptions: [] as Array<Record<string, unknown>>,
  logGrpcOptions: [] as Array<Record<string, unknown>>,
  sdkConfigs: [] as Array<Record<string, unknown>>,
  sdkStarts: 0,
  sdkShutdowns: 0,
}));

vi.mock("@opentelemetry/exporter-trace-otlp-http", () => {
  return {
    OTLPTraceExporter: class {
      constructor(options: Record<string, unknown>) {
        observed.traceHttpOptions.push(options);
      }
    },
  };
});

vi.mock("@opentelemetry/exporter-trace-otlp-grpc", () => {
  return {
    OTLPTraceExporter: class {
      constructor(options: Record<string, unknown>) {
        observed.traceGrpcOptions.push(options);
      }
    },
  };
});

vi.mock("@opentelemetry/exporter-logs-otlp-http", () => {
  return {
    OTLPLogExporter: class {
      constructor(options: Record<string, unknown>) {
        observed.logHttpOptions.push(options);
      }
    },
  };
});

vi.mock("@opentelemetry/exporter-logs-otlp-grpc", () => {
  return {
    OTLPLogExporter: class {
      constructor(options: Record<string, unknown>) {
        observed.logGrpcOptions.push(options);
      }
    },
  };
});

vi.mock("@opentelemetry/sdk-node", () => ({
  NodeSDK: class {
    constructor(config: Record<string, unknown>) {
      observed.sdkConfigs.push(config);
    }

    start(): void {
      observed.sdkStarts += 1;
    }

    async shutdown(): Promise<void> {
      observed.sdkShutdowns += 1;
    }
  },
}));

vi.mock("@opentelemetry/sdk-logs", () => ({
  BatchLogRecordProcessor: class {
    constructor(readonly exporter: unknown) {}
  },
}));

vi.mock("@opentelemetry/resources", () => ({
  Resource: class {
    constructor(readonly attributes: Record<string, string>) {}
  },
}));

vi.mock("../../src/tracing/resource.js", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../../src/tracing/resource.js")>();
  return {
    ...actual,
    // Detection performs network calls; exporter selection is what this suite
    // pins, so keep resources deterministic and offline.
    detectCloudResources: async () => ({
      provider: "unknown" as const,
      attributes: {},
    }),
  };
});

const originalEnv = { ...process.env };

function resetObserved(): void {
  observed.traceHttpOptions.length = 0;
  observed.traceGrpcOptions.length = 0;
  observed.logHttpOptions.length = 0;
  observed.logGrpcOptions.length = 0;
  observed.sdkConfigs.length = 0;
  observed.sdkStarts = 0;
  observed.sdkShutdowns = 0;
}

async function importTracing() {
  return import("../../src/tracing.js");
}

describe("initializeOpenTelemetry exporter selection", () => {
  beforeEach(() => {
    vi.resetModules();
    resetObserved();
    process.env = { ...originalEnv };
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    delete process.env.OTEL_EXPORTER_PROTOCOL;
    delete process.env.OTEL_GRPC_MTLS_ENABLED;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  it("does not initialize or load any exporter when the endpoint is unset", async () => {
    process.env.OTEL_EXPORTER_PROTOCOL = "grpc";
    const { initializeOpenTelemetry } = await importTracing();

    await expect(initializeOpenTelemetry()).resolves.toBeUndefined();

    expect(observed.traceHttpOptions).toHaveLength(0);
    expect(observed.traceGrpcOptions).toHaveLength(0);
    expect(observed.logHttpOptions).toHaveLength(0);
    expect(observed.logGrpcOptions).toHaveLength(0);
    expect(observed.sdkConfigs).toHaveLength(0);
    expect(observed.sdkStarts).toBe(0);
  });

  it("defaults to the HTTP trace and log exporters", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
      "http://collector:4318/v1/traces";
    const { initializeOpenTelemetry } = await importTracing();

    const sdk = await initializeOpenTelemetry();

    expect(sdk).toBeDefined();
    expect(observed.traceHttpOptions).toEqual([
      { url: "http://collector:4318/v1/traces" },
    ]);
    expect(observed.logHttpOptions).toEqual([
      { url: "http://collector:4318/v1/logs" },
    ]);
    expect(observed.traceGrpcOptions).toHaveLength(0);
    expect(observed.logGrpcOptions).toHaveLength(0);
    expect(observed.sdkStarts).toBe(1);
  });

  it("uses the gRPC trace and log exporters when protocol=grpc", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://collector:4317";
    process.env.OTEL_EXPORTER_PROTOCOL = "grpc";
    const { initializeOpenTelemetry } = await importTracing();

    const sdk = await initializeOpenTelemetry();

    expect(sdk).toBeDefined();
    expect(observed.traceGrpcOptions).toEqual([
      { url: "http://collector:4317" },
    ]);
    expect(observed.logGrpcOptions).toEqual([
      { url: "http://collector:4317" },
    ]);
    expect(observed.traceHttpOptions).toHaveLength(0);
    expect(observed.logHttpOptions).toHaveLength(0);
    expect(observed.sdkStarts).toBe(1);
  });

  it("treats an unrecognised protocol as HTTP without loading gRPC", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
      "http://collector:4318/v1/traces";
    process.env.OTEL_EXPORTER_PROTOCOL = "h2c";
    const { initializeOpenTelemetry } = await importTracing();

    await initializeOpenTelemetry();

    expect(observed.traceHttpOptions).toHaveLength(1);
    expect(observed.traceGrpcOptions).toHaveLength(0);
    expect(observed.logHttpOptions).toHaveLength(1);
    expect(observed.logGrpcOptions).toHaveLength(0);
  });

  it("leaves the log URL undefined for HTTP endpoints that are not /v1/traces", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://collector:4318";
    const { initializeOpenTelemetry } = await importTracing();

    await initializeOpenTelemetry();

    expect(observed.traceHttpOptions).toEqual([
      { url: "http://collector:4318" },
    ]);
    expect(observed.logHttpOptions).toEqual([{ url: undefined }]);
  });

  it("caches the initialization promise instead of constructing twice", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
      "http://collector:4318/v1/traces";
    const { initializeOpenTelemetry } = await importTracing();

    const [first, second] = await Promise.all([
      initializeOpenTelemetry(),
      initializeOpenTelemetry(),
    ]);
    const third = await initializeOpenTelemetry();

    expect(first).toBe(second);
    expect(third).toBe(first);
    expect(observed.sdkConfigs).toHaveLength(1);
    expect(observed.traceHttpOptions).toHaveLength(1);
    expect(observed.logHttpOptions).toHaveLength(1);
  });

  it("shuts the SDK down exactly once when started", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
      "http://collector:4318/v1/traces";
    const { initializeOpenTelemetry, shutdownOpenTelemetry } =
      await importTracing();

    await initializeOpenTelemetry();
    await shutdownOpenTelemetry();
    await shutdownOpenTelemetry();

    expect(observed.sdkShutdowns).toBe(1);
  });
});

describe("tracing module layout", () => {
  it("keeps every module under src/tracing/ at or below ~300 lines", async () => {
    const tracingDir = fileURLToPath(
      new URL("../../src/tracing/", import.meta.url),
    );
    const entries = await readdir(tracingDir, { withFileTypes: true });
    const files = entries
      .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"))
      .map((entry) => entry.name);

    expect(files.length).toBeGreaterThan(0);

    for (const file of files) {
      const contents = await readFile(path.join(tracingDir, file), "utf8");
      expect(contents.split(/\r?\n/).length, file).toBeLessThanOrEqual(300);
    }
  });
});
