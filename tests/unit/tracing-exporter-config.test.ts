/**
 * Exporter protocol selection + gRPC mTLS configuration.
 *
 * This is a sibling of `tests/unit/tracing.test.ts` rather than an extension of
 * it: that file mocks `@opentelemetry/api` (its `context.active()` stub returns
 * `{}` because span tests never read from it), which makes the real
 * `src/utils/logger.ts` blow up with `activeContext.getValue is not a function`.
 * `initializeOpenTelemetry()` logs through that logger on its failure path, so
 * the mTLS cases below need the unmocked OpenTelemetry context.
 *
 * `loadGrpcMtlsFromSecretLoader()` / `loadGrpcMtlsCredentials()` are module
 * private, but `initializeOpenTelemetry()` reaches them — and throws — before it
 * imports or constructs any exporter, so the failure handling is exercised here
 * through the exported entry point only. No production code is changed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const MTLS_CONFIG_ERROR =
  /neither secret-loader keys \(OTEL_MTLS_CA\/CERT\/KEY\) nor file paths \(OTEL_MTLS_CA_PATH\/CERT_PATH\/KEY_PATH\) are fully configured\./;

describe("OTLP exporter env parsing boundaries", () => {
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

  it("getExporterProtocol resolves grpc regardless of case or surrounding whitespace", async () => {
    const { getExporterProtocol } = await import("../../src/tracing.js");

    for (const value of ["grpc", "GRPC", "Grpc", "gRpC", " grpc ", "\tgrpc\n", "  GRPC  "]) {
      process.env.OTEL_EXPORTER_PROTOCOL = value;
      expect(getExporterProtocol(), `protocol=${JSON.stringify(value)}`).toBe("grpc");
    }
  });

  it("getExporterProtocol maps every near-miss, empty and unknown value to http", async () => {
    const { getExporterProtocol } = await import("../../src/tracing.js");

    // "grpcx"/"grpc-http"/"grpc." prove the comparison is exact equality rather
    // than a prefix match; ""/" "/"\t" prove the value is trimmed first.
    for (const value of [
      "http",
      "HTTP",
      "http ",
      "grpcx",
      "grpc-http",
      "grpc.",
      "g",
      "unknown",
      "otlp",
      "",
      " ",
      "\t",
    ]) {
      process.env.OTEL_EXPORTER_PROTOCOL = value;
      expect(getExporterProtocol(), `protocol=${JSON.stringify(value)}`).toBe("http");
    }

    delete process.env.OTEL_EXPORTER_PROTOCOL;
    expect(getExporterProtocol()).toBe("http");
  });

  it("isGrpcMtlsEnabled accepts every TRUE_VALUES entry in any case or padding", async () => {
    const { isGrpcMtlsEnabled } = await import("../../src/tracing.js");

    for (const value of [
      "true",
      "TRUE",
      "True",
      "tRuE",
      "  true  ",
      "1",
      " 1 ",
      "yes",
      "YES",
      "Yes",
      "yes\t",
      "on",
      "ON",
      "On",
      " on ",
    ]) {
      process.env.OTEL_GRPC_MTLS_ENABLED = value;
      expect(isGrpcMtlsEnabled(), `mtls=${JSON.stringify(value)}`).toBe(true);
    }
  });

  it("isGrpcMtlsEnabled rejects falsy-looking and out-of-set values", async () => {
    const { isGrpcMtlsEnabled } = await import("../../src/tracing.js");

    // "0"/"no"/"off"/"false" are the documented opposites; "2", "-1", "y",
    // "tRUE?" and the empty/blank strings are simply not in TRUE_VALUES.
    for (const value of [
      "0",
      "no",
      "NO",
      "off",
      "false",
      "False",
      "2",
      "-1",
      "y",
      "n",
      "",
      " ",
      "\t",
      "tRUE?",
    ]) {
      process.env.OTEL_GRPC_MTLS_ENABLED = value;
      expect(isGrpcMtlsEnabled(), `mtls=${JSON.stringify(value)}`).toBe(false);
    }

    delete process.env.OTEL_GRPC_MTLS_ENABLED;
    expect(isGrpcMtlsEnabled()).toBe(false);
  });
});

describe("gRPC mTLS credential failure handling", () => {
  const originalEnv = { ...process.env };

  const clearMtlsEnv = () => {
    delete process.env.OTEL_MTLS_CA;
    delete process.env.OTEL_MTLS_CERT;
    delete process.env.OTEL_MTLS_KEY;
    delete process.env.OTEL_MTLS_CA_PATH;
    delete process.env.OTEL_MTLS_CERT_PATH;
    delete process.env.OTEL_MTLS_KEY_PATH;
  };

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4317";
    process.env.OTEL_EXPORTER_PROTOCOL = "grpc";
    process.env.OTEL_GRPC_MTLS_ENABLED = "true";
    clearMtlsEnv();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.env = { ...originalEnv };
  });

  it("rejects with the configuration error when neither secret keys nor file paths exist", async () => {
    const { initializeOpenTelemetry } = await import("../../src/tracing.js");

    // Drives the secret-loader failure branch (the default env adapter throws
    // SecretNotFoundError, which is swallowed into `undefined`) and then the
    // throw for a completely unconfigured mTLS setup.
    await expect(initializeOpenTelemetry()).rejects.toThrow(MTLS_CONFIG_ERROR);
  });

  it("treats an empty secret-loader value as absent and falls back to file paths", async () => {
    const { initializeOpenTelemetry } = await import("../../src/tracing.js");
    const { secretLoader } = await import("../../src/utils/secret-loader.js");

    // A falsy `get()` result (rather than a throw) must not be turned into
    // zero-filled Buffers: the `if (!ca || !cert || !key) return undefined`
    // guard forces the file-path fallback, which is incomplete here.
    vi.spyOn(secretLoader, "get").mockReturnValue("");
    process.env.OTEL_MTLS_CA_PATH = "/tmp/otel-mtls-ca.pem";

    await expect(initializeOpenTelemetry()).rejects.toThrow(MTLS_CONFIG_ERROR);
  });

  it("swallows an unexpected secret-loader error instead of leaking it", async () => {
    const { initializeOpenTelemetry } = await import("../../src/tracing.js");
    const { secretLoader } = await import("../../src/utils/secret-loader.js");

    vi.spyOn(secretLoader, "get").mockImplementation(() => {
      throw new Error("vault unreachable");
    });

    const rejection = await initializeOpenTelemetry().catch((error: unknown) => error);
    expect(rejection).toBeInstanceOf(Error);
    expect((rejection as Error).message).toMatch(MTLS_CONFIG_ERROR);
    expect((rejection as Error).message).not.toMatch(/vault unreachable/);
  });

  it("propagates a file read failure when the file fallback is fully configured but unreadable", async () => {
    const { initializeOpenTelemetry } = await import("../../src/tracing.js");
    const { secretLoader } = await import("../../src/utils/secret-loader.js");

    vi.spyOn(secretLoader, "get").mockImplementation(() => {
      throw new Error("no secrets");
    });
    process.env.OTEL_MTLS_CA_PATH = "/nonexistent/otel-mtls-ca.pem";
    process.env.OTEL_MTLS_CERT_PATH = "/nonexistent/otel-mtls-cert.pem";
    process.env.OTEL_MTLS_KEY_PATH = "/nonexistent/otel-mtls-key.pem";

    // Unlike a secret-loader failure, a configured-but-missing PEM file must
    // surface instead of being silently downgraded to "mTLS not configured".
    await expect(initializeOpenTelemetry()).rejects.toThrow(/ENOENT/);
  });

  it("stays disabled, and never loads credentials, when the endpoint is blank", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "   ";
    const { initializeOpenTelemetry, isOpenTelemetryEnabled } = await import(
      "../../src/tracing.js"
    );

    expect(isOpenTelemetryEnabled()).toBe(false);
    await expect(initializeOpenTelemetry()).resolves.toBeUndefined();
  });
});
