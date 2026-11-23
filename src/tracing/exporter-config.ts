/**
 * Shared OTLP exporter option resolution.
 *
 * Keeps endpoint derivation in one place so trace and log exporters always
 * agree on the collector target. Values are read from the environment on each
 * call; nothing is cached at module load time.
 */

import type { ExporterProtocol } from "./protocol.js";
import type { GrpcMtlsCredentials } from "./mtls.js";

/** Options accepted by both the trace and log OTLP exporters. */
export type ExporterOptions = Record<string, unknown>;

/** Resolved options for the trace and log exporters. */
export interface ResolvedExporterOptions {
  trace: ExporterOptions;
  log: ExporterOptions;
}

/**
 * Resolve the trace endpoint.
 *
 * gRPC falls back to the standard local collector port; HTTP passes through
 * `OTEL_EXPORTER_OTLP_ENDPOINT` unchanged (undefined means "SDK default").
 */
export function resolveTraceUrl(protocol: ExporterProtocol): string | undefined {
  return protocol === "grpc"
    ? process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4317"
    : process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
}

/**
 * Resolve the log endpoint.
 *
 * gRPC sends logs to the same endpoint as traces. HTTP derives `/v1/logs`
 * from a `/v1/traces` base URL, mirroring the OTLP/HTTP specification.
 */
export function resolveLogUrl(
  protocol: ExporterProtocol,
  traceUrl: string | undefined,
): string | undefined {
  if (protocol === "grpc") return traceUrl;
  return traceUrl?.endsWith("/v1/traces")
    ? traceUrl.replace(/\/v1\/traces$/, "/v1/logs")
    : undefined;
}

/**
 * Build trace and log exporter options, wiring shared mTLS credentials when
 * they are present.
 */
export function buildExporterOptions(
  protocol: ExporterProtocol,
  sslCredentials?: unknown,
): ResolvedExporterOptions {
  const traceUrl = resolveTraceUrl(protocol);
  const logUrl = resolveLogUrl(protocol, traceUrl);

  const trace: ExporterOptions = { url: traceUrl };
  const log: ExporterOptions = { url: logUrl };

  if (protocol === "grpc" && sslCredentials) {
    trace.credentials = sslCredentials;
    log.credentials = sslCredentials;
  }

  return { trace, log };
}

/**
 * Create the shared gRPC SSL credentials used by both exporters.
 *
 * The `@grpc/grpc-js` module is imported lazily so HTTP-only deployments do
 * not pay for loading it.
 */
export async function createGrpcSslCredentials(
  credentials: GrpcMtlsCredentials | undefined,
): Promise<unknown | undefined> {
  if (!credentials) return undefined;

  const { credentials: grpcCredentials } = await import("@grpc/grpc-js");
  return grpcCredentials.createSsl(
    credentials.ca,
    credentials.key,
    credentials.cert,
  );
}
