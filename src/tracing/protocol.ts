/**
 * OTLP exporter protocol and tracing feature-flag resolution.
 *
 * All values are read lazily from `process.env` so that toggling a flag only
 * requires a module reload (or a process restart), never a rebuild.
 */

// ═══════════════════════════════════════════════════════════════════════════
// Exporter Protocol Selection
// ═══════════════════════════════════════════════════════════════════════════
//
// OTEL_EXPORTER_PROTOCOL controls which OTLP transport is used:
//
//   - "http" (default): Uses HTTP/protobuf via
//     @opentelemetry/exporter-trace-otlp-http. Lower operational
//     complexity; works through standard load balancers and proxies.
//     Default endpoint: OTEL_EXPORTER_OTLP_ENDPOINT (typically :4318).
//
//   - "grpc": Uses gRPC via @opentelemetry/exporter-trace-otlp-grpc.
//     Lower per-span overhead in high-throughput environments thanks to
//     multiplexed HTTP/2 streams. Requires a collector that supports
//     gRPC (default port 4317). When OTEL_GRPC_MTLS_ENABLED=true,
//     mutual TLS is configured using client certificates.
//
// Trade-offs:
//   - gRPC reduces connection churn and header overhead at scale.
//   - gRPC load balancing requires an L4 proxy or collector-side
//     routing; HTTP works through L7 reverse proxies out of the box.
//   - mTLS adds per-connection handshake cost but provides transport
//     authentication even within private networks.

/** Supported OTLP transport protocols. */
export type ExporterProtocol = "http" | "grpc";

const TRUE_VALUES = new Set(["true", "1", "yes", "on"]);

/**
 * Resolve the OTLP exporter protocol from env.
 *
 * @returns "http" or "grpc". Defaults to "http".
 */
export function getExporterProtocol(): ExporterProtocol {
  const proto = process.env.OTEL_EXPORTER_PROTOCOL?.trim().toLowerCase();
  if (proto === "grpc") return "grpc";
  return "http";
}

/**
 * Whether gRPC mTLS is enabled for the OTLP exporter.
 *
 * Only meaningful when {@link getExporterProtocol} returns "grpc".
 */
export function isGrpcMtlsEnabled(): boolean {
  const val = process.env.OTEL_GRPC_MTLS_ENABLED?.trim().toLowerCase() ?? "";
  return TRUE_VALUES.has(val);
}

/** Whether tracing is configured to export to a collector. */
export function isOpenTelemetryEnabled(): boolean {
  return Boolean(process.env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim());
}
