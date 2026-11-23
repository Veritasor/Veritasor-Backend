/**
 * Trace exporter construction.
 *
 * Selects the HTTP or gRPC OTLP trace exporter at runtime so only the
 * configured transport is ever loaded, then wraps it in the PII sanitizer and
 * pairs it with the route-aware sampler.
 */

import { buildExporterOptions } from "./exporter-config.js";
import type { ExporterProtocol } from "./protocol.js";

/** Constructor shape shared by both OTLP trace exporter packages. */
type TraceExporterConstructor = new (
  options: Record<string, unknown>,
) => unknown;

/**
 * Load the trace exporter constructor for the configured protocol.
 *
 * Each branch uses a dynamic import so the unused transport (and its
 * transitive dependencies) stays out of the process.
 */
async function loadTraceExporter(
  protocol: ExporterProtocol,
): Promise<TraceExporterConstructor> {
  if (protocol === "grpc") {
    const mod = await import("@opentelemetry/exporter-trace-otlp-grpc");
    return mod.OTLPTraceExporter as TraceExporterConstructor;
  }

  const mod = await import("@opentelemetry/exporter-trace-otlp-http");
  return mod.OTLPTraceExporter as TraceExporterConstructor;
}

/**
 * Build the sanitized trace exporter and its route-aware sampler.
 *
 * @param protocol - Resolved OTLP transport.
 * @param sslCredentials - Shared gRPC mTLS credentials, when enabled.
 */
export async function createTraceExporter(
  protocol: ExporterProtocol,
  sslCredentials?: unknown,
) {
  const options = buildExporterOptions(protocol, sslCredentials).trace;
  const Exporter = await loadTraceExporter(protocol);
  const rawExporter = new Exporter(options);

  // Kept dynamic to preserve the historical load order and avoid a
  // trace-exporter → sampler → metrics → tracing import cycle at module load.
  const [{ SanitizingSpanExporter }, { RouteAwareSampler }] = await Promise.all([
    import("./sanitizer.js"),
    import("./sampler.js"),
  ]);

  return {
    traceExporter: new SanitizingSpanExporter(rawExporter),
    sampler: new RouteAwareSampler(),
  };
}
