/**
 * Log exporter construction.
 *
 * Selects the HTTP or gRPC OTLP log exporter at runtime so only the configured
 * transport is ever loaded.
 */

import type { LogRecordExporter } from "@opentelemetry/sdk-logs";
import { buildExporterOptions } from "./exporter-config.js";
import type { ExporterProtocol } from "./protocol.js";

/** Constructor shape shared by both OTLP log exporter packages. */
type LogExporterConstructor = new (
  options: Record<string, unknown>,
) => LogRecordExporter;

/**
 * Load the log exporter constructor for the configured protocol.
 *
 * Each branch uses a dynamic import so the unused transport (and its
 * transitive dependencies) stays out of the process.
 */
async function loadLogExporter(
  protocol: ExporterProtocol,
): Promise<LogExporterConstructor> {
  if (protocol === "grpc") {
    const mod = await import("@opentelemetry/exporter-logs-otlp-grpc");
    return mod.OTLPLogExporter as LogExporterConstructor;
  }

  const mod = await import("@opentelemetry/exporter-logs-otlp-http");
  return mod.OTLPLogExporter as LogExporterConstructor;
}

/**
 * Build the OTLP log exporter for the configured protocol.
 *
 * @param protocol - Resolved OTLP transport.
 * @param sslCredentials - Shared gRPC mTLS credentials, when enabled.
 */
export async function createLogExporter(
  protocol: ExporterProtocol,
  sslCredentials?: unknown,
): Promise<LogRecordExporter> {
  const options = buildExporterOptions(protocol, sslCredentials).log;
  const Exporter = await loadLogExporter(protocol);
  return new Exporter(options);
}
