/**
 * OpenTelemetry SDK initialization.
 *
 * The public lifecycle entrypoint. Resolves exporter protocol, loads only the
 * configured transports, detects cloud resource attributes, and starts the
 * NodeSDK. Exporter packages are imported lazily so an HTTP deployment never
 * loads the gRPC stack (and vice versa).
 */

import { logger } from "../utils/logger.js";
import { detectCloudResources } from "./resource.js";
import {
  clearGrpcMtlsCredentials,
  getGrpcMtlsCredentials,
  loadGrpcMtlsCredentials,
  startGrpcMtlsFileWatchers,
  stopGrpcMtlsFileWatchers,
} from "./mtls.js";
import { createGrpcSslCredentials } from "./exporter-config.js";
import { createLogExporter } from "./log-exporter.js";
import { createTraceExporter } from "./trace-exporter.js";
import { getExporterProtocol, isOpenTelemetryEnabled } from "./protocol.js";
import {
  clearSdk,
  clearSdkStartPromise,
  getSdk,
  getSdkStartPromise,
  isSdkStarted,
  setSdk,
  setSdkStartPromise,
  type OpenTelemetrySdk,
} from "./sdk-state.js";

/** Guard against concurrent SDK reinitializations. */
let grpcMtlsReinitInProgress = false;

/**
 * Reinitialize the OpenTelemetry SDK with fresh credentials.
 *
 * Used for certificate rotation without process restart. Shuts down
 * the existing SDK (if any), clears cached state, and calls
 * {@link initializeOpenTelemetry} to create a new SDK instance.
 *
 * Guards against concurrent calls via `grpcMtlsReinitInProgress`.
 */
async function reinitializeOtelSdk(): Promise<void> {
  if (grpcMtlsReinitInProgress) return;
  grpcMtlsReinitInProgress = true;
  try {
    const currentSdk = getSdk();
    if (isSdkStarted() && currentSdk) {
      await currentSdk.shutdown();
      clearSdk();
    }
    stopGrpcMtlsFileWatchers();
    clearSdkStartPromise();
    clearGrpcMtlsCredentials();
    await initializeOpenTelemetry();
  } finally {
    grpcMtlsReinitInProgress = false;
  }
}

/**
 * Initialize the OpenTelemetry SDK when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
 *
 * The returned promise is cached for the lifetime of the process, so every
 * caller observes the same startup (or no-op when tracing is disabled).
 */
export async function initializeOpenTelemetry(): Promise<
  OpenTelemetrySdk | undefined
> {
  if (!isOpenTelemetryEnabled()) {
    return undefined;
  }

  const existingStart = getSdkStartPromise();
  if (existingStart) {
    return existingStart;
  }

  const protocol = getExporterProtocol();

  const startPromise = (async () => {
    // ── Load credentials for gRPC mTLS ───────────────────────────────
    if (protocol === "grpc") {
      await loadGrpcMtlsCredentials();
    }

    // ── Dynamic imports per protocol ─────────────────────────────────
    const [{ NodeSDK }, { BatchLogRecordProcessor }] = await Promise.all([
      import("@opentelemetry/sdk-node"),
      import("@opentelemetry/sdk-logs"),
    ]);

    // ── Build exporters (lazy transport imports) ─────────────────────
    const sslCredentials =
      protocol === "grpc"
        ? await createGrpcSslCredentials(getGrpcMtlsCredentials())
        : undefined;

    const [{ traceExporter, sampler }, logExporter] = await Promise.all([
      createTraceExporter(protocol, sslCredentials),
      createLogExporter(protocol, sslCredentials),
    ]);

    // Import Resource type for cloud-provider detection integration.
    const { Resource } = await import("@opentelemetry/resources");

    // Detect cloud-provider resource attributes with timeout guards.
    // Detection NEVER blocks startup — the SDK starts with whatever
    // attributes were collected before the combined deadline.
    let resourceAttributes: Record<string, string> = {};
    try {
      const detection = await detectCloudResources();
      if (detection.provider !== "unknown") {
        resourceAttributes = detection.attributes;
        logger.info({
          event: "cloud_resource_detected",
          provider: detection.provider,
          attributeCount: Object.keys(resourceAttributes).length,
        });
      }
    } catch (detectErr) {
      logger.debug({
        event: "cloud_resource_detection_skipped",
        error: detectErr instanceof Error ? detectErr.message : String(detectErr),
      });
    }

    const sdk = new NodeSDK({
      serviceName: process.env.OTEL_SERVICE_NAME ?? "veritasor-backend",
      resource: new Resource(resourceAttributes),
      traceExporter,
      sampler,
      logRecordProcessor: new BatchLogRecordProcessor(logExporter),
    });

    sdk.start();
    setSdk(sdk);

    // Start file watchers for gRPC mTLS cert rotation
    if (protocol === "grpc" && getGrpcMtlsCredentials()) {
      startGrpcMtlsFileWatchers(reinitializeOtelSdk);
    }

    logger.info({
      type: "opentelemetry",
      enabled: true,
      exporter: protocol === "grpc" ? "otlp-grpc" : "otlp-http",
      mtlsEnabled: protocol === "grpc" && getGrpcMtlsCredentials() != null,
    });

    return sdk;
  })().catch((error: unknown) => {
    clearSdkStartPromise();
    clearGrpcMtlsCredentials();
    stopGrpcMtlsFileWatchers();
    logger.error(
      {
        type: "opentelemetry",
        enabled: false,
        errorMessage: error instanceof Error ? error.message : String(error),
      },
      "opentelemetry: failed to initialize tracing exporter",
    );
    throw error;
  });

  setSdkStartPromise(startPromise);
  return startPromise;
}
