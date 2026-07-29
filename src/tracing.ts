import {
  SpanKind,
  SpanStatusCode,
  context,
  isSpanContextValid,
  propagation,
  trace,
  type Context,
  type Span,
} from "@opentelemetry/api";
import type { Request, Response } from "express";
import { watch } from 'node:fs';
import { readFile as readFileAsync } from 'node:fs/promises';
import { logger } from "./utils/logger.js";
import { secretLoader } from "./utils/secret-loader.js";

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

/**
 * Resolve the OTLP exporter protocol from env.
 *
 * @returns "http" or "grpc". Defaults to "http".
 */
export function getExporterProtocol(): 'http' | 'grpc' {
  const proto = process.env.OTEL_EXPORTER_PROTOCOL?.trim().toLowerCase();
  if (proto === 'grpc') return 'grpc';
  return 'http';
}

const TRUE_VALUES = new Set(["true", "1", "yes", "on"]);

/**
 * Whether gRPC mTLS is enabled for the OTLP exporter.
 *
 * Only meaningful when {@link getExporterProtocol} returns "grpc".
 */
export function isGrpcMtlsEnabled(): boolean {
  const val = process.env.OTEL_GRPC_MTLS_ENABLED?.trim().toLowerCase() ?? '';
  return TRUE_VALUES.has(val);
}

export const ALLOWED_BAGGAGE_KEYS = new Set(["tenant.id"]);

type OpenTelemetrySdk = {
  start: () => void;
  shutdown: () => Promise<void>;
};

let sdk: OpenTelemetrySdk | undefined;
let sdkStarted = false;
let sdkStartPromise: Promise<OpenTelemetrySdk | undefined> | undefined;

// ═══════════════════════════════════════════════════════════════════════════
// Cloud Provider Resource Detection
// ═══════════════════════════════════════════════════════════════════════════
//
// Detects cloud provider metadata (AWS, GCP, Kubernetes) and attaches
// resource attributes to every span so infra dashboards can correlate
// traces with hosts, regions, and clusters.
//
// Each detector is guarded by a configurable timeout
// (CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS, default 1000 ms) and a dedicated
// AbortController. Detection failures never block startup — the SDK starts
// with whatever attributes were collected before the deadline.

/** Default per-detector timeout in milliseconds. */
export const DEFAULT_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = 1_000

/** Maximum timeout to prevent misconfiguration from delaying boot. */
export const MAX_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = 5_000

/** Resolved attributes keyed by cloud.* / k8s.* / host.* convention. */
export type CloudResourceAttributes = Record<string, string>

/** Catalogue of resolved cloud attributes. */
export type CloudResourceDetectionResult = {
  provider: 'aws' | 'gcp' | 'kubernetes' | 'unknown'
  attributes: CloudResourceAttributes
}

/**
 * Resolve the per-detector timeout from env.
 *
 * Uses `CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS` (default 1000 ms),
 * clamped to [100, MAX_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS].
 */
export function resolveCloudDetectorTimeoutMs(): number {
  const raw = process.env.CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS
  const parsed = raw != null && raw !== '' ? Number(raw) : NaN
  const candidate = Number.isFinite(parsed) ? parsed : DEFAULT_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS
  return Math.max(100, Math.min(MAX_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS, candidate))
}

/**
 * Run a detector function with an AbortSignal timeout.
 *
 * Returns `attributes` when the detector completes within the deadline;
 * returns an empty object when the deadline expires or the detector throws.
 *
 * @param detector - Async function that returns a partial attributes map.
 * @param timeoutMs - Per-detector timeout in ms.
 * @param label    - Short label for observability (e.g. "aws", "gcp").
 */
async function detectWithTimeout(
  detector: (signal: AbortSignal) => Promise<CloudResourceAttributes>,
  timeoutMs: number,
  label: string,
): Promise<CloudResourceAttributes> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    if (timer && typeof timer.unref === 'function') timer.unref()
    return await detector(controller.signal)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    logger.debug({
      event: 'cloud_resource_detector_failed',
      provider: label,
      error: message,
    })
    return {}
  } finally {
    clearTimeout(timer)
  }
}

// ─── AWS EC2 Metadata detector ─────────────────────────────────────────────

const AWS_METADATA_BASE = 'http://169.254.169.254/latest/meta-data'

/**
 * Detect AWS resource attributes via the EC2 Instance Metadata Service
 * (IMDSv1 for broadest compatibility; IMDSv2 token retrieval is optional
 * but adds an extra round-trip that risks exceeding the timeout).
 */
export async function detectAwsResources(
  signal: AbortSignal,
  fetchImpl: typeof fetch = fetch,
): Promise<CloudResourceAttributes> {
  if (signal.aborted) return {}

  const attrs: CloudResourceAttributes = {}

  try {
    const [instanceId, instanceType, region, az, accountId] = await Promise.all([
      fetchImpl(`${AWS_METADATA_BASE}/instance-id`, { signal }).then(r => r.ok ? r.text() : ''),
      fetchImpl(`${AWS_METADATA_BASE}/instance-type`, { signal }).then(r => r.ok ? r.text() : ''),
      fetchImpl(`${AWS_METADATA_BASE}/placement/region`, { signal })
        .then(r => r.ok ? r.text() : '')
        .catch(() => ''),
      fetchImpl(`${AWS_METADATA_BASE}/placement/availability-zone`, { signal }).then(r => r.ok ? r.text() : ''),
      fetchImpl(`${AWS_METADATA_BASE}/identity-credentials/ec2/info`, { signal })
        .then(r => r.ok ? r.json() as { AccountId?: string } : null)
        .then(v => v?.AccountId ?? '')
        .catch(() => ''),
    ])

    if (instanceId) attrs['cloud.provider'] = 'aws'
    if (instanceId) attrs['cloud.platform'] = 'aws_ec2'
    if (instanceId) attrs['host.id'] = instanceId
    if (instanceType) attrs['host.type'] = instanceType
    if (region) attrs['cloud.region'] = region
    if (az) attrs['cloud.availability_zone'] = az
    if (accountId) attrs['cloud.account.id'] = accountId
  } catch {
    // Timeout or network error — return whatever we collected (likely empty)
  }

  return attrs
}

// ─── GCP Compute Engine Metadata detector ──────────────────────────────────

const GCP_METADATA_BASE = 'http://metadata.google.internal/computeMetadata/v1'

/**
 * Detect GCP resource attributes via the Compute Engine Metadata Server.
 *
 * Requires the `Metadata-Flavor: Google` header per GCP security
 * requirements. Falls back gracefully when run outside GCP.
 */
export async function detectGcpResources(
  signal: AbortSignal,
  fetchImpl: typeof fetch = fetch,
): Promise<CloudResourceAttributes> {
  if (signal.aborted) return {}

  const attrs: CloudResourceAttributes = {}
  const headers = { 'Metadata-Flavor': 'Google' }

  try {
    const [instanceId, instanceName, zone, projectId] = await Promise.all([
      fetchImpl(`${GCP_METADATA_BASE}/instance/id`, { signal, headers })
        .then(r => r.ok ? r.text() : ''),
      fetchImpl(`${GCP_METADATA_BASE}/instance/name`, { signal, headers })
        .then(r => r.ok ? r.text() : ''),
      fetchImpl(`${GCP_METADATA_BASE}/instance/zone`, { signal, headers })
        .then(r => r.ok ? r.text() : ''),
      fetchImpl(`${GCP_METADATA_BASE}/project/project-id`, { signal, headers })
        .then(r => r.ok ? r.text() : ''),
    ])

    // Extract region from zone (projects/PROJECT/zones/us-central1-a → us-central1)
    const region = zone ? zone.split('/').pop()?.replace(/-[a-z]$/, '') ?? '' : ''

    if (instanceId) attrs['cloud.provider'] = 'gcp'
    if (instanceId) attrs['cloud.platform'] = 'gcp_compute_engine'
    if (instanceId) attrs['host.id'] = instanceId
    if (instanceName) attrs['host.name'] = instanceName
    if (region) attrs['cloud.region'] = region
    if (zone) attrs['cloud.availability_zone'] = zone.split('/').pop() ?? zone
    if (projectId) attrs['cloud.account.id'] = projectId
  } catch {
    // Timeout or network error
  }

  return attrs
}

// ─── Kubernetes detector ───────────────────────────────────────────────────

/**
 * Detect Kubernetes resource attributes from the downwards API and
 * container runtime cgroups.
 *
 * This is a lightweight detector that does not require the k8s client
 * library — it reads env vars and /proc/self/cgroup, both of which are
 * available inside any Pod without extra dependencies.
 */
export async function detectKubernetesResources(
  signal: AbortSignal,
  readFileImpl: (path: string) => Promise<string> = (p) => readFileAsync(p, 'utf-8'),
): Promise<CloudResourceAttributes> {
  const attrs: CloudResourceAttributes = {}

  if (signal.aborted) return attrs

  const podName = process.env.KUBERNETES_POD_NAME ?? process.env.HOSTNAME ?? ''
  const namespace = process.env.KUBERNETES_NAMESPACE ?? ''
  const nodeName = process.env.KUBERNETES_NODE_NAME ?? ''

  if (podName) attrs['k8s.pod.name'] = podName
  if (namespace) attrs['k8s.namespace.name'] = namespace
  if (nodeName) attrs['k8s.node.name'] = nodeName
  if (podName) attrs['cloud.provider'] = attrs['cloud.provider'] ?? 'kubernetes'

  // Container ID from cgroup (first line matching /kubepods/...)
  try {
    const cgroup = await readFileImpl('/proc/self/cgroup')
    if (!signal.aborted) {
      for (const line of cgroup.split('\n')) {
        const parts = line.split(':')
        if (parts.length < 3) continue
        const path = parts[2] ?? ''
        // /kubepods/besteffort/pod<UID>/<container-id> OR /kubepods/burstable/...
        const match = path.match(/\/kubepods\/[^/]+\/pod[^/]+\/([0-9a-f]{64})/)
        if (match) {
          attrs['container.id'] = match[1]
          break
        }
        // Docker runtime: /docker/<container-id>
        const dockerMatch = path.match(/\/docker\/([0-9a-f]{64})/)
        if (dockerMatch) {
          attrs['container.id'] = dockerMatch[1]
          break
        }
      }
    }
  } catch {
    // /proc/self/cgroup may not be readable (e.g. non-Linux)
  }

  return attrs
}

/**
 * Run all cloud resource detectors in parallel with individual timeouts.
 *
 * Each detector is given `timeoutMs` to complete. The function returns
 * the merged attributes from any detectors that finish within the deadline.
 * When no detector returns attributes the result's `provider` is "unknown".
 *
 * This is the public entrypoint called during SDK initialisation.
 */
export async function detectCloudResources(
  timeoutMs: number = resolveCloudDetectorTimeoutMs(),
  fetchImpl: typeof fetch = fetch,
  readFileImpl: (path: string) => Promise<string> = (p) => readFileAsync(p, 'utf-8'),
): Promise<CloudResourceDetectionResult> {
  const [awsAttrs, gcpAttrs, k8sAttrs] = await Promise.all([
    detectWithTimeout((s) => detectAwsResources(s, fetchImpl), timeoutMs, 'aws'),
    detectWithTimeout((s) => detectGcpResources(s, fetchImpl), timeoutMs, 'gcp'),
    detectWithTimeout((s) => detectKubernetesResources(s, readFileImpl), timeoutMs, 'kubernetes'),
  ])

  // Merge: later detectors do NOT overwrite keys set by earlier ones
  const merged: CloudResourceAttributes = {}
  for (const attrs of [awsAttrs, gcpAttrs, k8sAttrs]) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v && !(k in merged)) merged[k] = v
    }
  }

  const provider =
    merged['cloud.provider'] === 'aws' ? 'aws' :
    merged['cloud.provider'] === 'gcp' ? 'gcp' :
    merged['k8s.pod.name'] ? 'kubernetes' :
    'unknown'

  return { provider, attributes: merged }
}

// ═══════════════════════════════════════════════════════════════════════════

const HTTP_HEADER_GETTER = {
  get(carrier: Request["headers"], key: string) {
    const value = carrier[key.toLowerCase()];
    return Array.isArray(value)
      ? value
      : value === undefined
        ? undefined
        : [value];
  },
  keys(carrier: Request["headers"]) {
    return Object.keys(carrier);
  },
};

export function isOpenTelemetryEnabled(): boolean {
  return Boolean(process.env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim());
}

// ─── gRPC mTLS credential management ───────────────────────────────────────

/**
 * Loaded gRPC mTLS credentials.
 *
 * `undefined` means mTLS is not enabled. When set, all three buffers
 * contain the PEM-encoded CA, client certificate, and private key.
 */
let grpcMtlsCredentials: {
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
} | undefined;

/**
 * Whether mTLS creds were loaded from file paths (true) or secret loader (false).
 * Files are watched for rotation; secret-loader creds rotate via reload().
 */
let grpcMtlsFromFiles = false;

/** Active file watchers for gRPC mTLS cert files. Cleared on SDK shutdown. */
const grpcMtlsWatchers: Array<ReturnType<typeof watch>> = [];

/** Debounce timer for file-watch-driven SDK reinitialization. */
let grpcMtlsDebounceTimer: ReturnType<typeof setTimeout> | undefined;

/** Guard against concurrent SDK reinitializations. */
let grpcMtlsReinitInProgress = false;

/**
 * Attempt to load PEM credential material from the secret loader.
 *
 * Keys tried: `OTEL_MTLS_CA`, `OTEL_MTLS_CERT`, `OTEL_MTLS_KEY`.
 * When all three resolve, the PEM strings are returned as Buffers.
 * When any key is missing the function returns `undefined` so the
 * caller can fall back to file-path loading.
 */
async function loadGrpcMtlsFromSecretLoader(): Promise<
  { ca: Buffer; cert: Buffer; key: Buffer } | undefined
> {
  try {
    const [ca, cert, key] = await Promise.all([
      secretLoader.get("OTEL_MTLS_CA"),
      secretLoader.get("OTEL_MTLS_CERT"),
      secretLoader.get("OTEL_MTLS_KEY"),
    ]);
    if (!ca || !cert || !key) return undefined;
    return {
      ca: Buffer.from(ca, "utf-8"),
      cert: Buffer.from(cert, "utf-8"),
      key: Buffer.from(key, "utf-8"),
    };
  } catch {
    // SecretNotLoadedError or SecretNotFoundError → fall back to files
    return undefined;
  }
}

/**
 * Load gRPC mTLS credentials.
 *
 * Prefers the secret loader (keys `OTEL_MTLS_CA`, `OTEL_MTLS_CERT`,
 * `OTEL_MTLS_KEY`) so operators can store PEM material in Vault, env,
 * or a file backend. Falls back to reading from filesystem paths
 * (`OTEL_MTLS_CA_PATH`, …) when the secret loader returns nothing.
 *
 * Returns `undefined` when mTLS is not enabled. Throws when mTLS is
 * enabled but neither backend provides all three PEM values.
 */
async function loadGrpcMtlsCredentials(): Promise<
  { ca: Buffer; cert: Buffer; key: Buffer } | undefined
> {
  if (!isGrpcMtlsEnabled()) return undefined;

  // 1. Try secret loader (supports Vault, env, file backends)
  const fromSecrets = await loadGrpcMtlsFromSecretLoader();
  if (fromSecrets) {
    grpcMtlsFromFiles = false;
    return fromSecrets;
  }

  // 2. Fall back to file paths
  const caPath = process.env.OTEL_MTLS_CA_PATH?.trim();
  const certPath = process.env.OTEL_MTLS_CERT_PATH?.trim();
  const keyPath = process.env.OTEL_MTLS_KEY_PATH?.trim();

  if (!caPath || !certPath || !keyPath) {
    throw new Error(
      "OTEL_GRPC_MTLS_ENABLED=true but neither secret-loader keys " +
        "(OTEL_MTLS_CA/CERT/KEY) nor file paths " +
        "(OTEL_MTLS_CA_PATH/CERT_PATH/KEY_PATH) are fully configured.",
    );
  }

  const [ca, cert, key] = await Promise.all([
    readFileAsync(caPath),
    readFileAsync(certPath),
    readFileAsync(keyPath),
  ]);

  grpcMtlsFromFiles = true;
  return { ca, cert, key };
}

/**
 * Start file watchers on the gRPC mTLS certificate paths.
 *
 * Only active when credentials were loaded from files (not the secret
 * loader). When any watched file changes, the exporter is reinitialised
 * so that rotated certificates take effect without a process restart.
 * A short debounce prevents storms when a certificate manager atomically
 * replaces multiple files in quick succession.
 */
function startGrpcMtlsFileWatchers(): void {
  if (!grpcMtlsFromFiles) return;

  const paths = [
    process.env.OTEL_MTLS_CA_PATH?.trim(),
    process.env.OTEL_MTLS_CERT_PATH?.trim(),
    process.env.OTEL_MTLS_KEY_PATH?.trim(),
  ].filter((p): p is string => Boolean(p));

  for (const filePath of paths) {
    try {
      const watcher = watch(filePath, (eventType) => {
        if (eventType !== 'change') return;
        if (grpcMtlsDebounceTimer) clearTimeout(grpcMtlsDebounceTimer);
        grpcMtlsDebounceTimer = setTimeout(() => {
          logger.info({
            event: 'otel_grpc_mtls_cert_changed',
            path: filePath,
          });
          reinitializeOtelSdk().catch((err) => {
            logger.error({
              event: 'otel_grpc_mtls_reinit_failed',
              error: err instanceof Error ? err.message : String(err),
            });
          });
        }, 500);
      });
      grpcMtlsWatchers.push(watcher);
    } catch {
      logger.debug({
        event: 'otel_grpc_mtls_watcher_failed',
        path: filePath,
      });
    }
  }
}

/**
 * Stop all gRPC mTLS file watchers and cancel any pending debounce timer.
 */
function stopGrpcMtlsFileWatchers(): void {
  if (grpcMtlsDebounceTimer) {
    clearTimeout(grpcMtlsDebounceTimer);
    grpcMtlsDebounceTimer = undefined;
  }
  for (const watcher of grpcMtlsWatchers) {
    try { watcher.close(); } catch { /* best-effort */ }
  }
  grpcMtlsWatchers.length = 0;
}

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
    if (sdkStarted && sdk) {
      await sdk.shutdown();
      sdkStarted = false;
      sdk = undefined;
    }
    stopGrpcMtlsFileWatchers();
    sdkStartPromise = undefined;
    grpcMtlsCredentials = undefined;
    grpcMtlsFromFiles = false;
    await initializeOpenTelemetry();
  } finally {
    grpcMtlsReinitInProgress = false;
  }
}

export async function initializeOpenTelemetry(): Promise<
  OpenTelemetrySdk | undefined
> {
  if (!isOpenTelemetryEnabled()) {
    return undefined;
  }

  if (sdkStartPromise) {
    return sdkStartPromise;
  }

  const protocol = getExporterProtocol();

  sdkStartPromise = (async () => {
    // ── Load credentials for gRPC mTLS ───────────────────────────────
    if (protocol === 'grpc') {
      grpcMtlsCredentials = await loadGrpcMtlsCredentials();
    }

    // ── Dynamic imports per protocol ─────────────────────────────────
    let OTLPTraceExporter: new (opts: Record<string, unknown>) => unknown;
    let OTLPLogExporter: new (opts: Record<string, unknown>) => unknown;

    const [
      { NodeSDK },
      { BatchLogRecordProcessor },
    ] = await Promise.all([
      import("@opentelemetry/sdk-node"),
      import("@opentelemetry/sdk-logs"),
    ]);

    if (protocol === 'grpc') {
      const [traceMod, logMod] = await Promise.all([
        import("@opentelemetry/exporter-trace-otlp-grpc"),
        import("@opentelemetry/exporter-logs-otlp-grpc"),
      ]);
      OTLPTraceExporter = traceMod.OTLPTraceExporter;
      OTLPLogExporter = logMod.OTLPLogExporter;
    } else {
      const [traceMod, logMod] = await Promise.all([
        import("@opentelemetry/exporter-trace-otlp-http"),
        import("@opentelemetry/exporter-logs-otlp-http"),
      ]);
      OTLPTraceExporter = traceMod.OTLPTraceExporter;
      OTLPLogExporter = logMod.OTLPLogExporter;
    }

    // ── Build exporter options ───────────────────────────────────────
    const traceUrl =
      protocol === 'grpc'
        ? process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? 'http://localhost:4317'
        : process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

    const logUrl =
      protocol === 'grpc'
        ? traceUrl
        : traceUrl?.endsWith("/v1/traces")
          ? traceUrl.replace(/\/v1\/traces$/, "/v1/logs")
          : undefined;

    const exporterOptions: Record<string, unknown> = { url: traceUrl };
    const logExporterOptions: Record<string, unknown> = { url: logUrl };

    // Wire gRPC mTLS credentials when enabled — shared across both exporters
    if (protocol === 'grpc' && grpcMtlsCredentials) {
      const { credentials: grpcCredentials } = await import("@grpc/grpc-js");
      const sslCreds = grpcCredentials.createSsl(
        grpcMtlsCredentials.ca,
        grpcMtlsCredentials.key,
        grpcMtlsCredentials.cert,
      );
      exporterOptions.credentials = sslCreds;
      logExporterOptions.credentials = sslCreds;
    }

    const rawExporter = new OTLPTraceExporter(exporterOptions);
    const logExporter = new OTLPLogExporter(logExporterOptions);

    const [{ SanitizingSpanExporter }, { RouteAwareSampler }] = await Promise.all([
      import("./tracing/sanitizer.js"),
      import("./tracing/sampler.js"),
    ]);
    const traceExporter = new SanitizingSpanExporter(rawExporter);
    const sampler = new RouteAwareSampler();

    // Import Resource type for cloud-provider detection integration.
    const { Resource } = await import("@opentelemetry/resources");

    // Detect cloud-provider resource attributes with timeout guards.
    // Detection NEVER blocks startup — the SDK starts with whatever
    // attributes were collected before the combined deadline.
    let resourceAttributes: Record<string, string> = {};
    try {
      const detection = await detectCloudResources();
      if (detection.provider !== 'unknown') {
        resourceAttributes = detection.attributes;
        logger.info({
          event: 'cloud_resource_detected',
          provider: detection.provider,
          attributeCount: Object.keys(resourceAttributes).length,
        });
      }
    } catch (detectErr) {
      logger.debug({
        event: 'cloud_resource_detection_skipped',
        error: detectErr instanceof Error ? detectErr.message : String(detectErr),
      });
    }

    sdk = new NodeSDK({
      serviceName: process.env.OTEL_SERVICE_NAME ?? "veritasor-backend",
      resource: new Resource(resourceAttributes),
      traceExporter,
      sampler,
      logRecordProcessor: new BatchLogRecordProcessor(logExporter),
    });

    sdk.start();
    sdkStarted = true;

    // Start file watchers for gRPC mTLS cert rotation
    if (protocol === 'grpc' && grpcMtlsCredentials) {
      startGrpcMtlsFileWatchers();
    }

    logger.info({
      type: "opentelemetry",
      enabled: true,
      exporter: protocol === 'grpc' ? "otlp-grpc" : "otlp-http",
      mtlsEnabled: protocol === 'grpc' && grpcMtlsCredentials != null,
    });

    return sdk;
  })().catch((error: unknown) => {
    sdkStartPromise = undefined;
    grpcMtlsCredentials = undefined;
    grpcMtlsFromFiles = false;
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

  return sdkStartPromise;
}

export async function shutdownOpenTelemetry(): Promise<void> {
  stopGrpcMtlsFileWatchers();
  if (!sdkStarted || !sdk) {
    return;
  }

  await sdk.shutdown();
  sdkStarted = false;
  sdk = undefined;
  grpcMtlsCredentials = undefined;
  grpcMtlsFromFiles = false;
}

export function getHttpRequestContext(req: Request): Context {
  if (!isOpenTelemetryEnabled()) {
    return context.active();
  }

  return propagation.extract(context.active(), req.headers, HTTP_HEADER_GETTER);
}

export function getActiveTraceExemplarLabels(): Record<string, string> {
  const activeSpan = trace.getActiveSpan();
  const spanContext = activeSpan?.spanContext();

  if (!spanContext || !isSpanContextValid(spanContext)) {
    return {};
  }

  return {
    trace_id: spanContext.traceId,
  };
}

export function startHttpRequestSpan(
  req: Request,
  res: Response,
  correlationId: string,
  next: () => void,
  onFinish?: () => void,
): void {
  if (!isOpenTelemetryEnabled()) {
    if (onFinish) {
      res.once("finish", onFinish);
    }
    next();
    return;
  }

  const tracer = trace.getTracer("veritasor-backend.http");
  const extractedContext = getHttpRequestContext(req);

  let requestContext = extractedContext;
  const b = propagation.getBaggage(extractedContext);
  if (b) {
    let newBaggage = propagation.createBaggage();
    for (const key of ALLOWED_BAGGAGE_KEYS) {
      const entry = b.getEntry(key);
      if (entry) {
        newBaggage = newBaggage.setEntry(key, entry);
      }
    }
    requestContext = propagation.setBaggage(extractedContext, newBaggage);
  }

  context.with(requestContext, () => {
    tracer.startActiveSpan(
      `HTTP ${req.method} ${req.path}`,
      {
        kind: SpanKind.SERVER,
        attributes: {
          "http.request.method": req.method,
          "url.path": req.path,
          "http.route": req.path,
          "client.address": req.ip,
          "user_agent.original": req.headers["user-agent"] ?? "",
          "veritasor.correlation_id": correlationId,
        },
      },
      (span) => {
        const activeBaggage = propagation.getBaggage(context.active());
        const tenantId = activeBaggage?.getEntry("tenant.id")?.value;
        if (tenantId) {
          span.setAttribute("tenant.id", tenantId);
        }

        const spanExecutionContext = context.active();
        let ended = false;
        const endSpan = () => {
          if (ended) {
            return;
          }
          ended = true;
          const route = (req.route?.path as string | undefined) ?? req.path;
          span.setAttribute("http.route", route);
          span.setAttribute("http.response.status_code", res.statusCode);
          if (res.statusCode >= 500) {
            span.setStatus({ code: SpanStatusCode.ERROR });
          }
          span.end();
        };

        res.once("finish", () => {
          context.with(spanExecutionContext, () => {
            onFinish?.();
            endSpan();
          });
        });
        res.once("close", () => {
          context.with(spanExecutionContext, endSpan);
        });

        try {
          next();
        } catch (error) {
          recordRedactedException(span, error);
          span.setStatus({ code: SpanStatusCode.ERROR });
          endSpan();
          throw error;
        }
      },
    );
  });
}

export async function traceSorobanRpcAttempt<T>(
  operationName: string,
  attempt: number,
  execute: () => Promise<T>,
): Promise<T> {
  if (!isOpenTelemetryEnabled()) {
    return execute();
  }

  const tracer = trace.getTracer("veritasor-backend.soroban");
  let currentContext = context.active();
  const b = propagation.getBaggage(currentContext);
  if (b) {
    currentContext = propagation.setBaggage(currentContext, b.removeEntry("tenant.id"));
  }

  return context.with(currentContext, () => {
    return tracer.startActiveSpan(
      `soroban.rpc ${operationName}`,
      {
        kind: SpanKind.CLIENT,
      attributes: {
        "rpc.system": "soroban",
        "rpc.method": operationName,
        "soroban.rpc.attempt": attempt,
        "retry.attempt": attempt,
      },
    },
    async (span) => {
      try {
        const result = await execute();
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (error) {
        recordRedactedException(span, error);
        span.setStatus({ code: SpanStatusCode.ERROR });
        throw error;
      } finally {
        span.end();
      }
    },
  );
  });
}

function recordRedactedException(span: Span, error: unknown): void {
  const errorName = error instanceof Error ? error.name : "NonError";
  span.recordException({
    name: errorName,
    message: "redacted",
  });
  span.setAttribute("error.type", errorName);
}
