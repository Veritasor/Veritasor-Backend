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
import { readFile } from 'node:fs/promises';
import { logger } from "./utils/logger.js";

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
  readFileImpl: (path: string) => Promise<string> = (p) => readFile(p, 'utf-8'),
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
  readFileImpl: (path: string) => Promise<string> = (p) => readFile(p, 'utf-8'),
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

export async function initializeOpenTelemetry(): Promise<
  OpenTelemetrySdk | undefined
> {
  if (!isOpenTelemetryEnabled()) {
    return undefined;
  }

  if (sdkStartPromise) {
    return sdkStartPromise;
  }

  sdkStartPromise = (async () => {
    const [
      { NodeSDK },
      { OTLPTraceExporter },
      { OTLPLogExporter },
      { BatchLogRecordProcessor }
    ] = await Promise.all([
      import("@opentelemetry/sdk-node"),
      import("@opentelemetry/exporter-trace-otlp-http"),
      import("@opentelemetry/exporter-logs-otlp-http"),
      import("@opentelemetry/sdk-logs")
    ]);

    const traceUrl = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    const logUrl = traceUrl?.endsWith("/v1/traces")
      ? traceUrl.replace(/\/v1\/traces$/, "/v1/logs")
      : undefined;

    const rawExporter = new OTLPTraceExporter({
      url: traceUrl,
    });

    const logExporter = new OTLPLogExporter({
      url: logUrl,
    });

    const { SanitizingSpanExporter } = await import(
      "./tracing/sanitizer.js"
    );
    const traceExporter = new SanitizingSpanExporter(rawExporter);

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
      logRecordProcessor: new BatchLogRecordProcessor(logExporter),
    });

    sdk.start();
    sdkStarted = true;

    logger.info({
      type: "opentelemetry",
      enabled: true,
      exporter: "otlp-http",
    });

    return sdk;
  })().catch((error: unknown) => {
    sdkStartPromise = undefined;
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
  if (!sdkStarted || !sdk) {
    return;
  }

  await sdk.shutdown();
  sdkStarted = false;
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
