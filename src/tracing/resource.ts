/**
 * Cloud-provider resource detection for the OpenTelemetry SDK.
 *
 * Detects AWS, GCP, and Kubernetes metadata and turns it into resource
 * attributes so infrastructure dashboards can correlate traces with hosts,
 * regions, and clusters.
 *
 * Each detector is guarded by a configurable timeout
 * (`CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS`, default 1000 ms) and a dedicated
 * `AbortController`. Detection failures never block startup — the SDK starts
 * with whatever attributes were collected before the deadline.
 */

import { readFile as readFileAsync } from "node:fs/promises";
import { logger } from "../utils/logger.js";

/** Default per-detector timeout in milliseconds. */
export const DEFAULT_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = 1_000;

/** Maximum timeout to prevent misconfiguration from delaying boot. */
export const MAX_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS = 5_000;

/** Resolved attributes keyed by cloud.* / k8s.* / host.* convention. */
export type CloudResourceAttributes = Record<string, string>;

/** Catalogue of resolved cloud attributes. */
export type CloudResourceDetectionResult = {
  provider: "aws" | "gcp" | "kubernetes" | "unknown";
  attributes: CloudResourceAttributes;
};

/**
 * Resolve the per-detector timeout from env.
 *
 * Uses `CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS` (default 1000 ms),
 * clamped to [100, MAX_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS].
 */
export function resolveCloudDetectorTimeoutMs(): number {
  const raw = process.env.CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS;
  const parsed = raw != null && raw !== "" ? Number(raw) : NaN;
  const candidate = Number.isFinite(parsed)
    ? parsed
    : DEFAULT_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS;
  return Math.max(100, Math.min(MAX_CLOUD_RESOURCE_DETECTOR_TIMEOUT_MS, candidate));
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
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    if (timer && typeof timer.unref === "function") timer.unref();
    return await detector(controller.signal);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.debug({
      event: "cloud_resource_detector_failed",
      provider: label,
      error: message,
    });
    return {};
  } finally {
    clearTimeout(timer);
  }
}

// ─── AWS EC2 Metadata detector ─────────────────────────────────────────────

const AWS_METADATA_BASE = "http://169.254.169.254/latest/meta-data";

/**
 * Detect AWS resource attributes via the EC2 Instance Metadata Service
 * (IMDSv1 for broadest compatibility; IMDSv2 token retrieval is optional
 * but adds an extra round-trip that risks exceeding the timeout).
 */
export async function detectAwsResources(
  signal: AbortSignal,
  fetchImpl: typeof fetch = fetch,
): Promise<CloudResourceAttributes> {
  if (signal.aborted) return {};

  const attrs: CloudResourceAttributes = {};

  try {
    const [instanceId, instanceType, region, az, accountId] = await Promise.all([
      fetchImpl(`${AWS_METADATA_BASE}/instance-id`, { signal }).then((r) => (r.ok ? r.text() : "")),
      fetchImpl(`${AWS_METADATA_BASE}/instance-type`, { signal }).then((r) => (r.ok ? r.text() : "")),
      fetchImpl(`${AWS_METADATA_BASE}/placement/region`, { signal })
        .then((r) => (r.ok ? r.text() : ""))
        .catch(() => ""),
      fetchImpl(`${AWS_METADATA_BASE}/placement/availability-zone`, { signal }).then((r) =>
        r.ok ? r.text() : "",
      ),
      fetchImpl(`${AWS_METADATA_BASE}/identity-credentials/ec2/info`, { signal })
        .then((r) => (r.ok ? (r.json() as Promise<{ AccountId?: string }>) : null))
        .then((v) => v?.AccountId ?? "")
        .catch(() => ""),
    ]);

    if (instanceId) attrs["cloud.provider"] = "aws";
    if (instanceId) attrs["cloud.platform"] = "aws_ec2";
    if (instanceId) attrs["host.id"] = instanceId;
    if (instanceType) attrs["host.type"] = instanceType;
    if (region) attrs["cloud.region"] = region;
    if (az) attrs["cloud.availability_zone"] = az;
    if (accountId) attrs["cloud.account.id"] = accountId;
  } catch {
    // Timeout or network error — return whatever we collected (likely empty)
  }

  return attrs;
}

// ─── GCP Compute Engine Metadata detector ──────────────────────────────────

const GCP_METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1";

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
  if (signal.aborted) return {};

  const attrs: CloudResourceAttributes = {};
  const headers = { "Metadata-Flavor": "Google" };

  try {
    const [instanceId, instanceName, zone, projectId] = await Promise.all([
      fetchImpl(`${GCP_METADATA_BASE}/instance/id`, { signal, headers }).then((r) =>
        r.ok ? r.text() : "",
      ),
      fetchImpl(`${GCP_METADATA_BASE}/instance/name`, { signal, headers }).then((r) =>
        r.ok ? r.text() : "",
      ),
      fetchImpl(`${GCP_METADATA_BASE}/instance/zone`, { signal, headers }).then((r) =>
        r.ok ? r.text() : "",
      ),
      fetchImpl(`${GCP_METADATA_BASE}/project/project-id`, { signal, headers }).then((r) =>
        r.ok ? r.text() : "",
      ),
    ]);

    // Extract region from zone (projects/PROJECT/zones/us-central1-a → us-central1)
    const region = zone ? (zone.split("/").pop()?.replace(/-[a-z]$/, "") ?? "") : "";

    if (instanceId) attrs["cloud.provider"] = "gcp";
    if (instanceId) attrs["cloud.platform"] = "gcp_compute_engine";
    if (instanceId) attrs["host.id"] = instanceId;
    if (instanceName) attrs["host.name"] = instanceName;
    if (region) attrs["cloud.region"] = region;
    if (zone) attrs["cloud.availability_zone"] = zone.split("/").pop() ?? zone;
    if (projectId) attrs["cloud.account.id"] = projectId;
  } catch {
    // Timeout or network error
  }

  return attrs;
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
  readFileImpl: (path: string) => Promise<string> = (p) => readFileAsync(p, "utf-8"),
): Promise<CloudResourceAttributes> {
  const attrs: CloudResourceAttributes = {};

  if (signal.aborted) return attrs;

  const podName = process.env.KUBERNETES_POD_NAME ?? process.env.HOSTNAME ?? "";
  const namespace = process.env.KUBERNETES_NAMESPACE ?? "";
  const nodeName = process.env.KUBERNETES_NODE_NAME ?? "";

  if (podName) attrs["k8s.pod.name"] = podName;
  if (namespace) attrs["k8s.namespace.name"] = namespace;
  if (nodeName) attrs["k8s.node.name"] = nodeName;
  if (podName) attrs["cloud.provider"] = attrs["cloud.provider"] ?? "kubernetes";

  // Container ID from cgroup (first line matching /kubepods/...)
  try {
    const cgroup = await readFileImpl("/proc/self/cgroup");
    if (!signal.aborted) {
      for (const line of cgroup.split("\n")) {
        const parts = line.split(":");
        if (parts.length < 3) continue;
        const path = parts[2] ?? "";
        // /kubepods/besteffort/pod<UID>/<container-id> OR /kubepods/burstable/...
        const match = path.match(/\/kubepods\/[^/]+\/pod[^/]+\/([0-9a-f]{64})/);
        if (match) {
          attrs["container.id"] = match[1];
          break;
        }
        // Docker runtime: /docker/<container-id>
        const dockerMatch = path.match(/\/docker\/([0-9a-f]{64})/);
        if (dockerMatch) {
          attrs["container.id"] = dockerMatch[1];
          break;
        }
      }
    }
  } catch {
    // /proc/self/cgroup may not be readable (e.g. non-Linux)
  }

  return attrs;
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
  readFileImpl: (path: string) => Promise<string> = (p) => readFileAsync(p, "utf-8"),
): Promise<CloudResourceDetectionResult> {
  const [awsAttrs, gcpAttrs, k8sAttrs] = await Promise.all([
    detectWithTimeout((s) => detectAwsResources(s, fetchImpl), timeoutMs, "aws"),
    detectWithTimeout((s) => detectGcpResources(s, fetchImpl), timeoutMs, "gcp"),
    detectWithTimeout((s) => detectKubernetesResources(s, readFileImpl), timeoutMs, "kubernetes"),
  ]);

  // Merge: later detectors do NOT overwrite keys set by earlier ones
  const merged: CloudResourceAttributes = {};
  for (const attrs of [awsAttrs, gcpAttrs, k8sAttrs]) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v && !(k in merged)) merged[k] = v;
    }
  }

  const provider =
    merged["cloud.provider"] === "aws"
      ? "aws"
      : merged["cloud.provider"] === "gcp"
        ? "gcp"
        : merged["k8s.pod.name"]
          ? "kubernetes"
          : "unknown";

  return { provider, attributes: merged };
}
