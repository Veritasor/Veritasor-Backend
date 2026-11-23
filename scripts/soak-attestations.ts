#!/usr/bin/env tsx
/**
 * Autocannon-based soak test harness for /api/v1/attestations submit path.
 *
 * Runs sustained load against a local (or remote) instance and reports
 * p50 / p95 / p99 latency, throughput, and error rates.  The process exits
 * with code 1 when the p95 latency or error rate exceeds configurable
 * thresholds -- making it safe to gate CI on the result.
 *
 * Usage:
 *   tsx scripts/soak-attestations.ts [options]
 *
 * Options (all overridable via env vars -- CLI flags take precedence):
 *   --url        Base URL                (SOAK_BASE_URL,  default http://127.0.0.1:3000)
 *   --path       Attestation path        (SOAK_PATH,      default /api/v1/attestations)
 *   --token      JWT auth token          (SOAK_AUTH_TOKEN, required)
 *   --duration   Seconds to run          (SOAK_DURATION,  default 30)
 *   --connections Concurrency            (SOAK_CONNECTIONS, default 10)
 *   --businessId Business ID             (SOAK_BUSINESS_ID, optional)
 *   --merkleRoot Merkle root hex         (SOAK_MERKLE_ROOT, default 0xab x 32)
 *   --p95ThresholdMs   p95 limit (ms)    (SOAK_P95_THRESHOLD_MS, default 500)
 *   --errorRateThreshold Error-rate cap  (SOAK_ERROR_RATE_THRESHOLD, default 0.01)
 *   --writeRatio 0-1 fraction of writes  (SOAK_WRITE_RATIO, default 1.0)
 *   --bailout     error count before bail (SOAK_BAILOUT, default 0 = no bail)
 *
 * Exit codes:
 *   0  all thresholds passed
 *   1  threshold breach or invocation error
 */

let _autocannonFn: ((options: AutocannonOptions) => Instance) | null = null;
let _autocannonTrack: ((instance: Instance, options?: TrackingOptions) => void) | null = null;

async function loadAutocannon(): Promise<void> {
  if (_autocannonFn) return;
  const acModule = await import("autocannon");
  const mod = acModule as Record<string, unknown>;
  _autocannonFn = (typeof mod.default === "function"
    ? mod.default
    : mod) as (options: AutocannonOptions) => Instance;
  _autocannonTrack = mod.track as (instance: Instance, options?: TrackingOptions) => void;
}

// --- types (supplementing @types/autocannon which lacks p95) ---

export interface Histogram {
  total: number;
  average: number;
  mean: number;
  stddev: number;
  min: number;
  max: number;
  p0_001: number;
  p0_01: number;
  p0_1: number;
  p1: number;
  p2_5: number;
  p10: number;
  p25: number;
  p50: number;
  p75: number;
  p90: number;
  p95: number;
  p97_5: number;
  p99: number;
  p99_9: number;
  p99_99: number;
  p99_999: number;
  [key: string]: number;
}

export interface Result {
  title: string | undefined;
  url: string;
  socketPath: string | undefined;
  requests: Histogram & { sent: number };
  latency: Histogram;
  throughput: Histogram;
  duration: number;
  errors: number;
  timeouts: number;
  start: Date;
  finish: Date;
  connections: number;
  pipelining: number;
  non2xx: number;
  "1xx": number;
  "2xx": number;
  "3xx": number;
  "4xx": number;
  "5xx": number;
  mismatches: number;
  resets: number;
}

interface AutocannonOptions {
  url: string;
  connections?: number;
  duration?: number | string;
  timeout?: number;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  bailout?: number;
  title?: string;
}

interface Instance {
  stop(): void;
  on(event: "done", listener: (result: Result) => void): Instance;
  on(event: "error", listener: (err: Error) => void): Instance;
  on(event: string, listener: (...args: unknown[]) => void): Instance;
}

interface TrackingOptions {
  renderProgressBar?: boolean;
  renderResultsTable?: boolean;
  renderLatencyTable?: boolean;
  outputStream?: NodeJS.WritableStream;
}

// --- CLI parsing ---

export interface SoakConfig {
  url: string;
  path: string;
  token: string;
  duration: number;
  connections: number;
  businessId: string;
  merkleRoot: string;
  p95ThresholdMs: number;
  errorRateThreshold: number;
  writeRatio: number;
  bailout: number;
  timeout: number;
}

function envStr(key: string, fallback: string): string {
  const v = process.env[key];
  return v && v.trim() !== "" ? v.trim() : fallback;
}

function envInt(key: string, fallback: number, min = 0): number {
  const raw = process.env[key];
  if (raw === undefined || raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= min ? n : fallback;
}

function envFloat(key: string, fallback: number, min = 0, max = 1): number {
  const raw = process.env[key];
  if (raw === undefined || raw === "") return fallback;
  const n = Number.parseFloat(raw);
  return Number.isFinite(n) && n >= min && n <= max ? n : fallback;
}

export function parseArgs(argv: string[]): Partial<SoakConfig> {
  const cfg: Partial<SoakConfig> = {};
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    switch (flag) {
      case "--url":         cfg.url = args[++i]; break;
      case "--path":        cfg.path = args[++i]; break;
      case "--token":       cfg.token = args[++i]; break;
      case "--duration":    cfg.duration = Number(args[++i]); break;
      case "--connections": cfg.connections = Number(args[++i]); break;
      case "--businessId":  cfg.businessId = args[++i]; break;
      case "--merkleRoot":  cfg.merkleRoot = args[++i]; break;
      case "--p95ThresholdMs":    cfg.p95ThresholdMs = Number(args[++i]); break;
      case "--errorRateThreshold": cfg.errorRateThreshold = Number(args[++i]); break;
      case "--writeRatio":  cfg.writeRatio = Number(args[++i]); break;
      case "--bailout":     cfg.bailout = Number(args[++i]); break;
      case "--timeout":     cfg.timeout = Number(args[++i]); break;
      default:
        break;
    }
  }
  return cfg;
}

export function buildConfig(argv: string[] = process.argv): SoakConfig {
  const cli = parseArgs(argv);
  return {
    url:         cli.url         ?? envStr("SOAK_BASE_URL", "http://127.0.0.1:3000"),
    path:        cli.path        ?? envStr("SOAK_PATH", "/api/v1/attestations"),
    token:       cli.token       ?? envStr("SOAK_AUTH_TOKEN", ""),
    duration:    cli.duration    ?? envInt("SOAK_DURATION", 30, 0),
    connections: cli.connections ?? envInt("SOAK_CONNECTIONS", 10, 1),
    businessId:  cli.businessId  ?? envStr("SOAK_BUSINESS_ID", ""),
    merkleRoot:  cli.merkleRoot  ?? envStr("SOAK_MERKLE_ROOT", `0x${"ab".repeat(32)}`),
    p95ThresholdMs:    cli.p95ThresholdMs    ?? envInt("SOAK_P95_THRESHOLD_MS", 500, 1),
    errorRateThreshold: cli.errorRateThreshold ?? envFloat("SOAK_ERROR_RATE_THRESHOLD", 0.01),
    writeRatio:  cli.writeRatio  ?? envFloat("SOAK_WRITE_RATIO", 1.0),
    bailout:     cli.bailout     ?? envInt("SOAK_BAILOUT", 0),
    timeout:     cli.timeout     ?? envInt("SOAK_TIMEOUT", 10, 1),
  };
}

// --- payload builders ---

let periodCounter = 0;

export function buildPeriod(runId: string): string {
  return `soak-${runId}-${Date.now()}-${periodCounter++}`.slice(0, 50);
}

export function buildSubmitPayload(cfg: SoakConfig, runId: string): string {
  const body: Record<string, unknown> = {
    merkleRoot: cfg.merkleRoot,
    period: buildPeriod(runId),
    version: "1.0.0",
    submit: false,
  };
  if (cfg.businessId) body.businessId = cfg.businessId;
  return JSON.stringify(body);
}

export function buildIdempotencyKey(runId: string, iteration: number): string {
  return `soak-${runId}-${Date.now()}-${iteration}`
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(0, 128);
}

// --- result formatting ---

export interface LatencyBucket {
  label: string;
  value: number;
}

export function extractLatencyBuckets(result: Result): LatencyBucket[] {
  const lat = result.latency;
  return [
    { label: "min",     value: lat.min },
    { label: "p50",     value: lat.p50 },
    { label: "p75",     value: lat.p75 },
    { label: "p90",     value: lat.p90 },
    { label: "p95",     value: lat.p95 },
    { label: "p99",     value: lat.p99 },
    { label: "max",     value: lat.max },
    { label: "average", value: lat.average },
  ];
}

export function formatLatencyTable(buckets: LatencyBucket[]): string {
  const header = "| Percentile | Latency (ms) |";
  const sep    = "|------------|-------------|";
  const rows = buckets.map(
    (b) => `| ${b.label.padEnd(10)} | ${b.value.toFixed(2).padStart(11)} |`,
  );
  return [header, sep, ...rows].join("\n");
}

export function formatSummary(result: Result, cfg: SoakConfig): string {
  const buckets = extractLatencyBuckets(result);
  const totalReqs = result.requests.total;
  const errRate = totalReqs > 0
    ? ((result.errors + result.timeouts + result.non2xx) / totalReqs * 100)
    : 0;

  const p95Status = result.latency.p95 <= cfg.p95ThresholdMs ? "pass" : "fail";
  const errStatus = errRate / 100 <= cfg.errorRateThreshold ? "pass" : "fail";

  const lines = [
    "",
    "=================================================================",
    "  Attestation Soak Test Results",
    "=================================================================",
    "",
    `  URL:            ${cfg.url}${cfg.path}`,
    `  Connections:    ${cfg.connections}`,
    `  Duration:       ${result.duration}s`,
    `  Total Requests: ${totalReqs}`,
    `  Throughput:     ${(result.throughput.average / 1024).toFixed(2)} KB/s`,
    "",
    "  -- Latency --",
    "",
    formatLatencyTable(buckets),
    "",
    "  -- Status Codes --",
    "",
    `  2xx: ${result["2xx"]}  |  3xx: ${result["3xx"]}  |  4xx: ${result["4xx"]}  |  5xx: ${result["5xx"]}`,
    `  Errors: ${result.errors}  |  Timeouts: ${result.timeouts}  |  Non-2xx: ${result.non2xx}`,
    `  Error Rate: ${errRate.toFixed(4)}%`,
    "",
    "  -- Thresholds --",
    "",
    `  p95 limit:   ${cfg.p95ThresholdMs} ms`,
    `  p95 actual:  ${result.latency.p95.toFixed(2)} ms  [${p95Status}_actual: ${p95Status === "pass" ? "PASS" : "FAIL"}]`,
    `  error limit: ${(cfg.errorRateThreshold * 100).toFixed(2)}%`,
    `  error actual:${errRate.toFixed(4)}%  [${errStatus}_actual: ${errStatus === "pass" ? "PASS" : "FAIL"}]`,
    "",
    "=================================================================",
    "",
  ];
  return lines.join("\n");
}

// --- threshold evaluation ---

export interface ThresholdCheck {
  passed: boolean;
  p95Passed: boolean;
  errorRatePassed: boolean;
  p95Actual: number;
  errorRateActual: number;
}

export function evaluateThresholds(result: Result, cfg: SoakConfig): ThresholdCheck {
  const totalReqs = result.requests.total;
  const errorRateActual = totalReqs > 0
    ? (result.errors + result.timeouts + result.non2xx) / totalReqs
    : 0;
  const p95Actual = result.latency.p95;
  const p95Passed = p95Actual <= cfg.p95ThresholdMs;
  const errorRatePassed = errorRateActual <= cfg.errorRateThreshold;

  return {
    passed: p95Passed && errorRatePassed,
    p95Passed,
    errorRatePassed,
    p95Actual,
    errorRateActual,
  };
}

// --- autocannon runner ---

export function buildAutocannonOptions(cfg: SoakConfig, runId: string): AutocannonOptions {
  const url = `${cfg.url.replace(/\/+$/, "")}${cfg.path}`;
  const isWrite = Math.random() < cfg.writeRatio;

  const opts: AutocannonOptions = {
    url,
    connections: cfg.connections,
    duration: cfg.duration,
    timeout: cfg.timeout,
    method: isWrite ? "POST" : "GET",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${cfg.token}`,
    },
  };

  if (isWrite) {
    opts.body = buildSubmitPayload(cfg, runId);
    opts.headers = {
      ...opts.headers,
      "Content-Type": "application/json",
      "Idempotency-Key": buildIdempotencyKey(runId, periodCounter),
    };
  }

  if (cfg.bailout > 0) {
    opts.bailout = cfg.bailout;
  }

  return opts;
}

export async function runSoak(cfg: SoakConfig, runId?: string): Promise<Result> {
  await loadAutocannon();
  const id = runId ?? `soak-${Date.now()}`;
  const opts = buildAutocannonOptions(cfg, id);
  return new Promise<Result>((resolve, reject) => {
    const instance = _autocannonFn!(opts);
    instance.on("done", (result: Result) => resolve(result));
    instance.on("error", (err: Error) => reject(err));
    _autocannonTrack!(instance, { renderProgressBar: true });
  });
}

// --- main ---

export async function main(argv: string[] = process.argv): Promise<number> {
  const cfg = buildConfig(argv);

  if (!cfg.token) {
    console.error("Error: SOAK_AUTH_TOKEN (or --token) is required.");
    console.error("Usage: tsx scripts/soak-attestations.ts --token <jwt>");
    return 1;
  }

  if (cfg.duration <= 0) {
    console.log("Duration is 0 -- nothing to run. Exiting cleanly.");
    return 0;
  }
  if (cfg.connections <= 0) {
    console.log("Connections is 0 -- nothing to run. Exiting cleanly.");
    return 0;
  }

  const runId = `soak-${Date.now()}`;
  console.log(`Starting soak test: ${cfg.connections} connections x ${cfg.duration}s against ${cfg.url}${cfg.path}`);

  try {
    const result = await runSoak(cfg, runId);
    const summary = formatSummary(result, cfg);
    process.stdout.write(summary);

    const check = evaluateThresholds(result, cfg);
    return check.passed ? 0 : 1;
  } catch (err) {
    console.error("Soak test failed:", err instanceof Error ? err.message : String(err));
    return 1;
  }
}

// Run when invoked directly (not imported by tests)
const isDirectRun =
  typeof process.argv[1] === "string" &&
  (process.argv[1].endsWith("/soak-attestations.ts") ||
   process.argv[1].endsWith("\\soak-attestations.ts"));

if (isDirectRun) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
