import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

export type K6MetricKind = "trend" | "rate" | "counter" | "gauge";

export interface K6TrendValues {
  avg?: number;
  min?: number;
  med?: number;
  max?: number;
  "p(90)"?: number;
  "p(95)"?: number;
  "p(99)"?: number;
  [key: string]: number | undefined;
}

export interface K6RateValues {
  rate?: number;
  passes?: number;
  fails?: number;
}

export interface K6CounterValues {
  count?: number;
  rate?: number;
}

export interface K6GaugeValues {
  value?: number;
  min?: number;
  max?: number;
}

export type K6MetricValues = K6TrendValues | K6RateValues | K6CounterValues | K6GaugeValues;

export interface K6Metric {
  type: K6MetricKind;
  contains?: string;
  values: K6MetricValues;
  thresholds?: Record<string, { ok: boolean; failed: boolean }>;
}

export interface K6Summary {
  metrics: Record<string, K6Metric>;
  root_group?: unknown;
  [key: string]: unknown;
}

export interface BaselineMeta {
  updatedAt: string;
  sourceRunId?: string;
  sourceBranch?: string;
  schemaVersion: number;
  checksum: string;
}

export interface K6Baseline {
  meta: BaselineMeta;
  metrics: Record<string, K6Metric>;
}

export interface MetricComparison {
  metric: string;
  kind: K6MetricKind;
  field: string;
  baseline: number | null;
  current: number | null;
  delta: number | null;
  deltaPercent: number | null;
  threshold: number;
  passed: boolean;
  note?: string;
}

export interface CompareResult {
  passed: boolean;
  thresholdPercent: number;
  comparisons: MetricComparison[];
  regressions: MetricComparison[];
  warnings: string[];
  baselinePath: string | null;
  summaryPath: string;
}

export const DEFAULT_THRESHOLD_PERCENT = 10;
export const BASELINE_SCHEMA_VERSION = 1;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

function isNonNullNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && !Number.isNaN(value);
}

function parsePositiveInteger(raw: unknown, fallback: number): number {
  if (typeof raw !== "string" && typeof raw !== "number") return fallback;
  const parsed = typeof raw === "number" ? Math.trunc(raw) : Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, MAX_SAFE_INTEGER);
}

function parsePositiveFloat(raw: unknown, fallback: number): number {
  if (typeof raw !== "string" && typeof raw !== "number") return fallback;
  const parsed = typeof raw === "number" ? raw : Number.parseFloat(raw);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 100) return fallback;
  return parsed;
}

function sanitizeBranchName(branch: string): string {
  if (typeof branch !== "string" || branch.trim() === "") {
    return "main";
  }
  const normalized = branch.trim().replace(/[^a-zA-Z0-9_./-]+/g, "_");
  return normalized === "" ? "main" : normalized;
}

function sanitizeMetricName(name: string): string {
  if (typeof name !== "string" || name.length === 0 || name.length > 512) {
    return "";
  }
  return name;
}

function computeChecksum(metrics: Record<string, K6Metric>): string {
  const serialized = JSON.stringify(
    Object.entries(metrics)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [k, v.type, v.values]),
  );
  let hash = 0;
  for (let i = 0; i < serialized.length; i++) {
    hash = (hash * 31 + serialized.charCodeAt(i)) >>> 0;
  }
  return `${hash.toString(16)}-${randomBytes(4).toString("hex")}`;
}

export function resolveBaselineDir(baseDir = process.cwd()): string {
  const resolved = resolve(baseDir, "ops", "k6", "baselines");
  mkdirSync(resolved, { recursive: true });
  return resolved;
}

export function resolveBaselinePath(branch: string, baseDir = process.cwd()): string {
  const name = sanitizeBranchName(branch);
  return join(resolveBaselineDir(baseDir), `${name}.json`);
}

function validateK6Metric(metric: unknown): metric is K6Metric {
  if (typeof metric !== "object" || metric === null) return false;
  const m = metric as Record<string, unknown>;
  if (!["trend", "rate", "counter", "gauge"].includes(m.type as string)) return false;
  if (typeof m.values !== "object" || m.values === null) return false;
  return true;
}

export function validateK6Summary(raw: unknown): K6Summary {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("k6 summary must be an object");
  }
  const root = raw as Record<string, unknown>;
  if (typeof root.metrics !== "object" || root.metrics === null) {
    throw new Error("k6 summary is missing the 'metrics' object");
  }
  const metrics: Record<string, K6Metric> = {};
  for (const [key, value] of Object.entries(root.metrics as Record<string, unknown>)) {
    const sanitized = sanitizeMetricName(key);
    if (!sanitized) continue;
    if (!validateK6Metric(value)) {
      throw new Error(`Invalid metric definition for '${key}'`);
    }
    metrics[sanitized] = value;
  }
  return { ...root, metrics };
}

export function readK6Summary(path: string): K6Summary {
  const resolved = resolve(path);
  if (!existsSync(resolved)) {
    throw new Error(`k6 summary file not found: ${resolved}`);
  }
  const stats = statSync(resolved);
  if (stats.size === 0) {
    throw new Error(`k6 summary file is empty: ${resolved}`);
  }
  if (stats.size > 50 * 1024 * 1024) {
    throw new Error(`k6 summary file exceeds size limit: ${resolved}`);
  }
  const raw = JSON.parse(readFileSync(resolved, "utf8"));
  return validateK6Summary(raw);
}

export function readBaseline(branch: string, baseDir = process.cwd()): K6Baseline | null {
  const path = resolveBaselinePath(branch, baseDir);
  if (!existsSync(path)) return null;
  const stats = statSync(path);
  if (stats.size === 0 || stats.size > 50 * 1024 * 1024) {
    return null;
  }
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    if (typeof raw !== "object" || raw === null) return null;
    const root = raw as Record<string, unknown>;
    if (typeof root.meta !== "object" || root.meta === null) return null;
    if (typeof root.metrics !== "object" || root.metrics === null) return null;
    const meta = root.meta as Record<string, unknown>;
    if (typeof meta.schemaVersion !== "number") return null;
    const metrics: Record<string, K6Metric> = {};
    for (const [key, value] of Object.entries(root.metrics as Record<string, unknown>)) {
      const sanitized = sanitizeMetricName(key);
      if (!sanitized) continue;
      if (!validateK6Metric(value)) continue;
      metrics[sanitized] = value;
    }
    return {
      meta: {
        updatedAt: typeof meta.updatedAt === "string" ? meta.updatedAt : new Date().toISOString(),
        sourceRunId: typeof meta.sourceRunId === "string" ? meta.sourceRunId : undefined,
        sourceBranch: typeof meta.sourceBranch === "string" ? meta.sourceBranch : undefined,
        schemaVersion: Math.min(Number(meta.schemaVersion), BASELINE_SCHEMA_VERSION),
        checksum: typeof meta.checksum === "string" ? meta.checksum : computeChecksum(metrics),
      },
      metrics,
    };
  } catch {
    return null;
  }
}

export function writeBaseline(
  branch: string,
  summary: K6Summary,
  opts?: { sourceRunId?: string; sourceBranch?: string; baseDir?: string },
): K6Baseline {
  const baseDir = opts?.baseDir ?? process.cwd();
  const path = resolveBaselinePath(branch, baseDir);
  const validated = validateK6Summary({ metrics: summary.metrics });
  const baseline: K6Baseline = {
    meta: {
      updatedAt: new Date().toISOString(),
      sourceRunId: opts?.sourceRunId,
      sourceBranch: opts?.sourceBranch ?? sanitizeBranchName(branch),
      schemaVersion: BASELINE_SCHEMA_VERSION,
      checksum: computeChecksum(validated.metrics),
    },
    metrics: validated.metrics,
  };
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(baseline, null, 2), "utf8");
  return baseline;
}

export const TREND_FIELDS = ["p(95)", "p(99)", "avg", "med", "max"] as const;
export const RATE_FIELDS = ["rate"] as const;
export const COUNTER_FIELDS = ["rate"] as const;
export const GAUGE_FIELDS = ["value"] as const;

function fieldsForKind(kind: K6MetricKind): readonly string[] {
  switch (kind) {
    case "trend":
      return TREND_FIELDS;
    case "rate":
      return RATE_FIELDS;
    case "counter":
      return COUNTER_FIELDS;
    case "gauge":
      return GAUGE_FIELDS;
    default:
      return [];
  }
}

function isHigherIsWorse(kind: K6MetricKind, field: string): boolean {
  if (kind === "trend") return true;
  if (kind === "counter" && field === "rate") return true;
  if (kind === "gauge") return true;
  if (kind === "rate") return true;
  return true;
}

function compareMetricField(opts: {
  metric: string;
  kind: K6MetricKind;
  field: string;
  baseline: number | null;
  current: number | null;
  thresholdPercent: number;
}): MetricComparison {
  const { metric, kind, field, baseline, current, thresholdPercent } = opts;
  let delta: number | null = null;
  let deltaPercent: number | null = null;
  let passed = true;
  let note: string | undefined;

  if (baseline === null && current === null) {
    return {
      metric,
      kind,
      field,
      baseline: null,
      current: null,
      delta: null,
      deltaPercent: null,
      threshold: thresholdPercent,
      passed: true,
      note: "no data on either side",
    };
  }

  if (baseline === null) {
    return {
      metric,
      kind,
      field,
      baseline: null,
      current,
      delta: null,
      deltaPercent: null,
      threshold: thresholdPercent,
      passed: true,
      note: "baseline missing: new metric",
    };
  }

  if (current === null) {
    return {
      metric,
      kind,
      field,
      baseline,
      current: null,
      delta: null,
      deltaPercent: null,
      threshold: thresholdPercent,
      passed: false,
      note: "current missing metric field",
    };
  }

  delta = current - baseline;
  const safeBaseline = baseline === 0 ? Math.min(current, 1e-9) : baseline;
  deltaPercent = (delta / safeBaseline) * 100;

  const higherWorse = isHigherIsWorse(kind, field);
  const regressed = higherWorse ? deltaPercent > thresholdPercent : deltaPercent < -thresholdPercent;

  if (baseline === 0 && current === 0) {
    passed = true;
  } else {
    passed = !regressed;
  }

  return {
    metric,
    kind,
    field,
    baseline,
    current,
    delta,
    deltaPercent,
    threshold: thresholdPercent,
    passed,
    note,
  };
}

export function compareSummaries(opts: {
  baseline: K6Baseline | null;
  current: K6Summary;
  thresholdPercent?: number;
  summaryPath: string;
}): CompareResult {
  const { baseline, current, summaryPath } = opts;
  const thresholdPercent = opts.thresholdPercent ?? DEFAULT_THRESHOLD_PERCENT;
  const warnings: string[] = [];
  const comparisons: MetricComparison[] = [];

  if (baseline === null) {
    warnings.push("no stored baseline found — all metrics are treated as passing (fail-closed requires a baseline)");
  }

  const metricKeys = new Set<string>();
  if (baseline) {
    for (const key of Object.keys(baseline.metrics)) metricKeys.add(key);
  }
  for (const key of Object.keys(current.metrics)) metricKeys.add(key);

  for (const metricKey of metricKeys) {
    const baseMetric = baseline?.metrics[metricKey] ?? null;
    const curMetric = current.metrics[metricKey] ?? null;
    const kind = (curMetric ?? baseMetric)!.type;

    if (baseMetric && curMetric && baseMetric.type !== curMetric.type) {
      warnings.push(`metric '${metricKey}' changed type from ${baseMetric.type} to ${curMetric.type}`);
    }

    const fields = fieldsForKind(kind);
    const baseValues = (baseMetric?.values ?? {}) as Record<string, unknown>;
    const curValues = (curMetric?.values ?? {}) as Record<string, unknown>;

    const seenFields = new Set<string>(fields);
    for (const key of Object.keys(curValues)) {
      if (kind === "trend" && /^p\(\d+\)$/.test(key)) seenFields.add(key);
    }

    for (const field of seenFields) {
      const baseRaw = baseValues[field];
      const curRaw = curValues[field];
      const baseVal = isNonNullNumber(baseRaw) ? (baseRaw as number) : null;
      const curVal = isNonNullNumber(curRaw) ? (curRaw as number) : null;
      comparisons.push(
        compareMetricField({
          metric: metricKey,
          kind,
          field,
          baseline: baseVal,
          current: curVal,
          thresholdPercent,
        }),
      );
    }
  }

  let passed = true;
  if (baseline === null) {
    passed = process.env.K6_COMPARE_FAIL_WITHOUT_BASELINE === "1" ? false : true;
  } else {
    for (const c of comparisons) {
      if (!c.passed) {
        passed = false;
        break;
      }
    }
  }

  const regressions = comparisons.filter((c) => !c.passed);

  return {
    passed,
    thresholdPercent,
    comparisons,
    regressions,
    warnings,
    baselinePath: baseline ? resolveBaselinePath(baseline.meta.sourceBranch ?? "main") : null,
    summaryPath,
  };
}

function formatNumber(n: number | null): string {
  if (n === null) return "N/A";
  if (Number.isInteger(n)) return n.toString();
  return n.toFixed(3);
}

export function formatCliSummary(result: CompareResult): string {
  const lines: string[] = [];
  lines.push(result.passed ? "✅ k6 perf comparison PASSED" : "❌ k6 perf comparison FAILED");
  lines.push(`   threshold: p95 regression > ${result.thresholdPercent}%`);
  if (result.baselinePath) lines.push(`   baseline:  ${result.baselinePath}`);
  lines.push(`   summary:   ${result.summaryPath}`);
  for (const w of result.warnings) lines.push(`   ⚠️  ${w}`);
  if (result.regressions.length > 0) {
    lines.push("");
    lines.push("Regressions:");
    lines.push(`  ${String.prototype.padEnd.call("METRIC", 44)}${String.prototype.padEnd.call("FIELD", 10)}${String.prototype.padEnd.call("BASELINE", 14)}${String.prototype.padEnd.call("CURRENT", 14)}${String.prototype.padEnd.call("DELTA%", 10)}`);
    for (const r of result.regressions) {
      const deltaPct = r.deltaPercent === null ? "N/A" : `${r.deltaPercent.toFixed(2)}%`;
      lines.push(`  ${String.prototype.padEnd.call(r.metric, 44)}${String.prototype.padEnd.call(r.field, 10)}${String.prototype.padEnd.call(formatNumber(r.baseline), 14)}${String.prototype.padEnd.call(formatNumber(r.current), 14)}${String.prototype.padEnd.call(deltaPct, 10)}`);
    }
  }
  return lines.join("\n");
}

export function formatPrSummary(result: CompareResult): string {
  const pass = result.passed ? "✅ Pass" : "❌ Fail";
  const rows = result.comparisons
    .filter((c) => c.field === "p(95)")
    .slice(0, 30)
    .map((c) => {
      const status = c.passed ? "✅" : "❌";
      const dp = c.deltaPercent === null ? "N/A" : `${c.deltaPercent.toFixed(2)}%`;
      return `| ${status} | \`${c.metric}\` | ${c.field} | ${formatNumber(c.baseline)}ms | ${formatNumber(c.current)}ms | ${dp} |`;
    })
    .join("\n");
  const warns = result.warnings.map((w) => `- ⚠️ ${w}`).join("\n") || "- none";
  return [
    `### k6 Performance Regression Gate`,
    ``,
    `- **Result**: ${pass}`,
    `- **Threshold**: +${result.thresholdPercent}% p95 latency`,
    `- **Baseline**: ${result.baselinePath ?? "_not found_"}`,
    ``,
    `#### Warnings`,
    `${warns}`,
    ``,
    `#### p(95) Metric Comparison`,
    `| Status | Metric | Field | Baseline | Current | Delta% |`,
    `|--------|--------|-------|----------|---------|--------|`,
    rows || "_no trend metrics present_",
  ].join("\n");
}

export interface CliArgs {
  mode: "compare" | "save-baseline";
  summaryPath: string;
  branch: string;
  thresholdPercent: number;
  sourceRunId?: string;
  writeGitHubStepSummary: boolean;
  failWithoutBaseline: boolean;
  prCommentFile?: string;
}

export function parseCliArgs(argv: string[]): CliArgs {
  const args = argv.slice(2);
  let mode: CliArgs["mode"] = "compare";
  let summaryPath = process.env.K6_SUMMARY_PATH ?? "";
  let branch = process.env.GITHUB_BASE_REF ?? process.env.GITHUB_REF_NAME ?? process.env.K6_BASELINE_BRANCH ?? "main";
  let thresholdPercent = parsePositiveFloat(
    process.env.K6_REGRESSION_THRESHOLD_PCT ?? process.env.K6_COMPARE_THRESHOLD,
    DEFAULT_THRESHOLD_PERCENT,
  );
  let sourceRunId: string | undefined = process.env.GITHUB_RUN_ID;
  let writeStepSummary = process.env.GITHUB_ACTIONS === "true";
  let failWithoutBaseline = process.env.K6_COMPARE_FAIL_WITHOUT_BASELINE === "1";
  let prCommentFile: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--mode" || a === "-m") {
      const v = args[++i];
      if (v === "compare" || v === "save-baseline") mode = v;
    } else if (a === "--summary" || a === "-s") {
      summaryPath = args[++i] ?? summaryPath;
    } else if (a === "--branch" || a === "-b") {
      branch = args[++i] ?? branch;
    } else if (a === "--threshold" || a === "-t") {
      thresholdPercent = parsePositiveFloat(args[++i], thresholdPercent);
    } else if (a === "--run-id") {
      sourceRunId = args[++i];
    } else if (a === "--write-step-summary") {
      writeStepSummary = true;
    } else if (a === "--no-step-summary") {
      writeStepSummary = false;
    } else if (a === "--fail-without-baseline") {
      failWithoutBaseline = true;
    } else if (a === "--pr-comment-file") {
      prCommentFile = args[++i];
    }
  }

  if (mode === "compare" && summaryPath === "") {
    throw new Error("--summary or K6_SUMMARY_PATH is required for compare mode");
  }
  if (mode === "save-baseline" && summaryPath === "") {
    throw new Error("--summary or K6_SUMMARY_PATH is required for save-baseline mode");
  }

  return {
    mode,
    summaryPath: resolve(summaryPath),
    branch: sanitizeBranchName(branch),
    thresholdPercent,
    sourceRunId,
    writeGitHubStepSummary: writeStepSummary,
    failWithoutBaseline,
    prCommentFile,
  };
}

function writeStepSummary(text: string): void {
  const stepSummaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!stepSummaryPath) return;
  try {
    mkdirSync(dirname(stepSummaryPath), { recursive: true });
    writeFileSync(stepSummaryPath, `${text}\n`, { flag: "a" });
  } catch {
    // ignore — step summary is best-effort
  }
}

function writePrCommentFile(path: string, text: string): void {
  try {
    mkdirSync(dirname(resolve(path)), { recursive: true });
    writeFileSync(resolve(path), text, "utf8");
  } catch {
    // ignore
  }
}

export async function main(argv: string[]): Promise<number> {
  const args = parseCliArgs(argv);
  const summary = readK6Summary(args.summaryPath);

  if (args.mode === "save-baseline") {
    const written = writeBaseline(args.branch, summary, {
      sourceRunId: args.sourceRunId,
      sourceBranch: args.branch,
    });
    const outPath = resolveBaselinePath(args.branch);
    process.stdout.write(`stored baseline for branch=${args.branch} at ${outPath}\n`);
    process.stdout.write(`  metrics: ${Object.keys(written.metrics).length}\n`);
    process.stdout.write(`  checksum: ${written.meta.checksum}\n`);
    return 0;
  }

  const baseline = readBaseline(args.branch);
  const result = compareSummaries({
    baseline,
    current: summary,
    thresholdPercent: args.thresholdPercent,
    summaryPath: args.summaryPath,
  });

  if (args.failWithoutBaseline && baseline === null) {
    result.passed = false;
  }

  const cli = formatCliSummary(result);
  process.stdout.write(`${cli}\n`);

  const prMarkdown = formatPrSummary(result);
  if (args.writeGitHubStepSummary) writeStepSummary(prMarkdown);
  if (args.prCommentFile) writePrCommentFile(args.prCommentFile, prMarkdown);

  return result.passed ? 0 : parsePositiveInteger(process.env.K6_COMPARE_EXIT_CODE, 10);
}

main(process.argv)
  .then((code) => process.exit(code))
  .catch((err) => {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`compare-k6: error: ${msg}\n`);
    process.exit(parsePositiveInteger(process.env.K6_COMPARE_EXIT_CODE_ERR, 99));
  });
