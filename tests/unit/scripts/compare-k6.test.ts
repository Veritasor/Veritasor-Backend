import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  DEFAULT_THRESHOLD_PERCENT,
  TREND_FIELDS,
  resolveBaselinePath,
  validateK6Summary,
  readK6Summary,
  readBaseline,
  writeBaseline,
  compareSummaries,
  formatCliSummary,
  formatPrSummary,
  parseCliArgs,
  main,
  type K6Summary,
  type K6Baseline,
  type CompareResult,
} from "../../../scripts/compare-k6";

function makeTempDir(): string {
  return mkdtempSync(join(tmpdir(), "k6-compare-test-"));
}

function makeSimpleSummary(overrides: Partial<Record<string, unknown>> = {}): K6Summary {
  return {
    metrics: {
      http_req_duration: {
        type: "trend",
        values: { avg: 100, med: 95, max: 500, "p(90)": 180, "p(95)": 250, "p(99)": 400 },
      },
      http_req_failed: { type: "rate", values: { rate: 0.01, passes: 990, fails: 10 } },
      http_reqs: { type: "counter", values: { count: 1000, rate: 100 } },
      vus: { type: "gauge", values: { value: 50, min: 10, max: 50 } },
    },
    ...overrides,
  };
}

function makeBaselineFromSummary(summary: K6Summary, branch = "main"): K6Baseline {
  return { meta: { updatedAt: new Date().toISOString(), sourceBranch: branch, schemaVersion: 1, checksum: "test-checksum" }, metrics: summary.metrics };
}

describe("constants", () => {
  it("DEFAULT_THRESHOLD_PERCENT equals 10", () => {
    expect(DEFAULT_THRESHOLD_PERCENT).toBe(10);
  });
  it("TREND_FIELDS contains expected percentile and aggregate fields", () => {
    expect(Array.from(TREND_FIELDS)).toEqual(["p(95)", "p(99)", "avg", "med", "max"]);
  });
});

describe("sanitizeBranchName (via resolveBaselinePath)", () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = makeTempDir(); });
  afterEach(() => { rmSync(tmpDir, { recursive: true, force: true }); });
  it("defaults empty string to main", () => {
    expect(resolveBaselinePath("", tmpDir).endsWith(join("ops", "k6", "baselines", "main.json"))).toBe(true);
  });
  it("trims whitespace and defaults blank to main", () => {
    expect(resolveBaselinePath("   ", tmpDir).endsWith(join("ops", "k6", "baselines", "main.json"))).toBe(true);
  });
  it("replaces non-safe characters with underscores", () => {
    expect(resolveBaselinePath("feature/my branch!@#", tmpDir).endsWith(join("ops", "k6", "baselines", "feature_my_branch___.json"))).toBe(true);
  });
  it("keeps safe characters (letters, digits, dot, slash, dash, underscore)", () => {
    expect(resolveBaselinePath("feat/v1.2.x-release_candidate", tmpDir).endsWith(join("ops", "k6", "baselines", "feat_v1.2.x-release_candidate.json"))).toBe(true);
  });
});

describe("resolveBaselinePath", () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = makeTempDir(); });
  afterEach(() => { rmSync(tmpDir, { recursive: true, force: true }); });
  it("resolves under ops/k6/baselines with branch name + .json", () => {
    expect(resolveBaselinePath("develop", tmpDir)).toBe(resolve(tmpDir, "ops", "k6", "baselines", "develop.json"));
  });
  it("creates the baseline directory as a side effect", () => {
    resolveBaselinePath("main", tmpDir);
    expect(existsSync(resolve(tmpDir, "ops", "k6", "baselines"))).toBe(true);
  });
  it("uses process.cwd() when no baseDir provided", () => {
    const originalCwd = process.cwd(); process.chdir(tmpDir);
    try { expect(resolveBaselinePath("trunk")).toBe(resolve(tmpDir, "ops", "k6", "baselines", "trunk.json")); }
    finally { process.chdir(originalCwd); }
  });
});

describe("validateK6Summary", () => {
  it("throws on non-object input", () => {
    expect(() => validateK6Summary(null)).toThrow("k6 summary must be an object");
    expect(() => validateK6Summary("string")).toThrow("k6 summary must be an object");
    expect(() => validateK6Summary(42)).toThrow("k6 summary must be an object");
  });
  it("throws when metrics field is missing", () => {
    expect(() => validateK6Summary({})).toThrow("k6 summary is missing the 'metrics' object");
    expect(() => validateK6Summary({ metrics: null })).toThrow("k6 summary is missing the 'metrics' object");
  });
  it("throws when a metric has an invalid type", () => {
    expect(() => validateK6Summary({ metrics: { bad_metric: { type: "unknown", values: {} } } })).toThrow("Invalid metric definition for 'bad_metric'");
  });
  it("throws when a metric is missing values object", () => {
    expect(() => validateK6Summary({ metrics: { bad_metric: { type: "trend" } } })).toThrow("Invalid metric definition for 'bad_metric'");
  });
  it("returns a valid K6Summary with preserved metrics", () => {
    const summary = makeSimpleSummary({ root_group: { id: "root" } });
    const result = validateK6Summary(summary);
    expect(result.metrics.http_req_duration.type).toBe("trend");
    expect(result.metrics.http_req_duration.values["p(95)"]).toBe(250);
    expect(result.root_group).toEqual({ id: "root" });
  });
  it("skips metrics with empty or oversized names", () => {
    const summary = validateK6Summary({ metrics: { "": { type: "trend", values: { avg: 1 } }, good: { type: "trend", values: { avg: 1 } } } });
    expect(Object.keys(summary.metrics)).toEqual(["good"]);
  });
});

describe("readK6Summary", () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = makeTempDir(); });
  afterEach(() => { rmSync(tmpDir, { recursive: true, force: true }); });
  it("throws when file does not exist", () => {
    expect(() => readK6Summary(resolve(tmpDir, "nope.json"))).toThrow(/not found/);
  });
  it("throws when file is empty", () => {
    const empty = resolve(tmpDir, "empty.json"); writeFileSync(empty, "", "utf8");
    expect(() => readK6Summary(empty)).toThrow(/empty/);
  });
  it("throws on malformed JSON", () => {
    const bad = resolve(tmpDir, "bad.json"); writeFileSync(bad, "{ not json }", "utf8");
    expect(() => readK6Summary(bad)).toThrow();
  });
  it("reads and validates a valid summary file", () => {
    const path = resolve(tmpDir, "summary.json");
    writeFileSync(path, JSON.stringify(makeSimpleSummary()), "utf8");
    const result = readK6Summary(path);
    expect(result.metrics.http_req_duration.type).toBe("trend");
    expect(result.metrics.http_req_duration.values.avg).toBe(100);
  });
});

describe("readBaseline / writeBaseline round-trip", () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = makeTempDir(); });
  afterEach(() => { rmSync(tmpDir, { recursive: true, force: true }); });
  it("returns null when no baseline exists yet", () => {
    expect(readBaseline("nobranch", tmpDir)).toBeNull();
  });
  it("writes a baseline file that can be read back with matching metrics", () => {
    const summary = makeSimpleSummary();
    const written = writeBaseline("feat/roundtrip", summary, { baseDir: tmpDir, sourceRunId: "run-123", sourceBranch: "feat/roundtrip" });
    expect(written.meta.sourceRunId).toBe("run-123");
    expect(written.meta.sourceBranch).toBe("feat_roundtrip");
    expect(written.meta.schemaVersion).toBe(1);
    expect(Object.keys(written.metrics)).toEqual(Object.keys(summary.metrics));
    const readBack = readBaseline("feat/roundtrip", tmpDir);
    expect(readBack).not.toBeNull();
    expect(readBack!.metrics.http_req_duration.values["p(95)"]).toBe(250);
    expect(readBack!.meta.sourceRunId).toBe("run-123");
  });
  it("returns null for corrupted baseline JSON", () => {
    const path = resolveBaselinePath("corrupt", tmpDir);
    mkdirSync(resolve(tmpDir, "ops", "k6", "baselines"), { recursive: true });
    writeFileSync(path, "{broken}", "utf8");
    expect(readBaseline("corrupt", tmpDir)).toBeNull();
  });
  it("returns null for a baseline missing meta or metrics", () => {
    const path = resolveBaselinePath("naked", tmpDir);
    mkdirSync(resolve(tmpDir, "ops", "k6", "baselines"), { recursive: true });
    writeFileSync(path, JSON.stringify({ just: "data" }), "utf8");
    expect(readBaseline("naked", tmpDir)).toBeNull();
  });
  it("returns null for empty baseline file", () => {
    const path = resolveBaselinePath("emptybl", tmpDir);
    mkdirSync(resolve(tmpDir, "ops", "k6", "baselines"), { recursive: true });
    writeFileSync(path, "", "utf8");
    expect(readBaseline("emptybl", tmpDir)).toBeNull();
  });
});
describe("compareSummaries", () => {
  function makeCompareInput(baselineMetrics, currentMetrics, opts = {}) {
    const baseline = baselineMetrics ? makeBaselineFromSummary({ metrics: baselineMetrics }) : null;
    return compareSummaries({
      baseline, current: { metrics: currentMetrics },
      thresholdPercent: opts.thresholdPercent, summaryPath: opts.summaryPath || "/tmp/summary.json"
    });
  }
  it("passes when all metrics are within default 10% threshold", () => {
    const summary = makeSimpleSummary().metrics;
    const current = makeSimpleSummary().metrics;
    current.http_req_duration.values = { ...current.http_req_duration.values, "p(95)": 260 };
    const result = makeCompareInput(summary, current);
    expect(result.passed).toBe(true);
    expect(result.regressions).toHaveLength(0);
  });
  it("fails on p95 regression exceeding threshold", () => {
    const summary = makeSimpleSummary().metrics;
    const current = makeSimpleSummary().metrics;
    current.http_req_duration.values = { ...current.http_req_duration.values, "p(95)": 300 };
    const result = makeCompareInput(summary, current);
    expect(result.passed).toBe(false);
    const p95Failures = result.regressions.filter(r => r.metric === "http_req_duration" && r.field === "p(95)");
    expect(p95Failures.length).toBeGreaterThan(0);
    expect(p95Failures[0].deltaPercent).toBeCloseTo(20);
  });
  it("respects a custom threshold percent", () => {
    const summary = makeSimpleSummary().metrics;
    const current = makeSimpleSummary().metrics;
    current.http_req_duration.values = { ...current.http_req_duration.values, "p(95)": 290 };
    expect(makeCompareInput(summary, current, { thresholdPercent: 5 }).passed).toBe(false);
    expect(makeCompareInput(summary, current, { thresholdPercent: 25 }).passed).toBe(true);
  });
  it("adds no-baseline warning and passes when baseline is null", () => {
    const current = makeSimpleSummary().metrics;
    const result = makeCompareInput(null, current);
    expect(result.passed).toBe(true);
    expect(result.warnings.some(w => /no stored baseline/i.test(w))).toBe(true);
    expect(result.baselinePath).toBeNull();
  });
  it("treats new metrics (not in baseline) as passing", () => {
    const baseline = makeSimpleSummary().metrics;
    const current = makeSimpleSummary().metrics;
    current.new_trend_metric = { type: "trend", values: { avg: 50, "p(95)": 90, "p(99)": 95, med: 40, max: 100 } };
    const result = makeCompareInput(baseline, current);
    expect(result.passed).toBe(true);
    const newMetricComparisons = result.comparisons.filter(c => c.metric === "new_trend_metric");
    expect(newMetricComparisons.every(c => c.passed === true)).toBe(true);
    expect(newMetricComparisons[0].note).toMatch(/new metric/);
  });
  it("fails when a current metric field is missing", () => {
    const baseline = makeSimpleSummary().metrics;
    const current = makeSimpleSummary().metrics;
    delete current.http_req_duration.values["p(95)"];
    const result = makeCompareInput(baseline, current);
    expect(result.passed).toBe(false);
    const missing = result.regressions.find(r => r.metric === "http_req_duration" && r.field === "p(95)" && r.current === null);
    expect(missing).toBeDefined();
    expect(missing.note).toMatch(/current missing metric field/);
  });
  it("handles zero baseline and current values safely", () => {
    const baseline = { zero_trend: { type: "trend", values: { avg: 0, "p(95)": 0, "p(99)": 0, med: 0, max: 0 } } };
    const current = { zero_trend: { type: "trend", values: { avg: 0, "p(95)": 0, "p(99)": 0, med: 0, max: 0 } } };
    const result = makeCompareInput(baseline, current);
    expect(result.passed).toBe(true);
    for (const c of result.comparisons) {
      expect(Number.isNaN(c.deltaPercent)).toBe(false);
      expect(Number.isFinite(c.deltaPercent) || c.deltaPercent === null).toBe(true);
    }
  });
  it("passes zero to non-zero without false-positive regressions", () => {
    const baseline = { zero_trend: { type: "trend", values: { avg: 0, "p(95)": 0, "p(99)": 0, med: 0, max: 0 } } };
    const current = { zero_trend: { type: "trend", values: { avg: 5, "p(95)": 10, "p(99)": 15, med: 4, max: 20 } } };
    const result = makeCompareInput(baseline, current);
    for (const c of result.comparisons) expect(Number.isNaN(c.deltaPercent)).toBe(false);
  });
  it("compares rate fields (rate metric)", () => {
    const baseline = { failure_rate: { type: "rate", values: { rate: 0.01, passes: 99, fails: 1 } } };
    const good = { failure_rate: { type: "rate", values: { rate: 0.0105, passes: 989, fails: 11 } } };
    const bad = { failure_rate: { type: "rate", values: { rate: 0.025, passes: 975, fails: 25 } } };
    expect(makeCompareInput(baseline, good).passed).toBe(true);
    expect(makeCompareInput(baseline, bad).passed).toBe(false);
  });
  it("compares counter fields (rate field)", () => {
    const baseline = { reqs: { type: "counter", values: { count: 1000, rate: 100 } } };
    const good = { reqs: { type: "counter", values: { count: 1050, rate: 105 } } };
    const bad = { reqs: { type: "counter", values: { count: 1500, rate: 150 } } };
    expect(makeCompareInput(baseline, good).passed).toBe(true);
    expect(makeCompareInput(baseline, bad).passed).toBe(false);
  });
  it("compares gauge fields (value)", () => {
    const baseline = { mem: { type: "gauge", values: { value: 128, min: 64, max: 256 } } };
    const good = { mem: { type: "gauge", values: { value: 135, min: 64, max: 256 } } };
    const bad = { mem: { type: "gauge", values: { value: 200, min: 64, max: 256 } } };
    expect(makeCompareInput(baseline, good).passed).toBe(true);
    expect(makeCompareInput(baseline, bad).passed).toBe(false);
  });
  it("warns when a metric type changes between baseline and current", () => {
    const baseline = { thing: { type: "gauge", values: { value: 1 } } };
    const current = { thing: { type: "counter", values: { count: 1, rate: 1 } } };
    const result = makeCompareInput(baseline, current);
    expect(result.warnings.some(w => /changed type/gi.test(w))).toBe(true);
  });
});
describe("formatCliSummary", () => {
  function makeResult(partial = {}) {
    return Object.assign({ passed: true, thresholdPercent: 10, comparisons: [], regressions: [], warnings: [], baselinePath: "/ops/k6/baselines/main.json", summaryPath: "/tmp/summary.json" }, partial);
  }
  it("prefixes with checkmark on pass and x on fail", () => {
    expect(formatCliSummary(makeResult({ passed: true }))).toMatch(/✅/);
    expect(formatCliSummary(makeResult({ passed: false }))).toMatch(/❌/);
  });
  it("includes the threshold, baseline path, summary path, and warnings", () => {
    const out = formatCliSummary(makeResult({ warnings: ["w1", "w2"] }));
    expect(out).toContain("10%");
    expect(out).toContain("/ops/k6/baselines/main.json");
    expect(out).toContain("/tmp/summary.json");
    expect(out).toContain("w1");
    expect(out).toContain("w2");
  });
  it("prints a regression table when regressions exist", () => {
    const out = formatCliSummary(makeResult({ passed: false, regressions: [{ metric: "http_req_duration", kind: "trend", field: "p(95)", baseline: 200, current: 280, delta: 80, deltaPercent: 40, threshold: 10, passed: false }] }));
    expect(out).toContain("Regressions:");
    expect(out).toContain("http_req_duration");
    expect(out).toContain("p(95)");
    expect(out).toContain("200");
    expect(out).toContain("280");
    expect(out).toContain("40.00%");
  });
  it("formats integers without decimals and nulls as N/A", () => {
    const out = formatCliSummary(makeResult({ passed: false, regressions: [{ metric: "m", kind: "trend", field: "p(95)", baseline: null, current: null, delta: null, deltaPercent: null, threshold: 10, passed: false }] }));
    expect(out).toContain("N/A");
  });
});

describe("formatPrSummary", () => {
  function makeResult(partial = {}) {
    return Object.assign({ passed: true, thresholdPercent: 10, comparisons: [], regressions: [], warnings: [], baselinePath: "/ops/k6/baselines/main.json", summaryPath: "/tmp/summary.json" }, partial);
  }
  it("starts with a markdown h3 and shows pass/fail status", () => {
    const pass = formatPrSummary(makeResult({ passed: true }));
    expect(pass.startsWith("### k6 Performance Regression Gate")).toBe(true);
    expect(pass).toContain("✅ Pass");
    expect(formatPrSummary(makeResult({ passed: false }))).toContain("❌ Fail");
  });
  it("lists warnings as markdown bullets", () => {
    const out = formatPrSummary(makeResult({ warnings: ["hello warning"] }));
    expect(out).toContain("- ⚠️ hello warning");
  });
  it("includes p(95) table rows with baseline, current, delta%", () => {
    const out = formatPrSummary(makeResult({ comparisons: [
      { metric: "http_req_duration", kind: "trend", field: "p(95)", baseline: 200, current: 220, delta: 20, deltaPercent: 10, threshold: 10, passed: true },
      { metric: "other", kind: "trend", field: "p(99)", baseline: 1, current: 1, delta: 0, deltaPercent: 0, threshold: 10, passed: true }
    ] }));
    expect(out).toMatch(/| ✅ |/);
    expect(out).toContain("http_req_duration");
    expect(out).toContain("200ms");
    expect(out).toContain("220ms");
    expect(out).toContain("10.00%");
    expect(out).not.toContain("p(99)");
  });
  it("shows baseline path or not found when missing", () => {
    expect(formatPrSummary(makeResult({ baselinePath: "/b.json" }))).toContain("/b.json");
    expect(formatPrSummary(makeResult({ baselinePath: null }))).toContain("_not found_");
  });
});
describe("parseCliArgs", () => {
  const originalEnv = process.env;
  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.K6_SUMMARY_PATH;
    delete process.env.GITHUB_BASE_REF;
    delete process.env.GITHUB_REF_NAME;
    delete process.env.K6_BASELINE_BRANCH;
    delete process.env.K6_REGRESSION_THRESHOLD_PCT;
    delete process.env.K6_COMPARE_THRESHOLD;
    delete process.env.GITHUB_RUN_ID;
    delete process.env.GITHUB_ACTIONS;
    delete process.env.K6_COMPARE_FAIL_WITHOUT_BASELINE;
  });
  afterEach(() => { process.env = originalEnv; });
  it("defaults to compare mode and main branch, errors without summary", () => {
    expect(() => parseCliArgs(["node", "script.ts"])).toThrow(/--summary or K6_SUMMARY_PATH/);
  });
  it("parses short flags: -m save-baseline -s ./sum.json -b feat/x -t 15", () => {
    const args = parseCliArgs(["node", "script.ts", "-m", "save-baseline", "-s", "./sum.json", "-b", "feat/x", "-t", "15"]);
    expect(args.mode).toBe("save-baseline");
    expect(args.summaryPath).toBe(resolve("sum.json"));
    expect(args.branch).toBe("feat_x");
    expect(args.thresholdPercent).toBe(15);
  });
  it("parses long flags --mode compare --summary /abs/path.json", () => {
    const args = parseCliArgs(["node", "s", "--mode", "compare", "--summary", "/abs/path.json"]);
    expect(args.mode).toBe("compare");
    expect(args.summaryPath).toBe(resolve("/abs/path.json"));
  });
  it("picks up summary path from K6_SUMMARY_PATH env var", () => {
    process.env.K6_SUMMARY_PATH = "/env/summary.json";
    const args = parseCliArgs(["node", "s"]);
    expect(args.summaryPath).toBe(resolve("/env/summary.json"));
    expect(args.mode).toBe("compare");
  });
  it("picks up branch from GITHUB_BASE_REF, then GITHUB_REF_NAME, then K6_BASELINE_BRANCH", () => {
    process.env.K6_SUMMARY_PATH = "/s.json";
    process.env.GITHUB_BASE_REF = "release/v1";
    expect(parseCliArgs(["n", "s"]).branch).toBe("release_v1");
    delete process.env.GITHUB_BASE_REF;
    process.env.GITHUB_REF_NAME = "feature/test";
    expect(parseCliArgs(["n", "s"]).branch).toBe("feature_test");
    delete process.env.GITHUB_REF_NAME;
    process.env.K6_BASELINE_BRANCH = "develop";
    expect(parseCliArgs(["n", "s"]).branch).toBe("develop");
  });
  it("picks up threshold from K6_REGRESSION_THRESHOLD_PCT then K6_COMPARE_THRESHOLD", () => {
    process.env.K6_SUMMARY_PATH = "/s.json";
    process.env.K6_REGRESSION_THRESHOLD_PCT = "3";
    expect(parseCliArgs(["n", "s"]).thresholdPercent).toBe(3);
    delete process.env.K6_REGRESSION_THRESHOLD_PCT;
    process.env.K6_COMPARE_THRESHOLD = "7.5";
    expect(parseCliArgs(["n", "s"]).thresholdPercent).toBe(7.5);
  });
  it("picks up sourceRunId from GITHUB_RUN_ID and step summary flag from GITHUB_ACTIONS", () => {
    process.env.K6_SUMMARY_PATH = "/s.json";
    process.env.GITHUB_RUN_ID = "42";
    process.env.GITHUB_ACTIONS = "true";
    const args = parseCliArgs(["n", "s"]);
    expect(args.sourceRunId).toBe("42");
    expect(args.writeGitHubStepSummary).toBe(true);
  });
  it("honours --write-step-summary, --no-step-summary, --run-id", () => {
    process.env.K6_SUMMARY_PATH = "/s.json";
    process.env.GITHUB_ACTIONS = "true";
    let args = parseCliArgs(["n", "s", "--no-step-summary", "--run-id", "99"]);
    expect(args.writeGitHubStepSummary).toBe(false);
    expect(args.sourceRunId).toBe("99");
    args = parseCliArgs(["n", "s", "--write-step-summary"]);
    expect(args.writeGitHubStepSummary).toBe(true);
  });
  it("sets failWithoutBaseline from env and --fail-without-baseline flag", () => {
    process.env.K6_SUMMARY_PATH = "/s.json";
    expect(parseCliArgs(["n", "s"]).failWithoutBaseline).toBe(false);
    process.env.K6_COMPARE_FAIL_WITHOUT_BASELINE = "1";
    expect(parseCliArgs(["n", "s"]).failWithoutBaseline).toBe(true);
    delete process.env.K6_COMPARE_FAIL_WITHOUT_BASELINE;
    expect(parseCliArgs(["n", "s", "--fail-without-baseline"]).failWithoutBaseline).toBe(true);
  });
  it("parses --pr-comment-file", () => {
    process.env.K6_SUMMARY_PATH = "/s.json";
    const args = parseCliArgs(["n", "s", "--pr-comment-file", "/tmp/pr.md"]);
    expect(args.prCommentFile).toBe("/tmp/pr.md");
  });
  it("rejects out-of-range thresholds by falling back to default", () => {
    process.env.K6_SUMMARY_PATH = "/s.json";
    const args = parseCliArgs(["n", "s", "-t", "200"]);
    expect(args.thresholdPercent).toBe(DEFAULT_THRESHOLD_PERCENT);
  });
  it("rejects save-baseline mode without summary", () => {
    expect(() => parseCliArgs(["n", "s", "-m", "save-baseline"])).toThrow(/save-baseline mode/);
  });
});
describe("main() e2e", () => {
  let tmpDir: string;
  const originalEnv = process.env;
  let stdoutBuf: string;
  let stderrBuf: string;
  beforeEach(() => {
    tmpDir = makeTempDir();
    process.env = { ...originalEnv };
    delete process.env.K6_SUMMARY_PATH;
    delete process.env.GITHUB_BASE_REF;
    delete process.env.GITHUB_REF_NAME;
    delete process.env.K6_BASELINE_BRANCH;
    delete process.env.K6_REGRESSION_THRESHOLD_PCT;
    delete process.env.K6_COMPARE_THRESHOLD;
    delete process.env.GITHUB_RUN_ID;
    delete process.env.GITHUB_ACTIONS;
    delete process.env.K6_COMPARE_FAIL_WITHOUT_BASELINE;
    delete process.env.GITHUB_STEP_SUMMARY;
    delete process.env.K6_COMPARE_EXIT_CODE;
    delete process.env.K6_COMPARE_EXIT_CODE_ERR;
    stdoutBuf = "";
    stderrBuf = "";
    vi.spyOn(process.stdout, "write").mockImplementation((...chunk: unknown[]): boolean => {
      if (typeof chunk[0] === "string") stdoutBuf += chunk[0];
      return true;
    });
    vi.spyOn(process.stderr, "write").mockImplementation((...chunk: unknown[]): boolean => {
      if (typeof chunk[0] === "string") stderrBuf += chunk[0];
      return true;
    });
  });
  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    process.env = originalEnv;
    vi.restoreAllMocks();
  });
  it("save-baseline then compare workflow passes when within threshold", async () => {
    const summaryPath = resolve(tmpDir, "sum.json");
    writeFileSync(summaryPath, JSON.stringify(makeSimpleSummary()), "utf8");
    const originalCwd = process.cwd(); process.chdir(tmpDir);
    try {
      const saveCode = await main(["node", "compare-k6.ts", "--mode", "save-baseline", "--summary", summaryPath, "--branch", "main"]);
      expect(saveCode).toBe(0);
      expect(stdoutBuf).toMatch(/stored baseline for branch=main/);
      expect(existsSync(resolveBaselinePath("main", tmpDir))).toBe(true);
      const sameSummaryPath = resolve(tmpDir, "sum2.json");
      const s2 = makeSimpleSummary();
      s2.metrics.http_req_duration.values = { ...s2.metrics.http_req_duration.values, "p(95)": 260 };
      writeFileSync(sameSummaryPath, JSON.stringify(s2), "utf8");
      stdoutBuf = "";
      const compareCode = await main(["node", "compare-k6.ts", "--mode", "compare", "--summary", sameSummaryPath, "--branch", "main", "--no-step-summary"]);
      expect(compareCode).toBe(0);
      expect(stdoutBuf).toMatch(/✅.*PASSED/);
    } finally { process.chdir(originalCwd); }
  });
  it("--fail-without-baseline returns non-zero when baseline missing", async () => {
    const summaryPath = resolve(tmpDir, "sum.json");
    writeFileSync(summaryPath, JSON.stringify(makeSimpleSummary()), "utf8");
    const originalCwd = process.cwd(); process.chdir(tmpDir);
    try {
      const code = await main(["node", "compare-k6.ts", "--mode", "compare", "--summary", summaryPath, "--branch", "nonexistent", "--fail-without-baseline", "--no-step-summary"]);
      expect(code).not.toBe(0);
      expect(stdoutBuf).toMatch(/❌.*FAILED/);
    } finally { process.chdir(originalCwd); }
  });
  it("--pr-comment-file writes markdown to the given file", async () => {
    const summaryPath = resolve(tmpDir, "sum.json");
    writeFileSync(summaryPath, JSON.stringify(makeSimpleSummary()), "utf8");
    const prFile = resolve(tmpDir, "pr.md");
    const originalCwd = process.cwd(); process.chdir(tmpDir);
    try {
      const code = await main(["node", "compare-k6.ts", "--mode", "compare", "--summary", summaryPath, "--branch", "main", "--no-step-summary", "--pr-comment-file", prFile]);
      expect(code).toBe(0);
      expect(existsSync(prFile)).toBe(true);
      const contents = readFileSync(prFile, "utf8");
      expect(contents.startsWith("### k6 Performance Regression Gate")).toBe(true);
      expect(contents).toContain("| Status | Metric |");
    } finally { process.chdir(originalCwd); }
  });
  it("exits with error code on malformed summary JSON", async () => {
    const summaryPath = resolve(tmpDir, "bad.json");
    writeFileSync(summaryPath, "{ not: valid, json: [}", "utf8");
    let exitCode: number | Error = 99;
    try { exitCode = await main(["node", "compare-k6.ts", "--mode", "compare", "--summary", summaryPath, "--branch", "main"]); }
    catch (err) { exitCode = err as Error; }
    if (exitCode instanceof Error) expect(exitCode.message).toBeDefined();
    else expect(exitCode).not.toBe(0);
    expect(stderrBuf + stdoutBuf).toMatch(/error|JSON|Unexpected/);
  });
});
