export const SCENARIO_NAMES = Object.freeze({
  steady: "steady_state",
  spike: "spike",
  soak: "soak",
  breakpoint: "breakpoint",
});

const DEFAULT_SUMMARY_TREND_STATS = Object.freeze([
  "min",
  "med",
  "avg",
  "p(90)",
  "p(95)",
  "p(99)",
  "max",
]);

const DEFAULT_TAGS = Object.freeze({
  endpoint: "attestations",
  service: "veritasor-backend",
  suite: "peak-attestation",
});

function readString(env, key, fallback) {
  const value = env[key];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function readInteger(env, key, fallback, minimum = 1) {
  const raw = env[key];
  if (raw === undefined || raw === null || raw === "") return fallback;

  const parsed = Number.parseInt(String(raw), 10);
  if (!Number.isFinite(parsed)) return fallback;

  return Math.max(minimum, parsed);
}

function readFloat(env, key, fallback) {
  const raw = env[key];
  if (raw === undefined || raw === null || raw === "") return fallback;

  const parsed = Number.parseFloat(String(raw));
  return Number.isFinite(parsed) ? parsed : fallback;
}

function readBoolean(env, key, fallback) {
  const raw = env[key];
  if (raw === undefined || raw === null || raw === "") return fallback;

  const normalized = String(raw).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;

  return fallback;
}

function clamp(value, minimum, maximum) {
  return Math.min(Math.max(value, minimum), maximum);
}

function normalizeBaseUrl(url) {
  return url.replace(/\/+$/, "");
}

function normalizePath(path) {
  const trimmed = path.trim();
  if (trimmed === "") return "/api/v1/attestations";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function sanitizeToken(value, fallback = "run") {
  const sanitized = value.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 16);
  return sanitized || fallback;
}

function sanitizeKey(value, fallback = "k6-run") {
  const sanitized = value.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 128);
  return sanitized || fallback;
}

function seconds(value) {
  return `${value}s`;
}

function totalStageDuration(stages) {
  return stages.reduce((sum, stage) => sum + readInteger({ value: stage.duration }, "value", 0, 0), 0);
}

function createScenarioThresholds(endpoint, scenarioNames) {
  const thresholds = {
    [`http_req_duration{endpoint:${endpoint}}`]: ["p(95)<300"],
    [`http_req_failed{endpoint:${endpoint}}`]: ["rate<0.001"],
  };

  for (const scenarioName of scenarioNames) {
    thresholds[`http_req_duration{endpoint:${endpoint},scenario:${scenarioName}}`] = ["p(95)<300"];
    thresholds[`http_req_failed{endpoint:${endpoint},scenario:${scenarioName}}`] = ["rate<0.001"];
  }

  return thresholds;
}

export function createPeakAttestationRuntimeConfig(env = {}) {
  const baseUrl = normalizeBaseUrl(readString(env, "K6_BASE_URL", "http://127.0.0.1:3000"));
  const path = normalizePath(readString(env, "K6_ATT_PATH", "/api/v1/attestations"));
  const writeRatio = clamp(readFloat(env, "K6_ATT_WRITE_RATIO", 1), 0, 1);

  return {
    authToken: readString(env, "K6_AUTH_TOKEN", ""),
    baseUrl,
    businessId: readString(env, "K6_ATT_BUSINESS_ID", ""),
    insecureSkipTlsVerify: readBoolean(env, "K6_INSECURE_SKIP_TLS_VERIFY", false),
    merkleRoot: readString(env, "K6_ATT_MERKLE_ROOT", `0x${"ab".repeat(32)}`),
    path,
    periodPrefix: sanitizeToken(readString(env, "K6_ATT_PERIOD_PREFIX", "perf")),
    requestTimeout: readString(env, "K6_ATT_TIMEOUT", "10s"),
    runId: sanitizeToken(readString(env, "K6_ATT_RUN_ID", "local")),
    submitOnChain: readBoolean(env, "K6_ATT_SUBMIT_ON_CHAIN", false),
    version: readString(env, "K6_ATT_VERSION", "1.0.0"),
    writeRatio,
  };
}

export function buildSyntheticPeriod({ scenarioName, vu, iteration, runId, periodPrefix = "perf" }) {
  const scenarioToken = sanitizeToken(scenarioName, "scenario").toLowerCase();
  const prefixToken = sanitizeToken(periodPrefix, "perf").toLowerCase();
  const runToken = sanitizeToken(runId, "run").toLowerCase();

  return `${prefixToken}-${scenarioToken}-${vu}-${iteration}-${runToken}`.slice(0, 50);
}

export function buildIdempotencyKey({ scenarioName, vu, iteration, runId }) {
  return sanitizeKey(`k6-${runId}-${scenarioName}-${vu}-${iteration}`, "k6-run");
}

export function createPeakAttestationOptions(env = {}) {
  const endpoint = DEFAULT_TAGS.endpoint;
  const steadyDurationSec = readInteger(env, "K6_ATT_STEADY_DURATION_SEC", 300);
  const steadyRate = readInteger(env, "K6_ATT_STEADY_RATE", 20);
  const steadyGapSec = readInteger(env, "K6_ATT_SCENARIO_GAP_SEC", 15);

  const spikeStartRate = readInteger(env, "K6_ATT_SPIKE_START_RATE", 20);
  const spikePeakRate = readInteger(env, "K6_ATT_SPIKE_PEAK_RATE", 150);
  const spikeStages = [
    { duration: readInteger(env, "K6_ATT_SPIKE_WARMUP_SEC", 60), target: spikeStartRate },
    { duration: readInteger(env, "K6_ATT_SPIKE_PEAK_SEC", 30), target: spikePeakRate },
    { duration: readInteger(env, "K6_ATT_SPIKE_RECOVERY_SEC", 60), target: spikeStartRate },
  ];

  const soakDurationSec = readInteger(env, "K6_ATT_SOAK_DURATION_SEC", 1800);
  const soakRate = readInteger(env, "K6_ATT_SOAK_RATE", 25);

  const breakpointStartRate = readInteger(env, "K6_ATT_BREAKPOINT_START_RATE", 25);
  const breakpointStepRate = readInteger(env, "K6_ATT_BREAKPOINT_STEP_RATE", 50);
  const breakpointSteps = readInteger(env, "K6_ATT_BREAKPOINT_STEPS", 6);
  const breakpointStageDurationSec = readInteger(env, "K6_ATT_BREAKPOINT_STAGE_SEC", 120);
  const breakpointStages = Array.from({ length: breakpointSteps }, (_, index) => ({
    duration: breakpointStageDurationSec,
    target: breakpointStartRate + breakpointStepRate * (index + 1),
  }));

  const scenarioNames = Object.values(SCENARIO_NAMES);
  const thresholds = createScenarioThresholds(endpoint, scenarioNames);

  let cursorSec = 0;
  const steadyStartTime = seconds(cursorSec);
  cursorSec += steadyDurationSec + steadyGapSec;

  const spikeStartTime = seconds(cursorSec);
  cursorSec += totalStageDuration(spikeStages) + steadyGapSec;

  const soakStartTime = seconds(cursorSec);
  cursorSec += soakDurationSec + steadyGapSec;

  const breakpointStartTime = seconds(cursorSec);

  return {
    discardResponseBodies: true,
    insecureSkipTLSVerify: readBoolean(env, "K6_INSECURE_SKIP_TLS_VERIFY", false),
    summaryTrendStats: DEFAULT_SUMMARY_TREND_STATS,
    tags: DEFAULT_TAGS,
    thresholds,
    userAgent: "veritasor-backend-k6/peak-attestation",
    scenarios: {
      [SCENARIO_NAMES.steady]: {
        duration: seconds(steadyDurationSec),
        exec: "steadyState",
        executor: "constant-arrival-rate",
        maxVUs: readInteger(env, "K6_ATT_STEADY_MAX_VUS", Math.max(steadyRate * 4, 80)),
        preAllocatedVUs: readInteger(env, "K6_ATT_STEADY_PREALLOCATED_VUS", Math.max(steadyRate * 2, 20)),
        rate: steadyRate,
        startTime: steadyStartTime,
        tags: { endpoint, load_profile: "steady" },
        timeUnit: "1s",
      },
      [SCENARIO_NAMES.spike]: {
        exec: "spike",
        executor: "ramping-arrival-rate",
        maxVUs: readInteger(env, "K6_ATT_SPIKE_MAX_VUS", Math.max(spikePeakRate * 4, 240)),
        preAllocatedVUs: readInteger(env, "K6_ATT_SPIKE_PREALLOCATED_VUS", Math.max(spikePeakRate * 2, 60)),
        stages: spikeStages.map((stage) => ({ duration: seconds(stage.duration), target: stage.target })),
        startRate: spikeStartRate,
        startTime: spikeStartTime,
        tags: { endpoint, load_profile: "spike" },
        timeUnit: "1s",
      },
      [SCENARIO_NAMES.soak]: {
        duration: seconds(soakDurationSec),
        exec: "soak",
        executor: "constant-arrival-rate",
        maxVUs: readInteger(env, "K6_ATT_SOAK_MAX_VUS", Math.max(soakRate * 4, 100)),
        preAllocatedVUs: readInteger(env, "K6_ATT_SOAK_PREALLOCATED_VUS", Math.max(soakRate * 2, 30)),
        rate: soakRate,
        startTime: soakStartTime,
        tags: { endpoint, load_profile: "soak" },
        timeUnit: "1s",
      },
      [SCENARIO_NAMES.breakpoint]: {
        exec: "breakpoint",
        executor: "ramping-arrival-rate",
        maxVUs: readInteger(
          env,
          "K6_ATT_BREAKPOINT_MAX_VUS",
          Math.max((breakpointStartRate + breakpointStepRate * breakpointSteps) * 4, 320),
        ),
        preAllocatedVUs: readInteger(
          env,
          "K6_ATT_BREAKPOINT_PREALLOCATED_VUS",
          Math.max((breakpointStartRate + breakpointStepRate) * 2, 80),
        ),
        stages: breakpointStages.map((stage) => ({ duration: seconds(stage.duration), target: stage.target })),
        startRate: breakpointStartRate,
        startTime: breakpointStartTime,
        tags: { endpoint, load_profile: "breakpoint" },
        timeUnit: "1s",
      },
    },
  };
}

export const sloThresholds = createScenarioThresholds(DEFAULT_TAGS.endpoint, Object.values(SCENARIO_NAMES));
