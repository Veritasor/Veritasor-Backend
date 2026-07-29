import http from "k6/http";
import exec from "k6/execution";
import { Rate, Trend } from "k6/metrics";
import { check, fail } from "k6";

const DEFAULT_BASE_URL = "http://127.0.0.1:3000";
const DEFAULT_PATH = "/api/v1/attestations";

const SCENARIO_NAME = "black_friday";

const SUMMARY_TREND_STATS = Object.freeze(["min", "med", "avg", "p(90)", "p(95)", "p(99)", "max"]);

const ENDPOINT_TAG = "attestations";

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
  if (trimmed === "") return DEFAULT_PATH;
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function sanitizeToken(value, fallback = "run") {
  const sanitized = value.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 16);
  return sanitized || fallback;
}

function seconds(value) {
  return `${value}s`;
}

function buildConfig(env) {
  const baseUrl = normalizeBaseUrl(readString(env, "K6_BASE_URL", DEFAULT_BASE_URL));
  const path = normalizePath(readString(env, "K6_BF_PATH", DEFAULT_PATH));
  const writeRatio = clamp(readFloat(env, "K6_BF_WRITE_RATIO", 1), 0, 1);

  return {
    authToken: readString(env, "K6_AUTH_TOKEN", ""),
    baseUrl,
    businessId: readString(env, "K6_BF_BUSINESS_ID", ""),
    insecureSkipTlsVerify: readBoolean(env, "K6_INSECURE_SKIP_TLS_VERIFY", false),
    merkleRoot: readString(env, "K6_BF_MERKLE_ROOT", `0x${"ab".repeat(32)}`),
    path,
    periodPrefix: sanitizeToken(readString(env, "K6_BF_PERIOD_PREFIX", "bf")),
    requestTimeout: readString(env, "K6_BF_TIMEOUT", "10s"),
    runId: sanitizeToken(readString(env, "K6_BF_RUN_ID", "local")),
    submitOnChain: readBoolean(env, "K6_BF_SUBMIT_ON_CHAIN", false),
    version: readString(env, "K6_BF_VERSION", "1.0.0"),
    writeRatio,
  };
}

function buildOptions(env) {
  const rampUpSec = readInteger(env, "K6_BF_RAMP_UP_SEC", 120);
  const peakRate1 = readInteger(env, "K6_BF_PEAK_RATE_1", 200);
  const peakDurationSec1 = readInteger(env, "K6_BF_PEAK_DURATION_SEC_1", 180);
  const dipRate = readInteger(env, "K6_BF_DIP_RATE", 150);
  const dipDurationSec = readInteger(env, "K6_BF_DIP_DURATION_SEC", 60);
  const surgeRate = readInteger(env, "K6_BF_SURGE_RATE", 300);
  const surgeDurationSec = readInteger(env, "K6_BF_SURGE_DURATION_SEC", 120);
  const peakRate2 = readInteger(env, "K6_BF_PEAK_RATE_2", 300);
  const peakDurationSec2 = readInteger(env, "K6_BF_PEAK_DURATION_SEC_2", 180);
  const cooldownTarget = readInteger(env, "K6_BF_COOLDOWN_TARGET", 50);
  const cooldownDurationSec = readInteger(env, "K6_BF_COOLDOWN_DURATION_SEC", 180);
  const startRate = readInteger(env, "K6_BF_START_RATE", 10);
  const p99ThresholdMs = readInteger(env, "K6_BF_P99_THRESHOLD_MS", 500);

  const thresholds = {
    [`http_req_duration{endpoint:${ENDPOINT_TAG},scenario:${SCENARIO_NAME}}`]: [`p(99)<${p99ThresholdMs}`],
    [`http_req_duration{endpoint:${ENDPOINT_TAG}}`]: ["p(95)<300"],
    [`http_req_failed{endpoint:${ENDPOINT_TAG},scenario:${SCENARIO_NAME}}`]: ["rate<0.001"],
    [`http_req_failed{endpoint:${ENDPOINT_TAG}}`]: ["rate<0.001"],
  };

  return {
    discardResponseBodies: true,
    insecureSkipTLSVerify: readBoolean(env, "K6_INSECURE_SKIP_TLS_VERIFY", false),
    summaryTrendStats: SUMMARY_TREND_STATS,
    tags: {
      endpoint: ENDPOINT_TAG,
      service: "veritasor-backend",
      suite: "black-friday",
    },
    thresholds,
    userAgent: "veritasor-backend-k6/black-friday",
    scenarios: {
      [SCENARIO_NAME]: {
        exec: "blackFriday",
        executor: "ramping-arrival-rate",
        startRate,
        timeUnit: "1s",
        preAllocatedVUs: readInteger(env, "K6_BF_PREALLOCATED_VUS", 100),
        maxVUs: readInteger(env, "K6_BF_MAX_VUS", 500),
        stages: [
          { duration: seconds(rampUpSec), target: peakRate1 },
          { duration: seconds(peakDurationSec1), target: peakRate1 },
          { duration: seconds(dipDurationSec), target: dipRate },
          { duration: seconds(surgeDurationSec), target: surgeRate },
          { duration: seconds(peakDurationSec2), target: peakRate2 },
          { duration: seconds(cooldownDurationSec), target: cooldownTarget },
        ],
        tags: { endpoint: ENDPOINT_TAG, load_profile: "black_friday" },
      },
    },
  };
}

export const options = buildOptions(__ENV);

const bfIterationDuration = new Trend("bf_iteration_duration", true);
const bfSloViolation = new Rate("bf_slo_violation");

http.setResponseCallback(http.expectedStatuses(200, 201));

function authHeaders(config) {
  return {
    Accept: "application/json",
    Authorization: `Bearer ${config.authToken}`,
  };
}

function buildSyntheticPeriod({ scenarioName, vu, iteration, runId, periodPrefix }) {
  const scenarioToken = sanitizeToken(scenarioName, "scenario").toLowerCase();
  const prefixToken = sanitizeToken(periodPrefix, "bf").toLowerCase();
  const runToken = sanitizeToken(runId, "run").toLowerCase();

  return `${prefixToken}-${scenarioToken}-${vu}-${iteration}-${runToken}`.slice(0, 50);
}

function buildIdempotencyKey({ scenarioName, vu, iteration, runId }) {
  return `k6-${runId}-${scenarioName}-${vu}-${iteration}`.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 128) || "k6-run";
}

function createSubmitPayload(config, scenarioName) {
  return {
    ...(config.businessId ? { businessId: config.businessId } : {}),
    merkleRoot: config.merkleRoot,
    period: buildSyntheticPeriod({
      scenarioName,
      vu: exec.vu.idInTest,
      iteration: exec.scenario.iterationInTest,
      periodPrefix: config.periodPrefix,
      runId: config.runId,
    }),
    submit: config.submitOnChain,
    version: config.version,
  };
}

function requestTags(operation) {
  return {
    endpoint: ENDPOINT_TAG,
    operation,
  };
}

function performIteration(config) {
  const scenarioName = exec.scenario.name;
  const writeRequest = Math.random() < config.writeRatio;
  const url = `${config.baseUrl}${config.path}`;
  const startedAt = Date.now();

  let response;
  let operation;

  if (writeRequest) {
    operation = "submit";
    response = http.post(url, JSON.stringify(createSubmitPayload(config, scenarioName)), {
      headers: {
        ...authHeaders(config),
        "Content-Type": "application/json",
        "Idempotency-Key": buildIdempotencyKey({
          scenarioName,
          vu: exec.vu.idInTest,
          iteration: exec.scenario.iterationInTest,
          runId: config.runId,
        }),
      },
      tags: requestTags(operation),
      timeout: config.requestTimeout,
    });
  } else {
    operation = "list";
    response = http.get(`${url}?page=1&limit=20`, {
      headers: authHeaders(config),
      tags: requestTags(operation),
      timeout: config.requestTimeout,
    });
  }

  const expectedStatus = operation === "submit" ? 201 : 200;
  const passed = check(response, {
    [`${operation} returns ${expectedStatus}`]: (res) => res.status === expectedStatus,
  });

  const tags = requestTags(operation);
  bfIterationDuration.add(Date.now() - startedAt, tags);
  bfSloViolation.add(!passed || response.timings.duration >= 300, tags);
}

export function setup() {
  const config = buildConfig(__ENV);

  if (!config.authToken) {
    fail("K6_AUTH_TOKEN is required for Black Friday performance scenarios.");
  }

  const smoke = http.get(`${config.baseUrl}${config.path}?page=1&limit=1`, {
    headers: authHeaders(config),
    tags: { endpoint: "attestation_setup", operation: "setup" },
    timeout: config.requestTimeout,
  });

  if (smoke.status !== 200) {
    fail(
      `Black Friday smoke check failed with HTTP ${smoke.status}. ` +
      "Verify K6_BASE_URL, K6_AUTH_TOKEN, and that the token resolves to a business.",
    );
  }

  return config;
}

export function blackFriday(config) {
  performIteration(config);
}
