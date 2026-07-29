export const SCENARIO_NAMES = Object.freeze({
  rampUp: "ramp_up_connections",
  steadyFanout: "steady_fanout",
  saturationStep: "saturation_step",
});

const DEFAULT_TAGS = Object.freeze({
  endpoint: "ws_attestations",
  service: "veritasor-backend",
  suite: "ws-fanout-saturation",
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

export const sloThresholds = Object.freeze({
  "ws_message_latency_ms": ["p(95)<200"],
  "ws_drop_rate": ["rate<0.05"],
  "ws_connection_errors": ["count<5"],
});

export function createWsSaturationOptions(env = {}) {
  const targetClients = readInteger(env, "K6_WS_TARGET_CLIENTS", 100);
  const rampDuration = `${readInteger(env, "K6_WS_RAMP_SEC", 15)}s`;
  const holdDuration = `${readInteger(env, "K6_WS_HOLD_SEC", 30)}s`;

  return {
    scenarios: {
      [SCENARIO_NAMES.rampUp]: {
        executor: "ramping-vus",
        startVUs: 10,
        stages: [
          { duration: rampDuration, target: Math.floor(targetClients / 2) },
          { duration: rampDuration, target: targetClients },
          { duration: holdDuration, target: targetClients },
          { duration: "10s", target: 0 },
        ],
        gracefulStop: "5s",
        tags: { ...DEFAULT_TAGS, scenario: SCENARIO_NAMES.rampUp },
      },
    },
    thresholds: sloThresholds,
    summaryTrendStats: ["min", "med", "avg", "p(90)", "p(95)", "p(99)", "max"],
  };
}

export function createWsSaturationRuntimeConfig(env = {}) {
  const rawBaseUrl = readString(env, "K6_BASE_URL", "http://127.0.0.1:3000");
  const baseUrl = rawBaseUrl.replace(/\/+$/, "");

  const rawPath = readString(env, "K6_WS_PATH", "/api/v1/ws/attestations");
  const path = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;

  const authToken = readString(env, "K6_AUTH_TOKEN", "");
  const maxDropRate = readFloat(env, "K6_WS_MAX_DROP_RATE", 0.05);
  const maxLatencyMs = readInteger(env, "K6_WS_MAX_LATENCY_MS", 200);
  const targetClients = readInteger(env, "K6_WS_TARGET_CLIENTS", 100);

  return {
    baseUrl,
    path,
    authToken,
    maxDropRate,
    maxLatencyMs,
    targetClients,
  };
}

export function buildWsUrl(baseUrl, path, token) {
  const wsProtocol = baseUrl.startsWith("https://") ? "wss://" : "ws://";
  const host = baseUrl.replace(/^https?:\/\//, "");
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const url = `${wsProtocol}${host}${cleanPath}`;
  if (!token) return url;
  return `${url}?token=${encodeURIComponent(token)}`;
}

export function validateMessagePayload(payload) {
  if (!payload || typeof payload !== "object") return false;
  const validTypes = ["attestation.submitted", "attestation.revoked"];
  return (
    validTypes.includes(payload.type) &&
    typeof payload.businessId === "string" &&
    payload.businessId.length > 0 &&
    typeof payload.attestationId === "string" &&
    payload.attestationId.length > 0 &&
    typeof payload.timestamp === "string"
  );
}
