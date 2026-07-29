import { describe, expect, it } from "vitest";
import {
  SCENARIO_NAMES,
  buildWsUrl,
  createWsSaturationOptions,
  createWsSaturationRuntimeConfig,
  sloThresholds,
  validateMessagePayload,
} from "../../../ops/k6/ws-saturation.config.js";

describe("ws-saturation k6 config", () => {
  it("exports SLO thresholds for WebSocket fan-out saturation", () => {
    expect(sloThresholds["ws_message_latency_ms"]).toEqual(["p(95)<200"]);
    expect(sloThresholds["ws_drop_rate"]).toEqual(["rate<0.05"]);
    expect(sloThresholds["ws_connection_errors"]).toEqual(["count<5"]);
  });

  it("builds options with default and customized environment variables", () => {
    const defaultOptions = createWsSaturationOptions({});
    const rampScenario = defaultOptions.scenarios[SCENARIO_NAMES.rampUp];

    expect(rampScenario.executor).toBe("ramping-vus");
    expect(rampScenario.stages[1].target).toBe(100);

    const customOptions = createWsSaturationOptions({
      K6_WS_TARGET_CLIENTS: "250",
      K6_WS_RAMP_SEC: "20",
      K6_WS_HOLD_SEC: "40",
    });
    const customRamp = customOptions.scenarios[SCENARIO_NAMES.rampUp];
    expect(customRamp.stages[0].duration).toBe("20s");
    expect(customRamp.stages[1].target).toBe(250);
    expect(customRamp.stages[2].duration).toBe("40s");
  });

  it("normalizes runtime configuration from environment", () => {
    const config = createWsSaturationRuntimeConfig({
      K6_BASE_URL: "https://ws.example.com/",
      K6_WS_PATH: "api/v1/ws/attestations",
      K6_AUTH_TOKEN: "jwt-test-token",
      K6_WS_MAX_DROP_RATE: "0.02",
      K6_WS_MAX_LATENCY_MS: "150",
      K6_WS_TARGET_CLIENTS: "300",
    });

    expect(config.baseUrl).toBe("https://ws.example.com");
    expect(config.path).toBe("/api/v1/ws/attestations");
    expect(config.authToken).toBe("jwt-test-token");
    expect(config.maxDropRate).toBe(0.02);
    expect(config.maxLatencyMs).toBe(150);
    expect(config.targetClients).toBe(300);
  });

  it("builds correct WebSocket URLs for http and https base URLs", () => {
    expect(buildWsUrl("http://localhost:3000", "/api/v1/ws/attestations", "token123")).toBe(
      "ws://localhost:3000/api/v1/ws/attestations?token=token123"
    );

    expect(buildWsUrl("https://api.veritasor.io", "api/v1/ws/attestations", "token@xyz")).toBe(
      "wss://api.veritasor.io/api/v1/ws/attestations?token=token%40xyz"
    );

    expect(buildWsUrl("http://localhost:3000", "/api/v1/ws/attestations", "")).toBe(
      "ws://localhost:3000/api/v1/ws/attestations"
    );
  });

  it("validates WebSocket message payload schema", () => {
    const validSubmitted = {
      type: "attestation.submitted",
      businessId: "biz-123",
      attestationId: "att-456",
      period: "2024-Q2",
      timestamp: "2026-07-29T12:00:00Z",
    };

    const validRevoked = {
      type: "attestation.revoked",
      businessId: "biz-123",
      attestationId: "att-456",
      period: "2024-Q2",
      timestamp: "2026-07-29T12:00:00Z",
    };

    expect(validateMessagePayload(validSubmitted)).toBe(true);
    expect(validateMessagePayload(validRevoked)).toBe(true);

    expect(validateMessagePayload(null)).toBe(false);
    expect(validateMessagePayload("string")).toBe(false);
    expect(validateMessagePayload({ type: "unknown.type" })).toBe(false);
    expect(validateMessagePayload({ type: "attestation.submitted", businessId: "" })).toBe(false);
    expect(validateMessagePayload({ type: "attestation.submitted", businessId: "b1", attestationId: "" })).toBe(false);
  });
});
