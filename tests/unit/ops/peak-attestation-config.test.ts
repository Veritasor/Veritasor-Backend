import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  SCENARIO_NAMES,
  buildIdempotencyKey,
  buildSyntheticPeriod,
  createPeakAttestationOptions,
  createPeakAttestationRuntimeConfig,
  sloThresholds,
} from "../../../ops/k6/peak-attestation.config.js";

function parseSeconds(value) {
  return Number.parseInt(value.replace(/s$/, ""), 10);
}

describe("peak-attestation k6 config", () => {
  it("exports the attestation SLO thresholds", () => {
    expect(sloThresholds["http_req_duration{endpoint:attestations}"]).toEqual(["p(95)<300"]);
    expect(sloThresholds["http_req_failed{endpoint:attestations}"]).toEqual(["rate<0.001"]);

    for (const scenarioName of Object.values(SCENARIO_NAMES)) {
      expect(sloThresholds[`http_req_duration{endpoint:attestations,scenario:${scenarioName}}`]).toEqual(["p(95)<300"]);
      expect(sloThresholds[`http_req_failed{endpoint:attestations,scenario:${scenarioName}}`]).toEqual(["rate<0.001"]);
    }
  });

  it("builds sequential steady, spike, soak, and breakpoint scenarios", () => {
    const options = createPeakAttestationOptions({});

    expect(options.scenarios[SCENARIO_NAMES.steady].executor).toBe("constant-arrival-rate");
    expect(options.scenarios[SCENARIO_NAMES.spike].executor).toBe("ramping-arrival-rate");
    expect(options.scenarios[SCENARIO_NAMES.soak].executor).toBe("constant-arrival-rate");
    expect(options.scenarios[SCENARIO_NAMES.breakpoint].executor).toBe("ramping-arrival-rate");

    const steadyStart = parseSeconds(options.scenarios[SCENARIO_NAMES.steady].startTime);
    const spikeStart = parseSeconds(options.scenarios[SCENARIO_NAMES.spike].startTime);
    const soakStart = parseSeconds(options.scenarios[SCENARIO_NAMES.soak].startTime);
    const breakpointStart = parseSeconds(options.scenarios[SCENARIO_NAMES.breakpoint].startTime);

    expect(steadyStart).toBe(0);
    expect(spikeStart).toBeGreaterThan(steadyStart);
    expect(soakStart).toBeGreaterThan(spikeStart);
    expect(breakpointStart).toBeGreaterThan(soakStart);
  });

  it("normalizes runtime config and clamps the write ratio", () => {
    const config = createPeakAttestationRuntimeConfig({
      K6_ATT_PATH: "api/v1/attestations",
      K6_ATT_RUN_ID: "nightly #42",
      K6_ATT_SUBMIT_ON_CHAIN: "true",
      K6_ATT_WRITE_RATIO: "1.7",
      K6_BASE_URL: "https://perf.example.com/",
    });

    expect(config.baseUrl).toBe("https://perf.example.com");
    expect(config.path).toBe("/api/v1/attestations");
    expect(config.runId).toBe("nightly42");
    expect(config.submitOnChain).toBe(true);
    expect(config.writeRatio).toBe(1);
  });

  it("builds bounded synthetic periods and deterministic idempotency keys", () => {
    const period = buildSyntheticPeriod({
      iteration: 12345,
      periodPrefix: "perf",
      runId: "nightly-123456",
      scenarioName: SCENARIO_NAMES.breakpoint,
      vu: 99,
    });

    const key = buildIdempotencyKey({
      iteration: 12345,
      runId: "nightly-123456",
      scenarioName: SCENARIO_NAMES.breakpoint,
      vu: 99,
    });

    expect(period.length).toBeLessThanOrEqual(50);
    expect(period).toContain("breakpoint");
    expect(key).toBe("k6-nightly-123456-breakpoint-99-12345");
  });

  it("ships a valid Grafana dashboard JSON artifact", () => {
    const dashboardPath = resolve(process.cwd(), "ops/k6/grafana/peak-attestation-dashboard.json");
    const dashboard = JSON.parse(readFileSync(dashboardPath, "utf8"));

    expect(dashboard.title).toBe("Veritasor Attestation Peak Load");
    expect(Array.isArray(dashboard.panels)).toBe(true);
    expect(dashboard.panels.length).toBeGreaterThanOrEqual(4);
  });
});
