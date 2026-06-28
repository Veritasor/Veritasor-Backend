import http from "k6/http";
import exec from "k6/execution";
import { Rate, Trend } from "k6/metrics";
import { check, fail } from "k6";
import {
  buildIdempotencyKey,
  buildSyntheticPeriod,
  createPeakAttestationOptions,
  createPeakAttestationRuntimeConfig,
  sloThresholds,
} from "./peak-attestation.config.js";

export const options = createPeakAttestationOptions(__ENV);
export { sloThresholds };

const runtimeConfig = createPeakAttestationRuntimeConfig(__ENV);
const attestationIterationDuration = new Trend("attestation_iteration_duration", true);
const attestationSloViolation = new Rate("attestation_slo_violation");

http.setResponseCallback(http.expectedStatuses(200, 201));

function authHeaders(config) {
  return {
    Accept: "application/json",
    Authorization: `Bearer ${config.authToken}`,
  };
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
    endpoint: "attestations",
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
  attestationIterationDuration.add(Date.now() - startedAt, tags);
  attestationSloViolation.add(!passed || response.timings.duration >= 300, tags);
}

export function setup() {
  if (!runtimeConfig.authToken) {
    fail("K6_AUTH_TOKEN is required for attestation performance scenarios.");
  }

  const smoke = http.get(`${runtimeConfig.baseUrl}${runtimeConfig.path}?page=1&limit=1`, {
    headers: authHeaders(runtimeConfig),
    tags: { endpoint: "attestation_setup", operation: "setup" },
    timeout: runtimeConfig.requestTimeout,
  });

  if (smoke.status !== 200) {
    fail(
      `Attestation smoke check failed with HTTP ${smoke.status}. ` +
      "Verify K6_BASE_URL, K6_AUTH_TOKEN, and that the token resolves to a business.",
    );
  }

  return runtimeConfig;
}

export function steadyState(config) {
  performIteration(config);
}

export function spike(config) {
  performIteration(config);
}

export function soak(config) {
  performIteration(config);
}

export function breakpoint(config) {
  performIteration(config);
}
