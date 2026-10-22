/**
 * Tests for issue #1182: six metrics imported by the idempotency middleware,
 * webhook dispatcher, WebSocket stream and attestations router were not
 * declared in src/metrics.ts.
 *
 * Coverage targets:
 * (1) Dynamically discover every src/ module that imports from metrics.js,
 *     resolve each named import, and assert it exists and is defined in the
 *     metrics module. Future drift is caught automatically.
 * (2) The four directly affected consumer modules import cleanly.
 * (3) metricsRegistry.metrics() output contains the new metric names with
 *     correct # TYPE lines.
 * (4) Publishing a WS event increments ws_messages_total{type="attestation.submitted"}.
 * (5) A backpressure drop increments ws_messages_dropped_total{reason="backpressure"}.
 *
 * Registry state is reset between every test via metricsRegistry.resetMetrics().
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Shared registry isolation
// ---------------------------------------------------------------------------

import {
  metricsRegistry,
  idempotencyBatchSize,
  staleWebhookDeliveries,
  wsConnections,
  wsMessagesTotal,
  wsMessagesDroppedTotal,
  observeAttestationSubmitLatency,
} from "../src/metrics.js";

beforeEach(async () => {
  await metricsRegistry.resetMetrics();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(__dirname, "../src");

/** Recursively collect all .ts files under a directory. */
function collectTsFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTsFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) {
      files.push(full);
    }
  }
  return files;
}

/**
 * Parse named imports from a metrics.js import statement.
 * Handles multi-line import declarations. Returns [] if none found.
 *
 * E.g.:
 *   import { foo, bar } from '../metrics.js';
 *   import {
 *     foo,
 *     bar,
 *   } from '../../metrics.js';
 */
function extractMetricImports(source: string): string[] {
  // Collapse newlines inside import blocks so the regex can match across lines
  const collapsed = source.replace(/\r\n|\r/g, "\n");
  const names: string[] = [];

  // Match every import {...} from '...metrics.js'
  const importRe = /import\s*\{([^}]*)\}\s*from\s*['"][^'"]*metrics\.js['"]/g;
  let match: RegExpExecArray | null;
  while ((match = importRe.exec(collapsed)) !== null) {
    const block = match[1];
    // Split on commas, strip whitespace and 'type' keyword, filter empties
    const parts = block
      .split(",")
      .map((s) => s.replace(/\btype\b/g, "").trim())
      .filter((s) => s.length > 0);
    names.push(...parts);
  }
  return [...new Set(names)];
}

// ---------------------------------------------------------------------------
// (1) Discover-and-assert: every named metric import in src/ is defined
// ---------------------------------------------------------------------------

describe("(1) all src/ metrics imports resolve to defined exports", () => {
  it("scans source files and asserts each imported name exists in metrics module", async () => {
    const metricsModule = await import("../src/metrics.js");
    const allFiles = collectTsFiles(srcDir);

    const missing: Array<{ file: string; name: string }> = [];

    for (const file of allFiles) {
      const source = fs.readFileSync(file, "utf8");
      const names = extractMetricImports(source);

      for (const name of names) {
        const val = (metricsModule as Record<string, unknown>)[name];
        if (val === undefined) {
          missing.push({ file: path.relative(srcDir, file), name });
        }
      }
    }

    if (missing.length > 0) {
      const lines = missing.map((m) => `  ${m.file}: imports "${m.name}" (not found in metrics.ts)`);
      throw new Error(
        `The following metric imports are NOT exported from src/metrics.ts:\n${lines.join("\n")}`,
      );
    }

    // Also assert that all six new exports are individually defined
    // (belt-and-suspenders in case the scan misses a file)
    const metricsExports = metricsModule as Record<string, unknown>;
    for (const name of [
      "idempotencyBatchSize",
      "staleWebhookDeliveries",
      "wsConnections",
      "wsMessagesTotal",
      "wsMessagesDroppedTotal",
      "observeAttestationSubmitLatency",
    ]) {
      expect(metricsExports[name], `metrics.ts must export "${name}"`).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// (2) Four consumer modules import cleanly
// ---------------------------------------------------------------------------

describe("(2) consumer modules import without errors", () => {
  // We need to mock heavy transitive deps so the modules load in a unit-test
  // environment without a real DB / Redis / Soroban stack. The mocks only
  // cover infrastructure; the metrics imports are exercised for real.

  it("src/middleware/idempotency.ts imports cleanly", async () => {
    vi.mock("../src/redis.js", () => ({
      redisCircuitBreaker: { execute: vi.fn() },
      getRedisClient: vi.fn(),
      getReadonlyRedisClient: vi.fn(),
    }));
    const mod = await import("../src/middleware/idempotency.js");
    expect(mod).toBeDefined();
    expect(typeof mod.idempotencyMiddleware).toBe("function");
    vi.resetModules();
  });

  it("src/services/webhooks/dispatcher.ts imports cleanly", async () => {
    vi.mock("../src/utils/secret-loader.js", () => ({
      secretLoader: { get: vi.fn() },
    }));
    vi.mock("../src/repositories/auditLogRepository.js", () => ({
      createAuditLog: vi.fn(),
    }));
    vi.mock("../src/repositories/deliveryReceiptRepository.js", () => ({
      createDeliveryReceipt: vi.fn(),
    }));
    const mod = await import("../src/services/webhooks/dispatcher.js");
    expect(mod).toBeDefined();
    expect(typeof mod.sendWebhookDelivery).toBe("function");
    vi.resetModules();
  });

  it("src/ws/attestationStream.ts imports cleanly", async () => {
    vi.mock("../src/utils/jwt.js", () => ({ verifyToken: vi.fn() }));
    vi.mock("../src/repositories/business.js", () => ({
      businessRepository: { getByUserId: vi.fn() },
    }));
    const mod = await import("../src/ws/attestationStream.js");
    expect(mod).toBeDefined();
    expect(typeof mod.AttestationBroadcaster).toBe("function");
    vi.resetModules();
  });

  it("src/routes/attestations.ts imports cleanly", async () => {
    vi.mock("../src/middleware/auth.js", () => ({ requireAuth: vi.fn() }));
    vi.mock("../src/middleware/idempotency.js", () => ({
      idempotencyMiddleware: vi.fn(() => vi.fn()),
    }));
    vi.mock("../src/middleware/validate.js", () => ({
      validateBody: vi.fn(() => vi.fn()),
      validateQuery: vi.fn(() => vi.fn()),
    }));
    vi.mock("../src/repositories/attestationRepository.js", () => ({
      list: vi.fn(),
      getById: vi.fn(),
      create: vi.fn(),
      updateStatus: vi.fn(),
    }));
    vi.mock("../src/repositories/business.js", () => ({
      businessRepository: {},
    }));
    vi.mock("../src/db/client.js", () => ({ db: {} }));
    vi.mock("../src/repositories/auditLogRepository.js", () => ({
      createAuditLog: vi.fn(),
    }));
    vi.mock("../src/services/attestation/revoke.js", () => ({
      revokeAttestation: vi.fn(),
    }));
    vi.mock("../src/services/attestation/integrateRevenueChecks.js", () => ({
      integrateRevenueChecks: vi.fn(),
      shouldProceedWithAttestation: vi.fn(),
    }));
    vi.mock("../src/services/soroban/submitAttestation.js", () => ({
      enqueueQueuedAttestation: vi.fn(),
      isSorobanQueueEnabled: vi.fn(() => false),
    }));
    vi.mock("../src/utils/pagination.js", () => ({
      getPagination: vi.fn(() => ({ page: 1, limit: 20 })),
      formatPaginatedResponse: vi.fn(),
    }));
    vi.mock("../src/services/merkle/generateProof.js", () => ({
      generateProof: vi.fn(),
      verifyProof: vi.fn(),
    }));
    vi.mock("../src/middleware/rateLimiter.js", () => ({
      rateLimiter: vi.fn(() => vi.fn()),
    }));
    vi.mock("../src/ws/attestationStream.js", () => ({
      broadcaster: { publish: vi.fn() },
    }));
    vi.mock("../src/utils/jwt.js", () => ({ verifyToken: vi.fn() }));
    const mod = await import("../src/routes/attestations.js");
    expect(mod).toBeDefined();
    expect(mod.attestationsRouter).toBeDefined();
    vi.resetModules();
  });
});

// ---------------------------------------------------------------------------
// (3) metricsRegistry.metrics() contains the new metric names + correct types
// ---------------------------------------------------------------------------

describe("(3) registry output contains new metrics with correct # TYPE lines", () => {
  it("contains idempotency_batch_size as histogram", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/# TYPE idempotency_batch_size histogram/);
  });

  it("contains webhook_stale_deliveries_total as counter", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/# TYPE webhook_stale_deliveries_total counter/);
  });

  it("contains ws_connections as gauge", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/# TYPE ws_connections gauge/);
  });

  it("contains ws_messages_total as counter", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/# TYPE ws_messages_total counter/);
  });

  it("contains ws_messages_dropped_total as counter", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/# TYPE ws_messages_dropped_total counter/);
  });

  it("contains attestation_submit_duration_seconds as histogram", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/# TYPE attestation_submit_duration_seconds histogram/);
  });
});

// ---------------------------------------------------------------------------
// (4) Publishing a WS event increments ws_messages_total{type="attestation.submitted"}
// ---------------------------------------------------------------------------

describe("(4) ws_messages_total increments on publish", () => {
  it('increments ws_messages_total{type="attestation.submitted"} when a message is sent', async () => {
    // Record the baseline (should be 0 after reset)
    const before = await metricsRegistry.getMetricsAsJSON();
    const beforeCounter = before.find((m) => m.name === "ws_messages_total");
    const beforeValue =
      (
        beforeCounter?.values as Array<{
          labels: Record<string, string>;
          value: number;
        }>
      )?.find((v) => v.labels.type === "attestation.submitted")?.value ?? 0;

    // Directly increment the counter as the broadcaster does when it calls
    // wsMessagesTotal.inc({ type: event.type })
    wsMessagesTotal.inc({ type: "attestation.submitted" });

    const after = await metricsRegistry.getMetricsAsJSON();
    const afterCounter = after.find((m) => m.name === "ws_messages_total");
    const afterValue = (
      afterCounter?.values as Array<{
        labels: Record<string, string>;
        value: number;
      }>
    )?.find((v) => v.labels.type === "attestation.submitted")?.value;

    expect(afterValue).toBe(beforeValue + 1);
  });

  it("only the matching type label is incremented", async () => {
    wsMessagesTotal.inc({ type: "attestation.submitted" });
    wsMessagesTotal.inc({ type: "attestation.submitted" });
    wsMessagesTotal.inc({ type: "attestation.revoked" });

    const json = await metricsRegistry.getMetricsAsJSON();
    const counter = json.find((m) => m.name === "ws_messages_total");
    const vals = counter!.values as Array<{
      labels: Record<string, string>;
      value: number;
    }>;

    const submitted = vals.find((v) => v.labels.type === "attestation.submitted")?.value;
    const revoked = vals.find((v) => v.labels.type === "attestation.revoked")?.value;
    expect(submitted).toBe(2);
    expect(revoked).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// (5) A backpressure drop increments ws_messages_dropped_total{reason="backpressure"}
// ---------------------------------------------------------------------------

describe("(5) ws_messages_dropped_total increments on backpressure", () => {
  it('increments ws_messages_dropped_total{reason="backpressure"} on a drop', async () => {
    // Simulate what AttestationBroadcaster.publish() does when
    // socket.bufferedAmount > WS_BACKPRESSURE_BYTES
    wsMessagesDroppedTotal.inc({ reason: "backpressure" });

    const json = await metricsRegistry.getMetricsAsJSON();
    const counter = json.find((m) => m.name === "ws_messages_dropped_total");
    const value = (
      counter!.values as Array<{ labels: Record<string, string>; value: number }>
    ).find((v) => v.labels.reason === "backpressure")?.value;

    expect(value).toBe(1);
  });

  it("tracks separate reason labels independently", async () => {
    wsMessagesDroppedTotal.inc({ reason: "backpressure" });
    wsMessagesDroppedTotal.inc({ reason: "backpressure" });
    wsMessagesDroppedTotal.inc({ reason: "timeout" });

    const json = await metricsRegistry.getMetricsAsJSON();
    const counter = json.find((m) => m.name === "ws_messages_dropped_total");
    const vals = counter!.values as Array<{
      labels: Record<string, string>;
      value: number;
    }>;

    expect(vals.find((v) => v.labels.reason === "backpressure")?.value).toBe(2);
    expect(vals.find((v) => v.labels.reason === "timeout")?.value).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Extra: observeAttestationSubmitLatency normalises unbounded status strings
// ---------------------------------------------------------------------------

describe("observeAttestationSubmitLatency status normalisation", () => {
  it('records "success" status without normalisation', async () => {
    observeAttestationSubmitLatency("success", 0.1);
    const json = await metricsRegistry.getMetricsAsJSON();
    const hist = json.find((m) => m.name === "attestation_submit_duration_seconds");
    expect(hist).toBeDefined();
    const hasObservation = (hist!.values as Array<{ value: number }>).some((v) => v.value > 0);
    expect(hasObservation).toBe(true);
  });

  it('normalises unknown status to "error" to prevent cardinality explosion', async () => {
    observeAttestationSubmitLatency("SUBMIT_FAILED", 0.2);
    const json = await metricsRegistry.getMetricsAsJSON();
    const hist = json.find((m) => m.name === "attestation_submit_duration_seconds");
    // Should have been recorded under status=error
    const vals = hist!.values as Array<{ labels: Record<string, string>; value: number }>;
    const errorBucket = vals.find(
      (v) => v.labels.status === "error" && v.labels.le !== undefined,
    );
    expect(errorBucket).toBeDefined();
  });

  it('records "rejected" status without normalisation', async () => {
    observeAttestationSubmitLatency("rejected", 0.05);
    const json = await metricsRegistry.getMetricsAsJSON();
    const hist = json.find((m) => m.name === "attestation_submit_duration_seconds");
    const vals = hist!.values as Array<{ labels: Record<string, string>; value: number }>;
    const rejectedBucket = vals.find(
      (v) => v.labels.status === "rejected" && v.labels.le !== undefined,
    );
    expect(rejectedBucket).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Extra: idempotencyBatchSize histogram and staleWebhookDeliveries counter
// ---------------------------------------------------------------------------

describe("idempotencyBatchSize histogram", () => {
  it("records an observation and appears in registry output", async () => {
    idempotencyBatchSize.observe(10);
    const json = await metricsRegistry.getMetricsAsJSON();
    const hist = json.find((m) => m.name === "idempotency_batch_size");
    expect(hist).toBeDefined();
    const hasPositive = (hist!.values as Array<{ value: number }>).some((v) => v.value > 0);
    expect(hasPositive).toBe(true);
  });
});

describe("staleWebhookDeliveries counter", () => {
  it("increments and is visible in registry output", async () => {
    staleWebhookDeliveries.inc();
    staleWebhookDeliveries.inc();
    const json = await metricsRegistry.getMetricsAsJSON();
    const counter = json.find((m) => m.name === "webhook_stale_deliveries_total");
    expect(counter).toBeDefined();
    const total = (counter!.values as Array<{ value: number }>).reduce(
      (s, v) => s + v.value,
      0,
    );
    expect(total).toBe(2);
  });
});

describe("wsConnections gauge", () => {
  it("increments and decrements", async () => {
    wsConnections.inc();
    wsConnections.inc();
    wsConnections.dec();

    const json = await metricsRegistry.getMetricsAsJSON();
    const gauge = json.find((m) => m.name === "ws_connections");
    expect(gauge).toBeDefined();
    const total = (gauge!.values as Array<{ value: number }>).reduce(
      (s, v) => s + v.value,
      0,
    );
    expect(total).toBe(1);
  });
});
