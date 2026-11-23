import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockQuery } = vi.hoisted(() => ({
  mockQuery: vi.fn(),
}));

vi.mock("../../../../src/db/client.js", () => ({
  db: { query: mockQuery },
}));

vi.mock("../../../../src/utils/secret-loader.js", () => ({
  secretLoader: { get: vi.fn() },
}));

vi.mock("../../../../src/metrics.js", async () => {
  const { Gauge, Registry } = await import("prom-client");
  const registry = new Registry();
  return {
    webhookSecretRotationStatus: new Gauge({
      name: "webhook_secret_rotation_status",
      help: "Rollout status of webhook secret rotation per subscription (1 = current / 0 = lagging)",
      labelNames: ["subscription_id", "business_id", "status"] as const,
      registers: [registry],
    }),
  };
});

import {
  getLatestSecretVersion,
  isSubscriptionCurrent,
  getAdoptionSnapshot,
  emitRotationStatus,
  reset,
} from "../../../../src/services/webhooks/secretRotation.js";
import { webhookSecretRotationStatus } from "../../../../src/metrics.js";

function setupMockDbRows(
  rows: Array<{ id: string; business_id: string; secret_version: number }>,
) {
  const maxVersion = rows.reduce(
    (max, r) => Math.max(max, r.secret_version),
    0,
  );
  mockQuery.mockImplementation(async (sql: string) => {
    if (sql.includes("MAX(secret_version)")) {
      return { rows: [{ latest_version: maxVersion }] };
    }
    if (sql.includes("FROM webhook_subscriptions")) {
      return { rows };
    }
    return { rows: [] };
  });
}

describe("secretRotation (DB-backed)", () => {
  beforeEach(() => {
    reset();
    mockQuery.mockReset();
    vi.restoreAllMocks();
  });

  describe("getLatestSecretVersion", () => {
    it("returns 0 when no subscriptions exist in DB", async () => {
      setupMockDbRows([]);
      await expect(getLatestSecretVersion()).resolves.toBe(0);
    });

    it("returns the maximum secret_version from DB rows", async () => {
      setupMockDbRows([
        { id: "sub-1", business_id: "biz-1", secret_version: 2 },
        { id: "sub-2", business_id: "biz-2", secret_version: 5 },
      ]);
      await expect(getLatestSecretVersion()).resolves.toBe(5);
    });
  });

  describe("isSubscriptionCurrent", () => {
    it("returns undefined when subscription is not in DB or id is empty", async () => {
      setupMockDbRows([
        { id: "sub-1", business_id: "biz-1", secret_version: 1 },
      ]);
      await expect(isSubscriptionCurrent("missing-sub")).resolves.toBeUndefined();
      await expect(isSubscriptionCurrent("")).resolves.toBeUndefined();
    });

    it("identifies current vs lagging subscriptions from DB secret_version", async () => {
      setupMockDbRows([
        { id: "sub-a", business_id: "biz-1", secret_version: 7 },
        { id: "sub-b", business_id: "biz-2", secret_version: 3 },
      ]);
      await expect(isSubscriptionCurrent("sub-a")).resolves.toBe(true);
      await expect(isSubscriptionCurrent("sub-b")).resolves.toBe(false);
    });
  });

  describe("getAdoptionSnapshot", () => {
    it("returns an empty array when DB has no subscriptions", async () => {
      setupMockDbRows([]);
      await expect(getAdoptionSnapshot()).resolves.toEqual([]);
    });

    it("builds identical snapshots across independent reads of the same DB", async () => {
      setupMockDbRows([
        { id: "sub-1", business_id: "biz-1", secret_version: 5 },
        { id: "sub-2", business_id: "biz-2", secret_version: 2 },
      ]);

      const snapshotProcessA = await getAdoptionSnapshot();
      const snapshotProcessB = await getAdoptionSnapshot();

      expect(snapshotProcessA).toEqual([
        {
          subscriptionId: "sub-1",
          businessId: "biz-1",
          currentVersion: 5,
          isCurrent: true,
        },
        {
          subscriptionId: "sub-2",
          businessId: "biz-2",
          currentVersion: 2,
          isCurrent: false,
        },
      ]);
      expect(snapshotProcessB).toEqual(snapshotProcessA);
    });
  });

  describe("emitRotationStatus", () => {
    it("resets and emits dashboard-compatible gauge labels from DB rows", async () => {
      const setSpy = vi.spyOn(webhookSecretRotationStatus, "set");
      const resetSpy = vi.spyOn(webhookSecretRotationStatus, "reset");

      setupMockDbRows([
        { id: "sub-1", business_id: "biz-1", secret_version: 3 },
        { id: "sub-2", business_id: "biz-2", secret_version: 1 },
      ]);

      await emitRotationStatus();

      expect(resetSpy).toHaveBeenCalledTimes(1);
      expect(setSpy).toHaveBeenCalledTimes(4);
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: "sub-1", business_id: "biz-1", status: "current" },
        1,
      );
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: "sub-1", business_id: "biz-1", status: "lagging" },
        0,
      );
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: "sub-2", business_id: "biz-2", status: "current" },
        0,
      );
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: "sub-2", business_id: "biz-2", status: "lagging" },
        1,
      );
    });

    it("is idempotent across repeated invocations", async () => {
      setupMockDbRows([
        { id: "sub-1", business_id: "biz-1", secret_version: 4 },
      ]);

      await emitRotationStatus();
      await emitRotationStatus();

      const metric = await webhookSecretRotationStatus.get();
      expect(metric.values).toHaveLength(2);
    });
  });
});
