import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
    metricsRegistry: registry,
    webhookSecretRotationStatus: new Gauge({
      name: "webhook_secret_rotation_status",
      help: "Rollout status of webhook secret rotation per subscription (1 = current / 0 = lagging)",
      labelNames: ["subscription_id", "business_id", "status"] as const,
      registers: [registry],
    }),
  };
});

import {
  setLatestSecretVersion,
  getLatestSecretVersion,
  reportSubscriptionVersion,
  removeSubscription,
  isSubscriptionCurrent,
  getAdoptionSnapshot,
  emitRotationStatus,
  reset,
} from "../../../../src/services/webhooks/secretRotation.js";
import { metricsRegistry, webhookSecretRotationStatus } from "../../../../src/metrics.js";

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

describe("secretRotation", () => {
  beforeEach(() => {
    reset();
    mockQuery.mockReset();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    reset();
  });

  describe("setLatestSecretVersion / getLatestSecretVersion", () => {
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

    it("starts at 0 and only increases monotonically", async () => {
      setupMockDbRows([]);
      expect(await getLatestSecretVersion()).toBe(0);

      setLatestSecretVersion(3);
      expect(await getLatestSecretVersion()).toBe(3);

      // Lower versions are ignored
      setLatestSecretVersion(1);
      expect(await getLatestSecretVersion()).toBe(3);

      // Equal version is a no-op
      setLatestSecretVersion(3);
      expect(await getLatestSecretVersion()).toBe(3);

      // Higher version updates latestSecretVersion
      setLatestSecretVersion(6);
      expect(await getLatestSecretVersion()).toBe(6);
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

    it("treats all subscriptions as current when latestSecretVersion === 0", async () => {
      setupMockDbRows([]);
      expect(await getLatestSecretVersion()).toBe(0);

      reportSubscriptionVersion("sub-1", "biz-1", 1);
      reportSubscriptionVersion("sub-2", "biz-2", 4);

      expect(await isSubscriptionCurrent("sub-1")).toBe(true);
      expect(await isSubscriptionCurrent("sub-2")).toBe(true);

      const snapshot = await getAdoptionSnapshot();
      expect(snapshot).toHaveLength(2);
      expect(snapshot.every((entry) => entry.isCurrent)).toBe(true);
    });

    it("reports a lagging subscription as isCurrent: false and flips after reportSubscriptionVersion with a newer version", async () => {
      setupMockDbRows([]);
      setLatestSecretVersion(5);

      // Initially lagging (version 2 < 5)
      reportSubscriptionVersion("sub-1", "biz-1", 2);
      expect(await isSubscriptionCurrent("sub-1")).toBe(false);

      let snapshot = await getAdoptionSnapshot();
      let entry = snapshot.find((s) => s.subscriptionId === "sub-1");
      expect(entry?.isCurrent).toBe(false);
      expect(entry?.currentVersion).toBe(2);

      // Flips to current after reporting version 5 (equal to latest)
      reportSubscriptionVersion("sub-1", "biz-1", 5);
      expect(await isSubscriptionCurrent("sub-1")).toBe(true);

      snapshot = await getAdoptionSnapshot();
      entry = snapshot.find((s) => s.subscriptionId === "sub-1");
      expect(entry?.isCurrent).toBe(true);
      expect(entry?.currentVersion).toBe(5);

      // Remains current when exceeding latest version
      reportSubscriptionVersion("sub-1", "biz-1", 8);
      expect(await isSubscriptionCurrent("sub-1")).toBe(true);
    });
  });

  describe("removeSubscription", () => {
    it("removes a subscription from tracking", async () => {
      setupMockDbRows([]);
      reportSubscriptionVersion("sub-1", "biz-1", 5);
      expect(await isSubscriptionCurrent("sub-1")).toBe(true);

      removeSubscription("sub-1");
      expect(await isSubscriptionCurrent("sub-1")).toBeUndefined();
    });

    it("no-ops when removing a non-existent subscription", () => {
      expect(() => removeSubscription("ghost")).not.toThrow();
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

    it("makes all subscriptions current when latestSecretVersion is 0 even with different row versions", async () => {
      mockQuery.mockImplementation(async (sql: string) => {
        if (sql.includes("MAX(secret_version)")) {
          return { rows: [{ latest_version: 0 }] };
        }
        if (sql.includes("FROM webhook_subscriptions")) {
          return {
            rows: [
              { id: "sub-1", business_id: "biz-1", secret_version: 2 },
              { id: "sub-2", business_id: "biz-2", secret_version: 5 },
            ],
          };
        }
        return { rows: [] };
      });

      const snapshot = await getAdoptionSnapshot();
      expect(snapshot).toEqual([
        {
          subscriptionId: "sub-1",
          businessId: "biz-1",
          currentVersion: 2,
          isCurrent: true,
        },
        {
          subscriptionId: "sub-2",
          businessId: "biz-2",
          currentVersion: 5,
          isCurrent: true,
        },
      ]);
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

    it("sets current/lagging gauge pairs (read from the registry) and resets stale labels", async () => {
      setupMockDbRows([]);
      setLatestSecretVersion(5);
      reportSubscriptionVersion("sub-1", "biz-1", 5); // current
      reportSubscriptionVersion("sub-2", "biz-2", 2); // lagging

      await emitRotationStatus();

      // Read gauge values via the metrics registry
      const metric = await metricsRegistry.getSingleMetric("webhook_secret_rotation_status")?.get();
      expect(metric).toBeDefined();

      const sub1Current = metric?.values.find(
        (v) => v.labels.subscription_id === "sub-1" && v.labels.status === "current",
      );
      const sub1Lagging = metric?.values.find(
        (v) => v.labels.subscription_id === "sub-1" && v.labels.status === "lagging",
      );
      expect(sub1Current?.value).toBe(1);
      expect(sub1Lagging?.value).toBe(0);

      const sub2Current = metric?.values.find(
        (v) => v.labels.subscription_id === "sub-2" && v.labels.status === "current",
      );
      const sub2Lagging = metric?.values.find(
        (v) => v.labels.subscription_id === "sub-2" && v.labels.status === "lagging",
      );
      expect(sub2Current?.value).toBe(0);
      expect(sub2Lagging?.value).toBe(1);

      // Verify JSON metrics from the registry
      const metricsJson = await metricsRegistry.getMetricsAsJSON();
      const rotationMetric = metricsJson.find(
        (m) => m.name === "webhook_secret_rotation_status",
      );
      expect(rotationMetric).toBeDefined();
      expect(rotationMetric?.values).toHaveLength(4);

      // Remove sub-2 to test stale label reset
      removeSubscription("sub-2");

      await emitRotationStatus();

      const updatedMetric = await metricsRegistry.getSingleMetric("webhook_secret_rotation_status")?.get();
      expect(updatedMetric?.values).toHaveLength(2);

      const staleSub2Values = updatedMetric?.values.filter(
        (v) => v.labels.subscription_id === "sub-2",
      );
      expect(staleSub2Values).toHaveLength(0);

      const sub1CurrentAfter = updatedMetric?.values.find(
        (v) => v.labels.subscription_id === "sub-1" && v.labels.status === "current",
      );
      expect(sub1CurrentAfter?.value).toBe(1);
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

  describe("reset", () => {
    it("clears all state and resets the gauge", async () => {
      setupMockDbRows([]);
      setLatestSecretVersion(10);
      reportSubscriptionVersion("sub-1", "biz-1", 10);
      await emitRotationStatus();

      expect(await getLatestSecretVersion()).toBe(10);
      expect(await isSubscriptionCurrent("sub-1")).toBe(true);

      reset();

      expect(await getLatestSecretVersion()).toBe(0);
      expect(await isSubscriptionCurrent("sub-1")).toBeUndefined();

      const metric = await metricsRegistry.getSingleMetric("webhook_secret_rotation_status")?.get();
      expect(metric?.values).toHaveLength(0);
    });
  });
});
