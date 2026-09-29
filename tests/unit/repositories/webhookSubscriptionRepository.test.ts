import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  getById,
  update,
  type WebhookMTLSConfig,
  type WebhookSubscription,
} from "../../../src/repositories/webhookSubscriptionRepository.js";
import type { UpdateWebhookSubscriptionInput } from "../../../src/schemas/webhookSubscription.js";

const dbQuery = vi.hoisted(() => vi.fn());

vi.mock("../../../src/db/client.js", () => ({
  db: { query: dbQuery },
}));

const mtlsConfig: WebhookMTLSConfig = {
  clientCertSecretId: "secret/client-cert",
  clientKeySecretId: "secret/client-key",
  caPinSecretId: "secret/ca-pin",
};

function rowFixture(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: "wh-1",
    business_id: "biz-1",
    url: "https://hooks.example.com/events",
    secret: "webhook-secret",
    event_filters: { "invoice.paid": true },
    enabled: true,
    max_payload_size: 4096,
    secret_version: 2,
    mtls_config: mtlsConfig,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-02T00:00:00.000Z",
    ...overrides,
  };
}

function updateWithMtlsConfig(
  value: WebhookMTLSConfig | null,
): UpdateWebhookSubscriptionInput & { mtlsConfig: WebhookMTLSConfig | null } {
  return { mtlsConfig: value } as UpdateWebhookSubscriptionInput & {
    mtlsConfig: WebhookMTLSConfig | null;
  };
}

describe("webhookSubscriptionRepository", () => {
  beforeEach(() => {
    dbQuery.mockReset();
  });

  describe("getById", () => {
    it("returns null when the scoped subscription does not exist", async () => {
      dbQuery.mockResolvedValueOnce({ rows: [] });

      await expect(getById("missing", "biz-1")).resolves.toBeNull();
      expect(dbQuery).toHaveBeenCalledWith(
        "SELECT * FROM webhook_subscriptions WHERE id = $1 AND business_id = $2",
        ["missing", "biz-1"],
      );
    });

    it("maps a found subscription including its mTLS config", async () => {
      dbQuery.mockResolvedValueOnce({ rows: [rowFixture()] });

      const result = await getById("wh-1", "biz-1");

      expect(result).toEqual<WebhookSubscription>({
        id: "wh-1",
        businessId: "biz-1",
        url: "https://hooks.example.com/events",
        secret: "webhook-secret",
        eventFilters: { "invoice.paid": true },
        enabled: true,
        maxPayloadSize: 4096,
        secretVersion: 2,
        mtlsConfig,
        createdAt: new Date("2026-01-01T00:00:00.000Z"),
        updatedAt: new Date("2026-01-02T00:00:00.000Z"),
      });
    });

    it("propagates database failures unchanged", async () => {
      const failure = new Error("database unavailable");
      dbQuery.mockRejectedValueOnce(failure);

      await expect(getById("wh-1", "biz-1")).rejects.toBe(failure);
    });
  });

  describe("update", () => {
    it("returns null when no row matches the update", async () => {
      dbQuery.mockResolvedValueOnce({ rows: [] });

      await expect(
        update("missing", "biz-1", updateWithMtlsConfig(mtlsConfig)),
      ).resolves.toBeNull();
      expect(dbQuery).toHaveBeenCalledWith(
        expect.stringContaining("UPDATE webhook_subscriptions"),
        [JSON.stringify(mtlsConfig), "missing", "biz-1"],
      );
    });

    it("returns the updated subscription when setting its mTLS config", async () => {
      dbQuery.mockResolvedValueOnce({ rows: [rowFixture()] });

      const result = await update("wh-1", "biz-1", updateWithMtlsConfig(mtlsConfig));

      expect(result?.mtlsConfig).toEqual(mtlsConfig);
      expect(dbQuery).toHaveBeenCalledWith(
        expect.stringContaining("mtls_config = $1"),
        [JSON.stringify(mtlsConfig), "wh-1", "biz-1"],
      );
    });

    it("stores null when clearing the mTLS config", async () => {
      dbQuery.mockResolvedValueOnce({ rows: [rowFixture({ mtls_config: null })] });

      const result = await update("wh-1", "biz-1", updateWithMtlsConfig(null));

      expect(result?.mtlsConfig).toBeNull();
      expect(dbQuery).toHaveBeenCalledWith(
        expect.stringContaining("mtls_config = $1"),
        [null, "wh-1", "biz-1"],
      );
    });

    it("looks up the existing row for an empty update and preserves the not-found contract", async () => {
      dbQuery.mockResolvedValueOnce({ rows: [] });

      await expect(update("missing", "biz-1", {})).resolves.toBeNull();
      expect(dbQuery).toHaveBeenCalledTimes(1);
      expect(dbQuery).toHaveBeenCalledWith(
        "SELECT * FROM webhook_subscriptions WHERE id = $1 AND business_id = $2",
        ["missing", "biz-1"],
      );
    });

    it("propagates database failures unchanged", async () => {
      const failure = new Error("database unavailable");
      dbQuery.mockRejectedValueOnce(failure);

      await expect(
        update("wh-1", "biz-1", updateWithMtlsConfig(mtlsConfig)),
      ).rejects.toBe(failure);
    });
  });
});
