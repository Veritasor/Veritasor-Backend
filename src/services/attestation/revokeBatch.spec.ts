import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Attestation } from "../../types/attestation.js";

const mocks = vi.hoisted(() => ({
  connect: vi.fn(),
  query: vi.fn(),
  release: vi.fn(),
  getById: vi.fn(),
  updateStatus: vi.fn(),
  createAuditLog: vi.fn(),
  getSorobanConfig: vi.fn(),
  createSorobanRpcServer: vi.fn(),
}));

vi.mock("../../db/client.js", () => ({
  db: { connect: mocks.connect },
}));

vi.mock("../../repositories/attestationRepository.js", () => ({
  getById: mocks.getById,
  updateStatus: mocks.updateStatus,
}));

vi.mock("../../repositories/auditLogRepository.js", () => ({
  createAuditLog: mocks.createAuditLog,
}));

vi.mock("../soroban/client.js", () => ({
  getSorobanConfig: mocks.getSorobanConfig,
  createSorobanRpcServer: mocks.createSorobanRpcServer,
}));

import { revokeBatchAttestations } from "./revokeBatch.js";

const client = {
  query: mocks.query,
  release: mocks.release,
};

const attestation: Attestation = {
  id: "attestation-1",
  businessId: "business-1",
  period: "2026-09",
  merkleRoot: "merkle-root",
  txHash: "transaction-hash",
  status: "confirmed",
  version: 1,
  createdAt: new Date("2026-09-01T00:00:00.000Z"),
  updatedAt: new Date("2026-09-01T00:00:00.000Z"),
};

describe("revokeBatchAttestations", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("SOROBAN_SOURCE_SECRET", "");
    mocks.connect.mockResolvedValue(client);
    mocks.query.mockResolvedValue(undefined);
    mocks.getById.mockImplementation(async (_client, id: string) => ({
      ...attestation,
      id,
    }));
    mocks.updateStatus.mockResolvedValue(undefined);
    mocks.createAuditLog.mockResolvedValue(undefined);
    mocks.getSorobanConfig.mockReturnValue({
      contractId: "contract-id",
      networkPassphrase: "network-passphrase",
      rpcUrl: "http://localhost",
    });
    mocks.createSorobanRpcServer.mockReturnValue({});
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("rejects an empty batch before opening a database connection", async () => {
    await expect(revokeBatchAttestations([], "admin-1")).rejects.toThrow(
      "No attestations provided for revocation.",
    );
    expect(mocks.connect).not.toHaveBeenCalled();
  });

  it("rejects batches larger than 500 before opening a database connection", async () => {
    const ids = Array.from({ length: 501 }, (_, index) => `attestation-${index}`);

    await expect(revokeBatchAttestations(ids, "admin-1")).rejects.toThrow(
      "Batch size capped at 500",
    );
    expect(mocks.connect).not.toHaveBeenCalled();
  });

  it("rolls back and releases the connection when an attestation is missing", async () => {
    mocks.getById.mockResolvedValueOnce(null);

    await expect(
      revokeBatchAttestations(["missing-id"], "admin-1"),
    ).rejects.toThrow("Attestation not found: missing-id");

    expect(mocks.query).toHaveBeenNthCalledWith(1, "BEGIN");
    expect(mocks.query).toHaveBeenNthCalledWith(2, "ROLLBACK");
    expect(mocks.updateStatus).not.toHaveBeenCalled();
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it("rolls back when an attestation is already revoked", async () => {
    mocks.getById.mockResolvedValueOnce({ ...attestation, status: "revoked" });

    await expect(
      revokeBatchAttestations([attestation.id], "admin-1"),
    ).rejects.toThrow(`Attestation ${attestation.id} is already revoked`);

    expect(mocks.query).toHaveBeenNthCalledWith(2, "ROLLBACK");
    expect(mocks.updateStatus).not.toHaveBeenCalled();
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it("returns the attestations and commits a successful batch", async () => {
    const ids = ["attestation-1", "attestation-2"];

    await expect(revokeBatchAttestations(ids, "admin-1")).resolves.toEqual(
      ids.map((id) => ({ ...attestation, id })),
    );

    expect(mocks.updateStatus).toHaveBeenCalledTimes(2);
    expect(mocks.createAuditLog).toHaveBeenCalledTimes(2);
    expect(mocks.query).toHaveBeenNthCalledWith(1, "BEGIN");
    expect(mocks.query).toHaveBeenNthCalledWith(2, "COMMIT");
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it("accepts the maximum batch size of 500", async () => {
    const ids = Array.from({ length: 500 }, (_, index) => `attestation-${index}`);

    await expect(revokeBatchAttestations(ids, "admin-1")).resolves.toHaveLength(
      500,
    );
    expect(mocks.getById).toHaveBeenCalledTimes(500);
    expect(mocks.query).toHaveBeenLastCalledWith("COMMIT");
  });
});
