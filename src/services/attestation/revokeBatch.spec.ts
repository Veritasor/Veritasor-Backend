import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Attestation } from "../../types/attestation.js";

const mocks = vi.hoisted(() => ({
  getClient: vi.fn(),
  query: vi.fn(),
  release: vi.fn(),
  getById: vi.fn(),
  updateStatus: vi.fn(),
  createAuditLog: vi.fn(),
  getSorobanConfig: vi.fn(),
  createSorobanRpcServer: vi.fn(),
  getAccount: vi.fn(),
  prepareTransaction: vi.fn(),
  sendTransaction: vi.fn(),
  Contract: vi.fn(function () {
    return {
      call: vi.fn(() => ({})),
    };
  }),
  TransactionBuilder: vi.fn(function () {
    const builder = {
      addOperation: vi.fn(() => builder),
      setTimeout: vi.fn(() => builder),
      build: vi.fn(() => ({})),
    };
    return builder;
  }),
  Keypair: {
    fromSecret: vi.fn(() => ({ publicKey: () => "GTESTPUBLICKEY" })),
  },
  validateSendTransactionResponse: vi.fn(),
  waitForConfirmation: vi.fn(),
  SorobanSubmissionError: class SorobanSubmissionError extends Error {
    code: string;
    response: unknown;
    constructor(message: string, code: string, response: unknown) {
      super(message);
      this.code = code;
      this.response = response;
    }
  },
}));

vi.mock("../../db/client.js", () => ({
  getPgClient: () => ({ getClient: mocks.getClient }),
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

vi.mock("../soroban/submitAttestation.js", () => ({
  validateSendTransactionResponse: mocks.validateSendTransactionResponse,
  waitForConfirmation: mocks.waitForConfirmation,
  SorobanSubmissionError: mocks.SorobanSubmissionError,
}));

vi.mock("@stellar/stellar-sdk", () => ({
  Contract: mocks.Contract,
  TransactionBuilder: mocks.TransactionBuilder,
  BASE_FEE: "100",
  Keypair: mocks.Keypair,
  nativeToScVal: (value: unknown) => value,
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
    vi.stubEnv("SOROBAN_SOURCE_SECRET", "test-source-secret");
    mocks.getClient.mockResolvedValue(client);
    mocks.query.mockResolvedValue(undefined);
    mocks.release.mockReturnValue(undefined);
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
    mocks.getAccount.mockResolvedValue({ accountId: () => "GTESTPUBLICKEY" });
    mocks.prepareTransaction.mockImplementation((tx: unknown) => ({
      ...(tx as object),
      sign: vi.fn(),
    }));
    mocks.sendTransaction.mockResolvedValue({
      status: "PENDING",
      hash: "transaction-hash",
    });
    mocks.validateSendTransactionResponse.mockReturnValue(undefined);
    mocks.waitForConfirmation.mockResolvedValue(undefined);
    mocks.createSorobanRpcServer.mockReturnValue({
      getAccount: mocks.getAccount,
      prepareTransaction: mocks.prepareTransaction,
      sendTransaction: mocks.sendTransaction,
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("rejects an empty batch before opening a database connection", async () => {
    await expect(revokeBatchAttestations([], "admin-1")).rejects.toThrow(
      "No attestations provided for revocation.",
    );
    expect(mocks.getClient).not.toHaveBeenCalled();
  });

  it("rejects batches larger than 500 before opening a database connection", async () => {
    const ids = Array.from({ length: 501 }, (_, index) => `attestation-${index}`);

    await expect(revokeBatchAttestations(ids, "admin-1")).rejects.toThrow(
      "Batch size capped at 500",
    );
    expect(mocks.getClient).not.toHaveBeenCalled();
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

  it("persists revoked status for every successful on-chain revocation before committing", async () => {
    const ids = ["attestation-1", "attestation-2"];

    await expect(revokeBatchAttestations(ids, "admin-1")).resolves.toEqual({
      revoked: ids,
      failed: [],
    });

    expect(mocks.updateStatus).toHaveBeenCalledTimes(2);
    for (const id of ids) {
      expect(mocks.updateStatus).toHaveBeenCalledWith(client, id, "revoked");
    }
    expect(mocks.createAuditLog).toHaveBeenCalledTimes(2);
    expect(mocks.query).toHaveBeenNthCalledWith(1, "BEGIN");
    expect(mocks.query).toHaveBeenNthCalledWith(2, "COMMIT");
    expect(mocks.updateStatus.mock.invocationCallOrder[1]).toBeLessThan(
      mocks.query.mock.invocationCallOrder[1],
    );
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it("accepts the maximum batch size of 500", async () => {
    const ids = Array.from({ length: 500 }, (_, index) => `attestation-${index}`);

    const result = await revokeBatchAttestations(ids, "admin-1");

    expect(result.revoked).toHaveLength(500);
    expect(result.failed).toEqual([]);
    expect(mocks.getById).toHaveBeenCalledTimes(500);
    expect(mocks.query).toHaveBeenLastCalledWith("COMMIT");
  });
});
