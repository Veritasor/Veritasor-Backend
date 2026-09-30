/**
 * Focused regression suite for the failure / empty-result paths in
 * `src/routes/attestations.ts` (issue #939).
 *
 * Evidence paths covered:
 *  - `src/routes/attestations.ts:203` — `resolveBusinessIdForUser` returns `null`
 *    when the business repository exposes neither lookup, or the lookup misses.
 *  - `src/routes/attestations.ts:227` — `getById` returns `null` when the record
 *    is missing *or* owned by a different business.
 *  - `src/routes/attestations.ts:266` — `revokeAttestation` returns `null` when
 *    the repository update does not produce a row, which the router must surface
 *    as a 500 `REVOKE_FAILED` instead of a silent success.
 *
 * The neighbouring normal paths are asserted too (200 revoke, 404 not-found,
 * 400 already-revoked, cross-business read) so a behaviour change in either
 * direction fails loudly. Repository access is stubbed, so every case is
 * deterministic and no database is required.
 */

import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  businessRepository: {} as Record<string, unknown>,
  attestationRepository: {
    create: vi.fn(),
    getById: vi.fn(),
    list: vi.fn(),
    updateStatus: vi.fn(),
  },
  createAuditLog: vi.fn(),
  broadcasterPublish: vi.fn(),
  observeAttestationSubmitLatency: vi.fn(),
  getPagination: vi.fn(),
  formatPaginatedResponse: vi.fn(),
}));

vi.mock("../../../src/repositories/business.js", () => ({
  businessRepository: mocks.businessRepository,
}));

vi.mock("../../../src/repositories/attestationRepository.js", () => ({
  create: mocks.attestationRepository.create,
  getById: mocks.attestationRepository.getById,
  list: mocks.attestationRepository.list,
  updateStatus: mocks.attestationRepository.updateStatus,
}));

vi.mock("../../../src/repositories/auditLogRepository.js", () => ({
  createAuditLog: mocks.createAuditLog,
}));

vi.mock("../../../src/db/client.js", () => ({
  db: { query: vi.fn() },
}));

vi.mock("../../../src/middleware/idempotency.js", () => ({
  idempotencyMiddleware: () => (_req: unknown, _res: unknown, next: () => void) => next(),
}));

vi.mock("../../../src/middleware/rateLimiter.js", () => ({
  rateLimiter: () => (_req: unknown, _res: unknown, next: () => void) => next(),
}));

vi.mock("../../../src/services/attestation/revoke.js", () => ({
  revokeAttestation: vi.fn(),
}));

vi.mock("../../../src/services/attestation/integrateRevenueChecks.js", () => ({
  integrateRevenueChecks: vi.fn(),
  shouldProceedWithAttestation: () => ({ proceed: true, reason: "" }),
}));

vi.mock("../../../src/services/soroban/submitAttestation.js", () => ({
  submitAttestation: vi.fn(),
  enqueueQueuedAttestation: vi.fn(),
  isSorobanQueueEnabled: () => false,
}));

vi.mock("../../../src/services/merkle/generateProof.js", () => ({
  generateProof: vi.fn(),
  verifyProof: vi.fn(() => true),
}));

vi.mock("../../../src/ws/attestationStream.js", () => ({
  broadcaster: { publish: mocks.broadcasterPublish },
}));

vi.mock("../../../src/metrics.js", () => ({
  observeAttestationSubmitLatency: mocks.observeAttestationSubmitLatency,
}));

vi.mock("../../../src/utils/pagination.js", () => ({
  getPagination: mocks.getPagination,
  formatPaginatedResponse: mocks.formatPaginatedResponse,
}));

const { attestationsRouter } = await import("../../../src/routes/attestations.js");
const { errorHandler } = await import("../../../src/middleware/errorHandler.js");

const app = express();
app.use(express.json());
app.use("/api/attestations", attestationsRouter);
app.use(errorHandler);

const AUTH = { "x-user-id": "user_1" };
const BUSINESS_ID = "biz_1";

/** Replace the whole business-repository surface (methods are absent when not provided). */
function setBusinessRepository(shape: Record<string, unknown>) {
  for (const key of Object.keys(mocks.businessRepository)) {
    delete mocks.businessRepository[key];
  }
  Object.assign(mocks.businessRepository, shape);
}

function row(overrides: Record<string, unknown> = {}) {
  return {
    id: "att_1",
    businessId: BUSINESS_ID,
    period: "2026-01",
    merkleRoot: "root_abc",
    txHash: "tx_abc",
    status: "submitted" as const,
    version: 3,
    createdAt: new Date("2026-01-05T10:00:00.000Z"),
    updatedAt: new Date("2026-01-06T11:00:00.000Z"),
    ...overrides,
  };
}

beforeEach(() => {
  setBusinessRepository({
    getByUserId: vi.fn().mockResolvedValue({ id: BUSINESS_ID }),
  });
  mocks.attestationRepository.create.mockReset();
  mocks.attestationRepository.getById.mockReset();
  mocks.attestationRepository.list.mockReset();
  mocks.attestationRepository.updateStatus.mockReset();
  mocks.createAuditLog.mockReset();
  mocks.broadcasterPublish.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DELETE/POST /:id/revoke — repository returns no row (evidence line 266)", () => {
  it("POST returns 500 REVOKE_FAILED instead of a silent success", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(row());
    mocks.attestationRepository.updateStatus.mockResolvedValue(null);

    const res = await request(app)
      .post("/api/attestations/att_1/revoke")
      .set(AUTH)
      .send({ reason: "confirmed fraud" });

    expect(res.status).toBe(500);
    expect(res.body.status).toBe("error");
    expect(res.body.vrtCode).toBe("REVOKE_FAILED");
    expect(res.body).not.toHaveProperty("data");
  });

  it("POST masks the internal failure detail (5xx envelope contract)", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(row());
    mocks.attestationRepository.updateStatus.mockResolvedValue(undefined);

    const res = await request(app).post("/api/attestations/att_1/revoke").set(AUTH).send({});

    expect(res.status).toBe(500);
    expect(res.body.message).toBe("An unexpected error occurred");
    expect(JSON.stringify(res.body)).not.toMatch(/Failed to revoke|Internal server error/);
  });

  it("DELETE returns 500 REVOKE_FAILED and leaves state untouched", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(row());
    mocks.attestationRepository.updateStatus.mockResolvedValue(null);

    const res = await request(app).delete("/api/attestations/att_1/revoke").set(AUTH);

    expect(res.status).toBe(500);
    expect(res.body.vrtCode).toBe("REVOKE_FAILED");
    // The transition was attempted exactly once and nothing else was mutated.
    expect(mocks.attestationRepository.updateStatus).toHaveBeenCalledTimes(1);
    expect(mocks.attestationRepository.updateStatus).toHaveBeenCalledWith(
      expect.anything(),
      "att_1",
      "revoked",
    );
    expect(mocks.broadcasterPublish).not.toHaveBeenCalled();
  });

  it("does not report success just because the read-back looked revocable", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(row());
    mocks.attestationRepository.updateStatus.mockResolvedValue(null);

    const res = await request(app).post("/api/attestations/att_1/revoke").set(AUTH).send({});

    expect(res.body.data).toBeUndefined();
    expect(res.body).not.toMatchObject({ status: "success" });
    expect(JSON.stringify(res.body)).not.toContain("revoked");
  });
});

describe("DELETE/POST /:id/revoke — neighbouring normal and boundary paths", () => {
  it("POST returns 200 with the revoked record on the happy path", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(row());
    mocks.attestationRepository.updateStatus.mockResolvedValue(
      row({
        status: "revoked",
        version: 4,
        updatedAt: new Date("2026-01-07T09:30:00.000Z"),
      }),
    );

    const res = await request(app)
      .post("/api/attestations/att_1/revoke")
      .set(AUTH)
      .send({ reason: "confirmed fraud" });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("success");
    expect(res.body.data).toMatchObject({
      id: "att_1",
      businessId: BUSINESS_ID,
      status: "revoked",
      revokedAt: "2026-01-07T09:30:00.000Z",
      version: "4",
    });
    expect(mocks.attestationRepository.updateStatus).toHaveBeenCalledWith(
      expect.anything(),
      "att_1",
      "revoked",
    );
  });

  it("returns 400 ALREADY_REVOKED without performing a second transition", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(row({ status: "revoked" }));

    const res = await request(app).post("/api/attestations/att_1/revoke").set(AUTH).send({});

    expect(res.status).toBe(400);
    expect(res.body.vrtCode).toBe("ALREADY_REVOKED");
    expect(mocks.attestationRepository.updateStatus).not.toHaveBeenCalled();
  });

  it("returns 404 ATTESTATION_NOT_FOUND when the record is missing", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(null);

    const res = await request(app).delete("/api/attestations/missing/revoke").set(AUTH);

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe("ATTESTATION_NOT_FOUND");
    expect(mocks.attestationRepository.updateStatus).not.toHaveBeenCalled();
  });

  it("maps a repository throw during revoke onto the REVOKE_FAILED contract without leaking", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.attestationRepository.getById.mockRejectedValue(new Error("DB connection lost"));

    const res = await request(app).post("/api/attestations/att_1/revoke").set(AUTH).send({});

    expect(res.status).toBe(500);
    expect(res.body.vrtCode).toBe("REVOKE_FAILED");
    expect(JSON.stringify(res.body)).not.toContain("DB connection lost");
    expect(mocks.attestationRepository.updateStatus).not.toHaveBeenCalled();
    consoleError.mockRestore();
  });
});

describe("GET /:id — getById returns null (evidence line 227)", () => {
  it("returns 404 ATTESTATION_NOT_FOUND for an unknown id", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(null);

    const res = await request(app).get("/api/attestations/att_unknown").set(AUTH);

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe("ATTESTATION_NOT_FOUND");
    expect(res.body).not.toHaveProperty("data");
  });

  it("returns 404 (not the record) when the attestation belongs to another business", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(
      row({ businessId: "biz_other", merkleRoot: "other-root", txHash: "other-tx" }),
    );

    const res = await request(app).get("/api/attestations/att_1").set(AUTH);

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe("ATTESTATION_NOT_FOUND");
    // The foreign record must not leak through the error payload or a partial body.
    expect(JSON.stringify(res.body)).not.toContain("biz_other");
    expect(JSON.stringify(res.body)).not.toContain("other-root");
    expect(JSON.stringify(res.body)).not.toContain("other-tx");
    expect(mocks.attestationRepository.getById).toHaveBeenCalledTimes(1);
  });

  it("returns the record for the owning business (neighbouring normal path)", async () => {
    mocks.attestationRepository.getById.mockResolvedValue(row());

    const res = await request(app).get("/api/attestations/att_1").set(AUTH);

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      id: "att_1",
      businessId: BUSINESS_ID,
      period: "2026-01",
      merkleRoot: "root_abc",
      txHash: "tx_abc",
      status: "submitted",
      revokedAt: null,
      version: "3",
      attestedAt: "2026-01-05T10:00:00.000Z",
    });
  });

  it("surfaces an unexpected repository error as a masked 500", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.attestationRepository.getById.mockRejectedValue(new Error("relation does not exist"));

    const res = await request(app).get("/api/attestations/att_1").set(AUTH);

    expect(res.status).toBe(500);
    expect(res.body.vrtCode).toBe("VRT-9999");
    expect(JSON.stringify(res.body)).not.toContain("relation does not exist");
  });
});

describe("resolveBusinessIdForUser returns null (evidence line 203)", () => {
  it("returns 404 BUSINESS_NOT_FOUND when the repository exposes no lookup at all", async () => {
    setBusinessRepository({});

    const res = await request(app).get("/api/attestations/att_1").set(AUTH);

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe("BUSINESS_NOT_FOUND");
    // No business context means no attestation read is attempted.
    expect(mocks.attestationRepository.getById).not.toHaveBeenCalled();
  });

  it("returns 404 BUSINESS_NOT_FOUND when the primary lookup misses", async () => {
    setBusinessRepository({ getByUserId: vi.fn().mockResolvedValue(null) });

    const res = await request(app).get("/api/attestations/att_1").set(AUTH);

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe("BUSINESS_NOT_FOUND");
    expect(mocks.attestationRepository.getById).not.toHaveBeenCalled();
  });

  it("uses the synchronous findByUserId fallback when getByUserId is absent", async () => {
    setBusinessRepository({ findByUserId: vi.fn().mockReturnValue({ id: BUSINESS_ID }) });
    mocks.attestationRepository.getById.mockResolvedValue(row());

    const res = await request(app).get("/api/attestations/att_1").set(AUTH);

    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe("att_1");
    expect(mocks.attestationRepository.getById).toHaveBeenCalledTimes(1);
  });

  it("returns 404 BUSINESS_NOT_FOUND when the fallback lookup misses", async () => {
    setBusinessRepository({ findByUserId: vi.fn().mockReturnValue(null) });

    const res = await request(app).delete("/api/attestations/att_1/revoke").set(AUTH);

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe("BUSINESS_NOT_FOUND");
    expect(mocks.attestationRepository.updateStatus).not.toHaveBeenCalled();
  });

  it("blocks revocation before any write when there is no business context", async () => {
    setBusinessRepository({});

    const res = await request(app).post("/api/attestations/att_1/revoke").set(AUTH).send({});

    expect(res.status).toBe(404);
    expect(res.body.vrtCode).toBe("BUSINESS_NOT_FOUND");
    expect(mocks.attestationRepository.getById).not.toHaveBeenCalled();
    expect(mocks.attestationRepository.updateStatus).not.toHaveBeenCalled();
  });
});
