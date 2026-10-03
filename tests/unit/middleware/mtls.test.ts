import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { mtlsMiddleware } from "../../../src/middleware/mtls.js";

vi.mock("../../../src/config/index.js", () => ({
  config: {
    mtls: {
      enabled: true,
      cnAllowlist: [],
      revocation: {
        enabled: true,
      },
    },
  },
}));

const { verifyClientCertificate } = vi.hoisted(() => ({
  verifyClientCertificate: vi.fn(),
}));

vi.mock("../../../src/middleware/mtlsRevocation.js", () => ({
  mtlsRevocationChecker: {
    verifyClientCertificate,
  },
}));

vi.mock("../../../src/utils/logger.js", () => ({
  logger: {
    warn: vi.fn(),
    info: vi.fn(),
    error: vi.fn(),
  },
}));

function createMockRequest(options: {
  authorized?: boolean;
  authorizationError?: string;
  cert?: Record<string, unknown> | null;
}): Request {
  return {
    socket: {
      authorized: options.authorized ?? true,
      authorizationError: options.authorizationError,
      getPeerCertificate: () => options.cert,
    },
  } as unknown as Request;
}

function createMockResponse() {
  const response = {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return response as Response & { statusCode: number; body: unknown };
}

async function flushMiddleware(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("mtlsMiddleware", () => {
  const next = vi.fn() as NextFunction;

  beforeEach(() => {
    next.mockReset();
    verifyClientCertificate.mockReset();
    verifyClientCertificate.mockResolvedValue({
      ok: true,
      status: "good",
      source: "ocsp",
    });
  });

  it("passes through when mTLS is disabled", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { enabled: boolean } }).mtls.enabled = false;

    const req = createMockRequest({ cert: null, authorized: false });
    const res = createMockResponse();
    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(200);
    expect(verifyClientCertificate).not.toHaveBeenCalled();

    (config as { mtls: { enabled: boolean } }).mtls.enabled = true;
  });

  it("rejects requests without an authorized client certificate", async () => {
    const req = createMockRequest({ authorized: false, cert: null });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(495);
    expect(res.body).toMatchObject({ code: "MTLS_UNAUTHORIZED" });
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects revoked client certificates", async () => {
    verifyClientCertificate.mockResolvedValueOnce({
      ok: false,
      status: "revoked",
      source: "ocsp",
      detail: "revoked by responder",
    });

    const req = createMockRequest({
      cert: {
        subject: { CN: "trusted-client" },
        raw: Buffer.from("cert"),
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_CERT_REVOKED" });
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects when revocation status cannot be validated", async () => {
    verifyClientCertificate.mockResolvedValueOnce({
      ok: false,
      status: "stale_ocsp",
      source: "ocsp",
      detail: "stale",
    });

    const req = createMockRequest({
      cert: {
        subject: { CN: "trusted-client" },
        raw: Buffer.from("cert"),
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_REVOCATION_CHECK_FAILED" });
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 503 when revocation verification throws unexpectedly", async () => {
    verifyClientCertificate.mockRejectedValueOnce(new Error("openssl crashed"));

    const req = createMockRequest({
      cert: {
        subject: { CN: "trusted-client" },
        raw: Buffer.from("cert"),
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(503);
    expect(res.body).toMatchObject({ code: "MTLS_INTERNAL_ERROR" });
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects legacy CN values that are not on the allowlist", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = ["trusted-client"];

    const req = createMockRequest({
      cert: {
        subject: { CN: "untrusted-client" },
        raw: Buffer.from("cert"),
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_CN_NOT_ALLOWED" });

    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = [];
  });

  it("accepts legacy CN allowlist matches when revocation is good", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = ["trusted-client"];

    const req = createMockRequest({
      cert: {
        subject: { CN: "trusted-client" },
        raw: Buffer.from("cert"),
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(next).toHaveBeenCalledOnce();
    expect((req as { clientCN?: string }).clientCN).toBe("trusted-client");

    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = [];
  });
});
