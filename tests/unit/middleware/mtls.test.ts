import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { mtlsMiddleware } from "../../../src/middleware/mtls.js";

vi.mock("../../../src/config/index.js", () => ({
  config: {
    mtls: {
      enabled: true,
      cnAllowlist: [],
      spiffeIdAllowlist: [],
      spiffe: {
        enabled: false,
        trustDomain: "example.org",
      },
    },
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

describe("mtlsMiddleware", () => {
  const next = vi.fn() as NextFunction;

  beforeEach(() => {
    next.mockReset();
  });

  it("passes through when mTLS is disabled", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { enabled: boolean } }).mtls.enabled = false;

    const req = createMockRequest({ cert: null, authorized: false });
    const res = createMockResponse();
    mtlsMiddleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(200);

    (config as { mtls: { enabled: boolean } }).mtls.enabled = true;
  });

  it("rejects requests without an authorized client certificate", () => {
    const req = createMockRequest({ authorized: false, cert: null });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);

    expect(res.statusCode).toBe(495);
    expect(res.body).toMatchObject({ code: "MTLS_UNAUTHORIZED" });
    expect(next).not.toHaveBeenCalled();
  });

  it("validates SPIFFE IDs when SPIFFE mode is enabled", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as {
      mtls: {
        spiffe: { enabled: boolean };
        spiffeIdAllowlist: string[];
      };
    }).mtls.spiffe.enabled = true;
    (config as { mtls: { spiffeIdAllowlist: string[] } }).mtls.spiffeIdAllowlist = [
      "spiffe://example.org/api",
    ];

    const req = createMockRequest({
      cert: {
        subjectaltname: "URI:spiffe://example.org/api",
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((req as { clientSpiffeId?: string }).clientSpiffeId).toBe(
      "spiffe://example.org/api",
    );

    (config as { mtls: { spiffe: { enabled: boolean } } }).mtls.spiffe.enabled = false;
    (config as { mtls: { spiffeIdAllowlist: string[] } }).mtls.spiffeIdAllowlist = [];
  });

  it("rejects SPIFFE IDs that are not on the allowlist", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as {
      mtls: {
        spiffe: { enabled: boolean };
        spiffeIdAllowlist: string[];
      };
    }).mtls.spiffe.enabled = true;
    (config as { mtls: { spiffeIdAllowlist: string[] } }).mtls.spiffeIdAllowlist = [
      "spiffe://example.org/allowed",
    ];

    const req = createMockRequest({
      cert: {
        subjectaltname: "URI:spiffe://example.org/other",
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_SPIFFE_ID_NOT_ALLOWED" });

    (config as { mtls: { spiffe: { enabled: boolean } } }).mtls.spiffe.enabled = false;
    (config as { mtls: { spiffeIdAllowlist: string[] } }).mtls.spiffeIdAllowlist = [];
  });

  it("rejects client certificates without a SPIFFE ID in the trust domain", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { spiffe: { enabled: boolean } } }).mtls.spiffe.enabled = true;

    const req = createMockRequest({
      cert: {
        subjectaltname: "DNS:legacy-client",
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_SPIFFE_ID_INVALID" });

    (config as { mtls: { spiffe: { enabled: boolean } } }).mtls.spiffe.enabled = false;
  });

  it("rejects legacy CN values that are not on the allowlist", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = ["trusted-client"];

    const req = createMockRequest({
      cert: {
        subject: { CN: "untrusted-client" },
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_CN_NOT_ALLOWED" });

    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = [];
  });

  it("accepts legacy CN allowlist matches when SPIFFE mode is disabled", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = ["trusted-client"];

    const req = createMockRequest({
      cert: {
        subject: { CN: "trusted-client" },
      },
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((req as { clientCN?: string }).clientCN).toBe("trusted-client");

    (config as { mtls: { cnAllowlist: string[] } }).mtls.cnAllowlist = [];
  });
});
