/**
 * Acceptance tests for SPIFFE-mode identity validation in handleMtls
 * (Issue #1189).
 *
 * In SPIFFE mode the client identity is the SPIFFE ID taken from the
 * certificate's URI SAN: it must belong to the configured trust domain, must
 * be on the (optional) MTLS_SPIFFE_ID_ALLOWLIST, and is exposed to downstream
 * code as `req.clientSpiffeId`. Every failure is a 403
 * MTLS_SPIFFE_ID_NOT_ALLOWED with the `spiffe_id_not_allowed` metric reason,
 * and a missing/malformed SPIFFE ID never falls back to the CN allowlist.
 */
import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import type { Request, Response } from "express";
import type { PeerCertificate } from "node:tls";
import type { mtlsMiddleware as MtlsMiddlewareFn } from "./mtls.js";
import type { MtlsAuthenticatedRequest } from "./mtls.js";

const { verifyClientCertificate, mockConfig, handshakeFailuresInc } = vi.hoisted(
  () => ({
    verifyClientCertificate: vi.fn(),
    handshakeFailuresInc: vi.fn(),
    mockConfig: {
      mtls: {
        enabled: true,
        cnAllowlist: [] as string[],
        spiffeIdAllowlist: [] as string[],
        spiffe: {
          enabled: true,
          trustDomain: "example.org",
          workloadApiSocket: "unix:///tmp/spire-agent/public/api.sock",
          refreshRatio: 0.7,
        },
      },
    },
  }),
);

vi.mock("../config/index.js", () => ({ config: mockConfig }));

vi.mock("./mtlsRevocation.js", () => ({
  mtlsRevocationChecker: {
    verifyClientCertificate,
  },
}));

vi.mock("../metrics.js", () => ({
  mtlsHandshakeFailuresTotal: { inc: handshakeFailuresInc },
  mtlsReloadsTotal: { inc: vi.fn() },
}));

vi.mock("../utils/logger.js", () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

const TRUSTED_ID = "spiffe://example.org/ns/a/sa/api";

function createMockRequest(options: {
  san?: string;
  cn?: string;
  authorized?: boolean;
  cert?: Record<string, unknown> | null;
}): Request {
  const cert =
    options.cert !== undefined
      ? options.cert
      : {
          subject: { CN: options.cn ?? "client-cn" },
          subjectaltname: options.san,
          raw: Buffer.from("cert"),
        };
  return {
    socket: {
      authorized: options.authorized ?? true,
      authorizationError: undefined,
      getPeerCertificate: () => cert,
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

describe("mtlsMiddleware in SPIFFE mode", () => {
  const next = vi.fn();
  let mtlsMiddleware: typeof MtlsMiddlewareFn;

  afterAll(() => {
    // Drop the module instances this file re-evaluated above (bound to this
    // file's config mock) so later test files in the same worker re-import
    // them against their own mock registry instead of inheriting ours.
    vi.resetModules();
  });

  beforeEach(async () => {
    // Re-evaluate the middleware against this file's mock registry: without
    // this, a test file that imported ./mtls.js earlier in the same worker
    // leaks its module instance (bound to a different config mock) in here.
    vi.resetModules();
    ({ mtlsMiddleware } = await import("./mtls.js"));
    next.mockReset();
    verifyClientCertificate.mockReset();
    handshakeFailuresInc.mockReset();
    verifyClientCertificate.mockResolvedValue({
      ok: true,
      status: "good",
      source: "ocsp",
    });
    mockConfig.mtls.enabled = true;
    mockConfig.mtls.spiffe.enabled = true;
    mockConfig.mtls.spiffe.trustDomain = "example.org";
    mockConfig.mtls.spiffeIdAllowlist = [];
    mockConfig.mtls.cnAllowlist = [];
  });

  it("accepts a SPIFFE ID in the trust domain that is on the allowlist and sets req.clientSpiffeId", async () => {
    mockConfig.mtls.spiffeIdAllowlist = [TRUSTED_ID];

    const req = createMockRequest({ san: `URI:${TRUSTED_ID}` });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(200);
    expect(
      (req as MtlsAuthenticatedRequest).clientSpiffeId,
    ).toBe(TRUSTED_ID);
    expect(handshakeFailuresInc).not.toHaveBeenCalled();
  });

  it("rejects with 403 when the SPIFFE ID is in the trust domain but not on a non-empty allowlist", async () => {
    mockConfig.mtls.spiffeIdAllowlist = [
      "spiffe://example.org/ns/b/sa/other",
    ];

    const req = createMockRequest({ san: `URI:${TRUSTED_ID}` });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_SPIFFE_ID_NOT_ALLOWED" });
    expect(next).not.toHaveBeenCalled();
    expect(handshakeFailuresInc).toHaveBeenCalledWith({
      reason: "spiffe_id_not_allowed",
    });
    expect((req as MtlsAuthenticatedRequest).clientSpiffeId).toBeUndefined();
  });

  it("rejects with 403 when the SAN belongs to another trust domain, even with an empty allowlist", async () => {
    mockConfig.mtls.spiffeIdAllowlist = [];

    const req = createMockRequest({
      san: "URI:spiffe://evil.org/ns/a/sa/api",
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_SPIFFE_ID_NOT_ALLOWED" });
    expect(next).not.toHaveBeenCalled();
    expect(handshakeFailuresInc).toHaveBeenCalledWith({
      reason: "spiffe_id_not_allowed",
    });
  });

  it("rejects with 403 when the certificate has no URI SAN", async () => {
    const req = createMockRequest({ san: undefined, cn: "legacy-cn" });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_SPIFFE_ID_NOT_ALLOWED" });
    expect(next).not.toHaveBeenCalled();
    expect(handshakeFailuresInc).toHaveBeenCalledWith({
      reason: "spiffe_id_not_allowed",
    });
  });

  it("never falls back to the CN allowlist when the SPIFFE ID is rejected", async () => {
    // Even with a CN allowlist that contains the certificate CN, a missing
    // SPIFFE ID must be rejected (fail closed).
    mockConfig.mtls.cnAllowlist = ["legacy-cn"];

    const req = createMockRequest({
      san: undefined,
      cn: "legacy-cn",
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: "MTLS_SPIFFE_ID_NOT_ALLOWED" });
    expect(next).not.toHaveBeenCalled();
  });

  it("does not consult the CN allowlist in SPIFFE mode", async () => {
    // CN allowlist does not contain the certificate CN, yet a valid SPIFFE ID
    // must still be accepted: in SPIFFE mode the CN allowlist is skipped.
    mockConfig.mtls.cnAllowlist = ["some-other-cn"];
    mockConfig.mtls.spiffeIdAllowlist = [TRUSTED_ID];

    const req = createMockRequest({
      san: `URI:${TRUSTED_ID}`,
      cn: "legacy-cn",
    });
    const res = createMockResponse();

    mtlsMiddleware(req, res, next);
    await flushMiddleware();

    expect(next).toHaveBeenCalledOnce();
    expect((req as MtlsAuthenticatedRequest).clientSpiffeId).toBe(TRUSTED_ID);
  });
});
