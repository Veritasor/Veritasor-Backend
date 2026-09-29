import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getSignedManifest: vi.fn(),
  error: vi.fn(),
}));

vi.mock("../services/webhooks/egressIpAllowList.js", () => ({
  getSignedManifest: mocks.getSignedManifest,
}));
vi.mock("../utils/logger.js", () => ({
  logger: { error: mocks.error },
}));

import { webhookEgressIpsRouter } from "./webhookEgressIps.js";

const app = express();
app.use(webhookEgressIpsRouter);

describe("webhookEgressIpsRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns the signed manifest with its cache and content headers", async () => {
    const signedManifest = {
      manifest: {
        version: 1,
        ips: ["203.0.113.10"],
        signedAt: "2026-09-28T12:00:00.000Z",
      },
      signature: "test-signature",
      algorithm: "hmac-sha256",
    };
    mocks.getSignedManifest.mockResolvedValue(signedManifest);

    const response = await request(app).get("/.well-known/webhook-egress-ips");

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe(
      "public, max-age=3600, stale-while-revalidate=60, stale-if-error=86400",
    );
    expect(response.headers["content-type"]).toContain("application/json");
    expect(response.body).toEqual(signedManifest);
    expect(mocks.getSignedManifest).toHaveBeenCalledOnce();
  });

  it("returns a stable error on generation failure and serves a later request", async () => {
    const failure = new Error("signing key unavailable");
    const recoveredManifest = {
      manifest: {
        version: 1,
        ips: ["203.0.113.11"],
        signedAt: "2026-09-28T12:01:00.000Z",
      },
      signature: "recovered-signature",
      algorithm: "hmac-sha256",
    };
    mocks.getSignedManifest
      .mockResolvedValueOnce({
        manifest: {},
        signature: "first",
        algorithm: "hmac-sha256",
      })
      .mockRejectedValueOnce(failure)
      .mockResolvedValueOnce(recoveredManifest);

    const firstResponse = await request(app).get("/.well-known/webhook-egress-ips");
    const failedResponse = await request(app).get("/.well-known/webhook-egress-ips");
    const recoveredResponse = await request(app).get("/.well-known/webhook-egress-ips");

    expect(firstResponse.status).toBe(200);
    expect(failedResponse.status).toBe(500);
    expect(failedResponse.body).toEqual({
      status: "error",
      code: "MANIFEST_GENERATION_FAILED",
      message: "Unable to generate egress IP manifest",
    });
    expect(recoveredResponse.status).toBe(200);
    expect(recoveredResponse.body).toEqual(recoveredManifest);
    expect(mocks.error).toHaveBeenCalledOnceWith(
      "Failed to generate webhook egress IP manifest",
      failure,
    );
    expect(mocks.getSignedManifest).toHaveBeenCalledTimes(3);
  });

  it("does not generate a manifest for unsupported methods or paths", async () => {
    const methodResponse = await request(app).post(
      "/.well-known/webhook-egress-ips",
    );
    const pathResponse = await request(app).get(
      "/.well-known/webhook-egress-ips/extra",
    );

    expect(methodResponse.status).toBe(404);
    expect(pathResponse.status).toBe(404);
    expect(mocks.getSignedManifest).not.toHaveBeenCalled();
  });
});