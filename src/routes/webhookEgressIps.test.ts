import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getSignedManifest: vi.fn(),
  loggerError: vi.fn(),
}));

vi.mock("../services/webhooks/egressIpAllowList.js", () => ({
  EgressManifestSigningKeyError: class EgressManifestSigningKeyError extends Error {},
  getSignedManifest: mocks.getSignedManifest,
}));
vi.mock("../utils/logger.js", () => ({
  logger: { error: mocks.loggerError },
}));

import { webhookEgressIpsRouter } from "./webhookEgressIps.js";
import { EgressManifestSigningKeyError } from "../services/webhooks/egressIpAllowList.js";

describe("webhook egress IP route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 503 without a signature when signing is unavailable", async () => {
    mocks.getSignedManifest.mockRejectedValue(new EgressManifestSigningKeyError());

    const app = express();
    app.use(webhookEgressIpsRouter);

    const response = await request(app).get("/.well-known/webhook-egress-ips");

    expect(response.status).toBe(503);
    expect(response.body).toEqual({
      status: "error",
      code: "EGRESS_MANIFEST_SIGNING_KEY_UNAVAILABLE",
      message: "Egress IP manifest signing is temporarily unavailable",
    });
    expect(response.body).not.toHaveProperty("signature");
  });
});
