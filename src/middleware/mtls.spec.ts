import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs/promises";
import tls from "node:tls";
import type { Server as HttpsServer } from "node:https";
import { config } from "../config/index.js";
import { registerMtlsServer, reloadMtlsCertificates } from "./mtls.js";
import { mtlsReloadsTotal } from "../metrics.js";

vi.mock("node:fs/promises");
vi.mock("node:tls");
vi.mock("../metrics.js", () => ({
  mtlsHandshakeFailuresTotal: { inc: vi.fn() },
  mtlsReloadsTotal: { inc: vi.fn() },
}));
vi.mock("../utils/logger.js", () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe("mTLS Reload SIGHUP Handler", () => {
  let mockServer: HttpsServer;

  beforeEach(() => {
    vi.resetAllMocks();
    config.mtls.enabled = true;
    config.mtls.spiffe.enabled = false;
    config.mtls.caPath = "/fake/ca.pem";
    config.mtls.certPath = "/fake/cert.pem";
    config.mtls.keyPath = "/fake/key.pem";

    mockServer = {
      setSecureContext: vi.fn(),
    } as unknown as HttpsServer;

    registerMtlsServer(mockServer);
  });

  afterEach(() => {
    registerMtlsServer(undefined as any);
  });

  it("should successfully reload and swap context when PEM is valid", async () => {
    vi.mocked(fs.readFile).mockResolvedValueOnce("valid ca")
      .mockResolvedValueOnce("valid cert")
      .mockResolvedValueOnce("valid key");
    
    vi.mocked(tls.createSecureContext).mockReturnValue({} as any);

    await reloadMtlsCertificates();

    expect(fs.readFile).toHaveBeenCalledTimes(3);
    expect(tls.createSecureContext).toHaveBeenCalledWith({
      ca: "valid ca",
      cert: "valid cert",
      key: "valid key",
    });
    expect(mockServer.setSecureContext).toHaveBeenCalledWith({
      ca: "valid ca",
      cert: "valid cert",
      key: "valid key",
      requestCert: true,
      rejectUnauthorized: false,
    });
    expect(mtlsReloadsTotal.inc).toHaveBeenCalledWith({ outcome: "success" });
  });

  it("should not reload if mTLS is disabled", async () => {
    config.mtls.enabled = false;
    await reloadMtlsCertificates();
    expect(fs.readFile).not.toHaveBeenCalled();
  });

  it("should not reload if SPIFFE is enabled", async () => {
    config.mtls.spiffe.enabled = true;
    await reloadMtlsCertificates();
    expect(fs.readFile).not.toHaveBeenCalled();
  });

  it("should handle error when PEM is invalid and not swap context", async () => {
    vi.mocked(fs.readFile).mockResolvedValue("invalid content");
    vi.mocked(tls.createSecureContext).mockImplementation(() => {
      throw new Error("Invalid PEM");
    });

    await reloadMtlsCertificates();

    expect(tls.createSecureContext).toHaveBeenCalled();
    expect(mockServer.setSecureContext).not.toHaveBeenCalled();
    expect(mtlsReloadsTotal.inc).toHaveBeenCalledWith({ outcome: "error" });
  });
});
