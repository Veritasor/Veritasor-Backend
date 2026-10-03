import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createSecretLoader: vi.fn(),
  warn: vi.fn(),
}));

vi.mock("../../utils/secret-loader.js", () => ({
  createSecretLoader: mocks.createSecretLoader,
}));
vi.mock("../../utils/logger.js", () => ({
  logger: { warn: mocks.warn },
}));

import {
  canonicaliseManifest,
  computeManifestSignature,
  getSignedManifest,
  MANIFEST_CACHE_TTL_SECONDS,
  MANIFEST_VERSION,
  verifyManifestSignature,
  WEBHOOK_EGRESS_IPS,
} from "./egressIpAllowList.js";

describe("webhook egress IP allow-list", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
    mocks.createSecretLoader.mockReturnValue({
      get: vi.fn().mockResolvedValue("loader-signing-key"),
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("exports the frozen IP list and manifest cache constants", () => {
    expect(WEBHOOK_EGRESS_IPS).toEqual([
      "203.0.113.10",
      "203.0.113.11",
      "203.0.113.12",
    ]);
    expect(Object.isFrozen(WEBHOOK_EGRESS_IPS)).toBe(true);
    expect(() => (WEBHOOK_EGRESS_IPS as string[]).push("203.0.113.13")).toThrow(
      TypeError,
    );
    expect(MANIFEST_VERSION).toBe(1);
    expect(MANIFEST_CACHE_TTL_SECONDS).toBe(3600);
  });

  it("canonicalises manifest keys and IPs deterministically", () => {
    expect(
      canonicaliseManifest({
        version: MANIFEST_VERSION,
        ips: ["203.0.113.12", "203.0.113.10"],
        signedAt: "2026-09-28T12:00:00.000Z",
      }),
    ).toBe(
      '{"ips":["203.0.113.10","203.0.113.12"],"signedAt":"2026-09-28T12:00:00.000Z","version":1}',
    );
  });

  it("generates a reproducible signed manifest using the loaded secret", async () => {
    const signed = await getSignedManifest(new Date("2026-09-28T12:00:00.000Z"));

    expect(signed).toEqual({
      manifest: {
        version: MANIFEST_VERSION,
        ips: [...WEBHOOK_EGRESS_IPS],
        signedAt: "2026-09-28T12:00:00.000Z",
      },
      signature: computeManifestSignature(
        '{"ips":["203.0.113.10","203.0.113.11","203.0.113.12"],"signedAt":"2026-09-28T12:00:00.000Z","version":1}',
        "loader-signing-key",
      ),
      algorithm: "hmac-sha256",
    });
    expect(verifyManifestSignature(signed, "loader-signing-key")).toBe(true);
    expect(mocks.createSecretLoader).toHaveBeenCalledOnce();
  });

  it("rejects tampered, malformed, and wrong-length signatures", () => {
    const manifest = {
      version: MANIFEST_VERSION,
      ips: [...WEBHOOK_EGRESS_IPS],
      signedAt: "2026-09-28T12:00:00.000Z",
    };
    const validSignature = computeManifestSignature(
      canonicaliseManifest(manifest),
      "test-signing-key",
    );

    expect(
      verifyManifestSignature(
        {
          manifest: { ...manifest, signedAt: "2026-09-28T12:00:01.000Z" },
          signature: validSignature,
          algorithm: "hmac-sha256",
        },
        "test-signing-key",
      ),
    ).toBe(false);
    expect(
      verifyManifestSignature(
        { manifest, signature: "not-hex", algorithm: "hmac-sha256" },
        "test-signing-key",
      ),
    ).toBe(false);
    expect(
      verifyManifestSignature(
        { manifest, signature: validSignature.slice(0, -2), algorithm: "hmac-sha256" },
        "test-signing-key",
      ),
    ).toBe(false);
  });

  it("uses the environment secret when secret loading fails", async () => {
    mocks.createSecretLoader.mockReturnValue({
      get: vi.fn().mockRejectedValue(new Error("secret service unavailable")),
    });
    vi.stubEnv("WEBHOOK_EGRESS_SIGNING_KEY", "environment-signing-key");

    const signed = await getSignedManifest(new Date("2026-09-28T12:00:00.000Z"));

    expect(verifyManifestSignature(signed, "environment-signing-key")).toBe(true);
    expect(mocks.warn).not.toHaveBeenCalled();
  });

  it("uses the development key and warns when no secret source is available", async () => {
    mocks.createSecretLoader.mockReturnValue({
      get: vi.fn().mockRejectedValue(new Error("secret service unavailable")),
    });
    vi.stubEnv("WEBHOOK_EGRESS_SIGNING_KEY", "");

    const signed = await getSignedManifest(new Date("2026-09-28T12:00:00.000Z"));

    expect(
      verifyManifestSignature(
        signed,
        "dev-insecure-signing-key-do-not-use-in-production",
      ),
    ).toBe(true);
    expect(mocks.warn).toHaveBeenCalledOnce();
    expect(mocks.warn).toHaveBeenCalledWith(
      expect.stringContaining("WEBHOOK_EGRESS_SIGNING_KEY not configured"),
    );
  });

  it("rejects an invalid clock value deterministically", async () => {
    await expect(getSignedManifest(new Date("invalid"))).rejects.toThrow(
      RangeError,
    );
  });
});
