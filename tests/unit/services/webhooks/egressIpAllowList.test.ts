/**
 * Tests for webhook egress IP allow-list (issue #534)
 *
 * Coverage targets:
 *  - canonicaliseManifest: deterministic serialisation
 *  - computeManifestSignature: HMAC correctness
 *  - verifyManifestSignature: accept/reject paths + timing-safe compare
 *  - getSignedManifest: signed payload shape, key fallback, clock injection
 *  - GET /.well-known/webhook-egress-ips: HTTP contract, caching headers, 500 path
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// Mock the secret loader so tests run without real secret infrastructure
// ---------------------------------------------------------------------------
vi.mock("../../../../src/utils/secret-loader.js", () => ({
  createSecretLoader: vi.fn(),
}));

import { createSecretLoader } from "../../../../src/utils/secret-loader.js";
import {
  canonicaliseManifest,
  computeManifestSignature,
  verifyManifestSignature,
  getSignedManifest,
  WEBHOOK_EGRESS_IPS,
  MANIFEST_VERSION,
  MANIFEST_CACHE_TTL_SECONDS,
  type EgressIpManifest,
  type SignedEgressIpManifest,
} from "../../../../src/services/webhooks/egressIpAllowList.js";

const SIGNING_KEY = "test-signing-key-for-webhook-egress-hmac-sha256-32b!";

function mockLoader(key: string): void {
  vi.mocked(createSecretLoader).mockReturnValue({
    get: vi.fn().mockResolvedValue(key),
    reload: vi.fn().mockResolvedValue(undefined),
  });
}

function mockLoaderThrows(): void {
  vi.mocked(createSecretLoader).mockReturnValue({
    get: vi.fn().mockRejectedValue(new Error("secret not found")),
    reload: vi.fn().mockResolvedValue(undefined),
  });
}

// ---------------------------------------------------------------------------
// canonicaliseManifest
// ---------------------------------------------------------------------------

describe("canonicaliseManifest", () => {
  const base: EgressIpManifest = {
    version: 1,
    ips: ["203.0.113.12", "203.0.113.10", "203.0.113.11"],
    signedAt: "2026-07-28T08:00:00.000Z",
  };

  it("produces valid JSON", () => {
    const result = canonicaliseManifest(base);
    expect(() => JSON.parse(result)).not.toThrow();
  });

  it("sorts the ips array ascending", () => {
    const result = JSON.parse(canonicaliseManifest(base));
    expect(result.ips).toEqual([
      "203.0.113.10",
      "203.0.113.11",
      "203.0.113.12",
    ]);
  });

  it("is idempotent – calling twice with same input returns same string", () => {
    expect(canonicaliseManifest(base)).toBe(canonicaliseManifest(base));
  });

  it("is deterministic regardless of ip insertion order", () => {
    const reversed: EgressIpManifest = {
      ...base,
      ips: ["203.0.113.11", "203.0.113.12", "203.0.113.10"],
    };
    expect(canonicaliseManifest(base)).toBe(canonicaliseManifest(reversed));
  });

  it("changes output when version changes", () => {
    const v2 = { ...base, version: 2 };
    expect(canonicaliseManifest(base)).not.toBe(canonicaliseManifest(v2));
  });

  it("changes output when signedAt changes", () => {
    const later = { ...base, signedAt: "2026-07-29T00:00:00.000Z" };
    expect(canonicaliseManifest(base)).not.toBe(canonicaliseManifest(later));
  });

  it("changes output when an IP is added", () => {
    const extra = { ...base, ips: [...base.ips, "10.0.0.1"] };
    expect(canonicaliseManifest(base)).not.toBe(canonicaliseManifest(extra));
  });
});

// ---------------------------------------------------------------------------
// computeManifestSignature
// ---------------------------------------------------------------------------

describe("computeManifestSignature", () => {
  const data = '{"ips":["203.0.113.10"],"signedAt":"2026-07-28T00:00:00.000Z","version":1}';

  it("returns a 64-char hex string (SHA-256 = 32 bytes = 64 hex chars)", () => {
    const sig = computeManifestSignature(data, SIGNING_KEY);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces the same value as a manual HMAC-SHA256", () => {
    const expected = crypto
      .createHmac("sha256", SIGNING_KEY)
      .update(data)
      .digest("hex");
    expect(computeManifestSignature(data, SIGNING_KEY)).toBe(expected);
  });

  it("differs with a different key", () => {
    expect(computeManifestSignature(data, SIGNING_KEY)).not.toBe(
      computeManifestSignature(data, "other-key")
    );
  });

  it("differs with a different payload", () => {
    expect(computeManifestSignature(data, SIGNING_KEY)).not.toBe(
      computeManifestSignature(data + " ", SIGNING_KEY)
    );
  });
});

// ---------------------------------------------------------------------------
// verifyManifestSignature
// ---------------------------------------------------------------------------

describe("verifyManifestSignature", () => {
  const manifest: EgressIpManifest = {
    version: 1,
    ips: ["203.0.113.10", "203.0.113.11"],
    signedAt: "2026-07-28T08:00:00.000Z",
  };

  function makeSigned(m: EgressIpManifest, key: string): SignedEgressIpManifest {
    const canonical = canonicaliseManifest(m);
    const signature = computeManifestSignature(canonical, key);
    return { manifest: m, signature, algorithm: "hmac-sha256" };
  }

  it("accepts a correctly signed manifest", () => {
    const signed = makeSigned(manifest, SIGNING_KEY);
    expect(verifyManifestSignature(signed, SIGNING_KEY)).toBe(true);
  });

  it("rejects a manifest with a tampered signature", () => {
    const signed = makeSigned(manifest, SIGNING_KEY);
    const tampered: SignedEgressIpManifest = {
      ...signed,
      signature: "deadbeef" + signed.signature.slice(8),
    };
    expect(verifyManifestSignature(tampered, SIGNING_KEY)).toBe(false);
  });

  it("rejects a manifest signed with a different key", () => {
    const signed = makeSigned(manifest, "wrong-key-entirely");
    expect(verifyManifestSignature(signed, SIGNING_KEY)).toBe(false);
  });

  it("rejects when the manifest ips have been modified after signing", () => {
    const signed = makeSigned(manifest, SIGNING_KEY);
    const tampered: SignedEgressIpManifest = {
      ...signed,
      manifest: { ...signed.manifest, ips: [...signed.manifest.ips, "1.2.3.4"] },
    };
    expect(verifyManifestSignature(tampered, SIGNING_KEY)).toBe(false);
  });

  it("rejects when the version is bumped after signing", () => {
    const signed = makeSigned(manifest, SIGNING_KEY);
    const tampered: SignedEgressIpManifest = {
      ...signed,
      manifest: { ...signed.manifest, version: 99 },
    };
    expect(verifyManifestSignature(tampered, SIGNING_KEY)).toBe(false);
  });

  it("rejects when signedAt is modified after signing", () => {
    const signed = makeSigned(manifest, SIGNING_KEY);
    const tampered: SignedEgressIpManifest = {
      ...signed,
      manifest: { ...signed.manifest, signedAt: "2025-01-01T00:00:00.000Z" },
    };
    expect(verifyManifestSignature(tampered, SIGNING_KEY)).toBe(false);
  });

  it("rejects a non-hex signature gracefully without throwing", () => {
    const signed = makeSigned(manifest, SIGNING_KEY);
    const invalid: SignedEgressIpManifest = {
      ...signed,
      signature: "not-hex-$$$###",
    };
    // Buffer.from('not-hex', 'hex') returns empty buffer, lengths differ
    expect(verifyManifestSignature(invalid, SIGNING_KEY)).toBe(false);
  });

  it("rejects an empty signature", () => {
    const signed = makeSigned(manifest, SIGNING_KEY);
    const invalid: SignedEgressIpManifest = { ...signed, signature: "" };
    expect(verifyManifestSignature(invalid, SIGNING_KEY)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getSignedManifest
// ---------------------------------------------------------------------------

describe("getSignedManifest", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("returns a signed manifest with correct shape", async () => {
    mockLoader(SIGNING_KEY);
    const result = await getSignedManifest();

    expect(result.algorithm).toBe("hmac-sha256");
    expect(result.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(result.manifest).toMatchObject({
      version: MANIFEST_VERSION,
      ips: expect.any(Array),
      signedAt: expect.any(String),
    });
  });

  it("includes all configured egress IPs, sorted", async () => {
    mockLoader(SIGNING_KEY);
    const result = await getSignedManifest();

    const sorted = [...WEBHOOK_EGRESS_IPS].sort();
    expect(result.manifest.ips).toEqual(sorted);
  });

  it("embeds the injectable clock as signedAt", async () => {
    mockLoader(SIGNING_KEY);
    const fixedNow = new Date("2026-07-28T12:00:00.000Z");
    const result = await getSignedManifest(fixedNow);

    expect(result.manifest.signedAt).toBe("2026-07-28T12:00:00.000Z");
  });

  it("produces a signature that passes verifyManifestSignature", async () => {
    mockLoader(SIGNING_KEY);
    const result = await getSignedManifest();

    expect(verifyManifestSignature(result, SIGNING_KEY)).toBe(true);
  });

  it("two calls at different times produce different signatures", async () => {
    mockLoader(SIGNING_KEY);
    const r1 = await getSignedManifest(new Date("2026-07-28T10:00:00.000Z"));
    const r2 = await getSignedManifest(new Date("2026-07-28T11:00:00.000Z"));

    expect(r1.signature).not.toBe(r2.signature);
  });

  it("falls back to env var when secret loader throws", async () => {
    mockLoaderThrows();
    const oldEnv = process.env["WEBHOOK_EGRESS_SIGNING_KEY"];
    process.env["WEBHOOK_EGRESS_SIGNING_KEY"] = "env-fallback-key-for-testing";

    try {
      const result = await getSignedManifest();
      expect(result.manifest.version).toBe(MANIFEST_VERSION);
      expect(result.signature).toBeTruthy();
    } finally {
      if (oldEnv === undefined) {
        delete process.env["WEBHOOK_EGRESS_SIGNING_KEY"];
      } else {
        process.env["WEBHOOK_EGRESS_SIGNING_KEY"] = oldEnv;
      }
    }
  });

  it("uses insecure fallback key when neither loader nor env has the key", async () => {
    mockLoaderThrows();
    const oldEnv = process.env["WEBHOOK_EGRESS_SIGNING_KEY"];
    delete process.env["WEBHOOK_EGRESS_SIGNING_KEY"];

    try {
      const result = await getSignedManifest();
      expect(result.manifest.version).toBe(MANIFEST_VERSION);
    } finally {
      if (oldEnv !== undefined) {
        process.env["WEBHOOK_EGRESS_SIGNING_KEY"] = oldEnv;
      }
    }
  });
});

// ---------------------------------------------------------------------------
// GET /.well-known/webhook-egress-ips – HTTP layer
// ---------------------------------------------------------------------------

import request from "supertest";
import express from "express";
import { webhookEgressIpsRouter } from "../../../../src/routes/webhookEgressIps.js";

describe("GET /.well-known/webhook-egress-ips", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockLoader(SIGNING_KEY);
  });

  it("responds 200 with JSON body containing manifest, signature, and algorithm", async () => {
    const app = express();
    app.use(webhookEgressIpsRouter);
    const res = await request(app).get("/.well-known/webhook-egress-ips");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.body).toMatchObject({
      algorithm: "hmac-sha256",
      signature: expect.stringMatching(/^[0-9a-f]{64}$/),
      manifest: {
        version: expect.any(Number),
        ips: expect.any(Array),
        signedAt: expect.any(String),
      },
    });
  });

  it("sets Cache-Control public max-age header", async () => {
    const app = express();
    app.use(webhookEgressIpsRouter);
    const res = await request(app).get("/.well-known/webhook-egress-ips");

    expect(res.headers["cache-control"]).toContain("public");
    expect(res.headers["cache-control"]).toContain(
      `max-age=${MANIFEST_CACHE_TTL_SECONDS}`
    );
  });

  it("returns a signature that verifies with the signing key", async () => {
    const app = express();
    app.use(webhookEgressIpsRouter);
    const res = await request(app).get("/.well-known/webhook-egress-ips");

    expect(verifyManifestSignature(res.body, SIGNING_KEY)).toBe(true);
  });

  it("includes ips from the canonical list in the manifest body", async () => {
    const app = express();
    app.use(webhookEgressIpsRouter);
    const res = await request(app).get("/.well-known/webhook-egress-ips");

    const sorted = [...WEBHOOK_EGRESS_IPS].sort();
    expect(res.body.manifest.ips).toEqual(sorted);
  });

  it("manifest version matches MANIFEST_VERSION constant", async () => {
    const app = express();
    app.use(webhookEgressIpsRouter);
    const res = await request(app).get("/.well-known/webhook-egress-ips");

    expect(res.body.manifest.version).toBe(MANIFEST_VERSION);
  });

  it("signedAt is a valid ISO-8601 timestamp", async () => {
    const app = express();
    app.use(webhookEgressIpsRouter);
    const res = await request(app).get("/.well-known/webhook-egress-ips");

    expect(new Date(res.body.manifest.signedAt).toISOString()).toBe(
      res.body.manifest.signedAt
    );
  });
});
