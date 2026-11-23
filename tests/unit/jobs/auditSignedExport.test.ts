/**
 * Tests for audit-log signed export job (issue #580)
 *
 * Coverage targets:
 *  - serialiseLogsAsNdjson: correct NDJSON output
 *  - sha256Hex: correct SHA-256 digest
 *  - buildTarball: produces valid gzip-compressed tar archive
 *  - loadSigningKey: secret loader + env fallback + error
 *  - signManifest: produces valid armored PGP signature
 *  - verifyExportSignature: accept/reject paths
 *  - generateSignedAuditExport: full flow, clock injection, key rotation
 *  - auditSignedExportJob: job runner integration, success/failure metrics
 */

import { describe, it, expect, vi, beforeEach, beforeAll } from "vitest";
import * as openpgp from "openpgp";
import { gunzipSync } from "node:zlib";

// ---------------------------------------------------------------------------
// Mocks – must come before subject imports
// ---------------------------------------------------------------------------

vi.mock("../../../src/utils/secret-loader.js", () => ({
  createSecretLoader: vi.fn(),
}));

vi.mock("../../../src/repositories/auditLogRepository.js", () => ({
  getAllAuditLogs: vi.fn(),
}));

// Mock jobRunner to avoid Pushgateway calls during unit tests
vi.mock("../../../src/jobs/jobRunner.js", () => ({
  runInstrumentedJob: vi.fn(
    (_name: string, fn: () => Promise<unknown>) => fn()
  ),
}));

import { createSecretLoader } from "../../../src/utils/secret-loader.js";
import { getAllAuditLogs } from "../../../src/repositories/auditLogRepository.js";
import {
  serialiseLogsAsNdjson,
  sha256Hex,
  buildTarball,
  loadSigningKey,
  signManifest,
  verifyExportSignature,
  generateSignedAuditExport,
  auditSignedExportJob,
  AUDIT_EXPORT_JOB_NAME,
} from "../../../src/jobs/auditSignedExport.js";
import type { AuditLog } from "../../../src/repositories/auditLogRepository.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeLog(overrides: Partial<AuditLog> = {}): AuditLog {
  return {
    id: "log-001",
    userId: "user-abc",
    action: "login",
    resource: "auth",
    resourceId: "session-001",
    metadata: { ip: "127.0.0.1" },
    contentHash: undefined,
    timestamp: new Date("2026-07-28T08:00:00.000Z"),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// serialiseLogsAsNdjson
// ---------------------------------------------------------------------------

describe("serialiseLogsAsNdjson", () => {
  it("returns an empty string for empty input", () => {
    expect(serialiseLogsAsNdjson([])).toBe("");
  });

  it("serialises a single log as one line of JSON", () => {
    const log = makeLog();
    const result = serialiseLogsAsNdjson([log]);
    const parsed = JSON.parse(result);
    expect(parsed.id).toBe(log.id);
  });

  it("separates multiple logs with newlines", () => {
    const logs = [makeLog({ id: "a" }), makeLog({ id: "b" })];
    const result = serialiseLogsAsNdjson(logs);
    const lines = result.split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).id).toBe("a");
    expect(JSON.parse(lines[1]).id).toBe("b");
  });

  it("serialises the timestamp as a string (JSON.stringify behaviour)", () => {
    const log = makeLog();
    const result = serialiseLogsAsNdjson([log]);
    const parsed = JSON.parse(result);
    expect(typeof parsed.timestamp).toBe("string");
  });

  it("includes all fields including metadata", () => {
    const log = makeLog({ metadata: { foo: "bar", n: 42 } });
    const result = serialiseLogsAsNdjson([log]);
    const parsed = JSON.parse(result);
    expect(parsed.metadata).toEqual({ foo: "bar", n: 42 });
  });
});

// ---------------------------------------------------------------------------
// sha256Hex
// ---------------------------------------------------------------------------

describe("sha256Hex", () => {
  it("returns a 64-char lowercase hex string", () => {
    expect(sha256Hex("hello")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns the well-known SHA-256 of 'hello'", () => {
    // echo -n 'hello' | sha256sum
    expect(sha256Hex("hello")).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });

  it("returns different hashes for different inputs", () => {
    expect(sha256Hex("a")).not.toBe(sha256Hex("b"));
  });

  it("is deterministic", () => {
    expect(sha256Hex("test")).toBe(sha256Hex("test"));
  });
});

// ---------------------------------------------------------------------------
// buildTarball
// ---------------------------------------------------------------------------

describe("buildTarball", () => {
  it("returns a non-empty Buffer", async () => {
    const files = new Map([["hello.txt", "hello world"]]);
    const buf = await buildTarball(files);
    expect(buf).toBeInstanceOf(Buffer);
    expect(buf.length).toBeGreaterThan(0);
  });

  it("produces valid gzip data (starts with gzip magic bytes 0x1f 0x8b)", async () => {
    const files = new Map([["a.json", '{"test":true}']]);
    const buf = await buildTarball(files);
    expect(buf[0]).toBe(0x1f);
    expect(buf[1]).toBe(0x8b);
  });

  it("produces data that can be gunzipped without error", async () => {
    const files = new Map([["test.txt", "content here"]]);
    const buf = await buildTarball(files);
    expect(() => gunzipSync(buf)).not.toThrow();
  });

  it("handles multiple files", async () => {
    const files = new Map([
      ["file1.txt", "content one"],
      ["file2.json", '{"key":"value"}'],
      ["file3.csv", "a,b,c\n1,2,3"],
    ]);
    const buf = await buildTarball(files);
    expect(buf.length).toBeGreaterThan(0);
    expect(buf[0]).toBe(0x1f);
  });

  it("handles empty files map (empty tarball)", async () => {
    const files = new Map<string, string>();
    const buf = await buildTarball(files);
    // Even empty tar produces valid gzip
    expect(buf[0]).toBe(0x1f);
    expect(buf[1]).toBe(0x8b);
  });

  it("handles unicode content", async () => {
    const files = new Map([["unicode.txt", "日本語テスト 🔐"]]);
    const buf = await buildTarball(files);
    expect(() => gunzipSync(buf)).not.toThrow();
  });

  it("produces larger output for larger content", async () => {
    const small = new Map([["s.txt", "small"]]);
    const large = new Map([["l.txt", "x".repeat(10_000)]]);
    const smallBuf = await buildTarball(small);
    const largeBuf = await buildTarball(large);
    expect(largeBuf.length).toBeGreaterThan(smallBuf.length);
  });
});

// ---------------------------------------------------------------------------
// loadSigningKey
// ---------------------------------------------------------------------------

describe("loadSigningKey", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("throws when neither loader nor env has the PGP key", async () => {
    vi.mocked(createSecretLoader).mockReturnValue({
      get: vi.fn().mockRejectedValue(new Error("not found")),
      reload: vi.fn(),
    });
    const old = process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];
    delete process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];

    try {
      await expect(loadSigningKey()).rejects.toThrow(
        "AUDIT_EXPORT_PGP_PRIVATE_KEY secret is not configured"
      );
    } finally {
      if (old !== undefined) process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"] = old;
    }
  });
});

// ---------------------------------------------------------------------------
// signManifest + verifyExportSignature – using freshly generated keys
// ---------------------------------------------------------------------------

describe("signManifest / verifyExportSignature", () => {
  let privateKey: openpgp.PrivateKey;
  let publicKey: openpgp.PublicKey;

  beforeAll(async () => {
    const keypair = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Test", email: "test@veritasor.test" }],
    });
    privateKey = await openpgp.readPrivateKey({ armoredKey: keypair.privateKey });
    publicKey = await openpgp.readKey({ armoredKey: keypair.publicKey });
  });

  it("signManifest returns an armored PGP signature string", async () => {
    const text = '{"exportVersion":1,"recordCount":5}';
    const sig = await signManifest(text, privateKey);
    expect(sig).toContain("-----BEGIN PGP SIGNATURE-----");
    expect(sig).toContain("-----END PGP SIGNATURE-----");
  });

  it("verifyExportSignature returns true for a valid signature", async () => {
    const text = '{"hello":"world"}';
    const sig = await signManifest(text, privateKey);
    const valid = await verifyExportSignature(text, sig, publicKey);
    expect(valid).toBe(true);
  });

  it("verifyExportSignature returns false for a tampered message", async () => {
    const text = '{"hello":"world"}';
    const sig = await signManifest(text, privateKey);
    const valid = await verifyExportSignature(text + " tampered", sig, publicKey);
    expect(valid).toBe(false);
  });

  it("verifyExportSignature returns false for a different public key", async () => {
    const text = "test message";
    const sig = await signManifest(text, privateKey);

    const other = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Other", email: "other@veritasor.test" }],
    });
    const otherPub = await openpgp.readKey({ armoredKey: other.publicKey });

    const valid = await verifyExportSignature(text, sig, otherPub);
    expect(valid).toBe(false);
  });

  it("verifyExportSignature returns false for a garbage signature", async () => {
    const valid = await verifyExportSignature(
      "anything",
      "not-a-pgp-signature",
      publicKey
    );
    expect(valid).toBe(false);
  });

  it("two signatures over the same text both verify successfully", async () => {
    const text = "same text";
    const sig1 = await signManifest(text, privateKey);
    const sig2 = await signManifest(text, privateKey);
    const [v1, v2] = await Promise.all([
      verifyExportSignature(text, sig1, publicKey),
      verifyExportSignature(text, sig2, publicKey),
    ]);
    expect(v1).toBe(true);
    expect(v2).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// generateSignedAuditExport – full flow
// ---------------------------------------------------------------------------

describe("generateSignedAuditExport", () => {
  let privateKeyArmored: string;
  let publicKeyObj: openpgp.PublicKey;

  beforeAll(async () => {
    const keypair = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Veritasor CI", email: "ci@veritasor.test" }],
    });
    privateKeyArmored = keypair.privateKey;
    publicKeyObj = await openpgp.readKey({ armoredKey: keypair.publicKey });
  });

  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(createSecretLoader).mockReturnValue({
      get: vi.fn().mockImplementation(async (key: string) => {
        if (key === "AUDIT_EXPORT_PGP_PRIVATE_KEY") return privateKeyArmored;
        throw new Error("secret not found: " + key);
      }),
      reload: vi.fn(),
    });
    vi.mocked(getAllAuditLogs).mockResolvedValue([]);
  });

  it("returns AuditExportResult with correct shape", async () => {
    const result = await generateSignedAuditExport();
    expect(result).toMatchObject({
      tarballBuffer: expect.any(Buffer),
      manifestSignature: expect.any(String),
      manifest: expect.objectContaining({
        exportVersion: 1,
        exportedAt: expect.any(String),
        recordCount: 0,
        logsFileSha256: expect.any(String),
        signingKeyFingerprint: expect.any(String),
      }),
      recordCount: 0,
    });
  });

  it("uses injectable clock for exportedAt", async () => {
    const fixed = new Date("2026-07-28T12:00:00.000Z");
    const result = await generateSignedAuditExport(fixed);
    expect(result.manifest.exportedAt).toBe("2026-07-28T12:00:00.000Z");
  });

  it("reflects record count from fetched logs", async () => {
    const logs = [makeLog({ id: "a" }), makeLog({ id: "b" }), makeLog({ id: "c" })];
    vi.mocked(getAllAuditLogs).mockResolvedValue(logs);

    const result = await generateSignedAuditExport();
    expect(result.recordCount).toBe(3);
    expect(result.manifest.recordCount).toBe(3);
  });

  it("logsFileSha256 matches sha256 of the serialised NDJSON", async () => {
    const logs = [makeLog()];
    vi.mocked(getAllAuditLogs).mockResolvedValue(logs);

    const result = await generateSignedAuditExport();
    const expectedHash = sha256Hex(serialiseLogsAsNdjson(logs));
    expect(result.manifest.logsFileSha256).toBe(expectedHash);
  });

  it("tarball buffer starts with valid gzip magic bytes", async () => {
    const result = await generateSignedAuditExport();
    expect(result.tarballBuffer[0]).toBe(0x1f);
    expect(result.tarballBuffer[1]).toBe(0x8b);
  });

  it("manifest signature passes PGP verification with the public key", async () => {
    vi.mocked(getAllAuditLogs).mockResolvedValue([makeLog()]);
    const result = await generateSignedAuditExport();

    const manifestJson = JSON.stringify(result.manifest, null, 2);
    const valid = await verifyExportSignature(
      manifestJson,
      result.manifestSignature,
      publicKeyObj
    );
    expect(valid).toBe(true);
  });

  it("manifestSignature is in PGP armored format", async () => {
    const result = await generateSignedAuditExport();
    expect(result.manifestSignature).toContain("-----BEGIN PGP SIGNATURE-----");
    expect(result.manifestSignature).toContain("-----END PGP SIGNATURE-----");
  });

  it("throws when PGP key is not configured", async () => {
    vi.mocked(createSecretLoader).mockReturnValue({
      get: vi.fn().mockRejectedValue(new Error("not found")),
      reload: vi.fn(),
    });
    const old = process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];
    delete process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];

    try {
      await expect(generateSignedAuditExport()).rejects.toThrow();
    } finally {
      if (old !== undefined) process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"] = old;
    }
  });

  it("uses env var fallback when secret loader throws", async () => {
    vi.mocked(createSecretLoader).mockReturnValue({
      get: vi.fn().mockRejectedValue(new Error("vault unavailable")),
      reload: vi.fn(),
    });
    process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"] = privateKeyArmored;

    try {
      const result = await generateSignedAuditExport();
      expect(result.tarballBuffer.length).toBeGreaterThan(0);
    } finally {
      delete process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];
    }
  });

  it("fetches the signing key fresh on each call (key rotation safety)", async () => {
    let getCallCount = 0;
    vi.mocked(createSecretLoader).mockImplementation(() => ({
      get: vi.fn().mockImplementation(async (key: string) => {
        if (key === "AUDIT_EXPORT_PGP_PRIVATE_KEY") {
          getCallCount++;
          return privateKeyArmored;
        }
        throw new Error("not found");
      }),
      reload: vi.fn(),
    }));

    await generateSignedAuditExport();
    await generateSignedAuditExport();

    // Each call should have fetched the key at least once
    expect(getCallCount).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// auditSignedExportJob – job runner integration
// ---------------------------------------------------------------------------

describe("auditSignedExportJob", () => {
  let privateKeyArmored: string;

  beforeAll(async () => {
    const keypair = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2048,
      userIDs: [{ name: "Job Test", email: "job@veritasor.test" }],
    });
    privateKeyArmored = keypair.privateKey;
  });

  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(createSecretLoader).mockReturnValue({
      get: vi.fn().mockImplementation(async (key: string) => {
        if (key === "AUDIT_EXPORT_PGP_PRIVATE_KEY") return privateKeyArmored;
        throw new Error("not found");
      }),
      reload: vi.fn(),
    });
  });

  it("returns success:true and itemsProcessed matching log count", async () => {
    const logs = [makeLog({ id: "a" }), makeLog({ id: "b" })];
    vi.mocked(getAllAuditLogs).mockResolvedValue(logs);

    const outcome = await auditSignedExportJob();
    expect(outcome.success).toBe(true);
    expect(outcome.itemsProcessed).toBe(2);
  });

  it("returns success:false when signing key is missing", async () => {
    vi.mocked(createSecretLoader).mockReturnValue({
      get: vi.fn().mockRejectedValue(new Error("not found")),
      reload: vi.fn(),
    });
    const old = process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];
    delete process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"];

    try {
      vi.mocked(getAllAuditLogs).mockResolvedValue([]);
      const outcome = await auditSignedExportJob();
      expect(outcome.success).toBe(false);
      expect(outcome.itemsProcessed).toBe(0);
    } finally {
      if (old !== undefined) process.env["AUDIT_EXPORT_PGP_PRIVATE_KEY"] = old;
    }
  });

  it("returns success:false when getAllAuditLogs throws", async () => {
    vi.mocked(getAllAuditLogs).mockRejectedValue(new Error("db failure"));

    const outcome = await auditSignedExportJob();
    expect(outcome.success).toBe(false);
    expect(outcome.itemsProcessed).toBe(0);
  });

  it("AUDIT_EXPORT_JOB_NAME constant is 'audit_signed_export'", () => {
    expect(AUDIT_EXPORT_JOB_NAME).toBe("audit_signed_export");
  });

  it("accepts an injectable clock parameter", async () => {
    vi.mocked(getAllAuditLogs).mockResolvedValue([makeLog()]);
    const fixed = new Date("2026-07-28T00:00:00.000Z");
    const outcome = await auditSignedExportJob(fixed);
    expect(outcome.success).toBe(true);
  });

  it("handles empty audit log store gracefully", async () => {
    vi.mocked(getAllAuditLogs).mockResolvedValue([]);
    const outcome = await auditSignedExportJob();
    expect(outcome.success).toBe(true);
    expect(outcome.itemsProcessed).toBe(0);
  });
});
