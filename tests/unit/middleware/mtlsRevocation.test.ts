import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("../../../src/config/index.js", () => ({
  config: {
    mtls: {
      caPath: "/tmp/ca.pem",
      revocation: {
        enabled: true,
        ocspCacheTtlMs: 300_000,
        ocspIssuerPath: "/tmp/issuer.pem",
        crlPath: "/tmp/clients.crl",
      },
    },
  },
}));

import {
  MtlsRevocationChecker,
  computeOcspCacheTtlMs,
  getStapledOcspResponse,
  parseCrlNextUpdate,
  parseOcspText,
  toPemCertificate,
} from "../../../src/middleware/mtlsRevocation.js";

describe("mtlsRevocation helpers", () => {
  it("parses good OCSP output with next update", () => {
    const result = parseOcspText(`
      /tmp/client-cert.pem: good
      This Update: Jul 28 10:00:00 2026 GMT
      Next Update: Jul 28 11:00:00 2026 GMT
    `);

    expect(result.status).toBe("good");
    expect(result.nextUpdate?.toISOString()).toContain("2026-07-28T11:00:00.000Z");
  });

  it("parses revoked OCSP output", () => {
    const result = parseOcspText("/tmp/client-cert.pem: revoked");
    expect(result.status).toBe("revoked");
  });

  it("parses unknown OCSP output without next update", () => {
    const result = parseOcspText("/tmp/client-cert.pem: unknown");
    expect(result.status).toBe("unknown");
    expect(result.nextUpdate).toBeUndefined();
  });

  it("parses CRL next update", () => {
    const nextUpdate = parseCrlNextUpdate("nextUpdate=Jul 28 11:30:00 2026 GMT");
    expect(nextUpdate?.toISOString()).toContain("2026-07-28T11:30:00.000Z");
  });

  it("returns undefined when CRL next update is missing", () => {
    expect(parseCrlNextUpdate("issuer=/CN=test")).toBeUndefined();
  });

  it("caps cache TTL to the smaller of config and OCSP freshness", () => {
    const now = () => new Date("2026-07-28T10:00:00.000Z");
    const ttl = computeOcspCacheTtlMs(
      new Date("2026-07-28T10:02:00.000Z"),
      now,
      300_000,
    );
    expect(ttl).toBe(120_000);
  });

  it("uses the configured cache TTL when no next update exists", () => {
    const now = () => new Date("2026-07-28T10:00:00.000Z");
    expect(computeOcspCacheTtlMs(undefined, now, 42_000)).toBe(42_000);
  });

  it("reads stapled OCSP from socket helpers", () => {
    expect(
      getStapledOcspResponse({
        getOCSPResponse: () => Buffer.from("staple"),
      } as never),
    ).toEqual(Buffer.from("staple"));
  });

  it("converts raw peer cert bytes into PEM", () => {
    const pem = toPemCertificate({
      raw: Buffer.from("hello"),
    } as never);
    expect(pem).toContain("BEGIN CERTIFICATE");
  });

  it("returns an already-encoded PEM certificate when present", () => {
    const pem = toPemCertificate({
      pemEncoded: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
    } as never);
    expect(pem).toContain("TEST");
  });

  it("throws when no usable certificate bytes are available", () => {
    expect(() => toPemCertificate({} as never)).toThrow(
      "Peer certificate raw DER bytes are required for revocation checks",
    );
  });
});

describe("MtlsRevocationChecker", () => {
  const now = () => new Date("2026-07-28T10:00:00.000Z");
  const checkerOptions = {
    now,
    createTempDir: vi.fn().mockResolvedValue("/tmp/veritasor-test"),
    writeTempFile: vi.fn().mockResolvedValue(undefined),
    removeTempDir: vi.fn().mockResolvedValue(undefined),
  };
  const rawCert = Buffer.from("client-cert");
  const peerCert = {
    raw: rawCert,
    serialNumber: "ABCD1234",
    subject: { CN: "trusted-client" },
  } as never;

  beforeEach(async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { revocation: { enabled: boolean; crlPath: string | undefined } } })
      .mtls.revocation.enabled = true;
    (config as { mtls: { revocation: { crlPath: string | undefined } } })
      .mtls.revocation.crlPath = "/tmp/clients.crl";
  });

  it("returns good when a stapled OCSP response verifies", async () => {
    const runOpenSsl = vi.fn().mockResolvedValue({
      stdout: "/tmp/client-cert.pem: good\nNext Update: Jul 28 11:00:00 2026 GMT\n",
      stderr: "",
    });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate(
      { ocspResponse: Buffer.from("ocsp") } as never,
      peerCert,
    );

    expect(result).toMatchObject({ ok: true, source: "ocsp", status: "good" });
    expect(runOpenSsl).toHaveBeenCalledOnce();
  });

  it("can be constructed with default dependencies", () => {
    expect(new MtlsRevocationChecker()).toBeInstanceOf(MtlsRevocationChecker);
  });

  it("caches good OCSP responses by response hash", async () => {
    const runOpenSsl = vi.fn().mockResolvedValue({
      stdout: "/tmp/client-cert.pem: good\nNext Update: Jul 28 11:00:00 2026 GMT\n",
      stderr: "",
    });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });
    const socket = { ocspResponse: Buffer.from("ocsp") } as never;

    await checker.verifyClientCertificate(socket, peerCert);
    await checker.verifyClientCertificate(socket, peerCert);

    expect(runOpenSsl).toHaveBeenCalledOnce();
  });

  it("rejects revoked OCSP responses", async () => {
    const runOpenSsl = vi.fn().mockResolvedValue({
      stdout: "/tmp/client-cert.pem: revoked\nNext Update: Jul 28 11:00:00 2026 GMT\n",
      stderr: "",
    });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate(
      { ocspResponse: Buffer.from("ocsp") } as never,
      peerCert,
    );

    expect(result).toMatchObject({ ok: false, status: "revoked", source: "ocsp" });
  });

  it("returns unknown when the stapled OCSP response is not conclusive", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { revocation: { crlPath: string | undefined } } })
      .mtls.revocation.crlPath = undefined;

    const runOpenSsl = vi.fn().mockResolvedValue({
      stdout: "/tmp/client-cert.pem: unknown\n",
      stderr: "",
    });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate(
      { ocspResponse: Buffer.from("ocsp") } as never,
      peerCert,
    );

    expect(result).toMatchObject({ ok: false, status: "unknown", source: "ocsp" });
  });

  it("falls back to CRL when the stapled OCSP response is stale", async () => {
    const runOpenSsl = vi
      .fn()
      .mockResolvedValueOnce({
        stdout: "/tmp/client-cert.pem: good\nNext Update: Jul 28 09:59:00 2026 GMT\n",
        stderr: "",
      })
      .mockResolvedValueOnce({
        stdout: "/tmp/client-cert.pem: OK\n",
        stderr: "",
      })
      .mockResolvedValueOnce({
        stdout: "nextUpdate=Jul 28 11:00:00 2026 GMT\n",
        stderr: "",
      });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate(
      { ocspResponse: Buffer.from("stale-ocsp") } as never,
      peerCert,
    );

    expect(result).toMatchObject({ ok: true, status: "good", source: "crl" });
    expect(runOpenSsl).toHaveBeenCalledTimes(3);
  });

  it("uses CRL fallback when no stapled OCSP response is present", async () => {
    const runOpenSsl = vi
      .fn()
      .mockResolvedValueOnce({
        stdout: "/tmp/client-cert.pem: OK\n",
        stderr: "",
      })
      .mockResolvedValueOnce({
        stdout: "nextUpdate=Jul 28 11:00:00 2026 GMT\n",
        stderr: "",
      });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate({} as never, peerCert);

    expect(result).toMatchObject({ ok: true, status: "good", source: "crl" });
  });

  it("caches CRL fallback results", async () => {
    const runOpenSsl = vi
      .fn()
      .mockResolvedValueOnce({
        stdout: "/tmp/client-cert.pem: OK\n",
        stderr: "",
      })
      .mockResolvedValueOnce({
        stdout: "nextUpdate=Jul 28 11:00:00 2026 GMT\n",
        stderr: "",
      });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    await checker.verifyClientCertificate({} as never, peerCert);
    await checker.verifyClientCertificate({} as never, peerCert);

    expect(runOpenSsl).toHaveBeenCalledTimes(2);
  });

  it("rejects when no OCSP response is present and CRL fallback is disabled", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { revocation: { crlPath: string | undefined } } })
      .mtls.revocation.crlPath = undefined;

    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl: vi.fn() });
    const result = await checker.verifyClientCertificate({} as never, peerCert);

    expect(result).toMatchObject({ ok: false, status: "ocsp_unavailable", source: "ocsp" });
  });

  it("rejects when the CRL reports the certificate as revoked", async () => {
    const runOpenSsl = vi
      .fn()
      .mockRejectedValueOnce(new Error("error 23 at 0 depth lookup: certificate revoked"))
      .mockResolvedValueOnce({
        stdout: "nextUpdate=Jul 28 11:00:00 2026 GMT\n",
        stderr: "",
      });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate({} as never, peerCert);

    expect(result).toMatchObject({ ok: false, status: "revoked", source: "crl" });
  });

  it("rejects when CRL verification output says the certificate is revoked", async () => {
    const runOpenSsl = vi
      .fn()
      .mockResolvedValueOnce({
        stdout: "error 23 at 0 depth lookup: certificate revoked",
        stderr: "",
      })
      .mockResolvedValueOnce({
        stdout: "nextUpdate=Jul 28 11:00:00 2026 GMT\n",
        stderr: "",
      });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate({} as never, peerCert);

    expect(result).toMatchObject({ ok: false, status: "revoked", source: "crl" });
  });

  it("returns CRL unavailable when fallback verification errors", async () => {
    const runOpenSsl = vi
      .fn()
      .mockRejectedValueOnce(new Error("unable to load CRL"))
      .mockResolvedValueOnce({
        stdout: "nextUpdate=Jul 28 11:00:00 2026 GMT\n",
        stderr: "",
      });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });

    const result = await checker.verifyClientCertificate({} as never, peerCert);

    expect(result).toMatchObject({ ok: false, status: "crl_unavailable", source: "crl" });
  });

  it("returns none when revocation checks are disabled", async () => {
    const { config } = await import("../../../src/config/index.js");
    (config as { mtls: { revocation: { enabled: boolean } } }).mtls.revocation.enabled = false;

    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl: vi.fn() });
    const result = await checker.verifyClientCertificate({} as never, peerCert);

    expect(result).toEqual({ ok: true, status: "good", source: "none" });
  });

  it("revalidates after an OCSP cache entry expires", async () => {
    let currentTime = new Date("2026-07-28T10:00:00.000Z");
    const runOpenSsl = vi
      .fn()
      .mockResolvedValueOnce({
        stdout: "/tmp/client-cert.pem: good\nNext Update: Jul 28 10:05:00 2026 GMT\n",
        stderr: "",
      })
      .mockResolvedValueOnce({
        stdout: "/tmp/client-cert.pem: good\nNext Update: Jul 28 10:15:00 2026 GMT\n",
        stderr: "",
      });
    const checker = new MtlsRevocationChecker({
      ...checkerOptions,
      runOpenSsl,
      now: () => currentTime,
    });
    const socket = { ocspResponse: Buffer.from("ocsp") } as never;

    await checker.verifyClientCertificate(socket, peerCert);
    currentTime = new Date("2026-07-28T10:06:00.000Z");
    await checker.verifyClientCertificate(socket, peerCert);

    expect(runOpenSsl).toHaveBeenCalledTimes(2);
  });

  it("clears cached results on demand", async () => {
    const runOpenSsl = vi.fn().mockResolvedValue({
      stdout: "/tmp/client-cert.pem: good\nNext Update: Jul 28 11:00:00 2026 GMT\n",
      stderr: "",
    });
    const checker = new MtlsRevocationChecker({ ...checkerOptions, runOpenSsl });
    const socket = { ocspResponse: Buffer.from("ocsp") } as never;

    await checker.verifyClientCertificate(socket, peerCert);
    checker.clearCache();
    await checker.verifyClientCertificate(socket, peerCert);

    expect(runOpenSsl).toHaveBeenCalledTimes(2);
  });
});
