import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { PeerCertificate, TLSSocket } from "node:tls";
import { config } from "../config/index.js";

const execFileAsync = promisify(execFile);

export type RevocationStatus =
  | "good"
  | "revoked"
  | "unknown"
  | "stale_ocsp"
  | "ocsp_unavailable"
  | "crl_unavailable";

export interface RevocationDecision {
  ok: boolean;
  status: RevocationStatus;
  source: "ocsp" | "crl" | "none";
  cacheTtlMs?: number;
  detail?: string;
}

interface CachedDecision {
  decision: RevocationDecision;
  expiresAtMs: number;
}

export interface OpenSslRunner {
  (
    command: string,
    args: string[],
  ): Promise<{ stdout: string; stderr: string }>;
}

export interface MtlsRevocationCheckerOptions {
  runOpenSsl?: OpenSslRunner;
  now?: () => Date;
  createTempDir?: (prefix: string) => Promise<string>;
  writeTempFile?: (path: string, contents: string | Buffer) => Promise<void>;
  removeTempDir?: (path: string) => Promise<void>;
}

interface OcspVerificationResult {
  status: "good" | "revoked" | "unknown";
  nextUpdate?: Date;
}

export class MtlsRevocationChecker {
  private readonly runOpenSsl: OpenSslRunner;
  private readonly now: () => Date;
  private readonly createTempDir: (prefix: string) => Promise<string>;
  private readonly writeTempFile: (path: string, contents: string | Buffer) => Promise<void>;
  private readonly removeTempDir: (path: string) => Promise<void>;
  private readonly cache = new Map<string, CachedDecision>();

  constructor(options: MtlsRevocationCheckerOptions = {}) {
    this.runOpenSsl = options.runOpenSsl ?? defaultOpenSslRunner;
    this.now = options.now ?? (() => new Date());
    this.createTempDir =
      options.createTempDir
      ?? ((prefix: string) => mkdtemp(join(tmpdir(), prefix)));
    this.writeTempFile = options.writeTempFile ?? writeFile;
    this.removeTempDir =
      options.removeTempDir
      ?? ((path: string) => rm(path, { recursive: true, force: true }));
  }

  async verifyClientCertificate(
    socket: TLSSocket,
    peerCert: PeerCertificate,
  ): Promise<RevocationDecision> {
    if (!config.mtls.revocation.enabled) {
      return { ok: true, status: "good", source: "none" };
    }

    const certPem = toPemCertificate(peerCert);
    const serialNumber = normalizeSerialNumber(peerCert.serialNumber);
    const stapledOcsp = getStapledOcspResponse(socket);

    if (stapledOcsp) {
      const ocspCacheKey = `ocsp:${serialNumber}:${sha256(stapledOcsp)}`;
      const cachedOcsp = this.getCached(ocspCacheKey);
      if (cachedOcsp) {
        return cachedOcsp;
      }

      const ocspDecision = await this.verifyOcspResponse(certPem, stapledOcsp);
      if (ocspDecision.ok || ocspDecision.status === "revoked") {
        this.setCached(ocspCacheKey, ocspDecision);
        return ocspDecision;
      }

      if (!config.mtls.revocation.crlPath) {
        return ocspDecision;
      }
    } else if (!config.mtls.revocation.crlPath) {
      return {
        ok: false,
        status: "ocsp_unavailable",
        source: "ocsp",
        detail: "No stapled OCSP response was provided by the client certificate path",
      };
    }

    const crlCacheKey = `crl:${serialNumber}:${config.mtls.revocation.crlPath ?? ""}`;
    const cachedCrl = this.getCached(crlCacheKey);
    if (cachedCrl) {
      return cachedCrl;
    }

    const crlDecision = await this.verifyViaCrl(certPem);
    this.setCached(crlCacheKey, crlDecision);
    return crlDecision;
  }

  clearCache(): void {
    this.cache.clear();
  }

  private getCached(key: string): RevocationDecision | undefined {
    const entry = this.cache.get(key);
    if (!entry) {
      return undefined;
    }
    if (entry.expiresAtMs <= this.now().getTime()) {
      this.cache.delete(key);
      return undefined;
    }
    return entry.decision;
  }

  private setCached(key: string, decision: RevocationDecision): void {
    const fallbackTtlMs = config.mtls.revocation.ocspCacheTtlMs;
    const ttlMs = Math.max(1_000, decision.cacheTtlMs ?? fallbackTtlMs);
    this.cache.set(key, {
      decision,
      expiresAtMs: this.now().getTime() + ttlMs,
    });
  }

  private async verifyOcspResponse(
    certPem: string,
    ocspResponse: Buffer,
  ): Promise<RevocationDecision> {
    const workdir = await this.createTempDir("veritasor-mtls-ocsp-");
    const certPath = join(workdir, "client-cert.pem");
    const ocspPath = join(workdir, "stapled-response.der");

    try {
      await this.writeTempFile(certPath, certPem);
      await this.writeTempFile(ocspPath, ocspResponse);

      const issuerPath =
        config.mtls.revocation.ocspIssuerPath ?? config.mtls.caPath!;

      const { stdout } = await this.runOpenSsl("openssl", [
        "ocsp",
        "-issuer",
        issuerPath,
        "-cert",
        certPath,
        "-CAfile",
        config.mtls.caPath!,
        "-respin",
        ocspPath,
        "-no_nonce",
        "-text",
      ]);

      const parsed = parseOcspText(stdout);
      if (parsed.status === "revoked") {
        return {
          ok: false,
          status: "revoked",
          source: "ocsp",
          cacheTtlMs: computeOcspCacheTtlMs(parsed.nextUpdate, this.now, config.mtls.revocation.ocspCacheTtlMs),
          detail: "Client certificate was revoked according to stapled OCSP",
        };
      }
      if (parsed.status === "unknown") {
        return {
          ok: false,
          status: "unknown",
          source: "ocsp",
          detail: "Stapled OCSP response returned unknown certificate status",
        };
      }
      if (!parsed.nextUpdate || parsed.nextUpdate.getTime() <= this.now().getTime()) {
        return {
          ok: false,
          status: "stale_ocsp",
          source: "ocsp",
          detail: "Stapled OCSP response is stale",
        };
      }

      return {
        ok: true,
        status: "good",
        source: "ocsp",
        cacheTtlMs: computeOcspCacheTtlMs(parsed.nextUpdate, this.now, config.mtls.revocation.ocspCacheTtlMs),
      };
    } catch (error) {
      return {
        ok: false,
        status: "ocsp_unavailable",
        source: "ocsp",
        detail: error instanceof Error ? error.message : String(error),
      };
    } finally {
      await this.removeTempDir(workdir);
    }
  }

  private async verifyViaCrl(certPem: string): Promise<RevocationDecision> {
    const crlPath = config.mtls.revocation.crlPath;
    if (!crlPath) {
      return {
        ok: false,
        status: "crl_unavailable",
        source: "crl",
        detail: "No CRL path configured for mTLS revocation fallback",
      };
    }

    const workdir = await this.createTempDir("veritasor-mtls-crl-");
    const certPath = join(workdir, "client-cert.pem");

    try {
      await this.writeTempFile(certPath, certPem);

      const [{ stdout: verifyStdout, stderr: verifyStderr }, { stdout: nextUpdateStdout }] =
        await Promise.all([
          this.runOpenSsl("openssl", [
            "verify",
            "-crl_check",
            "-CAfile",
            config.mtls.caPath!,
            "-CRLfile",
            crlPath,
            certPath,
          ]),
          this.runOpenSsl("openssl", [
            "crl",
            "-in",
            crlPath,
            "-noout",
            "-nextupdate",
          ]),
        ]);

      const nextUpdate = parseCrlNextUpdate(nextUpdateStdout);
      const cacheTtlMs = computeOcspCacheTtlMs(
        nextUpdate,
        this.now,
        config.mtls.revocation.ocspCacheTtlMs,
      );

      const combined = `${verifyStdout}\n${verifyStderr}`.toLowerCase();
      if (combined.includes("certificate revoked")) {
        return {
          ok: false,
          status: "revoked",
          source: "crl",
          cacheTtlMs,
          detail: "Client certificate was revoked according to CRL fallback",
        };
      }

      return {
        ok: true,
        status: "good",
        source: "crl",
        cacheTtlMs,
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      if (detail.toLowerCase().includes("certificate revoked")) {
        return {
          ok: false,
          status: "revoked",
          source: "crl",
          detail: "Client certificate was revoked according to CRL fallback",
        };
      }
      return {
        ok: false,
        status: "crl_unavailable",
        source: "crl",
        detail,
      };
    } finally {
      await this.removeTempDir(workdir);
    }
  }
}

function defaultOpenSslRunner(
  command: string,
  args: string[],
): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(command, args, { encoding: "utf8", maxBuffer: 1024 * 1024 });
}

export function getStapledOcspResponse(socket: TLSSocket): Buffer | undefined {
  const socketWithOcsp = socket as TLSSocket & {
    ocspResponse?: Buffer;
    getOCSPResponse?: () => Buffer | undefined;
  };

  const response = socketWithOcsp.ocspResponse ?? socketWithOcsp.getOCSPResponse?.();
  if (!response || response.length === 0) {
    return undefined;
  }
  return response;
}

export function toPemCertificate(peerCert: PeerCertificate): string {
  if (peerCert.raw) {
    return derToPem(peerCert.raw, "CERTIFICATE");
  }

  const certWithPem = peerCert as PeerCertificate & { pemEncoded?: string };
  if (
    typeof certWithPem.pemEncoded === "string"
    && certWithPem.pemEncoded.includes("BEGIN CERTIFICATE")
  ) {
    return certWithPem.pemEncoded;
  }

  throw new Error("Peer certificate raw DER bytes are required for revocation checks");
}

function derToPem(der: Buffer, label: string): string {
  const base64 = der.toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function normalizeSerialNumber(serialNumber: string | undefined): string {
  return (serialNumber ?? "").replace(/:/g, "").toLowerCase();
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function parseOcspText(stdout: string): OcspVerificationResult {
  const normalized = stdout.toLowerCase();
  let status: OcspVerificationResult["status"] = "unknown";
  if (normalized.includes(": good")) {
    status = "good";
  } else if (normalized.includes(": revoked")) {
    status = "revoked";
  }

  const nextUpdateMatch = stdout.match(/Next Update:\s*(.+)/i);
  const nextUpdate = nextUpdateMatch ? new Date(nextUpdateMatch[1].trim()) : undefined;

  return {
    status,
    nextUpdate: nextUpdate && !Number.isNaN(nextUpdate.getTime()) ? nextUpdate : undefined,
  };
}

export function parseCrlNextUpdate(stdout: string): Date | undefined {
  const match = stdout.match(/nextupdate=(.+)/i);
  if (!match) {
    return undefined;
  }
  const nextUpdate = new Date(match[1].trim());
  return Number.isNaN(nextUpdate.getTime()) ? undefined : nextUpdate;
}

export function computeOcspCacheTtlMs(
  nextUpdate: Date | undefined,
  now: () => Date,
  configuredTtlMs: number,
): number {
  if (!nextUpdate) {
    return configuredTtlMs;
  }

  const ttlMs = nextUpdate.getTime() - now().getTime();
  return Math.max(1_000, Math.min(configuredTtlMs, ttlMs));
}

export const mtlsRevocationChecker = new MtlsRevocationChecker();
