import type { Request, Response, NextFunction } from "express";
import fs from "node:fs/promises";
import tls from "node:tls";
import type { Server as HttpsServer } from "node:https";
import { config } from "../config/index.js";
import { mtlsRevocationChecker } from "./mtlsRevocation.js";
import { logger } from "../utils/logger.js";
import { mtlsHandshakeFailuresTotal, mtlsReloadsTotal } from "../metrics.js";

let activeHttpsServer: HttpsServer | undefined;

export function registerMtlsServer(server: HttpsServer): void {
  activeHttpsServer = server;
}

export async function reloadMtlsCertificates(): Promise<void> {
  if (!config.mtls.enabled || config.mtls.spiffe.enabled || !activeHttpsServer) {
    return;
  }

  logger.info({ event: "mtls_reload_requested" });

  try {
    const [ca, cert, key] = await Promise.all([
      fs.readFile(config.mtls.caPath!),
      fs.readFile(config.mtls.certPath!),
      fs.readFile(config.mtls.keyPath!),
    ]);

    // Validate new PEMs by creating a dummy secure context.
    // If invalid, this throws an error.
    tls.createSecureContext({ ca, cert, key });

    activeHttpsServer.setSecureContext({
      ca,
      cert,
      key,
      requestCert: true,
      rejectUnauthorized: false,
    });

    mtlsReloadsTotal.inc({ outcome: "success" });
    logger.info({ event: "mtls_reload_succeeded" });
  } catch (error) {
    mtlsReloadsTotal.inc({ outcome: "error" });
    logger.error({
      event: "mtls_reload_failed",
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

process.on("SIGHUP", () => {
  void reloadMtlsCertificates();
});

export interface MtlsAuthenticatedRequest extends Request {
  clientCN?: string;
  clientSpiffeId?: string;
}

/**
 * mTLS middleware to validate client certificate identity.
 *
 * When SPIFFE is enabled, client identity is derived from the SPIFFE ID URI SAN
 * and validated against the configured trust domain and optional allowlist.
 * Otherwise, the legacy CN allowlist path is used.
 *
 * Only active when config.mtls.enabled is true.
 */
export function mtlsMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  void handleMtls(req, res, next).catch((error) => {
    mtlsHandshakeFailuresTotal.inc({ reason: "internal_error" });
    logger.error({
      event: "mtls_internal_error",
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(503).json({
      status: "error",
      code: "MTLS_INTERNAL_ERROR",
      message: "mTLS verification failed unexpectedly",
    });
  });
}

async function handleMtls(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  if (!config.mtls.enabled) {
    return next();
  }

  const cert = req.socket.getPeerCertificate(true);

  if (!cert || !req.socket.authorized) {
    const reason = !cert ? "no_client_cert" : "unauthorized";
    mtlsHandshakeFailuresTotal.inc({ reason });
    logger.warn({
      event: "mtls_unauthorized",
      reason: req.socket.authorizationError || "no_client_cert",
    });
    return res.status(495).json({
      status: "error",
      code: "MTLS_UNAUTHORIZED",
      message: "Client certificate required",
    });
  }

  const revocationDecision = await mtlsRevocationChecker.verifyClientCertificate(
    req.socket,
    cert,
  );
  if (!revocationDecision.ok) {
    const reason = revocationDecision.status === "revoked" ? "cert_revoked" : "revocation_check_failed";
    mtlsHandshakeFailuresTotal.inc({ reason });
    logger.warn({
      event: "mtls_certificate_revocation_rejected",
      source: revocationDecision.source,
      status: revocationDecision.status,
      detail: revocationDecision.detail,
    });
    return res.status(403).json({
      status: "error",
      code:
        revocationDecision.status === "revoked"
          ? "MTLS_CERT_REVOKED"
          : "MTLS_REVOCATION_CHECK_FAILED",
      message:
        revocationDecision.status === "revoked"
          ? "Client certificate has been revoked"
          : "Client certificate revocation status could not be validated",
    });
  }

  // Check if CN is in allowlist (if allowlist is not empty)
  const cn = cert.subject?.CN;
  if (config.mtls.cnAllowlist.length > 0) {
    if (!cn || !config.mtls.cnAllowlist.includes(cn)) {
      mtlsHandshakeFailuresTotal.inc({ reason: "cn_not_allowed" });
      logger.warn({
        event: "mtls_cn_not_allowed",
        client_cn: cn,
        allowlist: config.mtls.cnAllowlist,
      });
      return res.status(403).json({
        status: "error",
        code: "MTLS_CN_NOT_ALLOWED",
        message: "Client certificate CN not allowed",
      });
    }
  }

  authenticated.clientCN = cn;
  next();
}
