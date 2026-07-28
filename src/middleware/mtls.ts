import type { Request, Response, NextFunction } from "express";
import { config } from "../config/index.js";
import { mtlsRevocationChecker } from "./mtlsRevocation.js";
import { logger } from "../utils/logger.js";

/**
 * mTLS middleware to validate client certificate and check CN against allowlist.
 * Only active when config.mtls.enabled is true.
 */
export function mtlsMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  void handleMtls(req, res, next).catch((error) => {
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

  // Get the client certificate from the request
  const cert = req.socket.getPeerCertificate(true);

  // Check if client certificate is present and valid
  if (!cert || !req.socket.authorized) {
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

  // Add client CN to request for downstream use
  (req as any).clientCN = cn;

  next();
}
