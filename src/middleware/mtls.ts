import type { Request, Response, NextFunction } from "express";
import { config } from "../config/index.js";
import { extractSpiffeIdFromCert } from "../spiffe/spiffeId.js";
import { logger } from "../utils/logger.js";

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
  if (!config.mtls.enabled) {
    return next();
  }

  const cert = req.socket.getPeerCertificate(true);

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

  const authenticated = req as MtlsAuthenticatedRequest;

  if (config.mtls.spiffe.enabled) {
    const spiffeId = extractSpiffeIdFromCert(cert, config.mtls.spiffe.trustDomain);
    if (!spiffeId) {
      logger.warn({
        event: "mtls_spiffe_id_missing",
        trust_domain: config.mtls.spiffe.trustDomain,
      });
      return res.status(403).json({
        status: "error",
        code: "MTLS_SPIFFE_ID_INVALID",
        message: "Client certificate must contain a valid SPIFFE ID",
      });
    }

    if (
      config.mtls.spiffeIdAllowlist.length > 0
      && !config.mtls.spiffeIdAllowlist.includes(spiffeId)
    ) {
      logger.warn({
        event: "mtls_spiffe_id_not_allowed",
        client_spiffe_id: spiffeId,
        allowlist: config.mtls.spiffeIdAllowlist,
      });
      return res.status(403).json({
        status: "error",
        code: "MTLS_SPIFFE_ID_NOT_ALLOWED",
        message: "Client SPIFFE ID not allowed",
      });
    }

    authenticated.clientSpiffeId = spiffeId;
    return next();
  }

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

  authenticated.clientCN = cn;
  next();
}
