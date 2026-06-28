import type { Request, Response, NextFunction } from "express";
import { config } from "../config/index.js";
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
