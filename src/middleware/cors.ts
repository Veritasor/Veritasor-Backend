import cors from "cors";
import type { CorsOptionsDelegate } from "cors";
import type { IncomingMessage } from "node:http";
import { config } from "../config/index.js";
import { logger } from "../utils/logger.js";

/**
 * Create the CORS middleware configured from application settings.
 *
 * Behaviour:
 * - **Allowlist mode** (production): Only origins listed in `ALLOWED_ORIGINS`
 *   receive CORS headers.  Rejected origins are logged as structured JSON
 *   (`type: "cors_rejected"`).
 * - **Wildcard mode** (development): All origins are reflected.
 *   `credentials` is forced to `false` per the CORS specification (wildcard
 *   origin cannot be combined with `Access-Control-Allow-Credentials: true`).
 * - **No Origin header**: Treated as same-origin / non-browser — always allowed.
 *
 * Security notes:
 * - Preflight responses are cached for 24 hours (`maxAge: 86 400`).
 * - Only the headers the API actually consumes are listed in
 *   `Access-Control-Allow-Headers`.
 * - `X-Request-ID` is exposed so clients can use it for tracing.
 *
 * @returns Express middleware function
 */
export function createCorsMiddleware() {
  const {
    origin,
    credentials,
    maxAge,
    allowedHeaders,
    exposedHeaders,
    methods,
  } = config.cors;

  const isWildcard = origin === "*";

  const originCallback: CorsOptionsDelegate<IncomingMessage> = (
    req,
    callback,
  ) => {
    const requestOrigin = (req as IncomingMessage).headers.origin;

    const sharedOptions = {
      maxAge,
      allowedHeaders: allowedHeaders as string[],
      exposedHeaders: exposedHeaders as string[],
      methods: methods as string[],
    };

    // No Origin header → same-origin or non-browser request → allow
    if (!requestOrigin) {
      return callback(null, {
        origin: true,
        credentials,
        ...sharedOptions,
      });
    }

    // Dev mode wildcard — reflect all origins, but no credentials
    if (isWildcard) {
      return callback(null, {
        origin: true,
        credentials: false,
        ...sharedOptions,
      });
    }

    // Production allowlist check
    const allowed = (origin as string[]).includes(requestOrigin);

    if (!allowed) {
      logger.warn(
        JSON.stringify({
          type: "cors_rejected",
          origin: requestOrigin,
          timestamp: new Date().toISOString(),
        }),
      );
    }

    callback(null, {
      origin: allowed,
      credentials,
      ...sharedOptions,
    });
  };

  return cors(originCallback);
}
