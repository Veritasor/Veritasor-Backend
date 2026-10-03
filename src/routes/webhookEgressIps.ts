/**
 * GET /.well-known/webhook-egress-ips
 *
 * Machine-readable, HMAC-signed manifest of the NAT egress IPs Veritasor uses
 * when dispatching outbound webhooks.  Enterprise tenants consume this endpoint
 * to keep their firewall allow-lists in sync.
 *
 * Response shape (JSON):
 * ```json
 * {
 *   "manifest": {
 *     "version": 1,
 *     "ips": ["203.0.113.10", "203.0.113.11"],
 *     "signedAt": "2026-07-28T08:00:00.000Z"
 *   },
 *   "signature": "<hex-hmac-sha256>",
 *   "algorithm": "hmac-sha256"
 * }
 * ```
 *
 * Verification recipe for consumers:
 *  1. Compute `HMAC-SHA256` over the canonical JSON of `manifest`
 *     (keys sorted alphabetically, ips array sorted).
 *  2. Compare with `signature` using a constant-time comparison.
 *  3. Reject manifests where `signedAt` is older than your acceptable staleness
 *     window (e.g. 2 × Cache-Control max-age).
 *
 * Caching:
 *  The response carries a `Cache-Control: public, max-age=3600` header so CDN
 *  edges and enterprise proxies can cache it without hitting the origin for
 *  every firewall refresh cycle.
 */

import { Router, Request, Response } from "express";
import {
  getSignedManifest,
} from "../services/webhooks/egressIpAllowList.js";
import { logger } from "../utils/logger.js";
import { formatCacheControl, CACHE_POLICIES } from "../utils/cachePolicy.js";

const egressPolicy = CACHE_POLICIES.find(
  (p) => p.name === 'webhook-egress-ips',
);

export const webhookEgressIpsRouter = Router();

webhookEgressIpsRouter.get(
  "/.well-known/webhook-egress-ips",
  async (_req: Request, res: Response): Promise<void> => {
    try {
      const signed = await getSignedManifest();

      res.set(
        "Cache-Control",
        egressPolicy
          ? formatCacheControl(egressPolicy.directives)
          : "public, max-age=3600, stale-while-revalidate=60"
      );
      res.set("Content-Type", "application/json; charset=utf-8");

      res.json(signed);
    } catch (err) {
      logger.error("Failed to generate webhook egress IP manifest", err);
      res.status(500).json({
        status: "error",
        code: "MANIFEST_GENERATION_FAILED",
        message: "Unable to generate egress IP manifest",
      });
    }
  }
);
