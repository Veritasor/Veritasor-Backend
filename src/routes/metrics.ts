import { createHash, timingSafeEqual } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { metricsRegistry } from "../metrics.js";

export function createMetricsRouter(bearerToken?: string): Router {
  const router = Router();

  router.get("/", async (req: Request, res: Response) => {
    if (bearerToken) {
      const authorization = req.get("authorization") ?? "";
      const suppliedToken = authorization.startsWith("Bearer ")
        ? authorization.slice("Bearer ".length)
        : "";
      const expectedDigest = createHash("sha256").update(bearerToken).digest();
      const suppliedDigest = createHash("sha256").update(suppliedToken).digest();
      if (!timingSafeEqual(expectedDigest, suppliedDigest)) {
        res.status(401).end();
        return;
      }
    }

    try {
      const metrics = await metricsRegistry.metrics();
      res.set("Content-Type", metricsRegistry.contentType);
      res.end(metrics);
    } catch {
      res.status(500).end();
    }
  });

  return router;
}
