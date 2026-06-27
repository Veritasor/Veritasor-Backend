import express, { type Express } from "express";
import type { Server } from "node:http";
import type { Request, Response, NextFunction } from "express";
import { config } from "./config/index.js";
import { createCorsMiddleware } from "./middleware/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import {
  apiVersionMiddleware,
  versionResponseMiddleware,
} from "./middleware/apiVersion.js";
import { metricsRegistry } from "./metrics.js";
import { analyticsRouter } from "./routes/analytics.js";
import { attestationsRouter } from "./routes/attestations.js";
import { authRouter } from "./routes/auth.js";
import businessRoutes from "./routes/businesses.js";
import { healthRouter } from "./routes/health.js";
import integrationsRouter from "./routes/integrations.js";
import integrationsRazorpayRouter from "./routes/integrations-razorpay.js";
import { integrationsShopifyRouter } from "./routes/integrations-shopify.js";
import { integrationsStripeRouter } from "./routes/integrations-stripe.js";
import { publicAttestationsRouter } from "./routes/publicAttestations.js";
import usersRouter from "./routes/users.js";
import { razorpayWebhookRouter } from "./routes/webhooks-razorpay.js";
import adminRouter from "./routes/admin.js";
import {
  runStartupDependencyReadinessChecks,
  StartupReadinessReport,
} from "./startup/readiness.js";
import { initializeOpenTelemetry } from "./tracing.js";

export const telemetryReady = initializeOpenTelemetry();

// Security middleware to reject prototype pollution attempts
const securityHeadersMiddleware = (req: Request, res: Response, next: NextFunction) => {
  if (req.query && Object.keys(req.query).some(key => key === '__proto__' || key === 'constructor' || key === 'prototype')) {
    res.status(400).json({
      status: 'error',
      code: 'VALIDATION_ERROR',
      message: 'Invalid query parameters'
    });
    return;
  }

  if (req.body && typeof req.body === 'object') {
    if (Object.keys(req.body).some(key => key === '__proto__' || key === 'constructor' || key === 'prototype')) {
      res.status(400).json({
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Invalid body fields'
      });
      return;
    }
  }

  next();
};

export function createApp(readinessReport: StartupReadinessReport): Express {
  const app = express();

  app.use(requestLogger);
  app.use(securityHeadersMiddleware);
  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);

  app.use("/api/webhooks/razorpay", razorpayWebhookRouter);

  // 3. Body Parsing
  app.use(express.json());
  app.use(createCorsMiddleware());

  if (process.env.METRICS_ENABLED === "true") {
    app.get("/metrics", async (_req: Request, res: Response) => {
      res.set("Content-Type", metricsRegistry.contentType);
      res.end(await metricsRegistry.metrics());
    });
  }

  app.use("/api/analytics", analyticsRouter);
  app.use("/api/v1/public/attestations", publicAttestationsRouter);
  app.use("/api/attestations", attestationsRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/businesses", businessRoutes);
  app.use("/api/health", healthRouter);
  app.use("/api/integrations", integrationsRouter);
  app.use("/api/integrations/razorpay", integrationsRazorpayRouter);
  app.use("/api/integrations/shopify", integrationsShopifyRouter);
  app.use("/api/integrations/stripe", integrationsStripeRouter);
  app.use("/api/users", usersRouter);
  app.use("/api/v1/admin", adminRouter);
  app.use("/api/admin", adminRouter);

  // 5. Error Handling
  app.use(errorHandler);

  return app;
}

/**
 * Synchronous application instance for test environments.
 * Uses a default "ready" report to skip async boot complexity in unit tests.
 */
export const app = createApp({ ready: true, checks: [] });

/**
 * Production server entry point.
 * Runs readiness checks before starting the listener.
 * 
 * @param port - Port to listen on.
 * @returns A promise that resolves to the started HTTP server.
 */
export async function startServer(port: number): Promise<Server> {
  await telemetryReady;

  // Switch to the persistent DB-backed token store for production deployments.
  // This must happen before any refresh requests are handled so that rotation
  // protection is shared across all instances and survives restarts.
  const { DbUsedTokenStore, setUsedTokenStore } = await import('./services/auth/usedTokenStore.js')
  setUsedTokenStore(new DbUsedTokenStore())

  const readinessReport = await runStartupDependencyReadinessChecks();

  if (!readinessReport.ready) {
    const failedChecks = readinessReport.checks
      .filter((check) => !check.ready)
      .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
      .join("; ");
    console.warn(`[Startup] Proceeding with failed readiness checks: ${failedChecks}`);
  }

  const application = createApp(readinessReport);

  return new Promise((resolve) => {
    const server = application.listen(port, () => {
      console.log(`[Server] Veritasor Backend listening on port ${port}`);
      resolve(server);
    });
  });
}
