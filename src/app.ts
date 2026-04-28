import express, { type Express } from "express";
import type { Server } from "node:http";
import { config } from "./config/index.js";
import { createCorsMiddleware } from "./middleware/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { analyticsRouter } from "./routes/analytics.js";
import { attestationsRouter } from "./routes/attestations.js";
import { authRouter } from "./routes/auth.js";
import businessRoutes from "./routes/businesses.js";
import { healthRouter } from "./routes/health.js";
import integrationsRouter from "./routes/integrations.js";
import integrationsRazorpayRouter from "./routes/integrations-razorpay.js";
import { integrationsShopifyRouter } from "./routes/integrations-shopify.js";
import { integrationsStripeRouter } from "./routes/integrations-stripe.js";
import usersRouter from "./routes/users.js";
import { razorpayWebhookRouter } from "./routes/webhooks-razorpay.js";
import { StartupReadinessReport, runStartupDependencyReadinessChecks } from "./startup/readiness.js";

/**
 * Creates and configures the Express application.
 * 
 * @param readinessReport - Report from startup dependency checks.
 * @returns Configured Express app instance.
 */
export function createApp(readinessReport: StartupReadinessReport): Express {
  const app = express();

  // 1. Pre-processing & Observability
  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);
  app.use(createCorsMiddleware());
  app.use(requestLogger);

  // 2. Webhook Handlers
  // Note: These must be mounted before express.json() if they require raw body access.
  app.use("/api/webhooks/razorpay", razorpayWebhookRouter);

  // 3. Body Parsing
  app.use(express.json());

  // 4. API Routes
  app.use("/api/analytics", analyticsRouter);
  app.use("/api/attestations", attestationsRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/businesses", businessRoutes);
  app.use("/api/health", healthRouter);
  app.use("/api/integrations", integrationsRouter);
  app.use("/api/integrations/razorpay", integrationsRazorpayRouter);
  app.use("/api/integrations/shopify", integrationsShopifyRouter);
  app.use("/api/integrations/stripe", integrationsStripeRouter);
  app.use("/api/users", usersRouter);

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