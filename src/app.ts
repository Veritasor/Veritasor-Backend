import express, { type Express } from "express";
import type { Server } from "node:http";
import { config } from "./config/index.js";
import { createCorsMiddleware } from "./middleware/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
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
import { StartupReadinessReport } from "./startup/readiness.js";
import type { Server } from "http";

export function createApp(readinessReport: StartupReadinessReport): Express {
  const app = express();



import { runStartupDependencyReadinessChecks } from "./startup/readiness.js";

export async function startServer(port: number): Promise<Server> {
  // Run startup dependency checks
  const readinessReport = await runStartupDependencyReadinessChecks();
  if (!readinessReport.ready) {
    const failedChecks = readinessReport.checks
      .filter((check) => !check.ready)
      .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
      .join("; ");
    console.warn(`Warning: Startup dependency checks failed: ${failedChecks}`);
  }

    // Log failed checks but continue with app creation
    console.error(`Startup readiness checks failed: ${failedChecks}`);
  }

  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);
  app.use(cors(config.cors));
  app.use(requestLogger);

  // Webhook signature verification depends on the exact raw bytes.
  app.use("/api/webhooks/razorpay", razorpayWebhookRouter);

  app.use(express.json());

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

  app.use(errorHandler);

  return app;
}

export const app = createApp({ ready: true, checks: [] });

export async function startServer(port: number): Promise<Server> {
  const { runStartupDependencyReadinessChecks } = await import("./startup/readiness.js");

  const readinessReport = await runStartupDependencyReadinessChecks();
  
  if (!readinessReport.ready) {
    const failedChecks = readinessReport.checks
      .filter((check) => !check.ready)
      .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
      .join("; ");
    console.warn(`[Startup] Proceeding with failed readiness checks: ${failedChecks}`);
  }

  const app = createApp(readinessReport);

  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      resolve(server);
    });
  });
}
     