import express, { type Express } from "express";
import cors from "cors";
import type { Server } from "node:http";
import { config } from "./config/index.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { analyticsRouter } from "./routes/analytics.js";
import { authRouter } from "./routes/auth.js";
import { attestationsRouter } from "./routes/attestations.js";
import businessRoutes from "./routes/businesses.js";
import { healthRouter } from "./routes/health.js";
import integrationsRouter from "./routes/integrations.js";
import integrationsRazorpayRouter from "./routes/integrations-razorpay.js";
import { runStartupDependencyReadinessChecks } from "./startup/readiness.js";

export function createApp(): Express {
  const app = express();

  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);
  app.use(cors());
  app.use(express.json());
  app.use(requestLogger);

  app.use("/api/health", healthRouter);
  app.use("/api/attestations", attestationsRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/businesses", businessRoutes);
  app.use("/api/analytics", analyticsRouter);
  app.use("/api/integrations", integrationsRouter);
  app.use("/api/integrations/razorpay", integrationsRazorpayRouter);

  app.use(errorHandler);

  return app;
}

export async function startServer(port: number): Promise<Server> {
  // Check startup readiness
  const readinessReport = await runStartupDependencyReadinessChecks();
  if (!readinessReport.ready) {
    const failedChecks = readinessReport.checks
      .filter((check) => !check.ready)
      .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
      .join("; ");
    throw new Error(`Startup checks failed: ${failedChecks}`);
  }

  const app = createApp();

  return app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}
