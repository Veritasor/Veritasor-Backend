import express, { type Express } from "express";
import cors from "cors";
import { runStartupDependencyReadinessChecks } from "./startup/readiness.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { analyticsRouter } from "./routes/analytics.js";
import { authRouter } from "./routes/auth.js";
import { attestationsRouter } from "./routes/attestations.js";
import businessRoutes from "./routes/businesses.js";
import { healthRouter } from "./routes/health.js";
import adminRouter from "./routes/admin.js";
import { StartupReadinessReport } from "./startup/readiness.js";
import type { Server } from "http";

/**
 * Creates and configures the Express application.
 *
 * @param readinessReport - Startup readiness check results
 * @returns Configured Express application
 */
export function createApp(readinessReport: StartupReadinessReport): Express {
  const app = express();

  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);
  app.use(cors());
  app.use(express.json());
  app.use(requestLogger);

  app.use("/api/health", healthRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/attestations", attestationsRouter);
  app.use("/api/businesses", businessRoutes);
  app.use("/api/analytics", analyticsRouter);
  app.use("/api/admin", adminRouter);

  app.use(errorHandler);

  return app;
}

/**
 * Starts the HTTP server with the configured Express application.
 *
 * @param port - Port to listen on
 * @returns Promise that resolves when server is listening
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

  const app = createApp(readinessReport);
  
  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      console.log(`[Server] Listening on port ${port}`);
      resolve(server);
    });
  });
}
