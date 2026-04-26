import express, { type Express } from "express";
import type { Server } from "node:http";
import { config } from "./config/index.js";
import { createCorsMiddleware } from "./middleware/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { analyticsRouter } from "./routes/analytics.js";
import { authRouter } from "./routes/auth.js";
import { attestationsRouter } from "./routes/attestations.js";
import businessRoutes from "./routes/businesses.js";
import { healthRouter } from "./routes/health.js";
import { StartupReadinessReport } from "./startup/readiness.js";

/**
 * Creates and configures the Express application.
 *
 * @param readinessReport - Startup readiness check results
 * @returns Configured Express application
 */
export function createApp(readinessReport: StartupReadinessReport): Express {
  const app = express();

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
  app.use(cors());
  app.use(express.json());
  app.use(requestLogger);

  app.use("/api/health", healthRouter);
  app.use("/api/attestations", attestationsRouter);
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
  const { runStartupDependencyReadinessChecks } = await import("./startup/readiness.js");
  
  const readinessReport = await runStartupDependencyReadinessChecks();
  const app = createApp(readinessReport);
  
  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      console.log(`Server listening on port ${port}`);
      resolve(server);
    });
  });
}
