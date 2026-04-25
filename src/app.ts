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

export const app: Express = express();

app.use(apiVersionMiddleware);
app.use(versionResponseMiddleware);
app.use(cors());
app.use(express.json());
app.use(requestLogger);

// Routes
app.use("/api/health", healthRouter);
app.use("/api/auth", authRouter);
app.use("/api/attestations", attestationsRouter);
app.use("/api/businesses", businessRoutes);
app.use("/api/analytics", analyticsRouter);
app.use("/api/admin", adminRouter);

app.use(errorHandler);

export async function startServer(port: number) {
  const readinessReport = await runStartupDependencyReadinessChecks();
  
  if (!readinessReport.ready) {
    const failedChecks = readinessReport.checks
      .filter((check) => !check.ready)
      .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
      .join("; ");
    console.warn(`[Startup] Proceeding with failed readiness checks: ${failedChecks}`);
  }

  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      console.log(`[Server] Listening on port ${port}`);
      resolve(server);
    });
  });
}
