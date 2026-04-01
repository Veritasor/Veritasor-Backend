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
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { errorHandler } from "./middleware/errorHandler.js";

  if (!readinessReport.ready) {
    const failedChecks = readinessReport.checks
      .filter((check) => !check.ready)
      .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
      .join("; ");

app.use(apiVersionMiddleware);
app.use(versionResponseMiddleware);
app.use(cors());
app.use(express.json());
app.use(requestLogger);

app.use("/api/health", healthRouter);
app.use("/api/attestations", attestationsRouter);
app.use(errorHandler);
