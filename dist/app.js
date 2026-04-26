import express from "express";
import cors from "cors";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { attestationsRouter } from "./routes/attestations.js";
import { healthRouter } from "./routes/health.js";
/**
 * Creates and configures the Express application.
 *
 * @param readinessReport - Startup readiness check results
 * @returns Configured Express application
 */
export function createApp(readinessReport) {
    const app = express();
    if (!readinessReport.ready) {
        const failedChecks = readinessReport.checks
            .filter((check) => !check.ready)
            .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
            .join("; ");
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
