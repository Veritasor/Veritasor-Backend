import express from "express";
import cors from "cors";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { analyticsRouter } from "./routes/analytics.js";
import { authRouter } from "./routes/auth.js";
import { attestationsRouter } from "./routes/attestations.js";
import businessRoutes from "./routes/businesses.js";
import { healthRouter } from "./routes/health.js";

export const app = express();

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

app.use(errorHandler);
