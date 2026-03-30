import express from "express";
import cors from "cors";
import { attestationsRouter } from "./routes/attestations.js";
import { healthRouter } from "./routes/health.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
import { errorHandler } from "./middleware/errorHandler.js";

export const app = express();

app.use(apiVersionMiddleware);
app.use(versionResponseMiddleware);
app.use(cors());
app.use(express.json());
app.use(requestLogger);

app.use("/api/health", healthRouter);
app.use("/api/attestations", attestationsRouter);
app.use(errorHandler);
