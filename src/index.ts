import "dotenv/config";
import express from "express";
import cors from "cors";
import { config } from "./config/index.js";
import { attestationsRouter } from "./routes/attestations.js";
import { healthRouter } from "./routes/health.js";
import { integrationsShopifyRouter } from "./routes/integrations-shopify.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import { analyticsRouter } from "./routes/analytics.js";
import { authRouter } from "./routes/auth.js";
import {
  apiVersionMiddleware,
  versionResponseMiddleware,
} from "./middleware/apiVersion.js";
import businessRoutes from "./routes/businesses.js";
import integrationsRazorpayRouter from "./routes/integrations-razorpay.js";
import integrationsRouter from "./routes/integrations.js";

export const app = express();
const PORT = process.env.PORT ?? 3000;

app.use(apiVersionMiddleware);
app.use(versionResponseMiddleware);
app.use(cors());
app.use(express.json());

// log each request before handing off to the routers
app.use(requestLogger);

app.use("/api/health", healthRouter);
app.use("/api/attestations", attestationsRouter);
app.use("/api/businesses", businessRoutes);
app.use("/api/analytics", analyticsRouter);
app.use("/api/integrations/razorpay", integrationsRazorpayRouter);
app.use("/api/integrations", integrationsRouter);

app.use(errorHandler);

if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    console.log(`Veritasor API listening on http://localhost:${PORT}`);
  });
}
