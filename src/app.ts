import cors from "cors";
import express, { type Express } from "express";
import type { Server } from "node:http";
import { config } from "./config/index.js";
import { apiVersionMiddleware, versionResponseMiddleware } from "./middleware/apiVersion.js";
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

export function createApp(): Express {
  const app = express();

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

export const app = createApp();

export async function startServer(port: number): Promise<Server> {
  return await new Promise((resolve) => {
    const server = app.listen(port, () => {
      resolve(server);
    });
  });
}
