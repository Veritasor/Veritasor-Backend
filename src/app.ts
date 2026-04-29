import express, { type Express } from "express";
import type { Server } from "node:http";
import type { Request, Response, NextFunction } from "express";
import { config } from "./config/index.js";
import { createCorsMiddleware } from "./middleware/cors.js";
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
import { StartupReadinessReport } from "./startup/readiness.js";

const apiVersionMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const requestedVersion = req.headers['x-api-version'];
  const supportedVersions = ['1', 'v1'];

  if (!requestedVersion) {
    res.setHeader('api-version', 'v1');
    next();
    return;
  }

  const versionStr = String(requestedVersion);
  const isSupported = supportedVersions.some(v => v === versionStr);

  if (!isSupported) {
    res.setHeader('api-version', 'v1');
    res.setHeader('api-version-fallback', 'true');
  } else {
    res.setHeader('api-version', 'v1');
  }

  next();
};

const versionResponseMiddleware = (req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Vary', 'Accept, X-API-Version');
  next();
};

// Security middleware to reject prototype pollution attempts
const securityHeadersMiddleware = (req: Request, res: Response, next: NextFunction) => {
  if (req.query && Object.keys(req.query).some(key => key === '__proto__' || key === 'constructor' || key === 'prototype')) {
    res.status(400).json({
      status: 'error',
      code: 'VALIDATION_ERROR',
      message: 'Invalid query parameters'
    });
    return;
  }

  if (req.body && typeof req.body === 'object') {
    if (Object.keys(req.body).some(key => key === '__proto__' || key === 'constructor' || key === 'prototype')) {
      res.status(400).json({
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Invalid body fields'
      });
      return;
    }
  }

  next();
};

export function createApp(readinessReport: StartupReadinessReport): Express {
  const app = express();

  app.use(securityHeadersMiddleware);
  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);

  app.use(express.json());
  app.use(createCorsMiddleware());
  app.use(requestLogger);

  app.use("/api/webhooks/razorpay", razorpayWebhookRouter);
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

export const app = createApp({ ready: true, checks: [] });

export async function startServer(port: number): Promise<Server> {
  const { runStartupDependencyReadinessChecks } = await import("./startup/readiness.js");

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
      resolve(server);
    });
  });
}