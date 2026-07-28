import express, { type Express } from "express";
import type { Server } from "node:http";
import type { Server as HttpsServer } from "node:https";
import type { Request, Response, NextFunction } from "express";
import fs from "node:fs/promises";
import { config } from "./config/index.js";
import { createCorsMiddleware } from "./middleware/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import {
  apiVersionMiddleware,
  versionResponseMiddleware,
} from "./middleware/apiVersion.js";
import { securityHeaders } from "./middleware/securityHeaders.js";
import { compressionMiddleware } from "./middleware/compression.js";
import { mtlsMiddleware } from "./middleware/mtls.js";
import { metricsRegistry } from "./metrics.js";
import { analyticsRouter } from "./routes/analytics.js";
import { attestationsRouter } from "./routes/attestations.js";
import { authRouter } from "./routes/auth.js";
import businessRoutes from "./routes/businesses.js";
import { healthRouter } from "./routes/health.js";
import integrationsRouter from "./routes/integrations.js";
import integrationsRazorpayRouter from "./routes/integrations-razorpay.js";
import { integrationsShopifyRouter } from "./routes/integrations-shopify.js";
import { integrationsStripeRouter } from "./routes/integrations-stripe.js";
import { publicAttestationsRouter } from "./routes/publicAttestations.js";
import usersRouter from "./routes/users.js";
import { jwksManager } from "./utils/jwks.js";
import { razorpayWebhookRouter } from "./routes/webhooks-razorpay.js";
import adminRouter from "./routes/admin.js";
import adminGraphqlRouter from "./routes/admin.graphql.js";
import {
  runStartupDependencyReadinessChecks,
  StartupReadinessReport,
} from "./startup/readiness.js";
import { replayFailedSubmissions } from "./startup/replayFailedSubmissions.js";
import { initializeOpenTelemetry } from "./tracing.js";
import {
  startIdempotencySweeper,
  type IdempotencySweeperHandle,
} from "./middleware/idempotency.js";
import {
  startDlqAgeScanner,
  type DlqAgeScannerHandle,
} from "./services/webhooks/deadLetterQueue.js";

/**
 * Handle to the running idempotency sweeper, if one was started. Stored
 * at module scope so the production boot path and tests can share a
 * single instance, and so `stopIdempotencySweeper()` is idempotent.
 */
let idempotencySweeperHandle: IdempotencySweeperHandle | null = null;

/**
 * Start the application-wide idempotency TTL sweeper.
 *
 * No-op in test environments so unit tests can drive `runOnce()` and
 * timer injection without racing a real interval.
 */
export async function startIdempotencySweeperIfNeeded(): Promise<IdempotencySweeperHandle | null> {
  if (process.env.NODE_ENV === 'test') return null;
  if (idempotencySweeperHandle) return idempotencySweeperHandle;
  idempotencySweeperHandle = await startIdempotencySweeper();
  return idempotencySweeperHandle;
}

/**
 * Stop the application-wide idempotency TTL sweeper, if one was started.
 * Safe to call multiple times.
 */
export async function stopIdempotencySweeper(): Promise<void> {
  if (!idempotencySweeperHandle) return;
  await idempotencySweeperHandle.stop();
  idempotencySweeperHandle = null;
}

let dlqAgeScannerHandle: DlqAgeScannerHandle | null = null;

export function startDlqAgeScannerIfNeeded(): DlqAgeScannerHandle | null {
  if (process.env.NODE_ENV === 'test') return null;
  if (dlqAgeScannerHandle) return dlqAgeScannerHandle;
  dlqAgeScannerHandle = startDlqAgeScanner();
  return dlqAgeScannerHandle;
}

export function stopDlqAgeScanner(): void {
  if (!dlqAgeScannerHandle) return;
  dlqAgeScannerHandle.stop();
  dlqAgeScannerHandle = null;
}

export const telemetryReady = initializeOpenTelemetry();

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

  app.use(requestLogger);
  app.use(securityHeaders);
  app.use(securityHeadersMiddleware);
  app.use(mtlsMiddleware);
  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);

  app.use("/api/webhooks/razorpay", razorpayWebhookRouter);

  // 3. Body Parsing
  app.use(express.json());
  app.use(createCorsMiddleware());

  // Response compression (brotli preferred, gzip fallback) with a BREACH guard
  // that refuses to compress responses carrying CSRF tokens or session cookies.
  app.use(compressionMiddleware());

  if (process.env.METRICS_ENABLED === "true") {
    app.get("/metrics", async (_req: Request, res: Response) => {
      res.set("Content-Type", metricsRegistry.contentType);
      res.end(await metricsRegistry.metrics());
    });
  }

  app.use("/api/analytics", analyticsRouter);
  app.use("/api/v1/public/attestations", publicAttestationsRouter);
  app.use("/api/attestations", attestationsRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/businesses", businessRoutes);
  app.use("/api/health", healthRouter);
  app.use("/api/integrations", integrationsRouter);
  app.use("/api/integrations/razorpay", integrationsRazorpayRouter);
  app.use("/api/integrations/shopify", integrationsShopifyRouter);
  app.use("/api/integrations/stripe", integrationsStripeRouter);
  app.use("/api/users", usersRouter);
  app.use("/api/v1/admin", adminRouter);
  app.use("/api/admin", adminRouter);
  app.use("/api/v1/admin", adminGraphqlRouter);

  app.get("/.well-known/jwks.json", async (_req: Request, res: Response) => {
    await jwksManager.ensureLoaded()

    const jwks = jwksManager.getJwksResponse()
    const etag = jwksManager.getEtag()
    const cacheSeconds = jwksManager.getCacheTtlSeconds()

    res.set("Cache-Control", `public, max-age=${cacheSeconds}, stale-while-revalidate=60`)
    res.set("ETag", etag)
    res.json(jwks)
  });

  // 5. Error Handling
  app.use(errorHandler);

  return app;
}

/**
 * Synchronous application instance for test environments.
 * Uses a default "ready" report to skip async boot complexity in unit tests.
 */
export const app = createApp({ ready: true, checks: [] });

/**
 * Production server entry point.
 * Runs readiness checks before starting the listener.
 * 
 * @param port - Port to listen on.
 * @returns A promise that resolves to the started HTTP/HTTPS server.
 */
export async function startServer(port: number): Promise<Server | HttpsServer> {
  await telemetryReady;

  // Switch to the persistent DB-backed token store for production deployments.
  // This must happen before any refresh requests are handled so that rotation
  // protection is shared across all instances and survives restarts.
  const { DbUsedTokenStore, setUsedTokenStore } = await import('./services/auth/usedTokenStore.js')
  setUsedTokenStore(new DbUsedTokenStore())

  const readinessReport = await runStartupDependencyReadinessChecks();

  if (!readinessReport.ready) {
    const failedChecks = readinessReport.checks
      .filter((check) => !check.ready)
      .map((check) => `${check.dependency}: ${check.reason ?? "failed"}`)
      .join("; ");
    console.warn(`[Startup] Proceeding with failed readiness checks: ${failedChecks}`);
  }

  replayFailedSubmissions().catch((err) => {
    console.warn(`[Startup] Failed submission replay encountered an error: ${err instanceof Error ? err.message : String(err)}`);
  });

  // Start the cooperative idempotency TTL sweeper. This drives the
  // `idempotency_keys_count` gauge and `idempotency_evictions_total`
  // counter, and is safe to run alongside the request path: its
  // interval is unref'd and its `runOnce()` swallows store errors.
  await startIdempotencySweeperIfNeeded();

  startDlqAgeScannerIfNeeded();

  const application = createApp(readinessReport);
  const { attachAttestationStream } = await import("./ws/attestationStream.js");

  return new Promise(async (resolve) => {
    let server: Server | HttpsServer;

    if (config.mtls.enabled) {
      // Load mTLS certificates
      const [ca, cert, key] = await Promise.all([
        fs.readFile(config.mtls.caPath!),
        fs.readFile(config.mtls.certPath!),
        fs.readFile(config.mtls.keyPath!),
      ]);

      // Create HTTPS server with mTLS
      const https = await import("node:https");
      server = https.createServer(
        {
          ca,
          cert,
          key,
          requestCert: true,
          rejectUnauthorized: false, // We handle rejection in middleware
        },
        application
      );
    } else {
      // Create regular HTTP server
      server = application.listen(port);
    }

    server.listen(port, () => {
      console.log(`[Server] Veritasor Backend listening on port ${port} (mTLS: ${config.mtls.enabled})`);
      resolve(server);
    });
    attachAttestationStream(server);
  });
}
