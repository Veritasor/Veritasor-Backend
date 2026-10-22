import express, { type Express } from "express";
import http, { type Server } from "node:http";
import type { Server as HttpsServer } from "node:https";
import type { Request, Response, NextFunction } from "express";
import fs from "node:fs/promises";
import { config } from "./config/index.js";
import { CachePolicies, setCacheControl } from "./utils/cacheControl.js";
import { createCorsMiddleware } from "./middleware/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestLogger } from "./middleware/requestLogger.js";
import {
  apiVersionMiddleware,
  versionResponseMiddleware,
} from "./middleware/apiVersion.js";
import { securityHeaders } from "./middleware/securityHeaders.js";
import { compressionMiddleware } from "./middleware/compression.js";
import {
  applyRotatedTlsMaterial,
  mtlsMiddleware,
  registerMtlsServer,
} from "./middleware/mtls.js";
import { createGrpcWorkloadApiClient } from "./spiffe/workloadApiClient.js";
import { createSvidProvider, type SvidProvider } from "./spiffe/svidProvider.js";
import { metricsRegistry } from "./metrics.js";
import { startStatsdDualWriteIfEnabled } from "./services/metrics/statsdBootstrap.js";
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
import { formatCacheControl, CACHE_POLICIES } from "./utils/cachePolicy.js";
import { razorpayWebhookRouter } from "./routes/webhooks-razorpay.js";
import { webhookEgressIpsRouter } from "./routes/webhookEgressIps.js";
import { webhookSubscriptionsRouter } from "./routes/webhook-subscriptions.js";
import adminRouter from "./routes/admin.js";
import {
  runStartupDependencyReadinessChecks,
  StartupReadinessReport,
} from "./startup/readiness.js";
import { replayFailedSubmissions } from "./startup/replayFailedSubmissions.js";
import { initializeOpenTelemetry } from "./tracing.js";
import {
  startIdempotencySweeperIfNeeded,
  stopIdempotencySweeper,
} from "./middleware/idempotency.js";
import {
  startPgBouncerScraperIfNeeded,
} from "./services/pgbouncerScraper.js";

export { stopIdempotencySweeper };

/** Active SPIFFE SVID provider when mTLS uses the Workload API. */
let activeSvidProvider: SvidProvider | undefined;

export function stopSpiffeSvidProviderIfNeeded(): void {
  activeSvidProvider?.stop();
  activeSvidProvider = undefined;
}

export const telemetryReady = initializeOpenTelemetry();

import {
  prototypePollutionGuard,
  hasForbiddenKeys,
  hasForbiddenQuery,
} from "./middleware/prototypePollution.js";

// Security middleware to reject prototype pollution attempts
export const securityHeadersMiddleware = prototypePollutionGuard;

export function createApp(readinessReport: StartupReadinessReport): Express {
  const app = express();

  app.set("trust proxy", config.trustProxy);
  app.use(requestLogger);
  app.use(securityHeaders);
  app.use(securityHeadersMiddleware);
  app.use(mtlsMiddleware);
  app.use(apiVersionMiddleware);
  app.use(versionResponseMiddleware);

  app.use("/api/webhooks/razorpay", razorpayWebhookRouter);

  // 3. Body Parsing
  app.use(express.json());
  app.use(securityHeadersMiddleware);
  app.use(createCorsMiddleware());

  // Webhook subscription CRUD API (after body parsing)
  app.use("/api/v1/webhook-subscriptions", webhookSubscriptionsRouter);

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
  // Provider routers must be mounted before the generic integrations router.
  // The generic router declares `/:integrationId`, which would otherwise
  // shadow single-segment provider paths such as DELETE /api/integrations/razorpay.
  app.use("/api/integrations/razorpay", integrationsRazorpayRouter);
  app.use("/api/integrations/shopify", integrationsShopifyRouter);
  app.use("/api/integrations/stripe", integrationsStripeRouter);
  app.use("/api/integrations", integrationsRouter);
  app.use("/api/users", usersRouter);
  app.use("/api/v1/admin", adminRouter);
  app.use("/api/admin", adminRouter);

  app.get("/.well-known/jwks.json", async (_req: Request, res: Response) => {
    await jwksManager.ensureLoaded()

    const jwks = jwksManager.getJwksResponse()
    const etag = jwksManager.getEtag()
    const cacheSeconds = jwksManager.getCacheTtlSeconds()

    const jwksPolicy = CACHE_POLICIES.find((p) => p.name === 'jwks');
    res.set(
      "Cache-Control",
      jwksPolicy
        ? formatCacheControl(jwksPolicy.directives)
        : `public, max-age=${cacheSeconds}, stale-while-revalidate=60`,
    );
    res.set("ETag", etag)
    res.json(jwks)
  });

  // Webhook egress IP allow-list (issue #534)
  app.use(webhookEgressIpsRouter);

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

  // Start the PgBouncer stats scraper for real-time queue depth monitoring.
  await startPgBouncerScraperIfNeeded();

  // Start StatsD dual-write when enabled (opt-in, default off).
  startStatsdDualWriteIfEnabled();

  const application = createApp(readinessReport);
  const { attachAttestationStream } = await import("./ws/attestationStream.js");

  let server: Server | HttpsServer;
  const httpsServerRef: { current?: HttpsServer } = {};

  if (config.mtls.enabled) {
    const https = await import("node:https");
    let ca: Buffer;
    let cert: Buffer;
    let key: Buffer;

    if (config.mtls.spiffe.enabled) {
      const svidProvider = createSvidProvider({
        trustDomain: config.mtls.spiffe.trustDomain,
        client: createGrpcWorkloadApiClient({
          socketAddress: config.mtls.spiffe.workloadApiSocket,
        }),
        refreshRatio: config.mtls.spiffe.refreshRatio,
        onRotate: (material) => {
          httpsServerRef.current?.setSecureContext({
            ca: material.ca,
            cert: material.cert,
            key: material.key,
            requestCert: true,
            rejectUnauthorized: false,
          });
        },
      });
      await svidProvider.start();
      activeSvidProvider = svidProvider;
      ({ ca, cert, key } = svidProvider.getTlsMaterial());
    } else {
      [ca, cert, key] = await Promise.all([
        fs.readFile(config.mtls.caPath!),
        fs.readFile(config.mtls.certPath!),
        fs.readFile(config.mtls.keyPath!),
      ]);
    }

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
    httpsServerRef.current = server as HttpsServer;
    if (!config.mtls.spiffe.enabled) {
      registerMtlsServer(httpsServerRef.current);
    }
  } else {
    // Create regular HTTP server
    server = http.createServer(application);
  }

  attachAttestationStream(server);

  return new Promise<Server | HttpsServer>((resolve, reject) => {
    const onError = (err: Error) => {
      server.removeListener("listening", onListening);
      reject(err);
    };

    const onListening = () => {
      server.removeListener("error", onError);
      console.log(`[Server] Veritasor Backend listening on port ${port} (mTLS: ${config.mtls.enabled})`);
      resolve(server);
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port);
  });
}
