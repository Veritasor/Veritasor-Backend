/**
 * Health check endpoint.
 *
 * Reports DB and Redis connectivity when enabled via env:
 * - DATABASE_URL: if set, runs SELECT 1 (db: 'ok' | 'down')
 * - REDIS_URL: if set, runs PING (redis: 'ok' | 'down'). Optional; Redis down does not fail overall status.
 *
 * Deep Dependency Mode (via query param ?mode=deep):
 * - Additionally checks Soroban RPC connectivity (soroban: 'ok' | 'down')
 * - Additionally checks Email service connectivity (email: 'ok' | 'down')
 * - Deep mode failures result in "unhealthy" status (503)
 *
 * Uses timeouts (default 2s each) to keep response time low.
 *
 * @security - No sensitive data exposed; all checks use read-only operations
 * @rate_limit - Not subject to rate limiting (health checks should be lightweight)
 */
import { Router, Request, Response } from "express";
import { z } from "zod";

/**
 * Stable JSON schema for health check response.
 * Used for validation and documentation of the load balancer probe contract.
 */
export const HealthDependencyStatusSchema = z.enum(["ok", "down"]);

export const HealthResponseSchema = z.object({
  status: z.enum(["ok", "degraded", "unhealthy"]),
  service: z.literal("veritasor-backend"),
  timestamp: z.string().datetime(),
  mode: z.enum(["shallow", "deep"]),
  db: HealthDependencyStatusSchema.optional(),
  redis: HealthDependencyStatusSchema.optional(),
  soroban: HealthDependencyStatusSchema.optional(),
  email: HealthDependencyStatusSchema.optional(),
});

export type HealthResponse = z.infer<typeof HealthResponseSchema>;

const PING_TIMEOUT_MS = 2000;

/**
 * Utility to wrap a promise with a timeout.
 * @param p - Promise to race against timeout
 * @param ms - Timeout in milliseconds
 * @returns Promise that resolves with p result or rejects on timeout
 */
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), ms),
    ),
  ]);
}

/**
 * Check database connectivity by executing a simple SELECT 1 query.
 * @returns Promise resolving to 'ok', 'down', or undefined if DATABASE_URL not set
 */
async function checkDb(): Promise<"ok" | "down" | undefined> {
  const url = process.env.DATABASE_URL;
  if (!url) return undefined;
  try {
    const { default: pg } = await import("pg");
    const client = new pg.Client({ connectionString: url });
    await withTimeout(
      (async () => {
        await client.connect();
        try {
          await client.query("SELECT 1");
          return;
        } finally {
          await client.end();
        }
      })(),
      PING_TIMEOUT_MS,
    );
    return "ok";
  } catch {
    return "down";
  }
}

/**
 * Check Redis connectivity by executing a PING command.
 * @returns Promise resolving to 'ok', 'down', or undefined if REDIS_URL not set
 */
async function checkRedis(): Promise<"ok" | "down" | undefined> {
  const url = process.env.REDIS_URL;
  if (!url) return undefined;
  try {
    // @ts-expect-error redis is an optional dependency
    const redisModule = await import("redis");
    const createClient = redisModule.createClient;
    const client = createClient({ url });
    await withTimeout(
      (async () => {
        await client.connect();
        try {
          await client.ping();
        } finally {
          await client.quit();
        }
      })(),
      PING_TIMEOUT_MS,
    );
    return "ok";
  } catch {
    return "down";
  }
}

/**
 * Check Soroban RPC connectivity by attempting to get network status.
 * Only runs if SOROBAN_RPC_URL is configured.
 * @returns Promise resolving to 'ok', 'down', or undefined if SOROBAN_RPC_URL not set
 */
async function checkSoroban(): Promise<"ok" | "down" | undefined> {
  const rpcUrl = process.env.SOROBAN_RPC_URL;
  if (!rpcUrl) return undefined;
  try {
    // Dynamic import to handle optional dependency
    // Try to load soroban-client; if not available, mark as down
    let SorobanClient: any;
    try {
      // @ts-expect-error soroban-client is an optional dependency
      SorobanClient = await import("soroban-client");
    } catch {
      // Module not installed - treat as unavailable
      return undefined;
    }
    if (!SorobanClient?.default) {
      return undefined;
    }
    const server = new SorobanClient.default.Server(rpcUrl, {
      allowHttp: rpcUrl.startsWith("http://"),
    });
    await withTimeout(server.getHealth(), PING_TIMEOUT_MS);
    return "ok";
  } catch {
    return "down";
  }
}

/**
 * Check Email service connectivity by attempting to ping the SMTP server.
 * Only runs if SMTP_HOST is configured.
 * @returns Promise resolving to 'ok', 'down', or undefined if SMTP_HOST not set
 */
async function checkEmail(): Promise<"ok" | "down" | undefined> {
  const smtpHost = process.env.SMTP_HOST;
  if (!smtpHost) return undefined;
  try {
    // Simple SMTP connection check - only verify host is reachable
    // We don't actually send email, just verify basic connectivity
    const smtpPort = parseInt(process.env.SMTP_PORT || "587", 10);

    // Use Node.js net module to check if SMTP port is open
    const net = await import("net");

    return new Promise<"ok" | "down">((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(PING_TIMEOUT_MS);

      socket.on("connect", () => {
        socket.destroy();
        resolve("ok");
      });

      socket.on("timeout", () => {
        socket.destroy();
        resolve("down");
      });

      socket.on("error", () => {
        socket.destroy();
        resolve("down");
      });

      socket.connect(smtpPort, smtpHost);
    });
  } catch {
    return "down";
  }
}

/**
 * Health check result body interface.
 */
interface HealthResponseBody {
  status: string;
  service: string;
  timestamp: string;
  mode?: "shallow" | "deep";
  db?: "ok" | "down";
  redis?: "ok" | "down";
  soroban?: "ok" | "down";
  email?: "ok" | "down";
}

export const healthRouter = Router();

/**
 * GET /health
 *
 * Basic health check: Checks database and Redis connectivity.
 * Query params:
 *   - mode: 'deep' to enable deep dependency mode (checks Soroban, Email)
 *
 * @security - No authentication required; designed for load balancers and orchestrators
 * @response 200 - All configured dependencies are healthy
 * @response 503 - One or more critical dependencies are down (in deep mode)
 */
healthRouter.get("/", async (req: Request, res: Response) => {
  const mode = (req.query.mode as string) || "shallow";
  const isDeepMode = mode === "deep";

  // Run basic checks
  const [db, redis] = await Promise.all([checkDb(), checkRedis()]);

  // Run deep checks if requested
  let soroban: "ok" | "down" | undefined;
  let email: "ok" | "down" | undefined;

  if (isDeepMode) {
    [soroban, email] = await Promise.all([checkSoroban(), checkEmail()]);
  }

  // Determine overall status
  // Basic mode: DB down = degraded, Redis down = still ok
  // Deep mode: Any critical dependency down = unhealthy (503)
  let status: string;
  let statusCode = 200;

  if (isDeepMode) {
    // Deep mode: any down = unhealthy
    const isDbDown = db === "down";
    const isSorobanDown = soroban === "down";
    const isEmailDown = email === "down";
    const criticalDown = isDbDown || isSorobanDown || isEmailDown;
    if (criticalDown) {
      status = "unhealthy";
      statusCode = 503;
    } else if (isDbDown || redis === "down" || isSorobanDown || isEmailDown) {
      status = "degraded";
      statusCode = 200;
    } else {
      status = "ok";
    }
  } else {
    // Shallow mode: only DB down causes degraded status
    status = db === "down" ? "degraded" : "ok";
  }

  const body: HealthResponseBody = {
    status,
    service: "veritasor-backend",
    timestamp: new Date().toISOString(),
    mode: isDeepMode ? "deep" : "shallow",
  };

  if (db !== undefined) body.db = db;
  if (redis !== undefined) body.redis = redis;
  if (isDeepMode) {
    if (soroban !== undefined) body.soroban = soroban;
    if (email !== undefined) body.email = email;
  }

  res.status(statusCode).json(body);
});
