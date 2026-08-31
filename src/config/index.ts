import { z } from "zod";
import { logger } from "../utils/logger.js";

export class ConfigValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigValidationError";
  }
}

export const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  ALLOWED_ORIGINS: z.string().optional(),
  JWT_SECRET: z.string().optional(),
  DATABASE_URL: z.string({
    required_error: "DATABASE_URL environment variable is required",
    invalid_type_error: "DATABASE_URL environment variable is required",
  }).url("DATABASE_URL must be a valid URL"),
  DATABASE_SESSION_URL: z.string().url("DATABASE_SESSION_URL must be a valid URL").optional(),
  PGPOOL_MAX: z.string().optional(),
  PG_IDLE_TIMEOUT_MS: z.string().optional(),
  PG_CONN_TIMEOUT_MS: z.string().optional(),
  PGSSL: z.string().optional(),
  PGSSL_REJECT_UNAUTHORIZED: z.string().optional(),
  PGBOUNCER_METRICS_ADMIN_URL: z.string().url(
    "PGBOUNCER_METRICS_ADMIN_URL must be a valid URL",
  ).refine(
    (value) => value.startsWith("postgres://") || value.startsWith("postgresql://"),
    "PGBOUNCER_METRICS_ADMIN_URL must use postgres or postgresql",
  ).optional(),
  PGBOUNCER_METRICS_SCRAPE_INTERVAL_MS: z.string().optional(),
  PGBOUNCER_METRICS_QUERY_TIMEOUT_MS: z.string().optional(),
  STELLAR_NETWORK: z.enum(["testnet", "public", "futurenet"]).default("testnet"),
  SOROBAN_RPC_URL: z.string().url().default("https://soroban-testnet.stellar.org"),
  SOROBAN_CONTRACT_ID: z.string().default(""),
  SOROBAN_NETWORK_PASSPHRASE: z.string().default("Test SDF Network ; September 2015"),
  SOROBAN_RETRY_BUDGET_MAX_RETRIES: z.string().optional(),
  SOROBAN_REPLAY_MAX_AGE_DAYS: z.string().optional(),
  SOROBAN_ADAPTIVE_BATCH_MIN_SIZE: z.string().optional(),
  SOROBAN_ADAPTIVE_BATCH_MAX_SIZE: z.string().optional(),
  SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA: z.string().optional(),
  SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER: z.string().optional(),
  SOROBAN_ADAPTIVE_BATCH_SENSITIVITY: z.string().optional(),
  SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING: z.string().optional(),
  SOROBAN_ADAPTIVE_BATCH_SAMPLE_INTERVAL_MS: z.string().optional(),
  DRR_SCHEDULER_TIER_WEIGHTS: z.string().optional(),
  DRR_SCHEDULER_QUANTUM: z.string().optional(),
  SECRET_LOADER: z.enum(["env", "file", "vault", "aws", "gsm"]).default("env"),
  SECRET_FILE_PATH: z.string().optional(),
  SECRET_CACHE_KMS_KEY_ID: z.string().optional(),
  SECRET_CACHE_PATH: z.string().optional(),
  SECRET_CACHE_TTL_MINUTES: z.string().optional(),
  VAULT_BASE_URL: z.string().url().optional(),
  VAULT_SECRET_PATH: z.string().optional(),
  VAULT_TOKEN: z.string().optional(),
  ROLE_PROMOTION_TTL_MINUTES: z.string().optional(),
  ENABLE_INTROSPECTION: z.string().optional(),
  GRAPHQL_DEV_BYPASS: z.string().optional(),
  ALLOW_ARBITRARY_OPERATIONS: z.string().optional(),
  PERSISTED_QUERY_SECRET: z.string().optional(),
  STATSD_HOST: z.string().optional(),
  STATSD_PORT: z.string().optional(),
  STATSD_PREFIX: z.string().optional(),
  STATSD_DUAL_WRITE_ENABLED: z.string().optional(),
  STATSD_DUAL_WRITE_INTERVAL_MS: z.string().optional(),
  OTEL_EXPORTER_PROTOCOL: z.enum(["http", "grpc"]).default("http"),
  OTEL_GRPC_MTLS_ENABLED: z.string().optional(),
  OTEL_MTLS_CA_PATH: z.string().optional(),
  OTEL_MTLS_CERT_PATH: z.string().optional(),
  OTEL_MTLS_KEY_PATH: z.string().optional(),
}).superRefine((data, ctx) => {
  if (data.NODE_ENV === "production") {
      if (!data.ALLOWED_ORIGINS || data.ALLOWED_ORIGINS.trim() === "") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "ALLOWED_ORIGINS must be set in production",
          path: ["ALLOWED_ORIGINS"]
        });
      }

      if (data.SECRET_LOADER === 'env') {
        if (!data.JWT_SECRET || data.JWT_SECRET.length < 32) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "JWT_SECRET must be at least 32 characters in production",
            path: ["JWT_SECRET"]
          });
        }
      }

      if (data.SECRET_LOADER === 'file' && !data.SECRET_FILE_PATH) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "SECRET_FILE_PATH is required when SECRET_LOADER=file",
          path: ["SECRET_FILE_PATH"]
        });
      }

      if (data.SECRET_LOADER === 'vault') {
        if (!data.VAULT_BASE_URL) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "VAULT_BASE_URL is required when SECRET_LOADER=vault",
            path: ["VAULT_BASE_URL"]
          });
        }
        if (!data.VAULT_SECRET_PATH) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "VAULT_SECRET_PATH is required when SECRET_LOADER=vault",
            path: ["VAULT_SECRET_PATH"]
          });
        }
      }
    }
});

const TRUE_VALUES = new Set(["true", "1", "yes", "on"]);
const FALSE_VALUES = new Set(["false", "0", "no", "off"]);

function parseBooleanEnv(name: string, rawValue: string | undefined, defaultValue: boolean): boolean {
  if (rawValue === undefined) {
    return defaultValue;
  }

  const normalized = rawValue.trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) {
    return true;
  }
  if (FALSE_VALUES.has(normalized)) {
    return false;
  }

  throw new ConfigValidationError(
    `${name} must be a boolean value (true/false, 1/0, yes/no, on/off)`,
  );
}

function parsePositiveIntEnv(name: string, rawValue: string | undefined, defaultValue: number): number {
  if (rawValue === undefined) {
    return defaultValue;
  }

  const value = Number.parseInt(rawValue.trim(), 10);
  if (!Number.isInteger(value) || value <= 0) {
    throw new ConfigValidationError(`${name} must be a positive integer`);
  }

  return value;
}

function parseDecimalEnv(name: string, rawValue: string | undefined, defaultValue: number, min: number, max: number): number {
  if (rawValue === undefined) {
    return defaultValue;
  }

  const value = Number(rawValue);
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new ConfigValidationError(`${name} must be a number between ${min} and ${max}`);
  }

  return value;
}

let parsedEnv: z.infer<typeof envSchema>;

try {
  // Try parsing the environment variables
  parsedEnv = envSchema.parse(process.env);
} catch (error) {
  if (error instanceof z.ZodError) {
    logger.error("Configuration validation failed", JSON.stringify(error.format()));
    const message = error.issues.map((issue) => issue.message).join("; ");
    throw new ConfigValidationError(`Invalid environment configuration: ${message}`);
  }
  throw error;
}

const isProduction = parsedEnv.NODE_ENV === "production";

if (parsedEnv.NODE_ENV === "development" && !parsedEnv.JWT_SECRET) {
  logger.warn("JWT_SECRET is missing in development. Using a default unsafe secret.");
  parsedEnv.JWT_SECRET = "default_dev_secret_for_local_testing_only";
}

/**
 * CORS allowed origins.
 * - Dev: * (allow all) unless ALLOWED_ORIGINS is set.
 * - Production: ALLOWED_ORIGINS (comma-separated), or [] if unset (strict).
 */
export function getAllowedOrigins(): string | string[] {
  const raw = parsedEnv.ALLOWED_ORIGINS;
  if (raw) {
    return raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  if (isProduction) {
    return [];
  }
  return "*";
}

function parseCsvList(rawValue: string | undefined): string[] {
  if (!rawValue) return [];
  return rawValue.split(",").map((s) => s.trim()).filter(Boolean);
}

function parseMtlsConfig(parsedEnv: z.infer<typeof envSchema>) {
  const enabled = parseBooleanEnv("MTLS_ENABLED", parsedEnv.MTLS_ENABLED, false);
  const spiffeEnabled = parseBooleanEnv(
    "MTLS_SPIFFE_ENABLED",
    parsedEnv.MTLS_SPIFFE_ENABLED,
    false,
  );
  const trustDomain = parsedEnv.SPIFFE_TRUST_DOMAIN?.trim() ?? "";

  if (enabled && spiffeEnabled && !trustDomain) {
    throw new ConfigValidationError(
      "SPIFFE_TRUST_DOMAIN must be set when MTLS_SPIFFE_ENABLED=true",
    );
  }

  if (enabled && !spiffeEnabled) {
    const caPath = parsedEnv.MTLS_CA_PATH?.trim();
    const certPath = parsedEnv.MTLS_CERT_PATH?.trim();
    const keyPath = parsedEnv.MTLS_KEY_PATH?.trim();
    if (!caPath || !certPath || !keyPath) {
      throw new ConfigValidationError(
        "MTLS_CA_PATH, MTLS_CERT_PATH, and MTLS_KEY_PATH must be set when MTLS_ENABLED=true and MTLS_SPIFFE_ENABLED is not true",
      );
    }
  }

  return {
    enabled,
    cnAllowlist: parseCsvList(parsedEnv.MTLS_CN_ALLOWLIST),
    spiffeIdAllowlist: parseCsvList(parsedEnv.MTLS_SPIFFE_ID_ALLOWLIST),
    caPath: parsedEnv.MTLS_CA_PATH?.trim(),
    certPath: parsedEnv.MTLS_CERT_PATH?.trim(),
    keyPath: parsedEnv.MTLS_KEY_PATH?.trim(),
    spiffe: {
      enabled: spiffeEnabled,
      trustDomain,
      workloadApiSocket:
        parsedEnv.SPIFFE_WORKLOAD_API_SOCKET?.trim()
        ?? "unix:///tmp/spire-agent/public/api.sock",
      refreshRatio: 0.7,
    },
  };
}

const mtlsConfig = parseMtlsConfig(parsedEnv);

export const config = {
  env: parsedEnv.NODE_ENV,
  jwtSecret: parsedEnv.JWT_SECRET as string,
  databaseUrl: parsedEnv.DATABASE_URL,
  db: {
    url: parsedEnv.DATABASE_URL,
    sessionUrl: parsedEnv.DATABASE_SESSION_URL || parsedEnv.DATABASE_URL,
    poolMax: parsePositiveIntEnv("PGPOOL_MAX", parsedEnv.PGPOOL_MAX, 10),
    idleTimeoutMs: parsePositiveIntEnv("PG_IDLE_TIMEOUT_MS", parsedEnv.PG_IDLE_TIMEOUT_MS, 30_000),
    connectionTimeoutMs: parsePositiveIntEnv("PG_CONN_TIMEOUT_MS", parsedEnv.PG_CONN_TIMEOUT_MS, 2_000),
    ssl: parseBooleanEnv("PGSSL", parsedEnv.PGSSL, false)
      ? {
          rejectUnauthorized: parseBooleanEnv(
              "PGSSL_REJECT_UNAUTHORIZED",
              parsedEnv.PGSSL_REJECT_UNAUTHORIZED,
              true,
            ),
        }
      : undefined,
  },
  otel: {
    exporterProtocol: parsedEnv.OTEL_EXPORTER_PROTOCOL,
    grpc: {
      mtls: {
        enabled: parseBooleanEnv("OTEL_GRPC_MTLS_ENABLED", parsedEnv.OTEL_GRPC_MTLS_ENABLED, false),
        caPath: parsedEnv.OTEL_MTLS_CA_PATH?.trim(),
        certPath: parsedEnv.OTEL_MTLS_CERT_PATH?.trim(),
        keyPath: parsedEnv.OTEL_MTLS_KEY_PATH?.trim(),
      },
    },
  },
  pgbouncerMetrics: {
    adminUrl: parsedEnv.PGBOUNCER_METRICS_ADMIN_URL,
    scrapeIntervalMs: parsePositiveIntEnv(
      "PGBOUNCER_METRICS_SCRAPE_INTERVAL_MS",
      parsedEnv.PGBOUNCER_METRICS_SCRAPE_INTERVAL_MS,
      15_000,
    ),
    queryTimeoutMs: parsePositiveIntEnv(
      "PGBOUNCER_METRICS_QUERY_TIMEOUT_MS",
      parsedEnv.PGBOUNCER_METRICS_QUERY_TIMEOUT_MS,
      2_000,
    ),
  },
  stellar: {
    network: parsedEnv.STELLAR_NETWORK,
  },
  cors: {
    /** Resolved origin allowlist (string[] in production, "*" in dev). */
    origin: getAllowedOrigins(),
    /** Allow credentials (cookies, Authorization header). Forced false in wildcard mode). */
    credentials: true,
    /** Preflight cache duration in seconds (24 hours). */
    maxAge: 86_400,
    /** Headers the client is allowed to send. */
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Request-ID",
      "Idempotency-Key",
    ],
    /** Headers exposed to the client in the response. */
    exposedHeaders: ["X-Request-ID"],
    /** HTTP methods allowed for cross-origin requests. */
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  },
  mtls: mtlsConfig,
  jobs: {
    attestationReminder: {
      // Run every minute
      schedule: "*/1 * * * *",
    },
    expiredRolePromotionRequests: {
      // Run every 5 minutes
      schedule: "*/5 * * * *",
    },
  },
  rolePromotion: {
    ttlMinutes: parsePositiveIntEnv(
      "ROLE_PROMOTION_TTL_MINUTES",
      parsedEnv.ROLE_PROMOTION_TTL_MINUTES,
      1440 // 24 hours
    ),
  },
  soroban: {
    /** Soroban RPC endpoint. Defaults to the public testnet node. */
    rpcUrl: parsedEnv.SOROBAN_RPC_URL,
    /** Backup Soroban RPC endpoint for hedged requests. Falls back to primary if unset. */
    backupRpcUrl: process.env.SOROBAN_BACKUP_RPC_URL || parsedEnv.SOROBAN_RPC_URL,
    /** Deployed attestation contract address (C…). Required in production. */
    contractId: parsedEnv.SOROBAN_CONTRACT_ID,
    /**
     * Stellar network passphrase.
     * Testnet:  'Test SDF Network ; September 2015'
     * Mainnet:  'Public Global Stellar Network ; September 2015'
     */
    networkPassphrase: parsedEnv.SOROBAN_NETWORK_PASSPHRASE,
    retryBudgetMaxRetries: parsePositiveIntEnv(
      "SOROBAN_RETRY_BUDGET_MAX_RETRIES",
      parsedEnv.SOROBAN_RETRY_BUDGET_MAX_RETRIES,
      20,
    ),
    replayMaxAgeDays: parsePositiveIntEnv(
      "SOROBAN_REPLAY_MAX_AGE_DAYS",
      parsedEnv.SOROBAN_REPLAY_MAX_AGE_DAYS,
      7,
    ),
    adaptiveBatch: {
      minBatchSize: parsePositiveIntEnv(
        "SOROBAN_ADAPTIVE_BATCH_MIN_SIZE",
        parsedEnv.SOROBAN_ADAPTIVE_BATCH_MIN_SIZE,
        1,
      ),
      maxBatchSize: parsePositiveIntEnv(
        "SOROBAN_ADAPTIVE_BATCH_MAX_SIZE",
        parsedEnv.SOROBAN_ADAPTIVE_BATCH_MAX_SIZE,
        100,
      ),
      ewmaAlpha: parseDecimalEnv(
        "SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA",
        parsedEnv.SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA,
        0.3,
        0.01,
        1.0,
      ),
      feeSpikeMultiplier: parseDecimalEnv(
        "SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER",
        parsedEnv.SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER,
        2.0,
        1.0,
        10.0,
      ),
      sensitivity: parseDecimalEnv(
        "SOROBAN_ADAPTIVE_BATCH_SENSITIVITY",
        parsedEnv.SOROBAN_ADAPTIVE_BATCH_SENSITIVITY,
        0.5,
        0.01,
        2.0,
      ),
      volatilityDampening: parseDecimalEnv(
        "SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING",
        parsedEnv.SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING,
        0.5,
        0.0,
        1.0,
      ),
      sampleIntervalMs: parsePositiveIntEnv(
        "SOROBAN_ADAPTIVE_BATCH_SAMPLE_INTERVAL_MS",
        parsedEnv.SOROBAN_ADAPTIVE_BATCH_SAMPLE_INTERVAL_MS,
        60_000,
      ),
    },
    drrScheduler: {
      /**
       * JSON-serialised tier-weight table for the DRR scheduler.
       * Example: '{"free":1,"starter":2,"growth":4,"enterprise":8}'
       * Parsed and validated at runtime by {@link resolveTierWeights}.
       */
      tierWeightsRaw: parsedEnv.DRR_SCHEDULER_TIER_WEIGHTS,
      /**
       * DRR quantum — credits awarded per tenant per round.
       * Higher quantum = larger burst slice per round, still fair overall.
       */
      quantum: parsePositiveIntEnv(
        "DRR_SCHEDULER_QUANTUM",
        parsedEnv.DRR_SCHEDULER_QUANTUM,
        10,
      ),
    },
  },
  secretLoader: {
    source: parsedEnv.SECRET_LOADER,
    filePath: parsedEnv.SECRET_FILE_PATH,
    /**
     * When `source` is `"vault"`, `VaultAdapter` (src/utils/secret-loader.ts)
     * auto-renews any renewable dynamic-secret lease Vault returns at 70% of
     * its `lease_duration` (with jitter), and falls back to a full reload —
     * rotating in-memory secrets from a fresh lease — if Vault denies
     * renewal. See `vault_lease_renewal_total` / `vault_lease_seconds_remaining`
     * in src/metrics.ts for observability into this.
     */
    vault: {
      baseUrl: parsedEnv.VAULT_BASE_URL,
      secretPath: parsedEnv.VAULT_SECRET_PATH,
      token: parsedEnv.VAULT_TOKEN,
    },
    cache: {
      kmsKeyId: parsedEnv.SECRET_CACHE_KMS_KEY_ID,
      path: parsedEnv.SECRET_CACHE_PATH,
      ttlMinutes: parsePositiveIntEnv("SECRET_CACHE_TTL_MINUTES", parsedEnv.SECRET_CACHE_TTL_MINUTES, 60 * 24), // default 24h
    }
  },
  redis: {
    /** Single-node Redis URL (redis[s]://...). Ignored when clusterNodes is set. */
    url: parsedEnv.REDIS_URL,
    /** Comma-separated cluster node list, e.g. "host1:7000,host2:7001". */
    clusterNodes: parsedEnv.REDIS_CLUSTER_NODES,
    tls: parseBooleanEnv("REDIS_TLS", parsedEnv.REDIS_TLS, false),
  },
  statsd: {
    host: parsedEnv.STATSD_HOST?.trim() ?? '127.0.0.1',
    port: parsePositiveIntEnv('STATSD_PORT', parsedEnv.STATSD_PORT, 8125),
    prefix: parsedEnv.STATSD_PREFIX?.trim() ?? 'veritasor.',
    dualWriteEnabled: parseBooleanEnv(
      'STATSD_DUAL_WRITE_ENABLED',
      parsedEnv.STATSD_DUAL_WRITE_ENABLED,
      false,
    ),
    dualWriteIntervalMs: Math.max(
      1000,
      parsePositiveIntEnv(
        'STATSD_DUAL_WRITE_INTERVAL_MS',
        parsedEnv.STATSD_DUAL_WRITE_INTERVAL_MS,
        10_000,
      ),
    ),
  },
  graphql: {
    /**
     * Controls whether GraphQL introspection is allowed.
     * - ENABLE_INTROSPECTION env var overrides NODE_ENV when set.
     * - Defaults to true in development/test, false in production.
     */
    enableIntrospection: parsedEnv.ENABLE_INTROSPECTION !== undefined
      ? parseBooleanEnv("ENABLE_INTROSPECTION", parsedEnv.ENABLE_INTROSPECTION, true)
      : !isProduction,
    /**
     * Controls whether arbitrary (ad-hoc) GraphQL operations are allowed.
     * In production, defaults to false (enforces persisted query allow-list).
     * Retains dev bypass toggle via GRAPHQL_DEV_BYPASS or ALLOW_ARBITRARY_OPERATIONS env var.
     */
    allowArbitraryOperations: (parsedEnv.GRAPHQL_DEV_BYPASS !== undefined || parsedEnv.ALLOW_ARBITRARY_OPERATIONS !== undefined)
      ? parseBooleanEnv("GRAPHQL_DEV_BYPASS", parsedEnv.GRAPHQL_DEV_BYPASS ?? parsedEnv.ALLOW_ARBITRARY_OPERATIONS, false)
      : !isProduction,
    persistedQuerySecret: parsedEnv.PERSISTED_QUERY_SECRET || 'default-dev-secret-do-not-use-in-prod',
  },
} as const;
