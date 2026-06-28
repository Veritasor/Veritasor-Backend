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
  PGPOOL_MAX: z.string().optional(),
  PG_IDLE_TIMEOUT_MS: z.string().optional(),
  PG_CONN_TIMEOUT_MS: z.string().optional(),
  PGSSL: z.string().optional(),
  PGSSL_REJECT_UNAUTHORIZED: z.string().optional(),
  STELLAR_NETWORK: z.enum(["testnet", "public", "futurenet"]).default("testnet"),
  SOROBAN_RPC_URL: z.string().url().default("https://soroban-testnet.stellar.org"),
  SOROBAN_CONTRACT_ID: z.string().default(""),
  SOROBAN_NETWORK_PASSPHRASE: z.string().default("Test SDF Network ; September 2015"),
  SOROBAN_RETRY_BUDGET_MAX_RETRIES: z.string().optional(),
  SECRET_LOADER: z.enum(["env", "file", "vault"]).default("env"),
  SECRET_FILE_PATH: z.string().optional(),
  VAULT_BASE_URL: z.string().url().optional(),
  VAULT_SECRET_PATH: z.string().optional(),
  VAULT_TOKEN: z.string().optional(),
  MTLS_ENABLED: z.string().optional(),
  MTLS_CA_PATH: z.string().optional(),
  MTLS_CERT_PATH: z.string().optional(),
  MTLS_KEY_PATH: z.string().optional(),
  MTLS_CN_ALLOWLIST: z.string().optional(),
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

export const config = {
  env: parsedEnv.NODE_ENV,
  jwtSecret: parsedEnv.JWT_SECRET as string,
  databaseUrl: parsedEnv.DATABASE_URL,
  db: {
    url: parsedEnv.DATABASE_URL,
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
  jobs: {
    attestationReminder: {
      // Run every minute
      schedule: "*/1 * * * *",
    },
  },
  soroban: {
    /** Soroban RPC endpoint. Defaults to the public testnet node. */
    rpcUrl: parsedEnv.SOROBAN_RPC_URL,
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
  },
  secretLoader: {
    source: parsedEnv.SECRET_LOADER,
    filePath: parsedEnv.SECRET_FILE_PATH,
    vault: {
      baseUrl: parsedEnv.VAULT_BASE_URL,
      secretPath: parsedEnv.VAULT_SECRET_PATH,
      token: parsedEnv.VAULT_TOKEN,
    },
  },
  mtls: {
    enabled: parseBooleanEnv("MTLS_ENABLED", parsedEnv.MTLS_ENABLED, false),
    caPath: parsedEnv.MTLS_CA_PATH,
    certPath: parsedEnv.MTLS_CERT_PATH,
    keyPath: parsedEnv.MTLS_KEY_PATH,
    cnAllowlist: parsedEnv.MTLS_CN_ALLOWLIST
      ? parsedEnv.MTLS_CN_ALLOWLIST.split(",").map(s => s.trim()).filter(Boolean)
      : [],
  },
} as const;
