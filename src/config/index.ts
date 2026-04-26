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
  DATABASE_URL: z.string().url("DATABASE_URL must be a valid URL"),
  STELLAR_NETWORK: z.enum(["testnet", "public", "futurenet"]).default("testnet"),
  SOROBAN_RPC_URL: z.string().url().default("https://soroban-testnet.stellar.org"),
  SOROBAN_CONTRACT_ID: z.string().default(""),
  SOROBAN_NETWORK_PASSPHRASE: z.string().default("Test SDF Network ; September 2015"),
}).superRefine((data, ctx) => {
  if (data.NODE_ENV === "production") {
    if (!data.ALLOWED_ORIGINS || data.ALLOWED_ORIGINS.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "ALLOWED_ORIGINS must be set in production",
        path: ["ALLOWED_ORIGINS"]
      });
    }
    if (!data.JWT_SECRET || data.JWT_SECRET.length < 32) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "JWT_SECRET must be at least 32 characters in production",
        path: ["JWT_SECRET"]
      });
    }
  }
});

let parsedEnv: z.infer<typeof envSchema>;

try {
  // Try parsing the environment variables
  parsedEnv = envSchema.parse(process.env);
} catch (error) {
  if (error instanceof z.ZodError) {
    logger.error("Configuration validation failed", JSON.stringify(error.format()));
    // Avoid silent failures and exit fast
    throw new ConfigValidationError("Invalid environment configuration. Check logs for details.");
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
  stellar: {
    network: parsedEnv.STELLAR_NETWORK,
  },
  cors: {
    /** Resolved origin allowlist (string[] in production, "*" in dev). */
    origin: getAllowedOrigins(),
    /** Allow credentials (cookies, Authorization header). Forced false in wildcard mode. */
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
  },
} as const;
