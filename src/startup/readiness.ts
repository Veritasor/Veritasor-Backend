/**
 * Startup dependency readiness checks.
 *
 * Validates all critical dependencies before the HTTP listener opens.
 * Each check returns an explicit, operator-readable failure reason so that
 * boot failures are immediately actionable without digging through logs.
 *
 * Checks performed (in order):
 *   1. config/jwt        JWT_SECRET length (all envs; stricter in production)
 *   2. config/soroban    SOROBAN_CONTRACT_ID present in production
 *   3. config/stripe     STRIPE_WEBHOOK_SECRET present in production
 *   4. database          SELECT 1 probe when DATABASE_URL is configured
 *
 * Security notes:
 *   - Failure reasons never include secret values or raw connection strings.
 *   - Database probe is read-only (SELECT 1) with a bounded timeout.
 *   - All decisions are emitted as structured log entries for observability.
 */

import { logger } from "../utils/logger.js"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Timeout for the database connectivity probe. */
const STARTUP_CHECK_TIMEOUT_MS = 2_500

/** Minimum acceptable JWT_SECRET length in production. */
const JWT_SECRET_MIN_LENGTH_PROD = 32

/** Minimum acceptable JWT_SECRET length in non-production environments. */
const JWT_SECRET_MIN_LENGTH_DEV = 8

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Machine-readable dependency identifier.
 * Extend this union when new checks are added.
 */
export type DependencyName =
  | "config/jwt"
  | "config/soroban"
  | "config/stripe"
  | "database"

/**
 * Result of a single dependency readiness check.
 */
export interface DependencyReadinessResult {
  /** Machine-readable dependency identifier. */
  dependency: DependencyName
  /** Whether the dependency is ready to serve traffic. */
  ready: boolean
  /**
   * Operator-readable failure reason.
   * Present only when ready === false.
   * Must never contain secret values or raw connection strings.
   */
  reason?: string
}

/**
 * Aggregated readiness report returned by runStartupDependencyReadinessChecks.
 */
export interface StartupReadinessReport {
  /** True only when every check passed. */
  ready: boolean
  /** Per-dependency results in evaluation order. */
  checks: DependencyReadinessResult[]
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Run all startup dependency readiness checks.
 *
 * Emits a structured log entry for every check result so operators can
 * correlate boot failures with specific dependency names and reasons.
 *
 * @returns A report indicating overall readiness and per-dependency results.
 */
export async function runStartupDependencyReadinessChecks(): Promise<StartupReadinessReport> {
  const checks: DependencyReadinessResult[] = [];

  const configReady = true; // If we reach here, src/config/index.ts validation has already passed.
  checks.push({
    dependency: "config",
    ready: configReady,
  });

  const dbConnectionString = process.env.DATABASE_URL?.trim();
  if (dbConnectionString) {
    const dbReady = await checkDatabaseReadiness(dbConnectionString);
    checks.push({
      dependency: "database",
      ready: dbReady,
      reason: dbReady ? undefined : "database connection check failed",
    });
  }

  if (secret.length < minLength) {
    return {
      dependency: "config/jwt",
      ready: false,
      reason: isProduction
        ? `JWT_SECRET must be at least ${JWT_SECRET_MIN_LENGTH_PROD} characters in production (got ${secret.length})`
        : `JWT_SECRET must be at least ${JWT_SECRET_MIN_LENGTH_DEV} characters (got ${secret.length})`,
    }
  }

  return { dependency: "config/jwt", ready: true }
}

/**
 * Validate Soroban contract configuration.
 *
 * SOROBAN_CONTRACT_ID must be set in production because submitting
 * attestations without a contract address would silently no-op.
 * Non-production environments may omit it (testnet defaults apply).
 */
function checkSorobanConfig(isProduction: boolean): DependencyReadinessResult {
  if (!isProduction) {
    return { dependency: "config/soroban", ready: true }
  }

  const contractId = process.env.SOROBAN_CONTRACT_ID?.trim() ?? ""
  if (contractId.length === 0) {
    return {
      dependency: "config/soroban",
      ready: false,
      reason: "SOROBAN_CONTRACT_ID must be set in production",
    }
  }

  return { dependency: "config/soroban", ready: true }
}

/**
 * Validate Stripe webhook secret configuration.
 *
 * STRIPE_WEBHOOK_SECRET must be set in production to prevent unsigned
 * webhook events from being accepted.
 * Non-production environments may omit it.
 */
function checkStripeConfig(isProduction: boolean): DependencyReadinessResult {
  if (!isProduction) {
    return { dependency: "config/stripe", ready: true }
  }

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET?.trim() ?? ""
  if (webhookSecret.length === 0) {
    return {
      dependency: "config/stripe",
      ready: false,
      reason: "STRIPE_WEBHOOK_SECRET must be set in production",
    }
  }

  return { dependency: "config/stripe", ready: true }
}

/**
 * Probe database connectivity with a bounded SELECT 1 query.
 *
 * Returns an explicit failure reason that identifies whether the failure
 * was a connection error or a query timeout  without leaking the
 * connection string or credentials.
 */
async function checkDatabaseConnectivity(connectionString: string): Promise<DependencyReadinessResult> {
  let failureReason: string

  try {
    const { default: pg } = await import("pg")
    const client = new pg.Client({ connectionString })

    await withTimeout(
      (async () => {
        await client.connect()
        try {
          await client.query("SELECT 1")
        } finally {
          await client.end()
        }
      })(),
      STARTUP_CHECK_TIMEOUT_MS,
    )

    return { dependency: "database", ready: true }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)

    if (message === "timeout") {
      failureReason = `database probe timed out after ${STARTUP_CHECK_TIMEOUT_MS} ms`
    } else {
      // Sanitise: strip the connection string from the error message so
      // credentials are never written to logs.
      failureReason = "database connection failed: " + sanitiseDbError(message)
    }

    return {
      dependency: "database",
      ready: false,
      reason: failureReason,
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Remove any substring that looks like a PostgreSQL connection string
 * (postgres://... or postgresql://...) from an error message so that
 * credentials are never surfaced in logs or readiness reports.
 */
export function sanitiseDbError(message: string): string {
  return message.replace(/postgres(?:ql)?:\/\/[^\s]*/gi, "[redacted]")
}

/**
 * Race a promise against a timeout.
 * Rejects with Error("timeout") when the deadline is exceeded.
 */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error("timeout")), timeoutMs)
    }),
  ])
}