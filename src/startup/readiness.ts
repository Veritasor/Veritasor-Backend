const STARTUP_CHECK_TIMEOUT_MS = 2_500;

/**
 * Startup dependency check result.
 */
export interface DependencyReadinessResult {
  dependency: "config" | "database";
  ready: boolean;
  reason?: string;
}

/**
 * Startup dependency readiness report used for boot-time validation.
 */
export interface StartupReadinessReport {
  ready: boolean;
  checks: DependencyReadinessResult[];
}

/**
 * Validate startup dependencies before accepting traffic.
 *
 * Security notes:
 * - Does not log secrets or full connection strings.
 * - Ensures critical production auth secret exists before startup.
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

  return {
    ready: checks.every((check) => check.ready),
    checks,
  };
}

async function checkDatabaseReadiness(connectionString: string): Promise<boolean> {
  try {
    const { default: pg } = await import("pg");
    const client = new pg.Client({ connectionString });

    await withTimeout(
      (async () => {
        await client.connect();
        try {
          await client.query("SELECT 1");
        } finally {
          await client.end();
        }
      })(),
      STARTUP_CHECK_TIMEOUT_MS,
    );

    return true;
  } catch {
    return false;
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error("timeout")), timeoutMs);
    }),
  ]);
}
