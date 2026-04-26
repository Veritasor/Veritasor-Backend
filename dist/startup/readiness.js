const STARTUP_CHECK_TIMEOUT_MS = 2_500;
/**
 * Validate startup dependencies before accepting traffic.
 *
 * Security notes:
 * - Does not log secrets or full connection strings.
 * - Ensures critical production auth secret exists before startup.
 */
export async function runStartupDependencyReadinessChecks() {
    const checks = [];
    const isProduction = process.env.NODE_ENV === "production";
    const jwtSecret = process.env.JWT_SECRET?.trim() ?? "";
    const configReady = !isProduction || jwtSecret.length >= 32;
    checks.push({
        dependency: "config",
        ready: configReady,
        reason: configReady
            ? undefined
            : "JWT_SECRET must be set to at least 32 characters in production",
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
async function checkDatabaseReadiness(connectionString) {
    try {
        const { default: pg } = await import("pg");
        const client = new pg.Client({ connectionString });
        await withTimeout((async () => {
            await client.connect();
            try {
                await client.query("SELECT 1");
            }
            finally {
                await client.end();
            }
        })(), STARTUP_CHECK_TIMEOUT_MS);
        return true;
    }
    catch {
        return false;
    }
}
function withTimeout(promise, timeoutMs) {
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            setTimeout(() => reject(new Error("timeout")), timeoutMs);
        }),
    ]);
}
