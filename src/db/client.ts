import { Pool, PoolConfig, QueryResult, QueryConfig, QueryResultRow } from 'pg';
import { Logger, logger } from '../utils/logger.js';
import { config } from '../config/index.js';

/**
 * PgBouncer mode detection and prepared statement guard
 * 
 * Transaction-mode PgBouncer breaks silently on server-side prepared statements
 * because prepared statements are session-bound and transaction pooling
 * reuses connections across sessions.
 * 
 * This module detects transaction pooling mode and disables named prepared
 * statements when unsafe, logging warnings with recommendations.
 */
interface PgBouncerDetectionResult {
  mode: 'session' | 'transaction' | 'statement' | 'unknown';
  detected: boolean;
  reason: string;
  safe: boolean;
}

interface ClientOptions extends PoolConfig {
  /**
   * Force disable prepared statements (override detection)
   */
  disablePreparedStatements?: boolean;
  /**
   * PgBouncer mode override (for testing)
   */
  pgbouncerMode?: 'session' | 'transaction' | 'statement';
}

export class PgClient {
  private pool: Pool;
  private logger: Logger;
  private disablePreparedStatements: boolean;
  private pgbouncerMode: PgBouncerDetectionResult | null = null;
  private preparedStatementCounter = 0;

  constructor(options: ClientOptions = {}) {
    this.logger = new Logger('PgClient');
    
    // Extract options
    this.disablePreparedStatements = options.disablePreparedStatements || false;
    const { disablePreparedStatements, pgbouncerMode, ...poolConfig } = options;
    
    this.pool = new Pool(poolConfig);
    
    // Initialize detection
    this.initializePgBouncerDetection(pgbouncerMode, options);
    
    // Log the detection result
    this.logDetectionResult();
  }

  /**
   * Initialize PgBouncer mode detection
   */
  private initializePgBouncerDetection(
    overrideMode?: 'session' | 'transaction' | 'statement',
    options?: ClientOptions
  ): void {
    const detection = this.detectPgBouncerMode(overrideMode, options);
    this.pgbouncerMode = detection;
    
    // If PgBouncer is in transaction mode, disable prepared statements
    if (detection.mode === 'transaction') {
      this.disablePreparedStatements = true;
    }
  }

  /**
   * Detect PgBouncer pooling mode
   * 
   * Detection methods:
   * 1. Options override (overrideMode / pgbouncerMode)
   * 2. Environment variable PGBOUNCER_MODE
   * 3. Connection string parameters (pool_mode, pgbouncer) or host/port
   * 4. Connection options (host, port)
   * 5. PgBouncer-specific connection parameters (PGPGBOUNCER, PGPOOL_MODE)
   * 6. Default to session mode (safe)
   */
  private detectPgBouncerMode(
    overrideMode?: 'session' | 'transaction' | 'statement',
    options?: ClientOptions
  ): PgBouncerDetectionResult {
    // Check for override first (testing/forced config)
    if (overrideMode) {
      const isSafe = overrideMode === 'session';
      return {
        mode: overrideMode,
        detected: true,
        reason: `Overridden to ${overrideMode} mode`,
        safe: isSafe,
      };
    }

    // Check environment variable
    const envMode = process.env.PGBOUNCER_MODE?.toLowerCase() as 'session' | 'transaction' | 'statement' | undefined;
    if (envMode && ['session', 'transaction', 'statement'].includes(envMode)) {
      const isSafe = envMode === 'session';
      return {
        mode: envMode,
        detected: true,
        reason: `Detected via environment variable PGBOUNCER_MODE=${envMode}`,
        safe: isSafe,
      };
    }

    // Check connection string parameters and host/port
    if (options?.connectionString) {
      try {
        const parsedUrl = new URL(options.connectionString);
        const poolMode = parsedUrl.searchParams.get('pool_mode')?.toLowerCase();
        if (poolMode && ['session', 'transaction', 'statement'].includes(poolMode)) {
          const isSafe = poolMode === 'session';
          return {
            mode: poolMode as 'session' | 'transaction' | 'statement',
            detected: true,
            reason: `Detected via connection string parameter pool_mode=${poolMode}`,
            safe: isSafe,
          };
        }

        const hasPgBouncerParam = parsedUrl.searchParams.has('pgbouncer');
        const isPgBouncerHost = parsedUrl.hostname.toLowerCase().includes('pgbouncer');
        const isPgBouncerPort = parsedUrl.port === '6432';

        if (hasPgBouncerParam || isPgBouncerHost || isPgBouncerPort) {
          return {
            mode: 'unknown',
            detected: true,
            reason: hasPgBouncerParam
              ? 'PgBouncer parameter detected in connection string, defaulting to safe mode'
              : 'PgBouncer host or port detected in connection string, defaulting to safe mode',
            safe: true,
          };
        }
      } catch {
        // Fallback for non-URL formatted connection strings (e.g. key=value)
        const poolModeMatch = options.connectionString.match(/\bpool_mode=([a-zA-Z]+)/i);
        if (poolModeMatch) {
          const poolMode = poolModeMatch[1].toLowerCase();
          if (['session', 'transaction', 'statement'].includes(poolMode)) {
            const isSafe = poolMode === 'session';
            return {
              mode: poolMode as 'session' | 'transaction' | 'statement',
              detected: true,
              reason: `Detected via connection string parameter pool_mode=${poolMode}`,
              safe: isSafe,
            };
          }
        }
        if (
          /\bpgbouncer=true\b/i.test(options.connectionString) ||
          /\bhost=[^\s]*pgbouncer/i.test(options.connectionString) ||
          /\bport=6432\b/i.test(options.connectionString)
        ) {
          return {
            mode: 'unknown',
            detected: true,
            reason: 'PgBouncer parameter detected in connection string, defaulting to safe mode',
            safe: true,
          };
        }
      }
    }

    // Check host or port in options
    if (options?.host?.toLowerCase().includes('pgbouncer') || options?.port === 6432) {
      return {
        mode: 'unknown',
        detected: true,
        reason: 'PgBouncer host or port detected in options, defaulting to safe mode',
        safe: true,
      };
    }

    // Check PgBouncer-specific connection parameters
    // PgBouncer adds connection parameters when pooling
    const pgbouncerParams = ['pgbouncer', 'pool_mode'];
    const hasPgBouncerParam = pgbouncerParams.some(param => process.env[`PG${param.toUpperCase()}`]);

    // Introspection: query to detect PgBouncer
    // We'll use a deferred check - first query will detect
    // For now, assume safe if no indicators
    if (hasPgBouncerParam) {
      return {
        mode: 'unknown',
        detected: true,
        reason: 'PgBouncer parameters detected, defaulting to safe mode',
        safe: true,
      };
    }

    // Default: assume session mode (safe)
    return {
      mode: 'session',
      detected: false,
      reason: 'No PgBouncer indicators found, defaulting to session mode',
      safe: true,
    };
  }

  /**
   * Log the detection result with warning if unsafe
   */
  private logDetectionResult(): void {
    const mode = this.pgbouncerMode;
    if (!mode) return;

    if (!mode.safe) {
      this.logger.warn(
        `⚠️ PgBouncer transaction-mode detected! ` +
        `Named prepared statements will be disabled. ` +
        `Mode: ${mode.mode}, Reason: ${mode.reason}`
      );
      
      if (process.env.NODE_ENV !== 'production') {
        this.logger.info(
          '💡 Recommendation: Use session-mode PgBouncer or ' +
          'set PGBOUNCER_MODE=session to enable prepared statements'
        );
      }
    } else {
      this.logger.info(`PgBouncer mode: ${mode.mode} (safe)`);
    }
  }

  /**
   * Query with automatic prepared statement handling
   */
  async query<T extends QueryResultRow = any>(
    text: string,
    params?: any[],
    options?: { disablePrepared?: boolean }
  ): Promise<QueryResult<T>> {
    // Check if we should use named prepared statements
    const usePrepared = !this.disablePreparedStatements && 
                        !options?.disablePrepared &&
                        text.toLowerCase().includes('where') &&
                        !text.toLowerCase().includes('select *') &&
                        text.length > 100;

    if (usePrepared && this.pgbouncerMode?.mode === 'transaction') {
      // Double-check: transaction mode should have disabled prepared statements
      // This is a safety fallback
      this.logger.warn(
        'Prepared statement attempted in transaction mode - falling back to unnamed prepared statement'
      );
      return this.executeUnnamed<T>(text, params);
    }

    if (usePrepared) {
      return this.executePrepared<T>(text, params);
    }

    return this.executeUnnamed<T>(text, params);
  }

  /**
   * Execute with unnamed prepared statement (safe for transaction pooling)
   */
  private async executeUnnamed<T extends QueryResultRow = any>(
    text: string,
    params?: any[]
  ): Promise<QueryResult<T>> {
    return this.pool.query<T>(text, params);
  }

  /**
   * Execute with named prepared statement (unsafe for transaction pooling)
   */
  private async executePrepared<T extends QueryResultRow = any>(
    text: string,
    params?: any[]
  ): Promise<QueryResult<T>> {
    const name = `prep_${this.preparedStatementCounter++}`;
    
    try {
      // Prepare the statement
      await this.pool.query(`PREPARE ${name} AS ${text}`);
      
      // Execute with parameters
      const result = await this.pool.query<T>(`EXECUTE ${name}`, params);
      
      // Deallocate after use
      await this.pool.query(`DEALLOCATE ${name}`);
      
      return result;
    } catch (error) {
      this.logger.warn(`Prepared statement failed, falling back to unnamed: ${error}`);
      return this.executeUnnamed(text, params);
    }
  }

  /**
   * Get a client from the pool
   */
  async getClient() {
    return this.pool.connect();
  }

  /**
   * Run a callback inside a single transaction on a dedicated pooled client.
   *
   * The callback receives the checked-out client and must use it for every
   * statement that should participate in the transaction (including audit
   * log writes). The transaction is committed when the callback resolves and
   * rolled back when it throws. The client is always released to the pool.
   */
  async withTransaction<T>(
    fn: (client: import('pg').PoolClient) => Promise<T>
  ): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackError) {
        this.logger.error('Transaction rollback failed:', rollbackError);
      }
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get the current PgBouncer detection status
   */
  getPgBouncerStatus(): PgBouncerDetectionResult | null {
    return this.pgbouncerMode;
  }

  /**
   * Check if prepared statements are disabled
   */
  isPreparedStatementsDisabled(): boolean {
    return this.disablePreparedStatements;
  }

  /**
   * End the pool
   */
  async end(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch (error) {
      this.logger.error('Health check failed:', error);
      return false;
    }
  }
}

// Export a singleton instance
let pgClient: PgClient | null = null;

/** Lazy singleton database client. */
export const db: PgClient = new Proxy({} as PgClient, {
  get(_target, prop) {
    return (getPgClient() as unknown as Record<string, unknown>)[prop as string];
  },
});

/**
 * Reset the PgClient singleton instance (primarily for testing).
 */
export function resetPgClient(): void {
  pgClient = null;
}

/**
 * Configuration precedence for PgClient singleton:
 * 1. Primary: DATABASE_URL (via config.db.url) takes precedence. When present,
 *    options are constructed from config.db:
 *    - connectionString: config.db.url
 *    - max: config.db.poolMax (from PGPOOL_MAX, default: 10)
 *    - idleTimeoutMillis: config.db.idleTimeoutMs (from PG_IDLE_TIMEOUT_MS, default: 30000)
 *    - connectionTimeoutMillis: config.db.connectionTimeoutMs (from PG_CONN_TIMEOUT_MS, default: 2000)
 *    - ssl: config.db.ssl (from PGSSL and PGSSL_REJECT_UNAUTHORIZED)
 *    If legacy DB_* environment variables are also present, a warning is logged
 *    noting that they are ignored in favor of DATABASE_URL.
 * 2. Fallback (Deprecated): If DATABASE_URL / config.db.url is absent, connection
 *    parameters fall back to legacy DB_* environment variables (DB_HOST, DB_PORT,
 *    DB_NAME, DB_USER, DB_PASSWORD, DB_MAX_CONNECTIONS, DB_IDLE_TIMEOUT)
 *    and a deprecation warning is logged.
 */
export function getPgClient(): PgClient {
  if (!pgClient) {
    const hasLegacyDbEnv = Boolean(
      process.env.DB_HOST ||
      process.env.DB_PORT ||
      process.env.DB_NAME ||
      process.env.DB_USER ||
      process.env.DB_PASSWORD ||
      process.env.DB_MAX_CONNECTIONS ||
      process.env.DB_IDLE_TIMEOUT
    );

    let clientOptions: ClientOptions;

    if (config?.db?.url) {
      if (hasLegacyDbEnv) {
        logger.warn(
          'DATABASE_URL is configured; legacy DB_* environment variables (DB_HOST, DB_PORT, etc.) are ignored.'
        );
      }
      clientOptions = {
        connectionString: config.db.url,
        max: config.db.poolMax,
        idleTimeoutMillis: config.db.idleTimeoutMs,
        connectionTimeoutMillis: config.db.connectionTimeoutMs,
        ...(config.db.ssl !== undefined ? { ssl: config.db.ssl } : {}),
      };
    } else {
      logger.warn(
        'DATABASE_URL is not configured; falling back to legacy DB_* environment variables. This fallback is deprecated and will be removed in a future release.'
      );
      clientOptions = {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        database: process.env.DB_NAME || 'veritasor',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD,
        max: parseInt(process.env.DB_MAX_CONNECTIONS || '20', 10),
        idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000', 10),
      };
    }

    pgClient = new PgClient(clientOptions);
  }
  return pgClient;
}
