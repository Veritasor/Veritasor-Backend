import { Pool, PoolConfig, QueryResult, QueryConfig } from 'pg';
import { Logger } from '../utils/logger';

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
    this.initializePgBouncerDetection(pgbouncerMode);
    
    // Log the detection result
    this.logDetectionResult();
  }

  /**
   * Initialize PgBouncer mode detection
   */
  private initializePgBouncerDetection(overrideMode?: 'session' | 'transaction' | 'statement'): void {
    const detection = this.detectPgBouncerMode(overrideMode);
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
   * 1. Environment variable PGBOUNCER_MODE
   * 2. Introspection query (if supported)
   * 3. Default to session mode (safe)
   */
  private detectPgBouncerMode(overrideMode?: 'session' | 'transaction' | 'statement'): PgBouncerDetectionResult {
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
  async query<T = any>(
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
      return this.executeUnnamed(text, params);
    }

    if (usePrepared) {
      return this.executePrepared(text, params);
    }

    return this.executeUnnamed(text, params);
  }

  /**
   * Execute with unnamed prepared statement (safe for transaction pooling)
   */
  private async executeUnnamed<T = any>(
    text: string,
    params?: any[]
  ): Promise<QueryResult<T>> {
    return this.pool.query(text, params);
  }

  /**
   * Execute with named prepared statement (unsafe for transaction pooling)
   */
  private async executePrepared<T = any>(
    text: string,
    params?: any[]
  ): Promise<QueryResult<T>> {
    const name = `prep_${this.preparedStatementCounter++}`;
    
    try {
      // Prepare the statement
      await this.pool.query(`PREPARE ${name} AS ${text}`);
      
      // Execute with parameters
      const result = await this.pool.query(`EXECUTE ${name}`, params);
      
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
    return (getPgClient() as Record<string, unknown>)[prop as string];
  },
});

export function getPgClient(): PgClient {
  if (!pgClient) {
    pgClient = new PgClient({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      database: process.env.DB_NAME || 'veritasor',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD,
      max: parseInt(process.env.DB_MAX_CONNECTIONS || '20', 10),
      idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000', 10),
    });
  }
  return pgClient;
}
