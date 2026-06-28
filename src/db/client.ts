import pg from 'pg';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

const SLOW_QUERY_MS = Number(process.env.SLOW_QUERY_MS) || 200;
const EXPLAIN_RATE_LIMIT_MS = Number(process.env.EXPLAIN_RATE_LIMIT_MS) || 1000;
const READ_REPLICA_URL = process.env.READ_REPLICA_URL || '';

function maskParams(params?: any[]): string {
  if (!params || params.length === 0) return '[]';
  return '[' + params.map(() => '?').join(', ') + ']';
}

let _explainPool: pg.Pool | null = null;
function getExplainPool(): pg.Pool {
  if (!_explainPool) {
    const url = READ_REPLICA_URL || config.db.url;
    _explainPool = new pg.Pool({
      connectionString: url,
      max: 2,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 2_000,
      ssl: config.db.ssl,
    });
  }
  return _explainPool;
}

let lastExplainTime = 0;
let runningExplains = 0;
const MAX_CONCURRENT_EXPLAINS = 1;

async function runExplain(text: string, params?: any[], durationMs?: number): Promise<void> {
  if (runningExplains >= MAX_CONCURRENT_EXPLAINS) return;
  const now = Date.now();
  if (now - lastExplainTime < EXPLAIN_RATE_LIMIT_MS) return;
  lastExplainTime = now;
  runningExplains++;
  try {
    const explainPool = getExplainPool();
    const explainText = `EXPLAIN (ANALYZE, BUFFERS) ${text}`;
    const result = await explainPool.query(explainText, params || []);
    const plan = result.rows.map(r => r['QUERY PLAN'] || JSON.stringify(r)).join('\n');
    logger.warn(JSON.stringify({
      event: 'slow_query_explain',
      durationMs: durationMs ?? 0,
      query: text.slice(0, 500),
      params: maskParams(params),
      thresholdMs: SLOW_QUERY_MS,
      plan,
    }));
  } catch {
    logger.warn(JSON.stringify({
      event: 'slow_query_explain_failed',
      query: text.slice(0, 500),
    }));
  } finally {
    runningExplains--;
  }
}

function wrapQuery(originalQuery: (text: string, params?: any[]) => Promise<pg.QueryResult>): (text: string, params?: any[]) => Promise<pg.QueryResult> {
  return async (text: string, params?: any[]) => {
    const t0 = Date.now();
    try {
      const result = await originalQuery(text, params);
      const elapsed = Date.now() - t0;
      if (elapsed >= SLOW_QUERY_MS) {
        logger.warn(JSON.stringify({
          event: 'slow_query_detected',
          durationMs: elapsed,
          query: text.slice(0, 500),
          params: maskParams(params),
          thresholdMs: SLOW_QUERY_MS,
          rowCount: result.rows.length,
        }));
        runExplain(text, params, elapsed);
      }
      return result;
    } catch (error) {
      const elapsed = Date.now() - t0;
      if (elapsed >= SLOW_QUERY_MS) {
        logger.warn(JSON.stringify({
          event: 'slow_query_error',
          durationMs: elapsed,
          query: text.slice(0, 500),
          params: maskParams(params),
          thresholdMs: SLOW_QUERY_MS,
        }));
      }
      throw error;
    }
  };
}

export const pool = new pg.Pool({
  connectionString: config.db.url,
  max: config.db.poolMax,
  idleTimeoutMillis: config.db.idleTimeoutMs,
  connectionTimeoutMillis: config.db.connectionTimeoutMs,
  ssl: config.db.ssl,
});

export const db = {
  query: wrapQuery((text: string, params?: any[]) => pool.query(text, params)),
};
