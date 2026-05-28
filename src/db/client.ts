import pg from 'pg';
import { config } from '../config/index.js';

export const pool = new pg.Pool({
  connectionString: config.db.url,
  max: config.db.poolMax,
  idleTimeoutMillis: config.db.idleTimeoutMs,
  connectionTimeoutMillis: config.db.connectionTimeoutMs,
  ssl: config.db.ssl,
});

export const db = {
  query: (text: string, params?: any[]) => pool.query(text, params),
};
