/**
 * Attestation Repository
 *
 * Data access layer for blockchain attestation records.
 * Provides CRUD operations for attestations with proper type safety and error handling.
 * Includes write conflict detection and handling for concurrent operations.
 *
 * High-volume query guidance
 * ──────────────────────────
 * All list/count queries are written to hit the indexes created by migration
 * 20260225_001_create_attestations_table.sql:
 *
 *   attestations_business_id_idx  ON attestations (business_id)
 *   attestations_status_idx       ON attestations (status)
 *   attestations_created_at_idx   ON attestations (created_at DESC)
 *
 * A per-query statement timeout is applied via `SET LOCAL statement_timeout`
 * inside a transaction-like wrapper so that runaway queries are cancelled
 * before they exhaust the connection pool.  The timeout is controlled by the
 * environment variable ATTESTATION_QUERY_TIMEOUT_MS (default 5000 ms).
 *
 * Structured log entries are emitted for:
 *   - queries that return more than SLOW_QUERY_ROW_THRESHOLD rows
 *   - queries that exceed SLOW_QUERY_WARN_MS elapsed time
 *
 * Read-replica routing is not implemented yet; the `client` parameter is
 * expected to be a primary-pool client.  When a read replica is added, pass
 * a replica client for `getById`, `getByBusinessAndPeriod`, and `list`.
 */

import {
  Attestation,
  AttestationStatus,
  CreateAttestationInput,
  AttestationFilters,
  PaginationParams,
  PaginatedResult,
  DbClient,
  ConflictError,
  ConflictErrorType,
  createConflictError,
  ReadConsistency,
  ConsistencyOptions,
} from '../types/attestation.js';
import { getAttestation } from '../services/soroban/getAttestation.js';
import { logger } from '../utils/logger.js';

/**
 * Database row type with snake_case column names
 */
interface AttestationRow {
  id: string;
  business_id: string;
  period: string;
  merkle_root: string;
  tx_hash: string;
  status: AttestationStatus;
  version: number;
  created_at: string;
  updated_at: string;
}

/**
 * Maps a database row to an Attestation object.
 * Converts snake_case to camelCase and timestamp strings to Date objects.
 */
function mapRowToAttestation(row: AttestationRow): Attestation {
  return {
    id: row.id,
    businessId: row.business_id,
    period: row.period,
    merkleRoot: row.merkle_root,
    txHash: row.tx_hash,
    status: row.status,
    version: row.version,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
  };
}

/**
 * Verifies a local attestation record against the Soroban chain state.
 * Handles indexing lag by auto-updating the database status.
 * Logs critical errors on data integrity violations (Merkle root mismatch).
 * 
 * @param client - Database client for potential updates
 * @param local - The attestation record from the database
 * @returns The (potentially updated) attestation record
 */
async function verifyConsistency(
  client: DbClient,
  local: Attestation
): Promise<Attestation> {
  try {
    const chainData = await getAttestation(local.businessId, local.period);

    if (!chainData) {
      // Chain has no record. If local is 'confirmed', this is a discrepancy.
      if (local.status === 'confirmed') {
        logger.warn(
          { id: local.id, businessId: local.businessId, period: local.period },
          'Consistency check: Attestation marked as confirmed in DB but not found on-chain'
        );
      }
      return local;
    }

    // Check for Merkle root mismatch (Integrity violation)
    if (chainData.merkle_root !== local.merkleRoot) {
      logger.error(
        {
          id: local.id,
          businessId: local.businessId,
          period: local.period,
          localRoot: local.merkleRoot,
          chainRoot: chainData.merkle_root,
        },
        'CRITICAL CONSISTENCY ERROR: Merkle root mismatch between DB and Chain'
      );
    }

    // Handle Indexing Lag: If chain says it's there but DB says pending/submitted, update DB.
    if (local.status === 'pending' || local.status === 'submitted') {
      logger.info(
        { id: local.id, businessId: local.businessId, period: local.period },
        'Consistency check: Auto-correcting indexing lag. Updating status to confirmed'
      );
      const updated = await updateStatus(client, local.id, 'confirmed');
      return updated || local;
    }

    return local;
  } catch (error) {
    logger.error(
      { err: error, id: local.id, businessId: local.businessId, period: local.period },
      'Consistency check: Failed to verify with Soroban'
    );
    // On network failure or other errors, fall back to local data but log it
    return local;
  }
}

/**
 * Creates a new attestation record in the database
 * 
 * @param client - Database client for executing queries
 * @param data   - Attestation data to insert
 * @returns Promise resolving to the created Attestation record
 * @throws ConflictError CONFLICT_TYPE_DUPLICATE if businessId + period already exists
 * @throws ConflictError CONFLICT_TYPE_FOREIGN_KEY if businessId does not exist
 *
 * Index used: attestations_business_id_idx (via UNIQUE constraint check)
 */
export async function create(
  client: DbClient,
  data: CreateAttestationInput
): Promise<Attestation> {
  const sql = `
    INSERT INTO attestations (business_id, period, merkle_root, tx_hash, status, version)
    VALUES ($1, $2, $3, $4, $5, 1)
    RETURNING *
  `;

  const params = [
    data.businessId,
    data.period,
    data.merkleRoot,
    data.txHash,
    data.status,
  ];

  try {
    await applyStatementTimeout(client, STATEMENT_TIMEOUT_MS);
    const t0 = Date.now();
    const result = await client.query<AttestationRow>(sql, params);
    warnIfSlow('create', Date.now() - t0, result.rows.length, { businessId: data.businessId });
    return mapRowToAttestation(result.rows[0]);
  } catch (error: any) {
    if (error.code === '23505') {
      throw createConflictError(
        ConflictErrorType.CONFLICT_TYPE_DUPLICATE,
        `Attestation for business ${data.businessId} and period ${data.period} already exists`,
        { businessId: data.businessId, period: data.period }
      );
    }
    if (error.code === '23503') {
      throw createConflictError(
        ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY,
        `Business with id ${data.businessId} does not exist`,
        { businessId: data.businessId }
      );
    }
    throw error;
  }
}

/**
 * Retrieves a single attestation by its unique identifier.
 *
 * The query uses the primary-key index (id) — no additional index hint needed.
 *
 * @param client - Database client for executing queries
 * @param id     - UUID of the attestation to retrieve
 * @returns Promise resolving to the Attestation record or null if not found
 */
export async function getById(
  client: DbClient,
  id: string,
  options: ConsistencyOptions = {}
): Promise<Attestation | null> {
  const sql = `SELECT * FROM attestations WHERE id = $1`;

  await applyStatementTimeout(client, STATEMENT_TIMEOUT_MS);
  const t0 = Date.now();
  const result = await client.query<AttestationRow>(sql, [id]);
  
  if (result.rows.length === 0) {
    return null;
  }
  
  const attestation = mapRowToAttestation(result.rows[0]);

  if (options.consistency === ReadConsistency.STRONG) {
    return verifyConsistency(client, attestation);
  }

  return attestation;
}

/**
 * Retrieves an attestation by business ID and period.
 *
 * Uses the composite UNIQUE index on (business_id, period) which is also
 * served by attestations_business_id_idx for the leading column.
 *
 * @param client     - Database client for executing queries
 * @param businessId - UUID of the business
 * @param period     - Time period identifier
 * @returns Promise resolving to the Attestation record or null if not found
 */
export async function getByBusinessAndPeriod(
  client: DbClient,
  businessId: string,
  period: string,
  options: ConsistencyOptions = {}
): Promise<Attestation | null> {
  // Explicit index hint via leading column ensures planner uses
  // attestations_business_id_idx even on large tables.
  const sql = `
    SELECT * FROM attestations
    WHERE business_id = $1
      AND period = $2
  `;

  await applyStatementTimeout(client, STATEMENT_TIMEOUT_MS);
  const t0 = Date.now();
  const result = await client.query<AttestationRow>(sql, [businessId, period]);
  
  if (result.rows.length === 0) {
    return null;
  }
  
  const attestation = mapRowToAttestation(result.rows[0]);

  if (options.consistency === ReadConsistency.STRONG) {
    return verifyConsistency(client, attestation);
  }

  return attestation;
}

/**
 * Lists attestations with optional filtering and pagination.
 *
 * Index usage:
 *   - businessId filter  → attestations_business_id_idx
 *   - userId filter      → attestations_business_id_idx (via JOIN)
 *   - ORDER BY           → attestations_created_at_idx
 *
 * Both the data query and the count query share the same filter params so
 * the planner can reuse the same index scan.
 *
 * @param client     - Database client for executing queries
 * @param filters    - Optional filters for businessId or userId
 * @param pagination - Limit and offset for pagination
 * @returns Promise resolving to paginated results with items and total count
 */
export async function list(
  client: DbClient,
  filters: AttestationFilters,
  pagination: PaginationParams
): Promise<PaginatedResult<Attestation>> {
  let dataQuery: string;
  let countQuery: string;
  let params: any[];

  if (filters.userId) {
    // JOIN path — planner uses attestations_business_id_idx on the FK column
    dataQuery = `
      SELECT a.* FROM attestations a
      INNER JOIN businesses b ON a.business_id = b.id
      WHERE b.user_id = $1
      ORDER BY a.created_at DESC
      LIMIT $2 OFFSET $3
    `;
    countQuery = `
      SELECT COUNT(*) FROM attestations a
      INNER JOIN businesses b ON a.business_id = b.id
      WHERE b.user_id = $1
    `;
    params = [filters.userId, pagination.limit, pagination.offset];
  } else if (filters.businessId) {
    // Direct filter — attestations_business_id_idx + attestations_created_at_idx
    dataQuery = `
      SELECT * FROM attestations
      WHERE business_id = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `;
    countQuery = `
      SELECT COUNT(*) FROM attestations
      WHERE business_id = $1
    `;
    params = [filters.businessId, pagination.limit, pagination.offset];
  } else {
    // Full scan — attestations_created_at_idx for ORDER BY
    dataQuery = `
      SELECT * FROM attestations
      ORDER BY created_at DESC
      LIMIT $1 OFFSET $2
    `;
    countQuery = `SELECT COUNT(*) FROM attestations`;
    params = [pagination.limit, pagination.offset];
  }

  await applyStatementTimeout(client, STATEMENT_TIMEOUT_MS);

  const countParams = filters.userId || filters.businessId ? [params[0]] : [];
  const t0 = Date.now();
  const countResult = await client.query<{ count: string }>(countQuery, countParams);
  const total = parseInt(countResult.rows[0].count, 10);

  const dataResult = await client.query<AttestationRow>(dataQuery, params);
  const elapsedMs = Date.now() - t0;
  const items = dataResult.rows.map(mapRowToAttestation);

  warnIfSlow('list', elapsedMs, items.length, {
    businessId: filters.businessId,
    userId: filters.userId,
    limit: pagination.limit,
    offset: pagination.offset,
    total,
  });

  return { items, total };
}

/**
 * Updates the status of an existing attestation with optimistic locking.
 *
 * The WHERE clause always includes `id` (primary key) so the update is a
 * single-row seek; no additional index is needed.
 *
 * @param client          - Database client for executing queries
 * @param id              - UUID of the attestation to update
 * @param status          - New status value
 * @param expectedVersion - Expected version for optimistic locking (optional)
 * @returns Promise resolving to the updated Attestation record or null if not found
 * @throws ConflictError CONFLICT_TYPE_VERSION if version mismatch
 */
export async function updateStatus(
  client: DbClient,
  id: string,
  status: AttestationStatus,
  expectedVersion?: number
): Promise<Attestation | null> {
  const validStatuses: AttestationStatus[] = ['pending', 'submitted', 'confirmed', 'failed', 'revoked'];
  if (!validStatuses.includes(status)) {
    throw new Error(`Invalid status: ${status}. Must be one of: ${validStatuses.join(', ')}`);
  }

  let sql: string;
  let params: any[];

  if (expectedVersion !== undefined) {
    sql = `
      UPDATE attestations
      SET status = $1, version = version + 1
      WHERE id = $2 AND version = $3
      RETURNING *
    `;
    params = [status, id, expectedVersion];
  } else {
    sql = `
      UPDATE attestations
      SET status = $1, version = version + 1
      WHERE id = $2
      RETURNING *
    `;
    params = [status, id];
  }

  try {
    await applyStatementTimeout(client, STATEMENT_TIMEOUT_MS);
    const t0 = Date.now();
    const result = await client.query<AttestationRow>(sql, params);
    warnIfSlow('updateStatus', Date.now() - t0, result.rows.length, { id, status });

    if (result.rows.length === 0) {
      if (expectedVersion !== undefined) {
        const existing = await getById(client, id);
        if (existing) {
          throw createConflictError(
            ConflictErrorType.CONFLICT_TYPE_VERSION,
            `Attestation ${id} has been modified by another process. Expected version ${expectedVersion}, current version ${existing.version}`,
            { id, expectedVersion, currentVersion: existing.version }
          );
        }
      }
      return null;
    }

    return mapRowToAttestation(result.rows[0]);
  } catch (error) {
    if (error instanceof ConflictError) throw error;
    throw error;
  }
}

/**
 * Updates an attestation record with optimistic locking support.
 *
 * @param client          - Database client for executing queries
 * @param id              - UUID of the attestation to update
 * @param updates         - Partial attestation data to update
 * @param expectedVersion - Expected version for optimistic locking (optional)
 * @returns Promise resolving to the updated Attestation record or null if not found
 * @throws ConflictError CONFLICT_TYPE_VERSION if version mismatch
 */
export async function update(
  client: DbClient,
  id: string,
  updates: Partial<Attestation>,
  expectedVersion?: number
): Promise<Attestation | null> {
  const allowedFields = ['merkle_root', 'tx_hash', 'status'];
  const setClauses: string[] = ['version = version + 1'];
  const params: any[] = [];
  let paramIndex = 1;

  for (const [key, value] of Object.entries(updates)) {
    if (['id', 'businessId', 'period', 'version', 'createdAt', 'updatedAt'].includes(key)) {
      continue;
    }
    const dbKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
    if (allowedFields.includes(dbKey)) {
      setClauses.push(`${dbKey} = $${paramIndex}`);
      params.push(value);
      paramIndex++;
    }
  }

  if (setClauses.length === 1) {
    throw new Error('No valid fields to update');
  }

  let sql: string;
  if (expectedVersion !== undefined) {
    sql = `
      UPDATE attestations
      SET ${setClauses.join(', ')}
      WHERE id = $${paramIndex} AND version = $${paramIndex + 1}
      RETURNING *
    `;
    params.push(id, expectedVersion);
  } else {
    sql = `
      UPDATE attestations
      SET ${setClauses.join(', ')}
      WHERE id = $${paramIndex}
      RETURNING *
    `;
    params.push(id);
  }

  try {
    await applyStatementTimeout(client, STATEMENT_TIMEOUT_MS);
    const t0 = Date.now();
    const result = await client.query<AttestationRow>(sql, params);
    warnIfSlow('update', Date.now() - t0, result.rows.length, { id });

    if (result.rows.length === 0) {
      if (expectedVersion !== undefined) {
        const existing = await getById(client, id);
        if (existing) {
          throw createConflictError(
            ConflictErrorType.CONFLICT_TYPE_VERSION,
            `Attestation ${id} has been modified by another process`,
            { id, expectedVersion, currentVersion: existing.version }
          );
        }
      }
      return null;
    }

    return mapRowToAttestation(result.rows[0]);
  } catch (error) {
    if (error instanceof ConflictError) throw error;
    throw error;
  }
}

/**
 * Attempts to create an attestation with automatic conflict handling.
 * Checks for an existing attestation before attempting insert.
 *
 * @param client  - Database client for executing queries
 * @param data    - Attestation data to insert
 * @param options - Options for conflict handling behaviour
 * @returns Promise resolving to the created Attestation record
 * @throws ConflictError if conflict cannot be resolved
 */
export async function createWithConflictCheck(
  client: DbClient,
  data: CreateAttestationInput,
  options: {
    returnExistingOnConflict?: boolean;
    retryOnConflict?: boolean;
    maxRetries?: number;
  } = {}
): Promise<Attestation> {
  const { returnExistingOnConflict = false, retryOnConflict = false, maxRetries = 3 } = options;

  const existing = await getByBusinessAndPeriod(client, data.businessId, data.period);
  if (existing) {
    if (returnExistingOnConflict) return existing;
    throw createConflictError(
      ConflictErrorType.CONFLICT_TYPE_DUPLICATE,
      `Attestation for business ${data.businessId} and period ${data.period} already exists`,
      { businessId: data.businessId, period: data.period, existingId: existing.id }
    );
  }

  let lastError: Error | null = null;
  let attempts = 0;
  const maxAttempts = retryOnConflict ? maxRetries : 1;

  while (attempts < maxAttempts) {
    try {
      return await create(client, data);
    } catch (error: any) {
      lastError = error;
      if (error instanceof ConflictError && error.type === ConflictErrorType.CONFLICT_TYPE_DUPLICATE) {
        if (retryOnConflict && attempts < maxAttempts - 1) {
          attempts++;
          const recheck = await getByBusinessAndPeriod(client, data.businessId, data.period);
          if (recheck) {
            if (returnExistingOnConflict) return recheck;
            throw error;
          }
          continue;
        }
      }
      throw error;
    }
  }

  throw lastError;
}

/**
 * Deletes an attestation record.
 *
 * @param client - Database client for executing queries
 * @param id     - UUID of the attestation to delete
 * @returns Promise resolving to true if deleted, false if not found
 */
export async function remove(
  client: DbClient,
  id: string
): Promise<boolean> {
  const sql = `DELETE FROM attestations WHERE id = $1 RETURNING id`;

  await applyStatementTimeout(client, STATEMENT_TIMEOUT_MS);
  const t0 = Date.now();
  const result = await client.query<{ id: string }>(sql, [id]);
  warnIfSlow('remove', Date.now() - t0, result.rows.length, { id });

  return result.rows.length > 0;
}
