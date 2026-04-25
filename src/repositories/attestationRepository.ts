/**
 * Attestation Repository
 * 
 * Data access layer for blockchain attestation records.
 * Provides CRUD operations for attestations with proper type safety and error handling.
 * Includes write conflict detection and handling for concurrent operations.
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
 * Maps a database row to an Attestation object
 * Converts snake_case to camelCase and timestamp strings to Date objects
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
 * @param data - Attestation data to insert
 * @returns Promise resolving to the created Attestation record with generated id and timestamps
 * @throws ConflictError with CONFLICT_TYPE_DUPLICATE if businessId + period combination already exists
 * @throws ConflictError with CONFLICT_TYPE_FOREIGN_KEY if businessId does not exist
 * 
 * Requirements: 1.1, 1.2, 1.3, 1.5, 5.1
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
    const result = await client.query<AttestationRow>(sql, params);
    return mapRowToAttestation(result.rows[0]);
  } catch (error: any) {
    // Handle unique constraint violation (duplicate businessId + period)
    if (error.code === '23505') {
      throw createConflictError(
        ConflictErrorType.CONFLICT_TYPE_DUPLICATE,
        `Attestation for business ${data.businessId} and period ${data.period} already exists`,
        { businessId: data.businessId, period: data.period }
      );
    }
    // Handle foreign key violation
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
 * Retrieves a single attestation by its unique identifier
 * 
 * @param client - Database client for executing queries
 * @param id - UUID of the attestation to retrieve
 * @returns Promise resolving to the Attestation record or null if not found
 * 
 * Requirements: 2.1, 2.2, 2.3, 2.4, 5.2
 */
export async function getById(
  client: DbClient,
  id: string,
  options: ConsistencyOptions = {}
): Promise<Attestation | null> {
  const sql = `SELECT * FROM attestations WHERE id = $1`;
  
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
 * Retrieves an attestation by business ID and period
 * Useful for checking existing attestations before creating new ones
 * 
 * @param client - Database client for executing queries
 * @param businessId - UUID of the business
 * @param period - Time period identifier
 * @returns Promise resolving to the Attestation record or null if not found
 */
export async function getByBusinessAndPeriod(
  client: DbClient,
  businessId: string,
  period: string,
  options: ConsistencyOptions = {}
): Promise<Attestation | null> {
  const sql = `SELECT * FROM attestations WHERE business_id = $1 AND period = $2`;
  
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
 * Lists attestations with optional filtering and pagination
 * 
 * @param client - Database client for executing queries
 * @param filters - Optional filters for businessId or userId
 * @param pagination - Limit and offset for pagination
 * @returns Promise resolving to paginated results with items and total count
 * 
 * Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 5.3
 */
export async function list(
  client: DbClient,
  filters: AttestationFilters,
  pagination: PaginationParams
): Promise<PaginatedResult<Attestation>> {
  // Build dynamic query based on filters
  let dataQuery: string;
  let countQuery: string;
  let params: any[];

  if (filters.userId) {
    // Join with businesses table for userId filter
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
    // Direct filter on businessId
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
    // No filters - return all attestations
    dataQuery = `
      SELECT * FROM attestations
      ORDER BY created_at DESC
      LIMIT $1 OFFSET $2
    `;
    countQuery = `SELECT COUNT(*) FROM attestations`;
    params = [pagination.limit, pagination.offset];
  }

  // Execute count query
  const countParams = filters.userId || filters.businessId ? [params[0]] : [];
  const countResult = await client.query<{ count: string }>(countQuery, countParams);
  const total = parseInt(countResult.rows[0].count, 10);

  // Execute data query
  const dataResult = await client.query<AttestationRow>(dataQuery, params);
  const items = dataResult.rows.map(mapRowToAttestation);

  return {
    items,
    total,
  };
}

/**
 * Updates the status of an existing attestation with optimistic locking
 * 
 * @param client - Database client for executing queries
 * @param id - UUID of the attestation to update
 * @param status - New status value (must be a valid AttestationStatus)
 * @param expectedVersion - Expected version for optimistic locking (optional, enables conflict detection)
 * @returns Promise resolving to the updated Attestation record or null if not found
 * @throws ConflictError with CONFLICT_TYPE_VERSION if version mismatch (concurrent modification detected)
 * @throws Error if status is not a valid AttestationStatus value
 * 
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 5.4
 */
export async function updateStatus(
  client: DbClient,
  id: string,
  status: AttestationStatus,
  expectedVersion?: number
): Promise<Attestation | null> {
  // Validate status is a valid AttestationStatus value
  const validStatuses: AttestationStatus[] = ['pending', 'submitted', 'confirmed', 'failed', 'revoked'];
  if (!validStatuses.includes(status)) {
    throw new Error(`Invalid status: ${status}. Must be one of: ${validStatuses.join(', ')}`);
  }

  let sql: string;
  let params: any[];

  if (expectedVersion !== undefined) {
    // Use optimistic locking with version check
    sql = `
      UPDATE attestations
      SET status = $1, version = version + 1
      WHERE id = $2 AND version = $3
      RETURNING *
    `;
    params = [status, id, expectedVersion];
  } else {
    // Standard update without version check
    sql = `
      UPDATE attestations
      SET status = $1, version = version + 1
      WHERE id = $2
      RETURNING *
    `;
    params = [status, id];
  }

  try {
    const result = await client.query<AttestationRow>(sql, params);

    // Check if row was updated
    if (result.rows.length === 0) {
      // If we expected a specific version, this is a conflict
      if (expectedVersion !== undefined) {
        // Check if the record exists to determine the type of failure
        const existing = await getById(client, id);
        if (existing) {
          throw createConflictError(
            ConflictErrorType.CONFLICT_TYPE_VERSION,
            `Attestation ${id} has been modified by another process. Expected version ${expectedVersion}, current version ${existing.version}`,
            { id, expectedVersion, currentVersion: existing.version }
          );
        }
        return null;
      }
      return null;
    }

    return mapRowToAttestation(result.rows[0]);
  } catch (error) {
    // Re-throw conflict errors
    if (error instanceof ConflictError) {
      throw error;
    }
    throw error;
  }
}

/**
 * Updates an attestation record with optimistic locking support
 * 
 * @param client - Database client for executing queries
 * @param id - UUID of the attestation to update
 * @param updates - Partial attestation data to update
 * @param expectedVersion - Expected version for optimistic locking (optional)
 * @returns Promise resolving to the updated Attestation record or null if not found
 * @throws ConflictError with CONFLICT_TYPE_VERSION if version mismatch
 * @throws ConflictError with CONFLICT_TYPE_NOT_FOUND if attestation doesn't exist
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

  // Build dynamic update query
  for (const [key, value] of Object.entries(updates)) {
    if (key === 'id' || key === 'businessId' || key === 'period' || 
        key === 'version' || key === 'createdAt' || key === 'updatedAt') {
      continue; // Skip non-updatable fields
    }
    const dbKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
    if (allowedFields.includes(dbKey)) {
      setClauses.push(`${dbKey} = \${paramIndex}`);
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
      WHERE id = \${paramIndex} AND version = \${paramIndex + 1}
      RETURNING *
    `;
    params.push(id, expectedVersion);
  } else {
    sql = `
      UPDATE attestations
      SET ${setClauses.join(', ')}
      WHERE id = \${paramIndex}
      RETURNING *
    `;
    params.push(id);
  }

  try {
    const result = await client.query<AttestationRow>(sql, params);

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
    if (error instanceof ConflictError) {
      throw error;
    }
    throw error;
  }
}

/**
 * Attempts to create an attestation with automatic conflict handling
 * Checks for existing attestation before attempting insert
 * 
 * @param client - Database client for executing queries
 * @param data - Attestation data to insert
 * @param options - Options for conflict handling behavior
 * @returns Promise resolving to the created Attestation record
 * @throws ConflictError if conflict cannot be resolved
 */
export async function createWithConflictCheck(
  client: DbClient,
  data: CreateAttestationInput,
  options: {
    /** If true, returns existing record instead of throwing on conflict */
    returnExistingOnConflict?: boolean;
    /** If true, retries the operation on transient conflicts */
    retryOnConflict?: boolean;
    /** Maximum number of retries for retry option */
    maxRetries?: number;
  } = {}
): Promise<Attestation> {
  const { returnExistingOnConflict = false, retryOnConflict = false, maxRetries = 3 } = options;

  // First check if an attestation already exists
  const existing = await getByBusinessAndPeriod(client, data.businessId, data.period);
  if (existing) {
    if (returnExistingOnConflict) {
      return existing;
    }
    throw createConflictError(
      ConflictErrorType.CONFLICT_TYPE_DUPLICATE,
      `Attestation for business ${data.businessId} and period ${data.period} already exists`,
      { businessId: data.businessId, period: data.period, existingId: existing.id }
    );
  }

  // Attempt to create with retry logic
  let lastError: Error | null = null;
  let attempts = 0;
  const maxAttempts = retryOnConflict ? maxRetries : 1;

  while (attempts < maxAttempts) {
    try {
      return await create(client, data);
    } catch (error: any) {
      lastError = error;
      
      // Check if it's a conflict error we can retry
      if (error instanceof ConflictError && error.type === ConflictErrorType.CONFLICT_TYPE_DUPLICATE) {
        if (retryOnConflict && attempts < maxAttempts - 1) {
          attempts++;
          // Re-check if still exists (another process might have created it)
          const recheck = await getByBusinessAndPeriod(client, data.businessId, data.period);
          if (recheck) {
            if (returnExistingOnConflict) {
              return recheck;
            }
            throw error;
          }
          continue;
        }
      }
      
      // For foreign key errors or non-conflict errors, don't retry
      throw error;
    }
  }
  
  throw lastError;
}

/**
 * Deletes an attestation record
 * 
 * @param client - Database client for executing queries
 * @param id - UUID of the attestation to delete
 * @returns Promise resolving to true if deleted, false if not found
 */
export async function remove(
  client: DbClient,
  id: string
): Promise<boolean> {
  const sql = `DELETE FROM attestations WHERE id = $1 RETURNING id`;
  
  const result = await client.query<{ id: string }>(sql, [id]);
  
  return result.rows.length > 0;
}
