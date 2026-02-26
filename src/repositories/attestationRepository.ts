/**
 * Attestation Repository
 * 
 * Data access layer for blockchain attestation records.
 * Provides CRUD operations for attestations with proper type safety and error handling.
 */

import {
  Attestation,
  AttestationStatus,
  CreateAttestationInput,
  AttestationFilters,
  PaginationParams,
  PaginatedResult,
  DbClient,
} from '../types/attestation.js';

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
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
  };
}

/**
 * Creates a new attestation record in the database
 * 
 * @param client - Database client for executing queries
 * @param data - Attestation data to insert
 * @returns Promise resolving to the created Attestation record with generated id and timestamps
 * @throws Database errors including unique constraint violations for duplicate businessId + period
 * 
 * Requirements: 1.1, 1.2, 1.3, 1.5, 5.1
 */
export async function create(
  client: DbClient,
  data: CreateAttestationInput
): Promise<Attestation> {
  const sql = `
    INSERT INTO attestations (business_id, period, merkle_root, tx_hash, status)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING *
  `;

  const params = [
    data.businessId,
    data.period,
    data.merkleRoot,
    data.txHash,
    data.status,
  ];

  const result = await client.query<AttestationRow>(sql, params);
  return mapRowToAttestation(result.rows[0]);
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
  id: string
): Promise<Attestation | null> {
  const sql = `SELECT * FROM attestations WHERE id = $1`;
  
  const result = await client.query<AttestationRow>(sql, [id]);
  
  if (result.rows.length === 0) {
    return null;
  }
  
  return mapRowToAttestation(result.rows[0]);
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
 * Updates the status of an existing attestation
 * 
 * @param client - Database client for executing queries
 * @param id - UUID of the attestation to update
 * @param status - New status value (must be a valid AttestationStatus)
 * @returns Promise resolving to the updated Attestation record or null if not found
 * @throws Error if status is not a valid AttestationStatus value
 * 
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 5.4
 */
export async function updateStatus(
  client: DbClient,
  id: string,
  status: AttestationStatus
): Promise<Attestation | null> {
  // Validate status is a valid AttestationStatus value
  const validStatuses: AttestationStatus[] = ['pending', 'submitted', 'confirmed', 'failed', 'revoked'];
  if (!validStatuses.includes(status)) {
    throw new Error(`Invalid status: ${status}. Must be one of: ${validStatuses.join(', ')}`);
  }

  const sql = `
    UPDATE attestations
    SET status = $1
    WHERE id = $2
    RETURNING *
  `;

  const result = await client.query<AttestationRow>(sql, [status, id]);

  // Return null if no rows affected (id not found)
  if (result.rows.length === 0) {
    return null;
  }

  return mapRowToAttestation(result.rows[0]);
}
