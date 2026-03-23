/**
 * Attestation Repository Type Definitions
 * 
 * This module defines all TypeScript interfaces and types for the attestation repository.
 * These types ensure type safety across the data access layer for blockchain attestation records.
 */

/**
 * Status enum for attestation records
 * Represents the current state of an attestation in its lifecycle
 */
export type AttestationStatus = 'pending' | 'submitted' | 'confirmed' | 'failed' | 'revoked';

/**
 * Core attestation record type
 * Represents a complete attestation record as stored in the database
 */
export interface Attestation {
  /** Unique identifier (UUID) */
  id: string;
  /** Reference to business entity (UUID) */
  businessId: string;
  /** Time period identifier (e.g., "2025-10", "2025-Q4") */
  period: string;
  /** Merkle tree root hash (0x + 64 hex characters) */
  merkleRoot: string;
  /** Blockchain transaction hash (0x + 64 hex characters) */
  txHash: string;
  /** Current attestation state */
  status: AttestationStatus;
  /** Version number for optimistic locking (incremented on each update) */
  version: number;
  /** Record creation timestamp */
  createdAt: Date;
  /** Last update timestamp */
  updatedAt: Date;
}

/**
 * Input type for creating attestations
 * Contains all required fields except auto-generated ones (id, timestamps)
 */
export interface CreateAttestationInput {
  /** Reference to business entity (UUID) */
  businessId: string;
  /** Time period identifier (e.g., "2025-10", "2025-Q4") */
  period: string;
  /** Merkle tree root hash (0x + 64 hex characters) */
  merkleRoot: string;
  /** Blockchain transaction hash (0x + 64 hex characters) */
  txHash: string;
  /** Initial attestation state */
  status: AttestationStatus;
}

/**
 * Filter options for listing attestations
 * All fields are optional to allow flexible querying
 */
export interface AttestationFilters {
  /** Filter by business ID */
  businessId?: string;
  /** Filter by user ID (joins with businesses table) */
  userId?: string;
}

/**
 * Pagination parameters for list queries
 */
export interface PaginationParams {
  /** Maximum number of items to return */
  limit: number;
  /** Number of items to skip */
  offset: number;
}

/**
 * Generic paginated result type
 * Contains both the data items and total count for pagination
 */
export interface PaginatedResult<T> {
  /** Array of items for the current page */
  items: T[];
  /** Total count of items matching the query (ignoring pagination) */
  total: number;
}

/**
 * Database client interface
 * Defines the contract for database operations used by the repository
 */
export interface DbClient {
  /**
   * Execute a SQL query with optional parameters
   * @param sql SQL query string with parameter placeholders ($1, $2, etc.)
   * @param params Optional array of parameter values
   * @returns Promise resolving to query result with rows array
   */
  query<T = any>(sql: string, params?: any[]): Promise<{ rows: T[] }>;
}

/**
 * Conflict error types for write conflict detection
 * These errors are thrown when concurrent operations conflict
 */
export enum ConflictErrorType {
  /** Duplicate key - business_id + period already exists */
  CONFLICT_TYPE_DUPLICATE = 'DUPLICATE',
  /** Version mismatch - record was modified by another process */
  CONFLICT_TYPE_VERSION = 'VERSION_MISMATCH',
  /** Foreign key constraint violation */
  CONFLICT_TYPE_FOREIGN_KEY = 'FOREIGN_KEY_VIOLATION',
  /** Record not found */
  CONFLICT_TYPE_NOT_FOUND = 'NOT_FOUND',
}

/**
 * Conflict error class for handling write conflicts
 * Provides detailed information about the conflict for proper handling
 */
export class ConflictError extends Error {
  public readonly type: ConflictErrorType;
  public readonly details: Record<string, any>;
  public readonly status: number;

  constructor(
    type: ConflictErrorType,
    message: string,
    details: Record<string, any> = {}
  ) {
    super(message);
    this.name = 'ConflictError';
    this.type = type;
    this.details = details;
    this.status = 409; // HTTP Conflict status code
  }
}

/**
 * Factory function to create a ConflictError with proper typing
 * 
 * @param type - The type of conflict that occurred
 * @param message - Human-readable error message
 * @param details - Additional context about the conflict
 * @returns A new ConflictError instance
 */
export function createConflictError(
  type: ConflictErrorType,
  message: string,
  details: Record<string, any> = {}
): ConflictError {
  return new ConflictError(type, message, details);
}
