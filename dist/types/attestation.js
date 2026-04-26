/**
 * Attestation Repository Type Definitions
 *
 * This module defines all TypeScript interfaces and types for the attestation repository.
 * These types ensure type safety across the data access layer for blockchain attestation records.
 */
/**
 * Conflict error types for write conflict detection
 * These errors are thrown when concurrent operations conflict
 */
export var ConflictErrorType;
(function (ConflictErrorType) {
    /** Duplicate key - business_id + period already exists */
    ConflictErrorType["CONFLICT_TYPE_DUPLICATE"] = "DUPLICATE";
    /** Version mismatch - record was modified by another process */
    ConflictErrorType["CONFLICT_TYPE_VERSION"] = "VERSION_MISMATCH";
    /** Foreign key constraint violation */
    ConflictErrorType["CONFLICT_TYPE_FOREIGN_KEY"] = "FOREIGN_KEY_VIOLATION";
    /** Record not found */
    ConflictErrorType["CONFLICT_TYPE_NOT_FOUND"] = "NOT_FOUND";
})(ConflictErrorType || (ConflictErrorType = {}));
/**
 * Conflict error class for handling write conflicts
 * Provides detailed information about the conflict for proper handling
 */
export class ConflictError extends Error {
    type;
    details;
    status;
    constructor(type, message, details = {}) {
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
export function createConflictError(type, message, details = {}) {
    return new ConflictError(type, message, details);
}
