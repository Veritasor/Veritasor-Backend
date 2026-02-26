/**
 * Fast-check Arbitrary Generators for Attestation Repository Property Tests
 * 
 * This module provides custom generators for property-based testing of the attestation repository.
 * Each generator produces valid random inputs that conform to the expected formats and constraints.
 */

import fc from 'fast-check';
import { AttestationStatus, CreateAttestationInput, PaginationParams } from '../../../src/types/attestation.js';

/**
 * Generates valid UUID v4 strings
 * Format: 8-4-4-4-12 hex digits (e.g., "550e8400-e29b-41d4-a716-446655440000")
 */
export const uuidArbitrary = (): fc.Arbitrary<string> => {
  const hexChar = () => fc.integer({ min: 0, max: 15 }).map(n => n.toString(16));
  
  return fc.tuple(
    fc.array(hexChar(), { minLength: 8, maxLength: 8 }),
    fc.array(hexChar(), { minLength: 4, maxLength: 4 }),
    fc.array(hexChar(), { minLength: 4, maxLength: 4 }),
    fc.array(hexChar(), { minLength: 4, maxLength: 4 }),
    fc.array(hexChar(), { minLength: 12, maxLength: 12 })
  ).map(([a, b, c, d, e]) => 
    `${a.join('')}-${b.join('')}-${c.join('')}-${d.join('')}-${e.join('')}`
  );
};

/**
 * Generates valid period strings
 * Formats: "YYYY-MM" (e.g., "2025-10") or "YYYY-QN" (e.g., "2025-Q4")
 */
export const periodArbitrary = (): fc.Arbitrary<string> => {
  return fc.oneof(
    // Monthly format: YYYY-MM
    fc.tuple(
      fc.integer({ min: 2020, max: 2030 }),
      fc.integer({ min: 1, max: 12 })
    ).map(([year, month]) => `${year}-${month.toString().padStart(2, '0')}`),
    
    // Quarterly format: YYYY-QN
    fc.tuple(
      fc.integer({ min: 2020, max: 2030 }),
      fc.integer({ min: 1, max: 4 })
    ).map(([year, quarter]) => `${year}-Q${quarter}`)
  );
};

/**
 * Generates valid Merkle root hashes
 * Format: "0x" + 64 hex characters
 */
export const merkleRootArbitrary = (): fc.Arbitrary<string> => {
  const hexChar = () => fc.integer({ min: 0, max: 15 }).map(n => n.toString(16));
  
  return fc.array(hexChar(), { minLength: 64, maxLength: 64 })
    .map(chars => `0x${chars.join('')}`);
};

/**
 * Generates valid transaction hashes
 * Format: "0x" + 64 hex characters
 */
export const txHashArbitrary = (): fc.Arbitrary<string> => {
  const hexChar = () => fc.integer({ min: 0, max: 15 }).map(n => n.toString(16));
  
  return fc.array(hexChar(), { minLength: 64, maxLength: 64 })
    .map(chars => `0x${chars.join('')}`);
};

/**
 * Generates valid attestation status values
 * Randomly selects from: pending, submitted, confirmed, failed, revoked
 */
export const statusArbitrary = (): fc.Arbitrary<AttestationStatus> => {
  return fc.constantFrom<AttestationStatus>(
    'pending',
    'submitted',
    'confirmed',
    'failed',
    'revoked'
  );
};

/**
 * Generates valid pagination parameters
 * - limit: 1-100 (reasonable page sizes)
 * - offset: 0-1000 (reasonable offset range)
 */
export const paginationParamsArbitrary = (): fc.Arbitrary<PaginationParams> => {
  return fc.record({
    limit: fc.integer({ min: 1, max: 100 }),
    offset: fc.integer({ min: 0, max: 1000 })
  });
};

/**
 * Generates complete CreateAttestationInput objects
 * Combines all individual generators to create valid attestation data
 */
export const createAttestationInputArbitrary = (): fc.Arbitrary<CreateAttestationInput> => {
  return fc.record({
    businessId: uuidArbitrary(),
    period: periodArbitrary(),
    merkleRoot: merkleRootArbitrary(),
    txHash: txHashArbitrary(),
    status: statusArbitrary()
  });
};

/**
 * Fast-check configuration for property tests
 * Sets the number of iterations per property test to 100
 */
export const propertyTestConfig = {
  numRuns: 100
};
