import { describe, it, expect, expectTypeOf } from 'vitest';
import {
  AttestationStatus,
  Attestation,
  CreateAttestationInput,
  ConflictError,
  ConflictErrorType,
  createConflictError,
  ReadConsistency
} from '../../../src/types/attestation';

describe('Attestation Types', () => {
  describe('AttestationStatus', () => {
    it('allows valid state transitions (type level)', () => {
      // These represent the runtime values of the types
      const validStatuses: AttestationStatus[] = [
        'pending',
        'submitted',
        'confirmed',
        'failed',
        'revoked',
      ];
      
      expect(validStatuses).toHaveLength(5);
      
      // Checking type-level constraints
      type ExpectedStatuses = 'pending' | 'submitted' | 'confirmed' | 'failed' | 'revoked';
      expectTypeOf<AttestationStatus>().toEqualTypeOf<ExpectedStatuses>();
    });

    it('rejects invalid inputs (type level)', () => {
      // @ts-expect-error - invalid status should cause a type error
      const invalidStatus: AttestationStatus = 'completed';
      
      // @ts-expect-error - another invalid status
      const anotherInvalid: AttestationStatus = 'unknown';

      // We just need these for the compiler to assert, no runtime behavior needed
      expect(invalidStatus).toBe('completed');
      expect(anotherInvalid).toBe('unknown');
    });
  });

  describe('Attestation Interface', () => {
    it('enforces required fields for a complete attestation', () => {
      const now = new Date();
      const attestation: Attestation = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        businessId: '987fcdeb-51a2-43d7-9012-345678901234',
        period: '2025-Q4',
        merkleRoot: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        txHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        status: 'pending',
        version: 1,
        createdAt: now,
        updatedAt: now,
      };

      expect(attestation.id).toBeDefined();
      expectTypeOf(attestation).toMatchTypeOf<Attestation>();
    });
  });

  describe('CreateAttestationInput', () => {
    it('enforces required input fields excluding auto-generated ones', () => {
      const input: CreateAttestationInput = {
        businessId: '987fcdeb-51a2-43d7-9012-345678901234',
        period: '2025-Q4',
        merkleRoot: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        txHash: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        status: 'pending',
      };

      expect(input.businessId).toBeDefined();

      // These shouldn't exist on CreateAttestationInput
      expectTypeOf(input).not.toHaveProperty('id');
      expectTypeOf(input).not.toHaveProperty('version');
      expectTypeOf(input).not.toHaveProperty('createdAt');
      expectTypeOf(input).not.toHaveProperty('updatedAt');
    });

    it('rejects invalid inputs for creation (type level)', () => {
      // @ts-expect-error - missing required fields
      const invalidInput: CreateAttestationInput = {
        businessId: '123',
      };
      expect(invalidInput.businessId).toBe('123');
    });
  });

  describe('ConflictError and ConflictErrorType', () => {
    it('creates a ConflictError with the correct type and defaults', () => {
      const error = new ConflictError(
        ConflictErrorType.CONFLICT_TYPE_DUPLICATE,
        'Duplicate attestation'
      );

      expect(error.name).toBe('ConflictError');
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
      expect(error.message).toBe('Duplicate attestation');
      expect(error.details).toEqual({});
      expect(error.status).toBe(409);
      expect(error).toBeInstanceOf(Error);
    });

    it('creates a ConflictError using the factory function with details', () => {
      const details = { period: '2025-Q4', businessId: '123' };
      const error = createConflictError(
        ConflictErrorType.CONFLICT_TYPE_VERSION,
        'Version mismatch',
        details
      );

      expect(error.name).toBe('ConflictError');
      expect(error.type).toBe(ConflictErrorType.CONFLICT_TYPE_VERSION);
      expect(error.message).toBe('Version mismatch');
      expect(error.details).toEqual(details);
      expect(error.status).toBe(409);
    });

    it('exposes all observable conflict types deterministically', () => {
      const types = Object.values(ConflictErrorType);
      expect(types).toContain(ConflictErrorType.CONFLICT_TYPE_DUPLICATE);
      expect(types).toContain(ConflictErrorType.CONFLICT_TYPE_VERSION);
      expect(types).toContain(ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY);
      expect(types).toContain(ConflictErrorType.CONFLICT_TYPE_NOT_FOUND);
    });
  });

  describe('ReadConsistency', () => {
    it('defines valid consistency levels', () => {
      expect(ReadConsistency.LOCAL).toBe('local');
      expect(ReadConsistency.STRONG).toBe('strong');
    });
  });
});
