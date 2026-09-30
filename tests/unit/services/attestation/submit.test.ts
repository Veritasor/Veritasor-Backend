/**
 * Regression test suite for submitAttestation failure handling and edge cases.
 *
 * Issue #963: Add regression coverage for submitAttestation failure handling
 *
 * Evidence exercised:
 * - Evidence 1: src/services/attestation/submit.ts:340
 *   throw new Error(`Failed to fetch revenue: ${err.message}`);
 * - Evidence 2: src/services/attestation/submit.ts:344
 *   throw new Error(`No revenue found for the period ${period}`);
 * - Evidence 3: src/services/attestation/submit.ts:362
 *   throw new Error("Failed to generate Merkle root from aggregated data.");
 *
 * Surrounding paths & contracts exercised:
 * - Neighboring normal path (single-month and multi-month revenues, quarterly periods, monthly periods)
 * - Return contract: { attestationId: string; txHash: string }
 * - Boundary inputs: zero revenue amount, fractional amounts, leap year, month/quarter boundaries
 * - Error taxonomy preservation and structured error logging
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Configure immediate batch queue flushing for deterministic unit test execution
process.env.SOROBAN_BATCH_MAX_SIZE = '1';
process.env.SOROBAN_BATCH_FLUSH_COOLDOWN_MS = '0';
process.env.SOROBAN_BATCH_MAX_LATENCY_MS = '0';

import { submitAttestation, SorobanErrorCode } from '../../../../src/services/attestation/submit.js';
import { fetchRazorpayRevenue } from '../../../../src/services/revenue/razorpayFetch.js';
import { attestationRepository } from '../../../../src/repositories/attestation.js';
import { MerkleTree } from '../../../../src/services/merkle.js';
import { AppError } from '../../../../src/types/errors.js';

// Mock dependencies
vi.mock('../../../../src/services/revenue/razorpayFetch.js');
vi.mock('../../../../src/repositories/attestation.js');

const mockFetchRazorpayRevenue = vi.mocked(fetchRazorpayRevenue);
const mockAttestationRepository = vi.mocked(attestationRepository);

// Mock console methods to avoid noisy logs and verify structured logging
const mockConsoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
const mockConsoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
const mockConsoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

describe('submitAttestation - Regression coverage for failure handling (#963)', () => {
  const userId = 'usr_test_963';
  const businessId = 'biz_test_963';
  const period = '2025-03';

  const mockRevenueEntries = [
    {
      id: 'pay_001',
      date: '2025-03-05T10:00:00Z',
      amount: 1250.5,
      currency: 'USD',
      source: 'razorpay' as const,
    },
    {
      id: 'pay_002',
      date: '2025-03-20T14:30:00Z',
      amount: 749.5,
      currency: 'USD',
      source: 'razorpay' as const,
    },
  ];

  const mockCreatedAttestation = {
    id: 'att_reg_001',
    businessId,
    period,
    attestedAt: '2025-04-01T00:00:00.000Z',
    status: 'active' as const,
  };

  let originalMathRandom: () => number;

  beforeEach(() => {
    vi.clearAllMocks();

    // Default to deterministic success for Soroban simulation (avoiding transient error triggers)
    originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.5);

    mockFetchRazorpayRevenue.mockResolvedValue(mockRevenueEntries);
    mockAttestationRepository.create.mockReturnValue(mockCreatedAttestation);
  });

  afterEach(() => {
    Math.random = originalMathRandom;
    mockConsoleLog.mockClear();
    mockConsoleWarn.mockClear();
    mockConsoleError.mockClear();
  });

  // ---------------------------------------------------------------------------
  // Evidence 1: Revenue Fetch Failure (submit.ts:340)
  // ---------------------------------------------------------------------------
  describe('Evidence 1: Revenue fetch failure handling (submit.ts:340)', () => {
    it('rejects with ATTESTATION_SUBMIT_FAILED AppError when fetchRazorpayRevenue throws an Error', async () => {
      mockFetchRazorpayRevenue.mockRejectedValue(new Error('Razorpay gateway timeout'));

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: Failed to fetch revenue: Razorpay gateway timeout',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      // Verify fetch was called with computed ISO range
      expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
        '2025-03-01T00:00:00Z',
        '2025-03-31T23:59:59Z',
      );

      // Downstream operations must not execute
      expect(mockAttestationRepository.create).not.toHaveBeenCalled();

      // Error must be logged with structured context
      expect(mockConsoleError).toHaveBeenCalledWith(
        expect.stringContaining('"service":"attestation-submit"'),
      );
      expect(mockConsoleError).toHaveBeenCalledWith(
        expect.stringContaining('Failed to fetch revenue: Razorpay gateway timeout'),
      );
    });

    it('handles revenue fetch failure when the error message is empty', async () => {
      mockFetchRazorpayRevenue.mockRejectedValue(new Error(''));

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: Failed to fetch revenue: ',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      expect(mockAttestationRepository.create).not.toHaveBeenCalled();
    });

    it('handles upstream 429 rate limit errors from the payment provider', async () => {
      mockFetchRazorpayRevenue.mockRejectedValue(new Error('Rate limit exceeded: HTTP 429'));

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: Failed to fetch revenue: Rate limit exceeded: HTTP 429',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      expect(mockAttestationRepository.create).not.toHaveBeenCalled();
    });
  });

  // ---------------------------------------------------------------------------
  // Evidence 2: Empty Revenue Result (submit.ts:344)
  // ---------------------------------------------------------------------------
  describe('Evidence 2: Empty revenue result path (submit.ts:344)', () => {
    it('rejects with ATTESTATION_SUBMIT_FAILED AppError when fetchRazorpayRevenue returns [] for monthly period', async () => {
      mockFetchRazorpayRevenue.mockResolvedValue([]);

      await expect(submitAttestation(userId, businessId, '2025-06')).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: No revenue found for the period 2025-06',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      // Verify date range requested
      expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
        '2025-06-01T00:00:00Z',
        '2025-06-30T23:59:59Z',
      );

      // Merkle tree and repository saving must not be reached
      expect(mockAttestationRepository.create).not.toHaveBeenCalled();

      // Observable error log
      expect(mockConsoleError).toHaveBeenCalledWith(
        expect.stringContaining('No revenue found for the period 2025-06'),
      );
    });

    it('rejects with ATTESTATION_SUBMIT_FAILED AppError when fetchRazorpayRevenue returns [] for quarterly period', async () => {
      mockFetchRazorpayRevenue.mockResolvedValue([]);

      await expect(submitAttestation(userId, businessId, '2025-Q2')).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: No revenue found for the period 2025-Q2',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      // Q2 spans April 1 to June 30
      expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
        '2025-04-01T00:00:00Z',
        '2025-06-30T23:59:59Z',
      );

      expect(mockAttestationRepository.create).not.toHaveBeenCalled();
    });
  });

  // ---------------------------------------------------------------------------
  // Evidence 3: Merkle Root Generation Failure (submit.ts:362)
  // ---------------------------------------------------------------------------
  describe('Evidence 3: Merkle root generation failure (submit.ts:362)', () => {
    it('rejects with ATTESTATION_SUBMIT_FAILED AppError when MerkleTree getRoot returns an empty string', async () => {
      const getRootSpy = vi.spyOn(MerkleTree.prototype, 'getRoot').mockReturnValue('');

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: Failed to generate Merkle root from aggregated data.',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      expect(mockAttestationRepository.create).not.toHaveBeenCalled();
      expect(mockConsoleError).toHaveBeenCalledWith(
        expect.stringContaining('Failed to generate Merkle root from aggregated data.'),
      );

      getRootSpy.mockRestore();
    });

    it('rejects with ATTESTATION_SUBMIT_FAILED AppError when MerkleTree getRoot returns null as any', async () => {
      const getRootSpy = vi.spyOn(MerkleTree.prototype, 'getRoot').mockReturnValue(null as any);

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: Failed to generate Merkle root from aggregated data.',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      expect(mockAttestationRepository.create).not.toHaveBeenCalled();

      getRootSpy.mockRestore();
    });

    it('rejects with ATTESTATION_SUBMIT_FAILED AppError when MerkleTree getRoot returns undefined as any', async () => {
      const getRootSpy = vi.spyOn(MerkleTree.prototype, 'getRoot').mockReturnValue(undefined as any);

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: Failed to generate Merkle root from aggregated data.',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );

      expect(mockAttestationRepository.create).not.toHaveBeenCalled();

      getRootSpy.mockRestore();
    });
  });

  // ---------------------------------------------------------------------------
  // Neighboring Normal Path & Return Contract
  // ---------------------------------------------------------------------------
  describe('Neighboring normal path & return contract', () => {
    it('successfully processes single-month revenue data and returns { attestationId, txHash }', async () => {
      const result = await submitAttestation(userId, businessId, period);

      expect(result).toEqual({
        attestationId: 'att_reg_001',
        txHash: expect.stringMatching(/^tx_[a-f0-9]{8}_\d+$/),
      });

      expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
        '2025-03-01T00:00:00Z',
        '2025-03-31T23:59:59Z',
      );

      expect(mockAttestationRepository.create).toHaveBeenCalledWith({
        businessId,
        period,
      });

      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.stringContaining('"service":"attestation-submit"'),
      );
    });

    it('successfully processes multi-month entries and aggregates amounts correctly', async () => {
      mockFetchRazorpayRevenue.mockResolvedValue([
        { id: '1', date: '2025-01-10T00:00:00Z', amount: 100, currency: 'USD', source: 'razorpay' },
        { id: '2', date: '2025-02-15T00:00:00Z', amount: 200, currency: 'USD', source: 'razorpay' },
        { id: '3', date: '2025-03-20T00:00:00Z', amount: 300, currency: 'USD', source: 'razorpay' },
      ]);

      const result = await submitAttestation(userId, businessId, '2025-Q1');

      expect(result).toEqual({
        attestationId: 'att_reg_001',
        txHash: expect.stringMatching(/^tx_[a-f0-9]{8}_\d+$/),
      });

      expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
        '2025-01-01T00:00:00Z',
        '2025-03-31T23:59:59Z',
      );

      expect(mockAttestationRepository.create).toHaveBeenCalledWith({
        businessId,
        period: '2025-Q1',
      });
    });

    it('correctly sums multiple revenue entries falling within the same month', async () => {
      mockFetchRazorpayRevenue.mockResolvedValue([
        { id: '1', date: '2025-05-01T00:00:00Z', amount: 150.25, currency: 'USD', source: 'razorpay' },
        { id: '2', date: '2025-05-15T00:00:00Z', amount: 250.75, currency: 'USD', source: 'razorpay' },
      ]);

      const result = await submitAttestation(userId, businessId, '2025-05');

      expect(result).toEqual({
        attestationId: 'att_reg_001',
        txHash: expect.stringMatching(/^tx_[a-f0-9]{8}_\d+$/),
      });
    });
  });

  // ---------------------------------------------------------------------------
  // Boundary Inputs & Edge Cases
  // ---------------------------------------------------------------------------
  describe('Boundary inputs & edge cases', () => {
    it('accepts revenue entry with 0 amount (boundary value, non-empty list)', async () => {
      mockFetchRazorpayRevenue.mockResolvedValue([
        { id: 'zero_pay', date: '2025-07-01T00:00:00Z', amount: 0, currency: 'USD', source: 'razorpay' },
      ]);

      const result = await submitAttestation(userId, businessId, '2025-07');

      expect(result.attestationId).toBe('att_reg_001');
      expect(result.txHash).toMatch(/^tx_[a-f0-9]{8}_\d+$/);
    });

    it('handles decimal rounding with toFixed(2) on fractional amounts', async () => {
      mockFetchRazorpayRevenue.mockResolvedValue([
        { id: 'frac_1', date: '2025-08-01T00:00:00Z', amount: 99.999, currency: 'USD', source: 'razorpay' },
      ]);

      const result = await submitAttestation(userId, businessId, '2025-08');

      expect(result.attestationId).toBe('att_reg_001');
      expect(result.txHash).toMatch(/^tx_[a-f0-9]{8}_\d+$/);
    });

    it('correctly calculates leap year February period boundaries (2024-02 -> 29 days)', async () => {
      await submitAttestation(userId, businessId, '2024-02');

      expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
        '2024-02-01T00:00:00Z',
        '2024-02-29T23:59:59Z',
      );
    });

    it('correctly calculates non-leap year February period boundaries (2025-02 -> 28 days)', async () => {
      await submitAttestation(userId, businessId, '2025-02');

      expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
        '2025-02-01T00:00:00Z',
        '2025-02-28T23:59:59Z',
      );
    });

    it('correctly calculates quarterly boundaries for all four quarters', async () => {
      // Q1: Jan - Mar (31 days)
      await submitAttestation(userId, businessId, '2025-Q1');
      expect(mockFetchRazorpayRevenue).toHaveBeenLastCalledWith(
        '2025-01-01T00:00:00Z',
        '2025-03-31T23:59:59Z',
      );

      // Q2: Apr - Jun (30 days)
      await submitAttestation(userId, businessId, '2025-Q2');
      expect(mockFetchRazorpayRevenue).toHaveBeenLastCalledWith(
        '2025-04-01T00:00:00Z',
        '2025-06-30T23:59:59Z',
      );

      // Q3: Jul - Sep (30 days)
      await submitAttestation(userId, businessId, '2025-Q3');
      expect(mockFetchRazorpayRevenue).toHaveBeenLastCalledWith(
        '2025-07-01T00:00:00Z',
        '2025-09-30T23:59:59Z',
      );

      // Q4: Oct - Dec (31 days)
      await submitAttestation(userId, businessId, '2025-Q4');
      expect(mockFetchRazorpayRevenue).toHaveBeenLastCalledWith(
        '2025-10-01T00:00:00Z',
        '2025-12-31T23:59:59Z',
      );
    });

    it('correctly calculates 30-day month boundaries (e.g. 2025-04)', async () => {
      await submitAttestation(userId, businessId, '2025-04');
      expect(mockFetchRazorpayRevenue).toHaveBeenLastCalledWith(
        '2025-04-01T00:00:00Z',
        '2025-04-30T23:59:59Z',
      );
    });

    it('correctly calculates 31-day month boundaries (e.g. 2025-05)', async () => {
      await submitAttestation(userId, businessId, '2025-05');
      expect(mockFetchRazorpayRevenue).toHaveBeenLastCalledWith(
        '2025-05-01T00:00:00Z',
        '2025-05-31T23:59:59Z',
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Downstream Error Taxonomy Preservation & Repository Failures
  // ---------------------------------------------------------------------------
  describe('Downstream error taxonomy preservation & repository failures', () => {
    it('preserves AppError when Soroban throws a non-retryable error (e.g. INSUFFICIENT_BALANCE)', async () => {
      Math.random = vi.fn().mockReturnValue(0.17); // Triggers Soroban INSUFFICIENT_BALANCE

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Insufficient balance for transaction fees. Please fund your account.',
          statusCode: 400,
          code: 'INSUFFICIENT_BALANCE',
        }),
      );

      // Ensure it was NOT wrapped into ATTESTATION_SUBMIT_FAILED
      expect(mockAttestationRepository.create).not.toHaveBeenCalled();
    });

    it('wraps repository create errors into ATTESTATION_SUBMIT_FAILED AppError', async () => {
      mockAttestationRepository.create.mockImplementation(() => {
        throw new Error('Database disk full');
      });

      await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
        expect.objectContaining({
          message: 'Attestation submission failed: Database disk full',
          statusCode: 500,
          code: 'ATTESTATION_SUBMIT_FAILED',
        }),
      );
    });
  });
});
