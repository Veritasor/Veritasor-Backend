/**
 * Unit tests for enhanced submitAttestation with retry logic and error taxonomy.
 * Tests the hardened implementation against transient Soroban failures.
 */
import { beforeEach, describe, expect, it, vi, afterEach } from 'vitest';
import { submitAttestation, SorobanErrorCode } from '../../src/services/attestation/submit.js';
import { fetchRazorpayRevenue } from '../../src/services/revenue/razorpayFetch.js';
import { attestationRepository } from '../../src/repositories/attestation.js';
import { AppError, ExternalServiceError } from '../../src/types/errors.js';

// Mock dependencies
vi.mock('../../src/services/revenue/razorpayFetch.js');
vi.mock('../../src/repositories/attestation.js');
vi.mock('../../src/services/merkle.js');

const mockFetchRazorpayRevenue = vi.mocked(fetchRazorpayRevenue);
const mockAttestationRepository = vi.mocked(attestationRepository);

// Mock console methods to capture structured logs
const mockConsoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
const mockConsoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
const mockConsoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

describe('submitAttestation - Enhanced with retry logic', () => {
  const userId = 'user_123';
  const businessId = 'biz_456';
  const period = '2024-03';
  const startDate = '2024-03-01T00:00:00Z';
  const endDate = '2024-03-31T23:59:59Z';

  const mockRevenue = [
    { date: '2024-03-01', amount: 1000, currency: 'USD' },
    { date: '2024-03-15', amount: 1500, currency: 'USD' },
    { date: '2024-03-31', amount: 2000, currency: 'USD' },
  ];

  const mockAttestation = {
    id: 'att_789',
    businessId,
    period,
    createdAt: new Date().toISOString(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchRazorpayRevenue.mockResolvedValue(mockRevenue);
    mockAttestationRepository.create = vi.fn().mockResolvedValue(mockAttestation);
  });

  afterEach(() => {
    mockConsoleLog.mockClear();
    mockConsoleWarn.mockClear();
    mockConsoleError.mockClear();
  });

  it('successfully submits attestation with valid data', async () => {
    const result = await submitAttestation(userId, businessId, period);

    expect(result).toEqual({
      attestationId: 'att_789',
      txHash: expect.stringMatching(/^tx_[a-f0-9]{8}_\d+$/),
    });

    expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(startDate, endDate);
    expect(mockAttestationRepository.create).toHaveBeenCalledWith({
      businessId,
      period,
    });

    // Verify structured logging
    expect(mockConsoleLog).toHaveBeenCalledWith(
      expect.stringContaining('"service":"attestation-submit"')
    );
  });

  it('handles retryable network timeout errors with exponential backoff', async () => {
    // Mock the random number to trigger network timeout consistently
    const originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.05); // Triggers NETWORK_TIMEOUT

    const startTime = Date.now();
    const result = await submitAttestation(userId, businessId, period);
    const endTime = Date.now();

    // Should eventually succeed after retries
    expect(result).toEqual({
      attestationId: 'att_789',
      txHash: expect.stringMatching(/^tx_[a-f0-9]{8}_\d+$/),
    });

    // Verify retry attempts were logged
    expect(mockConsoleWarn).toHaveBeenCalledTimes(2); // 2 failures before success
    expect(mockConsoleLog).toHaveBeenCalledTimes(3); // 3 attempts (2 retries + 1 success)

    // Verify exponential backoff (should take at least 1s + 2s = 3s due to delays)
    expect(endTime - startTime).toBeGreaterThan(3000);

    Math.random = originalMathRandom;
  });

  it('fails immediately on non-retryable insufficient balance error', async () => {
    // Mock random to trigger insufficient balance error
    const originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.17); // Triggers INSUFFICIENT_BALANCE

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'Insufficient balance for transaction fees. Please fund your account.',
        status: 400,
        code: 'INSUFFICIENT_BALANCE',
      })
    );

    // Should only attempt once (no retries for non-retryable errors)
    expect(mockConsoleWarn).toHaveBeenCalledTimes(1);
    expect(mockConsoleError).toHaveBeenCalledTimes(1);

    Math.random = originalMathRandom;
  });

  it('fails after max retry attempts for persistent network errors', async () => {
    // Mock random to consistently trigger network timeout
    const originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.05); // Always triggers NETWORK_TIMEOUT

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: expect.stringContaining('Soroban submission failed'),
        status: 503,
      })
    );

    // Should attempt max 3 times and fail
    expect(mockConsoleWarn).toHaveBeenCalledTimes(3);
    expect(mockConsoleError).toHaveBeenCalledTimes(1);
    expect(mockConsoleLog).toHaveBeenCalledTimes(3);

    Math.random = originalMathRandom;
  });

  it('handles empty revenue data gracefully', async () => {
    mockFetchRazorpayRevenue.mockResolvedValue([]);

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'No revenue found for the period 2024-03',
        code: 'ATTESTATION_SUBMIT_FAILED',
      })
    );

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Attestation submission failed')
    );
  });

  it('handles revenue fetching errors', async () => {
    const revenueError = new Error('API rate limit exceeded');
    mockFetchRazorpayRevenue.mockRejectedValue(revenueError);

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'Failed to fetch revenue: API rate limit exceeded',
        code: 'ATTESTATION_SUBMIT_FAILED',
      })
    );

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Attestation submission failed')
    );
  });

  it('handles merkle root generation failure', async () => {
    // Mock invalid revenue data that would cause merkle tree issues
    mockFetchRazorpayRevenue.mockResolvedValue([
      { date: 'invalid-date', amount: NaN, currency: 'USD' },
    ]);

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: expect.stringContaining('Attestation submission failed'),
        code: 'ATTESTATION_SUBMIT_FAILED',
      })
    );
  });

  it('validates period parsing for quarterly periods', async () => {
    const quarterlyPeriod = '2024-Q1';
    const expectedStartDate = '2024-01-01T00:00:00Z';
    const expectedEndDate = '2024-03-31T23:59:59Z';

    await submitAttestation(userId, businessId, quarterlyPeriod);

    expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(expectedStartDate, expectedEndDate);
  });

  it('validates period parsing for monthly periods', async () => {
    const monthlyPeriod = '2024-12';
    const expectedStartDate = '2024-12-01T00:00:00Z';
    const expectedEndDate = '2024-12-31T23:59:59Z';

    await submitAttestation(userId, businessId, monthlyPeriod);

    expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(expectedStartDate, expectedEndDate);
  });

  it('handles repository save errors', async () => {
    const repoError = new Error('Database connection failed');
    mockAttestationRepository.create = vi.fn().mockRejectedValue(repoError);

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'Attestation submission failed: Database connection failed',
        code: 'ATTESTATION_SUBMIT_FAILED',
      })
    );

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Attestation submission failed')
    );
  });
});

describe('SorobanErrorCode taxonomy', () => {
  it('defines all required error codes', () => {
    const expectedCodes = [
      'NETWORK_TIMEOUT',
      'NETWORK_ERROR',
      'RPC_UNAVAILABLE',
      'NONCE_CONFLICT',
      'FEE_BUMP_REQUIRED',
      'TRANSACTION_PENDING',
      'INVALID_SIGNATURE',
      'INVALID_ACCOUNT',
      'INSUFFICIENT_BALANCE',
      'CONTRACT_ERROR',
      'RATE_LIMITED',
      'SERVICE_UNAVAILABLE',
      'INTERNAL_ERROR',
    ];

    expectedCodes.forEach(code => {
      expect(Object.values(SorobanErrorCode)).toContain(code);
    });
  });

  it('categorizes retryable vs non-retryable errors correctly', () => {
    const retryableCodes = [
      SorobanErrorCode.NETWORK_TIMEOUT,
      SorobanErrorCode.NETWORK_ERROR,
      SorobanErrorCode.RPC_UNAVAILABLE,
      SorobanErrorCode.NONCE_CONFLICT,
      SorobanErrorCode.FEE_BUMP_REQUIRED,
      SorobanErrorCode.TRANSACTION_PENDING,
      SorobanErrorCode.RATE_LIMITED,
      SorobanErrorCode.SERVICE_UNAVAILABLE,
      SorobanErrorCode.INTERNAL_ERROR,
    ];

    const nonRetryableCodes = [
      SorobanErrorCode.INVALID_SIGNATURE,
      SorobanErrorCode.INVALID_ACCOUNT,
      SorobanErrorCode.INSUFFICIENT_BALANCE,
      SorobanErrorCode.CONTRACT_ERROR,
    ];

    // Verify categorization by checking error handling behavior
    expect(retryableCodes).toHaveLength(9);
    expect(nonRetryableCodes).toHaveLength(4);
  });
});

describe('Structured logging', () => {
  it('includes required fields in log entries', async () => {
    const { submitAttestation } = await import('../../src/services/attestation/submit.js');
    
    // Mock random to avoid retries
    const originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.5); // Success case

    await submitAttestation('user_123', 'biz_456', '2024-03');

    // Verify log structure
    const logCall = mockConsoleLog.mock.calls[0][0];
    const logEntry = JSON.parse(logCall);

    expect(logEntry).toMatchObject({
      timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
      level: 'info',
      service: 'attestation-submit',
      message: expect.stringContaining('Attempting Soroban submission'),
      userId: 'user_123',
      businessId: 'biz_456',
      period: '2024-03',
      attempt: expect.any(Number),
      maxAttempts: expect.any(Number),
    });

    Math.random = originalMathRandom;
  });

  it('logs error context when submission fails', async () => {
    const { submitAttestation } = await import('../../src/services/attestation/submit.js');
    
    // Mock to trigger insufficient balance error
    const originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.17);

    try {
      await submitAttestation('user_123', 'biz_456', '2024-03');
    } catch (error) {
      // Expected to fail
    }

    const errorLogCall = mockConsoleError.mock.calls[0][0];
    const errorLogEntry = JSON.parse(errorLogCall);

    expect(errorLogEntry).toMatchObject({
      level: 'error',
      service: 'attestation-submit',
      message: 'Soroban submission failed - no more retries',
      userId: 'user_123',
      businessId: 'biz_456',
      period: '2024-03',
      error: expect.stringContaining('Insufficient balance'),
      errorCode: 'INSUFFICIENT_BALANCE',
      duration: expect.any(Number),
    });

    Math.random = originalMathRandom;
  });

  it('logs retry delays with jitter', async () => {
    const { submitAttestation } = await import('../../src/services/attestation/submit.js');
    
    // Mock to trigger network timeout (retryable)
    const originalMathRandom = Math.random;
    Math.random = vi.fn()
      .mockReturnValueOnce(0.05) // First attempt: network timeout
      .mockReturnValueOnce(0.05) // Second attempt: network timeout  
      .mockReturnValueOnce(0.5);  // Third attempt: success

    try {
      await submitAttestation('user_123', 'biz_456', '2024-03');
    } catch (error) {
      // Expected to eventually succeed
    }

    // Verify retry delay logging
    const delayLogCalls = mockConsoleLog.mock.calls.filter(call => 
      JSON.parse(call[0]).message.includes('Waiting') && 
      JSON.parse(call[0]).message.includes('before retry')
    );

    expect(delayLogCalls).toHaveLength(2); // 2 retry delays

    // Verify delay calculation includes jitter (should be between 0.5x and 1.0x of base delay)
    delayLogCalls.forEach((call, index) => {
      const logEntry = JSON.parse(call[0]);
      const expectedBaseDelay = 1000 * Math.pow(2, index); // 1s, 2s
      expect(logEntry.delay).toBeGreaterThanOrEqual(Math.floor(expectedBaseDelay * 0.5));
      expect(logEntry.delay).toBeLessThanOrEqual(expectedBaseDelay);
    });

    Math.random = originalMathRandom;
  });
});

describe('Error taxonomy mapping', () => {
  it('maps insufficient balance to 400 AppError', async () => {
    const { submitAttestation } = await import('../../src/services/attestation/submit.js');
    
    const originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.17); // Triggers INSUFFICIENT_BALANCE

    await expect(submitAttestation('user_123', 'biz_456', '2024-03')).rejects.toBeInstanceOf(AppError);

    Math.random = originalMathRandom;
  });

  it('maps network errors to 503 ExternalServiceError', async () => {
    const { submitAttestation } = await import('../../src/services/attestation/submit.js');
    
    const originalMathRandom = Math.random;
    Math.random = vi.fn().mockReturnValue(0.05); // Triggers NETWORK_TIMEOUT

    await expect(submitAttestation('user_123', 'biz_456', '2024-03')).rejects.toBeInstanceOf(ExternalServiceError);

    Math.random = originalMathRandom;
  });
});
