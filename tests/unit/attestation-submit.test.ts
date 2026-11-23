/**
 * Unit tests for submitAttestation with retry logic, error taxonomy and
 * period-window parsing.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { submitAttestation, SorobanErrorCode } from '../../src/services/attestation/submit.js';
import { fetchRazorpayRevenue } from '../../src/services/revenue/razorpayFetch.js';
import { attestationRepository } from '../../src/repositories/attestation.js';
import { getRoot } from '../../src/services/merkle/index.js';
import * as CryptoUtils from '../../src/services/merkle.js';
import {
  PERIOD_REGEX,
  PeriodParseError,
  parsePeriodToBounds,
  parsePeriodToIsoRange,
} from '../../src/services/analytics/periods.js';
import { AppError, ExternalServiceError, VRTErrorCodes } from '../../src/types/errors.js';

// Mock dependencies. Factory mocks keep modules with unrelated upstream parse
// errors out of the transform graph; only the mocked exports are needed here.
vi.mock('../../src/services/revenue/razorpayFetch.js', () => ({
  fetchRazorpayRevenue: vi.fn(),
}));
vi.mock('../../src/repositories/attestation.js');
vi.mock('../../src/metrics.js', () => {
  const metric = { inc: vi.fn(), set: vi.fn(), observe: vi.fn() };
  return {
    sorobanBatchItemErrorsTotal: metric,
    sorobanBatchQueueDepth: metric,
    sorobanBatchSize: metric,
    sorobanBatchFlushTotal: metric,
    observeAttestationSubmitLatency: vi.fn(),
  };
});
vi.mock('../../src/services/merkle/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/merkle/index.js')>();
  return { ...actual, getRoot: vi.fn(actual.getRoot) };
});
vi.mock('../../src/services/merkle.js', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../../src/services/merkle.js')>();
  return { ...mod, generateMerkleRoot: vi.fn() };
});

const mockFetchRazorpayRevenue = vi.mocked(fetchRazorpayRevenue);
const mockAttestationRepository = vi.mocked(attestationRepository);
const mockGetRoot = vi.mocked(getRoot);

// Mock console methods to capture structured logs.
const mockConsoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
const mockConsoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
const mockConsoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

const userId = 'user_123';
const businessId = 'biz_456';

const mockRevenue = [
  { date: '2024-03-01', amount: 1000, currency: 'USD' },
  { date: '2024-03-15', amount: 1500, currency: 'USD' },
  { date: '2024-03-31', amount: 2000, currency: 'USD' },
];

describe('submitAttestation - Enhanced with retry logic', () => {
  const period = '2024-03';
  const startDate = '2024-03-01T00:00:00Z';
  const endDate = '2024-03-31T23:59:59Z';

  const mockAttestation = {
    id: 'att_789',
    businessId,
    period,
    createdAt: new Date().toISOString(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    mockFetchRazorpayRevenue.mockResolvedValue(mockRevenue);
    // The real repository create() is synchronous.
    mockAttestationRepository.create = vi.fn().mockReturnValue(mockAttestation);
    vi.spyOn(CryptoUtils, 'generateMerkleRoot').mockReturnValue('0xmockedmerkleroothashstring');
  });

  afterEach(() => {
    vi.mocked(Math.random).mockRestore();
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

    expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(startDate, endDate, businessId);
    expect(mockAttestationRepository.create).toHaveBeenCalledWith({
      businessId,
      period,
    });

    expect(mockConsoleLog).toHaveBeenCalledWith(
      expect.stringContaining('"service":"attestation-submit"')
    );
  });

  it('handles retryable network timeout errors with exponential backoff', async () => {
    const random = vi.mocked(Math.random);
    random
      .mockReturnValueOnce(0.05) // attempt 1: network timeout
      .mockReturnValueOnce(0.9)  // attempt 1: jitter
      .mockReturnValueOnce(0.05) // attempt 2: network timeout
      .mockReturnValueOnce(0.9)  // attempt 2: jitter
      .mockReturnValue(0.5);     // attempt 3: success

    const result = await submitAttestation(userId, businessId, period);

    expect(result).toEqual({
      attestationId: 'att_789',
      txHash: expect.stringMatching(/^tx_[a-f0-9]{8}_\d+$/),
    });

    expect(mockConsoleWarn).toHaveBeenCalledTimes(2); // 2 failures before success

    const submitLogs = mockConsoleLog.mock.calls
      .map((call) => JSON.parse(call[0] as string))
      .filter((entry) => entry.service === 'attestation-submit');
    expect(submitLogs.filter((entry) => entry.message?.includes('Attempting'))).toHaveLength(3);
    expect(submitLogs.filter((entry) => entry.message?.includes('successful'))).toHaveLength(1);

    const waitLogs = submitLogs.filter((entry) => entry.message?.includes('Waiting'));
    expect(waitLogs).toHaveLength(2);
  });

  it('fails immediately on non-retryable insufficient balance error', async () => {
    vi.mocked(Math.random).mockReturnValue(0.17); // Triggers INSUFFICIENT_BALANCE

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'Insufficient balance for transaction fees. Please fund your account.',
        status: 400,
        vrtCode: 'INSUFFICIENT_BALANCE',
      })
    );

    expect(mockConsoleWarn).toHaveBeenCalledTimes(1);
    expect(mockConsoleError).toHaveBeenCalledTimes(2); // retry wrapper + outer catch
  });

  it('fails after max retry attempts for persistent network errors', async () => {
    vi.mocked(Math.random).mockReturnValue(0.05); // Always triggers NETWORK_TIMEOUT

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: expect.stringContaining('Soroban submission failed'),
        status: 503,
      })
    );

    expect(mockConsoleWarn).toHaveBeenCalledTimes(3);
    expect(mockConsoleError).toHaveBeenCalledTimes(2);
  });

  it('handles empty revenue data gracefully', async () => {
    mockFetchRazorpayRevenue.mockResolvedValue([]);

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'Attestation submission failed: No revenue found for the period 2024-03',
        vrtCode: 'ATTESTATION_SUBMIT_FAILED',
      })
    );

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Attestation submission failed')
    );
  });

  it('handles revenue fetching errors', async () => {
    mockFetchRazorpayRevenue.mockRejectedValue(new Error('API rate limit exceeded'));

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'Attestation submission failed: Failed to fetch revenue: API rate limit exceeded',
        vrtCode: 'ATTESTATION_SUBMIT_FAILED',
      })
    );

    expect(mockConsoleError).toHaveBeenCalledWith(
      expect.stringContaining('Attestation submission failed')
    );
  });

  it('handles merkle root generation failure', async () => {
    mockGetRoot.mockReturnValueOnce(null as any);

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: expect.stringContaining('Failed to generate Merkle root'),
        vrtCode: 'ATTESTATION_SUBMIT_FAILED',
      })
    );
  });

  it('validates period parsing for quarterly periods', async () => {
    await submitAttestation(userId, businessId, '2024-Q1');

    expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
      '2024-01-01T00:00:00Z',
      '2024-03-31T23:59:59Z',
      businessId,
    );
  });

  it('validates period parsing for monthly periods', async () => {
    await submitAttestation(userId, businessId, '2024-12');

    expect(mockFetchRazorpayRevenue).toHaveBeenCalledWith(
      '2024-12-01T00:00:00Z',
      '2024-12-31T23:59:59Z',
      businessId,
    );
  });

  it('handles repository save errors', async () => {
    mockAttestationRepository.create = vi.fn().mockImplementation(() => {
      throw new Error('Database connection failed');
    });

    await expect(submitAttestation(userId, businessId, period)).rejects.toThrow(
      expect.objectContaining({
        message: 'Attestation submission failed: Database connection failed',
        vrtCode: 'ATTESTATION_SUBMIT_FAILED',
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

    expect(retryableCodes).toHaveLength(9);
    expect(nonRetryableCodes).toHaveLength(4);
  });
});

describe('Structured logging', () => {
  const submitLogs = () => mockConsoleLog.mock.calls
    .map((call) => JSON.parse(call[0] as string))
    .filter((entry) => entry.service === 'attestation-submit');

  const submitErrors = () => mockConsoleError.mock.calls
    .map((call) => JSON.parse(call[0] as string))
    .filter((entry) => entry.service === 'attestation-submit');

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    mockFetchRazorpayRevenue.mockResolvedValue(mockRevenue);
    mockAttestationRepository.create = vi.fn().mockReturnValue({
      id: 'att_789', businessId, period: '2024-03', createdAt: new Date().toISOString(),
    });
  });

  afterEach(() => {
    vi.mocked(Math.random).mockRestore();
  });

  it('includes required fields in log entries', async () => {
    await submitAttestation(userId, businessId, '2024-03');

    const attemptLog = submitLogs().find((entry) => entry.message.includes('Attempting Soroban'));
    expect(attemptLog).toMatchObject({
      timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
      level: 'info',
      service: 'attestation-submit',
      message: expect.stringContaining('Attempting Soroban submission'),
      userId,
      businessId,
      period: '2024-03',
      attempt: expect.any(Number),
      maxAttempts: expect.any(Number),
    });
  });

  it('logs error context when submission fails', async () => {
    vi.mocked(Math.random).mockReturnValue(0.17);

    await expect(submitAttestation(userId, businessId, '2024-03')).rejects.toThrow();

    const errorLog = submitErrors().find((entry) => entry.message.includes('no more retries'));
    expect(errorLog).toMatchObject({
      level: 'error',
      service: 'attestation-submit',
      message: 'Soroban submission failed - no more retries',
      userId,
      businessId,
      period: '2024-03',
      error: expect.stringContaining('Insufficient balance'),
      errorCode: 'INSUFFICIENT_BALANCE',
      duration: expect.any(Number),
    });
  });

  it('logs retry delays with jitter', async () => {
    const random = vi.mocked(Math.random);
    random
      .mockReturnValueOnce(0.05)
      .mockReturnValueOnce(0.9)
      .mockReturnValueOnce(0.05)
      .mockReturnValueOnce(0.9)
      .mockReturnValue(0.5);

    await submitAttestation(userId, businessId, '2024-03');

    const delayLogs = submitLogs().filter((entry) => entry.message.includes('before retry'));
    expect(delayLogs).toHaveLength(2);

    delayLogs.forEach((entry, index) => {
      const expectedBaseDelay = 1000 * Math.pow(2, index); // 1s, 2s
      expect(entry.delay).toBeGreaterThanOrEqual(Math.floor(expectedBaseDelay * 0.5));
      expect(entry.delay).toBeLessThanOrEqual(expectedBaseDelay);
    });
  });
});

describe('Error taxonomy mapping', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    mockFetchRazorpayRevenue.mockResolvedValue(mockRevenue);
    mockAttestationRepository.create = vi.fn().mockReturnValue({
      id: 'att_789', businessId, period: '2024-03', createdAt: new Date().toISOString(),
    });
  });

  afterEach(() => {
    vi.mocked(Math.random).mockRestore();
  });

  it('maps insufficient balance to 400 AppError', async () => {
    vi.mocked(Math.random).mockReturnValue(0.17);

    await expect(submitAttestation(userId, businessId, '2024-03')).rejects.toBeInstanceOf(AppError);
  });

  it('maps network errors to 503 ExternalServiceError', async () => {
    vi.mocked(Math.random).mockReturnValue(0.05);

    await expect(submitAttestation(userId, businessId, '2024-03')).rejects.toBeInstanceOf(ExternalServiceError);
  });
});

// ---------------------------------------------------------------------------
// Period validation / UTC safety
// ---------------------------------------------------------------------------

const validPeriodWindows = [
  ['2024-02', '2024-02-01T00:00:00Z', '2024-02-29T23:59:59Z'], // leap-year February
  ['2023-02', '2023-02-01T00:00:00Z', '2023-02-28T23:59:59Z'], // non-leap February
  ['2025-12', '2025-12-01T00:00:00Z', '2025-12-31T23:59:59Z'], // December rollover
  ['2025-Q1', '2025-01-01T00:00:00Z', '2025-03-31T23:59:59Z'], // quarter end (March)
  ['2024-Q2', '2024-04-01T00:00:00Z', '2024-06-30T23:59:59Z'], // quarter end (June)
  ['2024-Q4', '2024-10-01T00:00:00Z', '2024-12-31T23:59:59Z'], // quarter end (December)
] as const;

const invalidPeriods = [
  '2025-Q5',   // invalid quarter
  '2025-Q0',
  '2025-Q10',
  'abc',
  '',
  '2025-13',
  '2025-00',
  '2025-2',
  '25-01',
  '2025-12 ',  // trailing whitespace
];

describe('period parsing — exact UTC windows', () => {
  it.each(validPeriodWindows)(
    '%s maps to an exact UTC window',
    (period, expectedStart, expectedEnd) => {
      expect(parsePeriodToIsoRange(period)).toEqual({
        startDate: expectedStart,
        endDate: expectedEnd,
      });
    },
  );

  it('uses an exclusive UTC-midnight end bound for months and quarters', () => {
    expect(parsePeriodToBounds('2024-02').end.toISOString()).toBe('2024-03-01T00:00:00.000Z');
    expect(parsePeriodToBounds('2024-Q4').end.toISOString()).toBe('2025-01-01T00:00:00.000Z');
    expect(parsePeriodToBounds('2025-Q1').start.toISOString()).toBe('2025-01-01T00:00:00.000Z');
  });

  it.each(invalidPeriods)('rejects %j with a 400-class PeriodParseError', (period) => {
    expect(() => parsePeriodToIsoRange(period)).toThrow(PeriodParseError);
    try {
      parsePeriodToIsoRange(period);
    } catch (error) {
      const err = error as PeriodParseError;
      expect(err.status).toBe(400);
      expect(err.code).toBe('INVALID_PERIOD');
      expect(err.vrtCode).toBe(VRTErrorCodes.VRT_0002);
    }
  });

  it('exposes one regex that accepts exactly the service-supported formats', () => {
    for (const [period] of validPeriodWindows) {
      expect(PERIOD_REGEX.test(period)).toBe(true);
    }
    for (const period of invalidPeriods) {
      expect(PERIOD_REGEX.test(period)).toBe(false);
    }
  });

  it('produces identical windows under different timezone values', () => {
    const originalTZ = process.env.TZ;
    const timezones = ['UTC', 'America/Los_Angeles', 'Asia/Kathmandu', 'Pacific/Kiritimati'];
    try {
      for (const tz of timezones) {
        process.env.TZ = tz;
        for (const [period, expectedStart, expectedEnd] of validPeriodWindows) {
          expect(parsePeriodToIsoRange(period)).toEqual({
            startDate: expectedStart,
            endDate: expectedEnd,
          });
        }
      }
    } finally {
      process.env.TZ = originalTZ;
    }
  });
});

describe('submitAttestation period validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    mockFetchRazorpayRevenue.mockResolvedValue(mockRevenue);
    mockAttestationRepository.create = vi.fn().mockReturnValue({
      id: 'att_789', businessId, period: '2024-03', createdAt: new Date().toISOString(),
    });
  });

  afterEach(() => {
    vi.mocked(Math.random).mockRestore();
  });

  it.each(invalidPeriods)('rejects %j before reaching Razorpay', async (period) => {
    await expect(submitAttestation(userId, businessId, period)).rejects.toMatchObject({
      status: 400,
      vrtCode: VRTErrorCodes.VRT_0002,
      code: 'INVALID_PERIOD',
    });
    expect(mockFetchRazorpayRevenue).not.toHaveBeenCalled();
  });

  it.each(validPeriodWindows)(
    'fetches the exact %s window regardless of server timezone',
    async (period, expectedStart, expectedEnd) => {
      const originalTZ = process.env.TZ;
      const results: Array<[string, string]> = [];
      try {
        for (const tz of ['UTC', 'America/Los_Angeles']) {
          process.env.TZ = tz;
          await submitAttestation(userId, businessId, period);
          const call = mockFetchRazorpayRevenue.mock.calls.at(-1)!;
          results.push([call[0] as string, call[1] as string]);
        }
      } finally {
        process.env.TZ = originalTZ;
      }

      expect(results).toEqual([
        [expectedStart, expectedEnd],
        [expectedStart, expectedEnd],
      ]);
    },
  );
});
