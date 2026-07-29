import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { scValToNative } from '@stellar/stellar-sdk';
import {
  SorobanSubmissionError,
  waitForConfirmation,
  validateConfirmedResult,
  computeAttestationDedupeKey,
  resolveAttestationDedupeTtlMs,
  DEFAULT_ATTESTATION_DEDUPE_TTL_MS,
  MIN_ATTESTATION_DEDUPE_TTL_MS,
  checkAttestationDedupe,
  markAttestationSubmitted,
} from '../../../../src/services/soroban/submitAttestation.js';

vi.mock('@stellar/stellar-sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@stellar/stellar-sdk')>();
  return {
    ...actual,
    scValToNative: vi.fn(),
  };
});

const mockScValToNative = vi.mocked(scValToNative);

const VALID_TX_HASH = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

// ---------------------------------------------------------------------------
// waitForConfirmation
// ---------------------------------------------------------------------------

describe('waitForConfirmation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns the response when getTransaction returns SUCCESS on the first attempt', async () => {
    const server = {
      getTransaction: vi.fn().mockResolvedValue({ status: 'SUCCESS', ledger: 42 }),
    };
    const result = await waitForConfirmation(server as any, VALID_TX_HASH, 2000, 3);
    expect(result).toMatchObject({ status: 'SUCCESS', ledger: 42 });
    expect(server.getTransaction).toHaveBeenCalledTimes(1);
  });

  it('resolves after one NOT_FOUND followed by SUCCESS', async () => {
    const getTransaction = vi
      .fn()
      .mockResolvedValueOnce({ status: 'NOT_FOUND' })
      .mockResolvedValueOnce({ status: 'SUCCESS', ledger: 99 });

    const promise = waitForConfirmation({ getTransaction } as any, VALID_TX_HASH, 2000, 3);
    await vi.advanceTimersByTimeAsync(2000);
    await expect(promise).resolves.toMatchObject({ status: 'SUCCESS', ledger: 99 });
    expect(getTransaction).toHaveBeenCalledTimes(2);
  });

  it('resolves after multiple NOT_FOUND before SUCCESS', async () => {
    const getTransaction = vi
      .fn()
      .mockResolvedValueOnce({ status: 'NOT_FOUND' })
      .mockResolvedValueOnce({ status: 'NOT_FOUND' })
      .mockResolvedValueOnce({ status: 'NOT_FOUND' })
      .mockResolvedValueOnce({ status: 'SUCCESS' });

    const promise = waitForConfirmation({ getTransaction } as any, VALID_TX_HASH, 2000, 5);
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(2000);
    await expect(promise).resolves.toMatchObject({ status: 'SUCCESS' });
    expect(getTransaction).toHaveBeenCalledTimes(4);
  });

  it('throws CONFIRMATION_FAILED when getTransaction returns FAILED', async () => {
    const server = { getTransaction: vi.fn().mockResolvedValue({ status: 'FAILED' }) };
    let error: unknown;
    try {
      await waitForConfirmation(server as any, VALID_TX_HASH, 2000, 3);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('CONFIRMATION_FAILED');
  });

  it('throws CONFIRMATION_TIMEOUT after exhausting all NOT_FOUND attempts', async () => {
    const getTransaction = vi.fn().mockResolvedValue({ status: 'NOT_FOUND' });
    const promise = waitForConfirmation({ getTransaction } as any, VALID_TX_HASH, 2000, 3);
    const caught = promise.catch((e) => e);
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(2000);

    const error = await caught;
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('CONFIRMATION_TIMEOUT');
    expect((error as SorobanSubmissionError).message).toContain(VALID_TX_HASH);
    expect((error as SorobanSubmissionError).message).toContain('3 polling attempts');
  });

  it('stops polling early if maxAttempts is 1', async () => {
    const getTransaction = vi.fn().mockResolvedValue({ status: 'NOT_FOUND' });
    const promise = waitForConfirmation({ getTransaction } as any, VALID_TX_HASH, 2000, 1);
    const caught = promise.catch((e) => e);
    const error = await caught;
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('CONFIRMATION_TIMEOUT');
    expect(getTransaction).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// validateConfirmedResult
// ---------------------------------------------------------------------------

describe('validateConfirmedResult', () => {
  const SUBMITTED_ROOT = '0xabc123';

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('throws RESULT_VALIDATION_FAILED when returnValue is undefined', () => {
    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: undefined } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('RESULT_VALIDATION_FAILED');
    expect((error as SorobanSubmissionError).message).toContain('no return value');
  });

  it('throws RESULT_VALIDATION_FAILED when returnValue is null', () => {
    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: null } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('RESULT_VALIDATION_FAILED');
  });

  it('throws RESULT_VALIDATION_FAILED when scValToNative throws', () => {
    mockScValToNative.mockImplementation(() => {
      throw new Error('unexpected scval format');
    });

    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('RESULT_VALIDATION_FAILED');
    expect((error as SorobanSubmissionError).message).toContain('Failed to decode');
    expect((error as SorobanSubmissionError).cause).toBeInstanceOf(Error);
  });

  it('throws RESULT_VALIDATION_FAILED when decoded value is not an object', () => {
    mockScValToNative.mockReturnValue('just a string');

    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).message).toContain('not a valid object');
  });

  it('throws RESULT_VALIDATION_FAILED when merkle_root is missing', () => {
    mockScValToNative.mockReturnValue({ timestamp: 100 });

    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).message).toContain('does not contain a merkle_root');
  });

  it('throws RESULT_MISMATCH when on-chain root differs from submitted root', () => {
    mockScValToNative.mockReturnValue({ merkle_root: 'wrong_root', timestamp: 100 });

    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).code).toBe('RESULT_MISMATCH');
    expect((error as SorobanSubmissionError).message).toContain('does not match submitted value');
    expect((error as SorobanSubmissionError).cause).toMatchObject({
      expected: SUBMITTED_ROOT,
      actual: 'wrong_root',
    });
  });

  it('throws RESULT_VALIDATION_FAILED when timestamp is missing', () => {
    mockScValToNative.mockReturnValue({ merkle_root: SUBMITTED_ROOT });

    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).message).toContain('does not contain a valid timestamp');
  });

  it('throws RESULT_VALIDATION_FAILED when timestamp is NaN', () => {
    mockScValToNative.mockReturnValue({ merkle_root: SUBMITTED_ROOT, timestamp: NaN });

    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).message).toContain('does not contain a valid timestamp');
  });

  it('returns merkleRoot and timestamp on successful validation', () => {
    mockScValToNative.mockReturnValue({ merkle_root: SUBMITTED_ROOT, timestamp: 99999 });

    const result = validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    expect(result).toEqual({ merkleRoot: SUBMITTED_ROOT, timestamp: 99999 });
  });

  it('returns validated values when merkle_root is a non-string value that coerces to the matching root', () => {
    mockScValToNative.mockReturnValue({ merkle_root: 42, timestamp: 5 });

    const result = validateConfirmedResult({ returnValue: {} } as any, '42');
    expect(result).toEqual({ merkleRoot: '42', timestamp: 5 });
  });

  it('throws RESULT_VALIDATION_FAILED when merkle_root is empty after coercion', () => {
    mockScValToNative.mockReturnValue({ merkle_root: null, timestamp: 5 });

    let error: unknown;
    try {
      validateConfirmedResult({ returnValue: {} } as any, SUBMITTED_ROOT);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(SorobanSubmissionError);
    expect((error as SorobanSubmissionError).message).toContain('does not contain a merkle_root');
  });
});

// ---------------------------------------------------------------------------
// Cross-batch idempotency deduplication
// ---------------------------------------------------------------------------

const makeTestParams = (overrides?: Partial<import('../../../../src/services/soroban/submitAttestation.js').SubmitAttestationParams>) => ({
  business: 'biz-1',
  period: '2026-Q3',
  merkleRoot: '0xabc123',
  timestamp: 1720000000000n,
  version: 'v1',
  sourcePublicKey: 'GABC1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890',
  ...overrides,
});

describe('computeAttestationDedupeKey', () => {
  it('produces a 64-char hex string (SHA-256)', () => {
    const key = computeAttestationDedupeKey(makeTestParams());
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic: same inputs → same hash', () => {
    const a = computeAttestationDedupeKey(makeTestParams());
    const b = computeAttestationDedupeKey(makeTestParams());
    expect(a).toBe(b);
  });

  it('differs when the merkleRoot changes', () => {
    const a = computeAttestationDedupeKey(makeTestParams({ merkleRoot: '0xaaa' }));
    const b = computeAttestationDedupeKey(makeTestParams({ merkleRoot: '0xbbb' }));
    expect(a).not.toBe(b);
  });

  it('differs when the period changes', () => {
    const a = computeAttestationDedupeKey(makeTestParams({ period: '2026-Q1' }));
    const b = computeAttestationDedupeKey(makeTestParams({ period: '2026-Q2' }));
    expect(a).not.toBe(b);
  });

  it('differs when the business changes', () => {
    const a = computeAttestationDedupeKey(makeTestParams({ business: 'biz-a' }));
    const b = computeAttestationDedupeKey(makeTestParams({ business: 'biz-b' }));
    expect(a).not.toBe(b);
  });
});

describe('resolveAttestationDedupeTtlMs', () => {
  const ORIGINAL = { ...process.env };

  afterEach(() => {
    delete process.env.ATTESTATION_DEDUPE_TTL_MS;
    if (ORIGINAL.ATTESTATION_DEDUPE_TTL_MS != null) {
      process.env.ATTESTATION_DEDUPE_TTL_MS = ORIGINAL.ATTESTATION_DEDUPE_TTL_MS;
    }
  });

  it('returns the default when env is unset', () => {
    delete process.env.ATTESTATION_DEDUPE_TTL_MS;
    expect(resolveAttestationDedupeTtlMs()).toBe(DEFAULT_ATTESTATION_DEDUPE_TTL_MS);
  });

  it('reads from ATTESTATION_DEDUPE_TTL_MS env var', () => {
    process.env.ATTESTATION_DEDUPE_TTL_MS = '120000';
    expect(resolveAttestationDedupeTtlMs()).toBe(120_000);
  });

  it('clamps below the minimum', () => {
    process.env.ATTESTATION_DEDUPE_TTL_MS = '5000';
    expect(resolveAttestationDedupeTtlMs()).toBe(MIN_ATTESTATION_DEDUPE_TTL_MS);
  });

  it('falls back to default for non-numeric values', () => {
    process.env.ATTESTATION_DEDUPE_TTL_MS = 'not-a-number';
    expect(resolveAttestationDedupeTtlMs()).toBe(DEFAULT_ATTESTATION_DEDUPE_TTL_MS);
  });
});

describe('checkAttestationDedupe', () => {
  it('returns false (no dedupe) when Redis key is absent', async () => {
    const redisClient = { get: vi.fn().mockResolvedValue(null) };
    const result = await checkAttestationDedupe(makeTestParams(), redisClient);
    expect(result).toBe(false);
    expect(redisClient.get).toHaveBeenCalledTimes(1);
  });

  it('returns true (dedupe hit) when Redis key exists', async () => {
    const redisClient = { get: vi.fn().mockResolvedValue('some-tx-hash') };
    const result = await checkAttestationDedupe(makeTestParams(), redisClient);
    expect(result).toBe(true);
  });

  it('returns false (fail-open) on Redis errors', async () => {
    const redisClient = { get: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')) };
    const result = await checkAttestationDedupe(makeTestParams(), redisClient);
    expect(result).toBe(false);
  });

  it('uses a scoped key prefix', async () => {
    const redisClient = { get: vi.fn().mockResolvedValue(null) };
    await checkAttestationDedupe(makeTestParams(), redisClient);
    expect(redisClient.get).toHaveBeenCalledWith(
      expect.stringMatching(/^attestation:dedupe:[0-9a-f]{64}$/)
    );
  });
});

describe('markAttestationSubmitted', () => {
  it('stores the tx hash with the computed dedupe key and TTL', async () => {
    const redisClient = { set: vi.fn().mockResolvedValue('OK') };
    await markAttestationSubmitted(makeTestParams(), 'deadbeef', redisClient, 300_000);
    expect(redisClient.set).toHaveBeenCalledWith(
      expect.stringMatching(/^attestation:dedupe:/),
      'deadbeef',
      'PX',
      300_000,
    );
  });

  it('does not throw on Redis errors (best-effort)', async () => {
    const redisClient = { set: vi.fn().mockRejectedValue(new Error('ECONNREFUSED')) };
    await expect(
      markAttestationSubmitted(makeTestParams(), 'deadbeef', redisClient, 300_000)
    ).resolves.toBeUndefined();
  });
});
