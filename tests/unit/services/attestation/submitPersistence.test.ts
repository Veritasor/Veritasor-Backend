import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Attestation } from '../../../../src/types/attestation.js';

vi.mock('../../../../src/db/client.js', () => ({ db: {} }));
vi.mock('../../../../src/repositories/attestationRepository.js', () => ({ create: vi.fn() }));
vi.mock('../../../../src/services/revenue/razorpayFetch.js', () => ({
  fetchRazorpayRevenue: vi.fn().mockResolvedValue([
    { date: '2026-01-01', amount: 100, currency: 'USD' },
  ]),
}));
vi.mock('../../../../src/services/merkle/index.js', () => ({
  buildTree: vi.fn(), getRoot: vi.fn().mockReturnValue('abcdef0123456789'),
}));
vi.mock('../../../../src/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('../../../../src/metrics.js', () => ({
  sorobanBatchSize: { observe: vi.fn() },
  sorobanBatchFlushTotal: { inc: vi.fn() },
  sorobanBatchItemErrorsTotal: { inc: vi.fn() },
  sorobanBatchQueueDepth: { set: vi.fn() },
}));

import { db } from '../../../../src/db/client.js';
import { create } from '../../../../src/repositories/attestationRepository.js';
import { submitAttestation } from '../../../../src/services/attestation/submit.js';

describe('submission persistence', () => {
  beforeEach(() => {
    vi.spyOn(Math, 'random').mockReturnValue(0.5);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.mocked(create).mockReset();
  });
  afterEach(() => vi.restoreAllMocks());

  it('waits for the SQL insert and returns the persisted ID', async () => {
    let persist!: (value: Attestation) => void;
    vi.mocked(create).mockReturnValue(new Promise(resolve => { persist = resolve; }));
    let settled = false;
    const result = submitAttestation('user', 'business', '2026-01')
      .then(value => { settled = true; return value; });
    await vi.waitFor(() => expect(create).toHaveBeenCalled(), { timeout: 2000 });
    expect(create).toHaveBeenCalledWith(db, {
      businessId: 'business', period: '2026-01', merkleRoot: 'abcdef0123456789',
      txHash: expect.stringMatching(/^tx_abcdef01_\d+$/), status: 'submitted',
    });
    expect(settled).toBe(false);
    persist({
      id: 'database-id', businessId: 'business', period: '2026-01',
      merkleRoot: 'abcdef0123456789', txHash: 'tx', status: 'submitted', version: 1,
      createdAt: new Date(), updatedAt: new Date(),
    });
    await expect(result).resolves.toEqual({
      attestationId: 'database-id', txHash: expect.stringMatching(/^tx_abcdef01_\d+$/),
    });
  });

  it('rejects when persistence fails instead of reporting a successful submission', async () => {
    vi.mocked(create).mockRejectedValue(new Error('database unavailable'));
    await expect(submitAttestation('user', 'business', '2026-01')).rejects.toMatchObject({
      message: 'Attestation submission failed: database unavailable',
      vrtCode: 'ATTESTATION_SUBMIT_FAILED',
    });
  });
});
