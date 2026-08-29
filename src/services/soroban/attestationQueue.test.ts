import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  drainQueuedAttestations,
  enqueueQueuedAttestation,
  isSorobanQueueEnabled,
  resetQueuedAttestationStore,
} from './submitAttestation.js';

const SAMPLE_PARAMS = {
  business: 'business-123',
  period: '2025-09',
  merkleRoot: 'abc123',
  timestamp: Date.now(),
  version: '1.0.0',
  sourcePublicKey: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
  submit: true,
  userId: 'user-123',
};

describe('Soroban degraded attestation queue', () => {
  beforeEach(() => {
    resetQueuedAttestationStore();
    delete process.env.SOROBAN_DEGRADED_QUEUE_ENABLED;
    vi.restoreAllMocks();
  });

  it('enqueues requests when the degraded queue is enabled and deduplicates duplicates', () => {
    process.env.SOROBAN_DEGRADED_QUEUE_ENABLED = 'true';

    const first = enqueueQueuedAttestation(SAMPLE_PARAMS, { idempotencyKey: 'idem-1' });
    const second = enqueueQueuedAttestation(SAMPLE_PARAMS, { idempotencyKey: 'idem-1' });

    expect(isSorobanQueueEnabled()).toBe(true);
    expect(first.queued).toBe(true);
    expect(second.queued).toBe(false);
    expect(second.reason).toBe('duplicate');
    expect(drainQueuedAttestations(10)).resolves.toHaveLength(1);
  });

  it('keeps the queue bounded and returns a queue-full error when the limit is exceeded', () => {
    process.env.SOROBAN_DEGRADED_QUEUE_ENABLED = 'true';
    const original = process.env.SOROBAN_DEGRADED_QUEUE_MAX_ITEMS;
    process.env.SOROBAN_DEGRADED_QUEUE_MAX_ITEMS = '1';

    try {
      const first = enqueueQueuedAttestation(SAMPLE_PARAMS, { idempotencyKey: 'a' });
      const second = enqueueQueuedAttestation({ ...SAMPLE_PARAMS, merkleRoot: 'def456' }, { idempotencyKey: 'b' });

      expect(first.queued).toBe(true);
      expect(second.queued).toBe(false);
      expect(second.reason).toBe('queue_full');
    } finally {
      if (original === undefined) delete process.env.SOROBAN_DEGRADED_QUEUE_MAX_ITEMS;
      else process.env.SOROBAN_DEGRADED_QUEUE_MAX_ITEMS = original;
    }
  });
});
