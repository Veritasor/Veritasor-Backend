/**
 * tests/unit/jobs/sorobanAttestationDrainer.test.ts
 *
 * Dedicated test suite for src/jobs/sorobanAttestationDrainer.ts
 *
 * Covers:
 *  - SOROBAN_ATTESTATION_DRAINER_JOB_NAME constant value
 *  - sorobanAttestationDrainerJob success path (queue enabled, items drained)
 *  - sorobanAttestationDrainerJob no-op path (queue disabled)
 *  - sorobanAttestationDrainerJob empty-queue path (nothing due)
 *  - sorobanAttestationDrainerJob partial failure (some items fail, overall success)
 *  - sorobanAttestationDrainerJob drainQueuedAttestations throws → success:false
 *  - Default parameter behaviour (limit, now)
 *  - Invalid / boundary limit values forwarded to drainQueuedAttestations
 *  - Logger calls for success, failure, and error paths
 */

import { beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import * as pushgatewayClientModule from '../../../src/jobs/pushgatewayClient.js';
import * as submitAttestationModule from '../../../src/services/soroban/submitAttestation.js';
import { logger } from '../../../src/utils/logger.js';

// ── Module mocks ─────────────────────────────────────────────────────────────

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('../../../src/services/soroban/submitAttestation.js', () => ({
  isSorobanQueueEnabled: vi.fn(),
  drainQueuedAttestations: vi.fn(),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Returns a minimal fake pushgateway client that resolves immediately. */
function fakePushgatewayClient() {
  return {
    pushJobMetrics: vi.fn(async () => {}),
    deleteJobGrouping: vi.fn(async () => {}),
  };
}

/** Typed shorthand for the mocked helpers. */
const mockedIsSorobanQueueEnabled = vi.mocked(
  submitAttestationModule.isSorobanQueueEnabled,
);
const mockedDrainQueuedAttestations = vi.mocked(
  submitAttestationModule.drainQueuedAttestations,
);

// ── Test setup ────────────────────────────────────────────────────────────────

let pushgatewayClientSpy: MockInstance;

beforeEach(() => {
  vi.clearAllMocks();
  // Provide a no-network pushgateway so runInstrumentedJob never makes real
  // HTTP calls and tests do not depend on PUSHGATEWAY_URL being set.
  pushgatewayClientSpy = vi
    .spyOn(pushgatewayClientModule, 'getPushgatewayClient')
    .mockReturnValue(fakePushgatewayClient());
});

// ── Imports that must come AFTER vi.mock() calls ──────────────────────────────
// We import inside each describe/it block via a dynamic import so that the
// mocks registered above are already in place when the module is evaluated.
// However, because vitest hoists vi.mock() calls at the module level, a
// top-level import works just as well. We keep it at top-level for clarity.
import {
  SOROBAN_ATTESTATION_DRAINER_JOB_NAME,
  sorobanAttestationDrainerJob,
} from '../../../src/jobs/sorobanAttestationDrainer.js';

// ── SOROBAN_ATTESTATION_DRAINER_JOB_NAME ─────────────────────────────────────

describe('SOROBAN_ATTESTATION_DRAINER_JOB_NAME', () => {
  it('equals the expected sentinel string', () => {
    expect(SOROBAN_ATTESTATION_DRAINER_JOB_NAME).toBe('soroban_attestation_drainer');
  });

  it('is a non-empty string', () => {
    expect(typeof SOROBAN_ATTESTATION_DRAINER_JOB_NAME).toBe('string');
    expect(SOROBAN_ATTESTATION_DRAINER_JOB_NAME.length).toBeGreaterThan(0);
  });
});

// ── sorobanAttestationDrainerJob — queue disabled ────────────────────────────

describe('sorobanAttestationDrainerJob — queue disabled', () => {
  beforeEach(() => {
    mockedIsSorobanQueueEnabled.mockReturnValue(false);
  });

  it('returns itemsProcessed:0 and success:true when queue is disabled', async () => {
    const outcome = await sorobanAttestationDrainerJob();
    expect(outcome).toEqual({ itemsProcessed: 0, success: true });
  });

  it('does not call drainQueuedAttestations when queue is disabled', async () => {
    await sorobanAttestationDrainerJob();
    expect(mockedDrainQueuedAttestations).not.toHaveBeenCalled();
  });

  it('does not log an error when queue is disabled', async () => {
    await sorobanAttestationDrainerJob();
    expect(logger.error).not.toHaveBeenCalled();
  });

  it('still pushes metrics to the pushgateway even when queue is disabled', async () => {
    const client = fakePushgatewayClient();
    pushgatewayClientSpy.mockReturnValue(client);

    await sorobanAttestationDrainerJob();

    expect(client.pushJobMetrics).toHaveBeenCalledOnce();
    expect(client.pushJobMetrics).toHaveBeenCalledWith(
      SOROBAN_ATTESTATION_DRAINER_JOB_NAME,
      expect.any(String),
    );
  });

  it('deletes the pushgateway grouping on success (disabled → success:true)', async () => {
    const client = fakePushgatewayClient();
    pushgatewayClientSpy.mockReturnValue(client);

    await sorobanAttestationDrainerJob();

    expect(client.deleteJobGrouping).toHaveBeenCalledOnce();
    expect(client.deleteJobGrouping).toHaveBeenCalledWith(
      SOROBAN_ATTESTATION_DRAINER_JOB_NAME,
      expect.any(String),
    );
  });
});

// ── sorobanAttestationDrainerJob — queue enabled, empty drain ─────────────────

describe('sorobanAttestationDrainerJob — queue enabled, nothing due', () => {
  beforeEach(() => {
    mockedIsSorobanQueueEnabled.mockReturnValue(true);
    mockedDrainQueuedAttestations.mockResolvedValue([]);
  });

  it('returns itemsProcessed:0 and success:true when drain returns empty', async () => {
    const outcome = await sorobanAttestationDrainerJob();
    expect(outcome).toEqual({ itemsProcessed: 0, success: true });
  });

  it('calls drainQueuedAttestations with the default limit of 10', async () => {
    await sorobanAttestationDrainerJob();
    expect(mockedDrainQueuedAttestations).toHaveBeenCalledWith(10);
  });

  it('logs a "drained" info event even when no items were processed', async () => {
    await sorobanAttestationDrainerJob();
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'soroban_attestation_drainer',
        queuedCount: 0,
        successful: 0,
        failed: 0,
      }),
      expect.any(String),
    );
  });
});

// ── sorobanAttestationDrainerJob — queue enabled, items drained ───────────────

describe('sorobanAttestationDrainerJob — queue enabled, items drained', () => {
  beforeEach(() => {
    mockedIsSorobanQueueEnabled.mockReturnValue(true);
  });

  it('returns itemsProcessed equal to the number of drained entries', async () => {
    const drainedItems = [
      { item: {} as ReturnType<typeof mockedDrainQueuedAttestations extends Promise<infer T> ? T : never>[0]['item'], result: { txHash: 'abc', status: 'confirmed' as const } },
      { item: {} as ReturnType<typeof mockedDrainQueuedAttestations extends Promise<infer T> ? T : never>[0]['item'], result: { txHash: 'def', status: 'confirmed' as const } },
      { item: {} as ReturnType<typeof mockedDrainQueuedAttestations extends Promise<infer T> ? T : never>[0]['item'], result: { txHash: 'ghi', status: 'confirmed' as const } },
    ];
    mockedDrainQueuedAttestations.mockResolvedValue(drainedItems);

    const outcome = await sorobanAttestationDrainerJob();

    expect(outcome).toEqual({ itemsProcessed: 3, success: true });
  });

  it('returns success:true even when all drained items have errors', async () => {
    mockedDrainQueuedAttestations.mockResolvedValue([
      { item: {} as never, error: new Error('tx failed') },
      { item: {} as never, error: new Error('rpc down') },
    ]);

    const outcome = await sorobanAttestationDrainerJob();

    // The drainer's own success flag is about whether it ran without throwing,
    // not about whether every individual item succeeded.
    expect(outcome).toEqual({ itemsProcessed: 2, success: true });
  });

  it('correctly counts successful and failed entries in the log payload', async () => {
    mockedDrainQueuedAttestations.mockResolvedValue([
      { item: {} as never, result: { txHash: 'aaa', status: 'confirmed' as const } },
      { item: {} as never, error: new Error('boom') },
      { item: {} as never, result: { txHash: 'bbb', status: 'pending' as const } },
    ]);

    await sorobanAttestationDrainerJob();

    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'soroban_attestation_drainer',
        queuedCount: 3,
        successful: 2,
        failed: 1,
      }),
      expect.any(String),
    );
  });

  it('includes the `now` timestamp in the log payload', async () => {
    mockedDrainQueuedAttestations.mockResolvedValue([]);
    const now = 1_700_000_000_000;

    await sorobanAttestationDrainerJob(10, now);

    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ now }),
      expect.any(String),
    );
  });

  it('does not log an error when drain succeeds', async () => {
    mockedDrainQueuedAttestations.mockResolvedValue([
      { item: {} as never, result: { txHash: 'zzz', status: 'confirmed' as const } },
    ]);

    await sorobanAttestationDrainerJob();

    expect(logger.error).not.toHaveBeenCalled();
  });

  it('pushes metrics and cleans up the pushgateway grouping on success', async () => {
    const client = fakePushgatewayClient();
    pushgatewayClientSpy.mockReturnValue(client);
    mockedDrainQueuedAttestations.mockResolvedValue([
      { item: {} as never, result: { txHash: '111', status: 'confirmed' as const } },
    ]);

    await sorobanAttestationDrainerJob();

    expect(client.pushJobMetrics).toHaveBeenCalledWith(
      SOROBAN_ATTESTATION_DRAINER_JOB_NAME,
      expect.any(String),
    );
    expect(client.deleteJobGrouping).toHaveBeenCalledWith(
      SOROBAN_ATTESTATION_DRAINER_JOB_NAME,
      expect.any(String),
    );
    // Same run id for both calls
    const pushRunId = client.pushJobMetrics.mock.calls[0][1];
    const deleteRunId = client.deleteJobGrouping.mock.calls[0][1];
    expect(pushRunId).toBe(deleteRunId);
  });
});

// ── sorobanAttestationDrainerJob — drain throws ──────────────────────────────

describe('sorobanAttestationDrainerJob — drainQueuedAttestations throws', () => {
  beforeEach(() => {
    mockedIsSorobanQueueEnabled.mockReturnValue(true);
  });

  it('returns itemsProcessed:0 and success:false when drain throws', async () => {
    mockedDrainQueuedAttestations.mockRejectedValue(new Error('DB connection lost'));

    const outcome = await sorobanAttestationDrainerJob();

    expect(outcome).toEqual({ itemsProcessed: 0, success: false });
  });

  it('does not rethrow — the job swallows the error', async () => {
    mockedDrainQueuedAttestations.mockRejectedValue(new Error('network timeout'));

    await expect(sorobanAttestationDrainerJob()).resolves.not.toThrow();
  });

  it('logs an error event when drain throws', async () => {
    const drainError = new Error('rpc failure');
    mockedDrainQueuedAttestations.mockRejectedValue(drainError);

    await sorobanAttestationDrainerJob();

    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'soroban_attestation_drainer_error' }),
      expect.any(String),
    );
  });

  it('includes the original error in the error log', async () => {
    const drainError = new Error('upstream exploded');
    mockedDrainQueuedAttestations.mockRejectedValue(drainError);

    await sorobanAttestationDrainerJob();

    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ error: drainError }),
      expect.any(String),
    );
  });

  it('pushes metrics but does NOT delete the pushgateway grouping on failure', async () => {
    const client = fakePushgatewayClient();
    pushgatewayClientSpy.mockReturnValue(client);
    mockedDrainQueuedAttestations.mockRejectedValue(new Error('boom'));

    await sorobanAttestationDrainerJob();

    expect(client.pushJobMetrics).toHaveBeenCalledOnce();
    expect(client.deleteJobGrouping).not.toHaveBeenCalled();
  });
});

// ── sorobanAttestationDrainerJob — limit parameter ───────────────────────────

describe('sorobanAttestationDrainerJob — limit parameter', () => {
  beforeEach(() => {
    mockedIsSorobanQueueEnabled.mockReturnValue(true);
    mockedDrainQueuedAttestations.mockResolvedValue([]);
  });

  it('passes a custom limit to drainQueuedAttestations', async () => {
    await sorobanAttestationDrainerJob(25);
    expect(mockedDrainQueuedAttestations).toHaveBeenCalledWith(25);
  });

  it('passes limit=1 (minimum boundary) without modification', async () => {
    await sorobanAttestationDrainerJob(1);
    expect(mockedDrainQueuedAttestations).toHaveBeenCalledWith(1);
  });

  it('passes limit=100 (upper boundary) without modification', async () => {
    await sorobanAttestationDrainerJob(100);
    expect(mockedDrainQueuedAttestations).toHaveBeenCalledWith(100);
  });

  it('passes a zero limit through to drainQueuedAttestations unchanged (drainer does not validate)', async () => {
    // The drainer forwards the limit as-is; drainQueuedAttestations itself
    // clamps invalid values internally. The job should not throw.
    await sorobanAttestationDrainerJob(0);
    expect(mockedDrainQueuedAttestations).toHaveBeenCalledWith(0);
  });

  it('passes a negative limit through without throwing', async () => {
    await sorobanAttestationDrainerJob(-5);
    expect(mockedDrainQueuedAttestations).toHaveBeenCalledWith(-5);
  });

  it('uses the default limit of 10 when called with no arguments', async () => {
    await sorobanAttestationDrainerJob();
    expect(mockedDrainQueuedAttestations).toHaveBeenCalledWith(10);
  });
});

// ── sorobanAttestationDrainerJob — now parameter ─────────────────────────────

describe('sorobanAttestationDrainerJob — now parameter', () => {
  beforeEach(() => {
    mockedIsSorobanQueueEnabled.mockReturnValue(true);
    mockedDrainQueuedAttestations.mockResolvedValue([]);
  });

  it('accepts a custom now value and embeds it in the log without throwing', async () => {
    const fixedNow = 9_999_999_999_999;
    await sorobanAttestationDrainerJob(10, fixedNow);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ now: fixedNow }),
      expect.any(String),
    );
  });

  it('defaults now to approximately Date.now() when not provided', async () => {
    const before = Date.now();
    await sorobanAttestationDrainerJob(10);
    const after = Date.now();

    const logCall = vi.mocked(logger.info).mock.calls.find(([arg]) =>
      typeof arg === 'object' && arg !== null && 'event' in arg && arg.event === 'soroban_attestation_drainer',
    );
    expect(logCall).toBeDefined();
    const nowLogged = (logCall![0] as Record<string, unknown>).now as number;
    expect(nowLogged).toBeGreaterThanOrEqual(before);
    expect(nowLogged).toBeLessThanOrEqual(after);
  });
});

// ── sorobanAttestationDrainerJob — return shape contract ─────────────────────

describe('sorobanAttestationDrainerJob — return shape (public contract)', () => {
  it('always returns an object with itemsProcessed (number) and success (boolean)', async () => {
    for (const [queueEnabled, drainResult] of [
      [false, null],
      [true, []],
      [true, [{ item: {} as never, result: { txHash: 'x', status: 'confirmed' as const } }]],
    ] as const) {
      mockedIsSorobanQueueEnabled.mockReturnValue(queueEnabled as boolean);
      if (drainResult !== null) {
        mockedDrainQueuedAttestations.mockResolvedValue(drainResult as Awaited<ReturnType<typeof mockedDrainQueuedAttestations>>);
      }

      const outcome = await sorobanAttestationDrainerJob();

      expect(typeof outcome.itemsProcessed).toBe('number');
      expect(typeof outcome.success).toBe('boolean');
      expect(outcome.itemsProcessed).toBeGreaterThanOrEqual(0);
    }
  });

  it('always resolves (never rejects) regardless of internal state', async () => {
    mockedIsSorobanQueueEnabled.mockReturnValue(true);
    mockedDrainQueuedAttestations.mockRejectedValue(new Error('catastrophic'));

    await expect(sorobanAttestationDrainerJob()).resolves.toBeDefined();
  });
});
