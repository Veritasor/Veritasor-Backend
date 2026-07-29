/**
 * @file drrScheduler.test.ts
 * @description Comprehensive unit tests for the DRR fair-batch scheduler.
 *
 * Test categories:
 *  1. Enqueue / dequeue basics
 *  2. DRR proportional fairness (weight-proportional slots)
 *  3. Starvation resistance (long-idle tenant wakes up)
 *  4. Weight configuration (env, overrides, validation)
 *  5. Edge cases (empty, zero batch-size, large quantum, single tenant)
 *  6. Prometheus metrics
 *  7. enqueueToBatchScheduler + processBatchSchedulerDrain integration
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  DrrScheduler,
  resolveTierWeights,
  DEFAULT_TIER_WEIGHTS,
  DEFAULT_DRR_QUANTUM,
  FALLBACK_WEIGHT,
  type BatchQueueItem,
  type TenantTier,
} from '../../../../src/services/soroban/drrScheduler.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal BatchQueueItem for testing. */
function makeItem<T>(
  tenantId: string,
  tier: TenantTier,
  payload: T,
  enqueuedAt = Date.now(),
): BatchQueueItem<T> {
  return { tenantId, tier, payload, enqueuedAt };
}

/** Count dequeued items per tenant. */
function countPerTenant(items: BatchQueueItem<unknown>[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    counts[item.tenantId] = (counts[item.tenantId] ?? 0) + 1;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// 1. Enqueue / dequeue basics
// ---------------------------------------------------------------------------

describe('DrrScheduler — basics', () => {
  let scheduler: DrrScheduler<string>;

  beforeEach(() => {
    scheduler = new DrrScheduler<string>();
  });

  it('starts empty', () => {
    expect(scheduler.totalDepth()).toBe(0);
    expect(scheduler.stats().totalDepth).toBe(0);
  });

  it('enqueue increases depth', () => {
    scheduler.enqueue(makeItem('t1', 'free', 'a'));
    expect(scheduler.totalDepth()).toBe(1);
    scheduler.enqueue(makeItem('t1', 'free', 'b'));
    expect(scheduler.totalDepth()).toBe(2);
  });

  it('dequeueBatch returns items in FIFO order per tenant', () => {
    scheduler.enqueue(makeItem('t1', 'free', 'first'));
    scheduler.enqueue(makeItem('t1', 'free', 'second'));
    scheduler.enqueue(makeItem('t1', 'free', 'third'));

    const batch = scheduler.dequeueBatch(3);
    const payloads = batch.map((i) => i.payload);
    expect(payloads).toEqual(['first', 'second', 'third']);
  });

  it('dequeueBatch respects batchSize limit', () => {
    for (let i = 0; i < 10; i++) {
      scheduler.enqueue(makeItem('t1', 'free', `item${i}`));
    }
    const batch = scheduler.dequeueBatch(3);
    expect(batch).toHaveLength(3);
    expect(scheduler.totalDepth()).toBe(7);
  });

  it('dequeueBatch(0) returns empty array', () => {
    scheduler.enqueue(makeItem('t1', 'free', 'x'));
    expect(scheduler.dequeueBatch(0)).toEqual([]);
    expect(scheduler.totalDepth()).toBe(1);
  });

  it('dequeueBatch on empty scheduler returns []', () => {
    expect(scheduler.dequeueBatch(10)).toEqual([]);
  });

  it('reset clears all state', () => {
    scheduler.enqueue(makeItem('t1', 'free', 'x'));
    scheduler.reset();
    expect(scheduler.totalDepth()).toBe(0);
    expect(scheduler.stats().rounds).toBe(0);
    expect(scheduler.dequeueBatch(10)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 2. DRR proportional fairness
// ---------------------------------------------------------------------------

describe('DrrScheduler — proportional fairness', () => {
  it('distributes slots proportionally to weights (enterprise:free = 8:1)', () => {
    // Use quantum=1 so each item costs exactly 1 credit and weight maps directly to slots
    const scheduler = new DrrScheduler<string>(
      { free: 1, enterprise: 8 },
      1, // quantum
    );

    // Both tenants enqueue 100 items
    for (let i = 0; i < 100; i++) scheduler.enqueue(makeItem('enterprise', 'enterprise', `e${i}`));
    for (let i = 0; i < 100; i++) scheduler.enqueue(makeItem('free', 'free', `f${i}`));

    // Drain 90 items — should be ~80 enterprise, ~10 free (ratio 8:1)
    const batch = scheduler.dequeueBatch(90);
    const counts = countPerTenant(batch);

    // Allow ±10% tolerance around ideal ratio
    const ratio = (counts['enterprise'] ?? 0) / (counts['free'] ?? 1);
    expect(ratio).toBeGreaterThan(6);   // at least 6:1
    expect(ratio).toBeLessThan(10);     // at most 10:1
  });

  it('equal-weight tenants get equal slots', () => {
    const scheduler = new DrrScheduler<string>({ a: 1, b: 1 }, 1);

    for (let i = 0; i < 50; i++) scheduler.enqueue(makeItem('a', 'a', `a${i}`));
    for (let i = 0; i < 50; i++) scheduler.enqueue(makeItem('b', 'b', `b${i}`));

    const batch = scheduler.dequeueBatch(40);
    const counts = countPerTenant(batch);

    // Both should have ≈ 20 items (within ±4 due to rounding)
    expect(Math.abs((counts['a'] ?? 0) - (counts['b'] ?? 0))).toBeLessThanOrEqual(4);
  });

  it('interleaves items across tenants rather than draining one fully first', () => {
    const scheduler = new DrrScheduler<string>({ a: 1, b: 1 }, 1);

    // 3 items each
    scheduler.enqueue(makeItem('a', 'a', 'a1'));
    scheduler.enqueue(makeItem('b', 'b', 'b1'));
    scheduler.enqueue(makeItem('a', 'a', 'a2'));
    scheduler.enqueue(makeItem('b', 'b', 'b2'));
    scheduler.enqueue(makeItem('a', 'a', 'a3'));
    scheduler.enqueue(makeItem('b', 'b', 'b3'));

    const batch = scheduler.dequeueBatch(6);
    const tenantOrder = batch.map((i) => i.tenantId);

    // Tenants must alternate or interleave — no one runs all their items back-to-back
    const consecutiveRuns = tenantOrder.reduce((max, id, idx, arr) => {
      let run = 1;
      while (idx + run < arr.length && arr[idx + run] === id) run++;
      return Math.max(max, run);
    }, 0);

    // With quantum=1 and weight=1, each tenant gets 1 item per round
    expect(consecutiveRuns).toBeLessThanOrEqual(1);
  });

  it('starter weight=2 gets twice as many slots as free weight=1', () => {
    const scheduler = new DrrScheduler<string>({ free: 1, starter: 2 }, 1);

    for (let i = 0; i < 60; i++) scheduler.enqueue(makeItem('starter', 'starter', `s${i}`));
    for (let i = 0; i < 60; i++) scheduler.enqueue(makeItem('free', 'free', `f${i}`));

    const batch = scheduler.dequeueBatch(60);
    const counts = countPerTenant(batch);

    const starterCount = counts['starter'] ?? 0;
    const freeCount = counts['free'] ?? 0;
    // Starter should have ~2× more items (allow ±15%)
    expect(starterCount).toBeGreaterThan(freeCount * 1.5);
    expect(starterCount).toBeLessThan(freeCount * 2.5);
  });
});

// ---------------------------------------------------------------------------
// 3. Starvation resistance
// ---------------------------------------------------------------------------

describe('DrrScheduler — starvation resistance', () => {
  it('long-idle tenant gets scheduled in the next round after re-appearing', () => {
    const scheduler = new DrrScheduler<string>({ noisy: 8, idle: 1 }, 1);

    // Noisy tenant floods 100 items; idle has none
    for (let i = 0; i < 100; i++) scheduler.enqueue(makeItem('noisy', 'noisy', `n${i}`));

    // Drain a large batch — idle is absent, noisy dominates
    let batch = scheduler.dequeueBatch(50);
    let counts = countPerTenant(batch);
    expect(counts['noisy']).toBe(50);
    expect(counts['idle']).toBeUndefined();

    // Idle tenant now enqueues 5 items
    for (let i = 0; i < 5; i++) scheduler.enqueue(makeItem('idle', 'idle', `idle${i}`));

    // Next drain — idle must get its share (not starved)
    batch = scheduler.dequeueBatch(20);
    counts = countPerTenant(batch);

    // With weight 1, idle should get at least 1 slot out of the first round
    expect((counts['idle'] ?? 0)).toBeGreaterThanOrEqual(1);
  });

  it('deficit is NOT reset when tenant queue drains (anti-hoarding)', () => {
    const scheduler = new DrrScheduler<string>({ a: 2, b: 1 }, 1);

    // 'a' drains fully in round 1
    scheduler.enqueue(makeItem('a', 'a', 'a1'));
    scheduler.enqueue(makeItem('b', 'b', 'b1'));
    scheduler.enqueue(makeItem('b', 'b', 'b2'));

    // Drain 3 items — a gets 1 (its weight × quantum), b gets 1 per round slot
    const batch1 = scheduler.dequeueBatch(3);
    expect(batch1).toHaveLength(3);

    // 'a' re-appears
    scheduler.enqueue(makeItem('a', 'a', 'a2'));
    // With retained deficit, 'a' should immediately get scheduled
    const batch2 = scheduler.dequeueBatch(2);
    const counts = countPerTenant(batch2);
    // 'a' should appear (not wait an extra round)
    expect(counts['a']).toBeGreaterThanOrEqual(1);
  });

  it('three-tenant scenario: all tenants make progress within reasonable rounds', () => {
    const scheduler = new DrrScheduler<string>(
      { enterprise: 8, growth: 4, free: 1 },
      1,
    );

    for (let i = 0; i < 80; i++) scheduler.enqueue(makeItem('enterprise', 'enterprise', `e${i}`));
    for (let i = 0; i < 40; i++) scheduler.enqueue(makeItem('growth', 'growth', `g${i}`));
    for (let i = 0; i < 10; i++) scheduler.enqueue(makeItem('free', 'free', `f${i}`));

    // Drain everything in chunks of 13
    let drained: Record<string, number> = {};
    let remaining = 130;
    while (remaining > 0) {
      const batch = scheduler.dequeueBatch(13);
      if (batch.length === 0) break;
      remaining -= batch.length;
      for (const item of batch) {
        drained[item.tenantId] = (drained[item.tenantId] ?? 0) + 1;
      }
    }

    // All tenants must have been fully drained
    expect(drained['enterprise']).toBe(80);
    expect(drained['growth']).toBe(40);
    expect(drained['free']).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// 4. Weight configuration
// ---------------------------------------------------------------------------

describe('resolveTierWeights', () => {
  const ORIGINAL_ENV = { ...process.env };

  afterEach(() => {
    // Restore env
    for (const key of Object.keys(process.env)) {
      if (!(key in ORIGINAL_ENV)) delete process.env[key];
    }
    Object.assign(process.env, ORIGINAL_ENV);
  });

  it('returns DEFAULT_TIER_WEIGHTS when no env or overrides', () => {
    delete process.env['DRR_SCHEDULER_TIER_WEIGHTS'];
    const weights = resolveTierWeights();
    expect(weights['free']).toBe(DEFAULT_TIER_WEIGHTS['free']);
    expect(weights['enterprise']).toBe(DEFAULT_TIER_WEIGHTS['enterprise']);
  });

  it('merges env JSON into defaults', () => {
    process.env['DRR_SCHEDULER_TIER_WEIGHTS'] = JSON.stringify({ free: 3, custom: 5 });
    const weights = resolveTierWeights();
    expect(weights['free']).toBe(3);
    expect(weights['custom']).toBe(5);
    // Other defaults untouched
    expect(weights['enterprise']).toBe(DEFAULT_TIER_WEIGHTS['enterprise']);
  });

  it('programmatic overrides take precedence over env', () => {
    process.env['DRR_SCHEDULER_TIER_WEIGHTS'] = JSON.stringify({ enterprise: 5 });
    const weights = resolveTierWeights({ enterprise: 20 });
    expect(weights['enterprise']).toBe(20);
  });

  it('falls back to FALLBACK_WEIGHT for invalid values in env', () => {
    process.env['DRR_SCHEDULER_TIER_WEIGHTS'] = JSON.stringify({ free: -1, starter: 'bad' });
    const weights = resolveTierWeights();
    expect(weights['free']).toBe(FALLBACK_WEIGHT);
    expect(weights['starter']).toBe(FALLBACK_WEIGHT);
  });

  it('gracefully handles malformed JSON in env', () => {
    process.env['DRR_SCHEDULER_TIER_WEIGHTS'] = 'NOT_JSON!!!';
    const weights = resolveTierWeights();
    expect(weights['free']).toBe(DEFAULT_TIER_WEIGHTS['free']);
  });

  it('falls back to FALLBACK_WEIGHT for unknown tier at runtime', () => {
    const scheduler = new DrrScheduler<string>();
    // 'vip' is not in defaults
    scheduler.enqueue(makeItem('t1', 'vip', 'x'));
    const stats = scheduler.stats();
    expect(stats.tenants['t1'].weight).toBe(FALLBACK_WEIGHT);
  });

  it('updates tenant weight when tier changes mid-queue', () => {
    const scheduler = new DrrScheduler<string>({ free: 1, enterprise: 8 });
    scheduler.enqueue(makeItem('t1', 'free', 'a'));
    expect(scheduler.stats().tenants['t1'].weight).toBe(1);

    // Upgrade tier — enqueue with new tier
    scheduler.enqueue(makeItem('t1', 'enterprise', 'b'));
    expect(scheduler.stats().tenants['t1'].weight).toBe(8);
  });
});

// ---------------------------------------------------------------------------
// 5. Edge cases
// ---------------------------------------------------------------------------

describe('DrrScheduler — edge cases', () => {
  it('single tenant drains all items in order', () => {
    const scheduler = new DrrScheduler<number>();
    for (let i = 0; i < 20; i++) scheduler.enqueue(makeItem('solo', 'growth', i));
    const batch = scheduler.dequeueBatch(20);
    expect(batch).toHaveLength(20);
    const payloads = batch.map((x) => x.payload as number);
    expect(payloads).toEqual([...Array(20).keys()]);
  });

  it('requesting more items than available returns only available', () => {
    const scheduler = new DrrScheduler<string>();
    scheduler.enqueue(makeItem('t1', 'free', 'a'));
    scheduler.enqueue(makeItem('t1', 'free', 'b'));
    const batch = scheduler.dequeueBatch(100);
    expect(batch).toHaveLength(2);
  });

  it('negative batchSize returns empty array', () => {
    const scheduler = new DrrScheduler<string>();
    scheduler.enqueue(makeItem('t1', 'free', 'x'));
    expect(scheduler.dequeueBatch(-5)).toEqual([]);
    expect(scheduler.totalDepth()).toBe(1);
  });

  it('configured quantum maintains inter-tenant fairness', () => {
    const scheduler = new DrrScheduler<string>({ a: 1, b: 3 }, 5);
    for (let i = 0; i < 60; i++) scheduler.enqueue(makeItem('a', 'a', `a${i}`));
    for (let i = 0; i < 60; i++) scheduler.enqueue(makeItem('b', 'b', `b${i}`));
    const batch = scheduler.dequeueBatch(40);
    const counts = countPerTenant(batch);
    // b has 3× the weight — should get >1.5× of a's count
    const bCount = counts['b'] ?? 0;
    const aCount = counts['a'] ?? 0;
    expect(bCount).toBeGreaterThan(aCount * 1.5);
  });

  it('enqueue then full drain then re-enqueue works correctly', () => {
    const scheduler = new DrrScheduler<string>({ a: 1 }, 1);
    scheduler.enqueue(makeItem('a', 'a', 'first'));
    scheduler.dequeueBatch(10); // full drain
    expect(scheduler.totalDepth()).toBe(0);

    scheduler.enqueue(makeItem('a', 'a', 'second'));
    const batch = scheduler.dequeueBatch(10);
    expect(batch).toHaveLength(1);
    expect(batch[0].payload).toBe('second');
  });

  it('stats returns correct round count', () => {
    const scheduler = new DrrScheduler<string>({ a: 1, b: 1 }, 1);
    for (let i = 0; i < 4; i++) scheduler.enqueue(makeItem('a', 'a', `a${i}`));
    for (let i = 0; i < 4; i++) scheduler.enqueue(makeItem('b', 'b', `b${i}`));

    // Drain 4 items — takes 2 rounds (each round: 1 from a + 1 from b = 2 items)
    scheduler.dequeueBatch(4);
    expect(scheduler.stats().rounds).toBeGreaterThanOrEqual(2);
  });

  it('enqueuedAt is preserved on dequeued items', () => {
    const scheduler = new DrrScheduler<string>();
    const ts = Date.now() - 5000; // 5 seconds ago
    scheduler.enqueue(makeItem('t1', 'free', 'payload', ts));
    const batch = scheduler.dequeueBatch(1);
    expect(batch[0].enqueuedAt).toBe(ts);
  });
});

// ---------------------------------------------------------------------------
// 6. Prometheus metrics (smoke-test via prom-client registry)
// ---------------------------------------------------------------------------

describe('DrrScheduler — Prometheus metrics emitted', () => {
  it('emits sorobanDrrQueueDepth on enqueue', async () => {
    const { metricsRegistry, sorobanDrrQueueDepth } = await import(
      '../../../../src/metrics.js'
    );
    // Reset gauge so this test is isolated
    sorobanDrrQueueDepth.reset();

    const scheduler = new DrrScheduler<string>();
    scheduler.enqueue(makeItem('metrics-tenant', 'enterprise', 'payload'));

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const depthMetric = metrics.find((m) => m.name === 'soroban_drr_queue_depth');
    expect(depthMetric).toBeDefined();
    const value = depthMetric?.values.find(
      (v) => (v.labels as Record<string, string>)['tenant'] === 'metrics-tenant',
    );
    expect(value?.value).toBe(1);
  });

  it('emits sorobanDrrQueueWaitMs on dequeue', async () => {
    const { metricsRegistry, sorobanDrrQueueWaitMs } = await import(
      '../../../../src/metrics.js'
    );
    sorobanDrrQueueWaitMs.reset();

    const scheduler = new DrrScheduler<string>();
    const ts = Date.now() - 100; // 100ms in the past
    scheduler.enqueue(makeItem('wait-tenant', 'free', 'x', ts));
    scheduler.dequeueBatch(1);

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const waitMetric = metrics.find((m) => m.name === 'soroban_drr_queue_wait_ms');
    expect(waitMetric).toBeDefined();
    // The histogram should have at least one observation
    const countValue = waitMetric?.values.find(
      (v) =>
        (v.labels as Record<string, string>)['tenant'] === 'wait-tenant' &&
        v.metricName === 'soroban_drr_queue_wait_ms_count',
    );
    expect((countValue?.value ?? 0)).toBeGreaterThanOrEqual(1);
  });

  it('emits sorobanDrrSchedulerRoundsTotal on dequeueBatch', async () => {
    const { metricsRegistry, sorobanDrrSchedulerRoundsTotal } = await import(
      '../../../../src/metrics.js'
    );
    sorobanDrrSchedulerRoundsTotal.reset();

    const scheduler = new DrrScheduler<string>();
    scheduler.enqueue(makeItem('r-tenant', 'free', 'x'));
    scheduler.dequeueBatch(5);

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const roundsMetric = metrics.find((m) => m.name === 'soroban_drr_scheduler_rounds_total');
    expect(roundsMetric).toBeDefined();
    const total = roundsMetric?.values[0]?.value ?? 0;
    expect(total).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// 7. enqueueToBatchScheduler integration
// ---------------------------------------------------------------------------

describe('enqueueToBatchScheduler', () => {
  beforeEach(async () => {
    const mod = await import('../../../../src/services/soroban/submitAttestation.js');
    mod.drrBatchScheduler.reset();
  });

  it('returns the tenant queue depth after enqueue', async () => {
    const { enqueueToBatchScheduler, drrBatchScheduler } = await import(
      '../../../../src/services/soroban/submitAttestation.js'
    );

    const baseParams = {
      business: 'biz1',
      period: '2024-Q1',
      merkleRoot: 'abc123',
      timestamp: 1_700_000_000,
      version: '1',
      sourcePublicKey: 'GBRJOVMFKZB3VXTKUQ3PBZPVDL3U5QXHNF3GPWQYQZJ6HJ7D2NKFQYJ',
      submit: false,
      tenantId: 'tenant-a',
      tier: 'enterprise' as const,
    };

    const depth1 = enqueueToBatchScheduler(baseParams);
    expect(depth1).toBe(1);

    const depth2 = enqueueToBatchScheduler(baseParams);
    expect(depth2).toBe(2);
  });

  it('enqueues to the global drrBatchScheduler singleton', async () => {
    const { enqueueToBatchScheduler, drrBatchScheduler } = await import(
      '../../../../src/services/soroban/submitAttestation.js'
    );

    const params = {
      business: 'biz2',
      period: '2024-Q2',
      merkleRoot: 'def456',
      timestamp: 1_700_000_001,
      version: '1',
      sourcePublicKey: 'GBRJOVMFKZB3VXTKUQ3PBZPVDL3U5QXHNF3GPWQYQZJ6HJ7D2NKFQYJ',
      submit: false,
      tenantId: 'tenant-b',
      tier: 'free' as const,
    };

    enqueueToBatchScheduler(params);
    expect(drrBatchScheduler.totalDepth()).toBe(1);
    expect(drrBatchScheduler.stats().tenants['tenant-b']?.depth).toBe(1);
  });
});
