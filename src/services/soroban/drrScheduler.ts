/**
 * @file drrScheduler.ts
 * @description Deficit Round-Robin (DRR) fair scheduler for multi-tenant
 * Soroban batch-queue submissions.
 *
 * ## Problem
 * A noisy tenant can enqueue many attestation items and monopolise the
 * next batch slot, starving lower-volume tenants.
 *
 * ## Solution — Deficit Round-Robin (DRR)
 * Each tenant carries a *deficit counter* that accumulates quantum credits
 * every round. Items are dequeued from a tenant only when the deficit covers
 * their weight (always 1 in our case). Tenants with higher `tier` weights
 * accumulate credits faster and therefore get proportionally larger slice of
 * each batch — but they can never starve other tenants because the round-robin
 * ensures every non-empty tenant is visited every cycle.
 *
 * ## Key properties
 * - **Fair**: credit share is proportional to `tenantWeight`.
 * - **Starvation-free**: idle tenants that re-appear get fresh credit in the
 *   very next round (deficit is **not** reset when a tenant's queue drains —
 *   this is the standard DRR anti-hoarding rule).
 * - **Configurable weights**: weights are looked up from
 *   `DRR_SCHEDULER_TIER_WEIGHTS` (JSON env) or fall back to the built-in
 *   `DEFAULT_TIER_WEIGHTS` table.
 * - **Observable**: `sorobanDrrQueueWaitMs` histogram and `sorobanDrrQueueDepth`
 *   gauge are updated on every enqueue/dequeue.
 *
 * @see https://en.wikipedia.org/wiki/Deficit_round_robin
 */

import { logger } from '../../utils/logger.js';
import {
  sorobanDrrQueueWaitMs,
  sorobanDrrQueueDepth,
  sorobanDrrSchedulerRoundsTotal,
  sorobanDrrDequeuesTotal,
} from '../../metrics.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A tenant tier label, used as the weight-lookup key. */
export type TenantTier = 'free' | 'starter' | 'growth' | 'enterprise' | string;

/** A single item waiting in the batch queue. */
export type BatchQueueItem<T = unknown> = {
  /** Stable tenant identifier (e.g. businessId). */
  tenantId: string;
  /** Tier determines the DRR weight for this tenant. */
  tier: TenantTier;
  /** The actual payload to be batched. */
  payload: T;
  /**
   * Monotonic timestamp (ms) when the item was enqueued.
   * Used to compute queue-wait latency metrics.
   */
  enqueuedAt: number;
};

/** Per-tenant state maintained by the scheduler. */
interface TenantState<T> {
  /** Items waiting to be dequeued, in FIFO order. */
  queue: BatchQueueItem<T>[];
  /**
   * Accumulated deficit credits.
   * Credits are added every round; items consume 1 credit each.
   */
  deficit: number;
  /** Weight assigned to this tenant (derived from tier config). */
  weight: number;
}

/** Snapshot returned by {@link DrrScheduler.stats}. */
export type DrrSchedulerStats = {
  /** Total items across all tenant queues. */
  totalDepth: number;
  /** Per-tenant queue depth and deficit snapshot. */
  tenants: Record<string, { depth: number; deficit: number; weight: number }>;
  /** Total scheduler rounds executed since construction. */
  rounds: number;
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Default DRR quantum per round.
 * Each tenant receives `weight × quantum` credits per round.
 * A higher quantum allows larger bursts per round while remaining fair
 * across tenants within the round.
 */
export const DEFAULT_DRR_QUANTUM = 10;

/**
 * Built-in tier weights.
 * Configurable via `DRR_SCHEDULER_TIER_WEIGHTS` env var (JSON object).
 * Keys are tier names, values are positive integers.
 */
export const DEFAULT_TIER_WEIGHTS: Record<TenantTier, number> = {
  free: 1,
  starter: 2,
  growth: 4,
  enterprise: 8,
};

/** Fallback weight for unknown tiers. */
export const FALLBACK_WEIGHT = 1;

/**
 * Resolves the DRR tier-weight table.
 *
 * Reads `DRR_SCHEDULER_TIER_WEIGHTS` from the environment as a JSON object
 * (e.g. `{"free":1,"starter":3,"enterprise":10}`).
 * Falls back to `DEFAULT_TIER_WEIGHTS` when unset or unparseable.
 *
 * Values are validated to be positive integers; invalid entries are replaced
 * by the fallback weight with a warning.
 *
 * @returns A resolved, validated weight table.
 */
export function resolveTierWeights(
  overrides?: Record<string, number>,
): Record<TenantTier, number> {
  const base: Record<TenantTier, number> = { ...DEFAULT_TIER_WEIGHTS };

  // Attempt to parse environment override
  const raw = process.env['DRR_SCHEDULER_TIER_WEIGHTS'];
  if (raw) {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [tier, val] of Object.entries(parsed as Record<string, unknown>)) {
          if (typeof val === 'number' && Number.isInteger(val) && val > 0) {
            base[tier] = val;
          } else {
            logger.warn(
              { tier, val },
              'drr-scheduler: invalid weight in DRR_SCHEDULER_TIER_WEIGHTS, using fallback',
            );
            base[tier] = FALLBACK_WEIGHT;
          }
        }
      }
    } catch {
      logger.warn(
        { raw },
        'drr-scheduler: failed to parse DRR_SCHEDULER_TIER_WEIGHTS, using defaults',
      );
    }
  }

  // Apply programmatic overrides last (highest precedence)
  if (overrides) {
    for (const [tier, val] of Object.entries(overrides)) {
      if (typeof val === 'number' && Number.isInteger(val) && val > 0) {
        base[tier] = val;
      } else {
        logger.warn(
          { tier, val },
          'drr-scheduler: invalid weight in overrides, using fallback',
        );
        base[tier] = FALLBACK_WEIGHT;
      }
    }
  }

  return base;
}

// ---------------------------------------------------------------------------
// DrrScheduler class
// ---------------------------------------------------------------------------

/**
 * Deficit Round-Robin fair scheduler for multi-tenant batch queues.
 *
 * @typeParam T - Payload type stored inside {@link BatchQueueItem}.
 *
 * @example
 * ```ts
 * const scheduler = new DrrScheduler<AttestationPayload>();
 *
 * // Tenant "alice" (enterprise, weight 8) enqueues 5 items
 * for (let i = 0; i < 5; i++) {
 *   scheduler.enqueue({ tenantId: 'alice', tier: 'enterprise', payload: { ... }, enqueuedAt: Date.now() });
 * }
 *
 * // Tenant "bob" (free, weight 1) enqueues 5 items
 * for (let i = 0; i < 5; i++) {
 *   scheduler.enqueue({ tenantId: 'bob', tier: 'free', payload: { ... }, enqueuedAt: Date.now() });
 * }
 *
 * // Drain a batch of 10 — alice gets ~8, bob gets ~2 (weight ratio 8:1)
 * const batch = scheduler.dequeueBatch(10);
 * ```
 */
export class DrrScheduler<T = unknown> {
  /** Per-tenant state keyed by tenantId. */
  private readonly tenants = new Map<string, TenantState<T>>();

  /**
   * Ordered list of active tenant IDs (those with non-empty queues).
   * Maintained in round-robin insertion order.
   */
  private activeOrder: string[] = [];

  /** Resolved tier → weight mapping. */
  private readonly tierWeights: Record<TenantTier, number>;

  /** DRR quantum: credits added per tenant per round. */
  private readonly quantum: number;

  /** Total scheduler rounds executed (for stats/observability). */
  private rounds = 0;

  /**
   * @param tierWeights - Optional weight overrides (merged on top of env + defaults).
   * @param quantum     - Credits awarded per tenant per round (default: {@link DEFAULT_DRR_QUANTUM}).
   */
  constructor(
    tierWeights?: Record<string, number>,
    quantum: number = DEFAULT_DRR_QUANTUM,
  ) {
    this.tierWeights = resolveTierWeights(tierWeights);
    this.quantum = quantum > 0 ? Math.floor(quantum) : DEFAULT_DRR_QUANTUM;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Adds an item to the back of the tenant's queue.
   *
   * If this is the first item for a tenant, a fresh {@link TenantState} is
   * created (deficit starts at 0, mirroring standard DRR semantics for new
   * arrivals — the tenant starts earning credits from the next round).
   *
   * Updates the `sorobanDrrQueueDepth` Prometheus gauge.
   */
  enqueue(item: BatchQueueItem<T>): void {
    const { tenantId, tier } = item;

    let state = this.tenants.get(tenantId);
    if (!state) {
      const weight = this.resolveWeight(tier);
      state = { queue: [], deficit: 0, weight };
      this.tenants.set(tenantId, state);
    } else {
      // Update weight if tier changes (e.g. plan upgrade mid-flight)
      state.weight = this.resolveWeight(tier);
    }

    state.queue.push(item);

    // Track in active-order if not already present
    if (!this.activeOrder.includes(tenantId)) {
      this.activeOrder.push(tenantId);
    }

    sorobanDrrQueueDepth.set({ tenant: tenantId }, state.queue.length);

    logger.debug(
      { tenantId, tier, weight: state.weight, depth: state.queue.length },
      'drr-scheduler: item enqueued',
    );
  }

  /**
   * Drains up to `batchSize` items from the queue using Deficit Round-Robin.
   *
   * **Algorithm per round:**
   * 1. For each tenant in `activeOrder` (round-robin), add `weight × quantum` credits.
   * 2. Dequeue items while deficit ≥ 1 (each item costs 1 credit).
   * 3. If the tenant's queue drains mid-round, stop consuming (retain surplus
   *    deficit for next round — standard DRR anti-starvation rule).
   * 4. Repeat until `batchSize` items are collected or all queues empty.
   *
   * Updates `sorobanDrrQueueWaitMs` histogram and `sorobanDrrQueueDepth` gauge
   * for each dequeued item.
   *
   * @param batchSize - Maximum number of items to return.
   * @returns An array of items in DRR-fair interleaved order.
   */
  dequeueBatch(batchSize: number): BatchQueueItem<T>[] {
    if (batchSize <= 0) return [];

    const result: BatchQueueItem<T>[] = [];

    while (result.length < batchSize && this.activeOrder.length > 0) {
      this.rounds++;
      sorobanDrrSchedulerRoundsTotal.inc();

      // Take a snapshot of active tenants for this round — new enqueues
      // mid-round are deferred to the next cycle.
      const roundOrder = [...this.activeOrder];
      const exhausted: string[] = [];

      for (const tenantId of roundOrder) {
        if (result.length >= batchSize) break;

        const state = this.tenants.get(tenantId);
        if (!state || state.queue.length === 0) {
          exhausted.push(tenantId);
          continue;
        }

        // Award credits for this round
        state.deficit += state.weight * this.quantum;

        // Consume items while we have credits and budget
        while (state.deficit >= 1 && state.queue.length > 0 && result.length < batchSize) {
          const item = state.queue.shift()!;
          state.deficit -= 1;

          const waitMs = Date.now() - item.enqueuedAt;
          sorobanDrrQueueWaitMs.observe({ tenant: tenantId }, waitMs);
          sorobanDrrDequeuesTotal.inc({ tenant: tenantId });

          result.push(item);
        }

        sorobanDrrQueueDepth.set({ tenant: tenantId }, state.queue.length);

        if (state.queue.length === 0) {
          exhausted.push(tenantId);
          // Do NOT reset deficit — DRR retains surplus for the next arrival
        }
      }

      // Remove exhausted tenants from the active order for this cycle
      if (exhausted.length > 0) {
        this.activeOrder = this.activeOrder.filter((id) => !exhausted.includes(id));
      }
    }

    logger.debug(
      { collected: result.length, batchSize, rounds: this.rounds },
      'drr-scheduler: batch dequeued',
    );

    return result;
  }

  /**
   * Returns the total number of items queued across all tenants.
   */
  totalDepth(): number {
    let total = 0;
    for (const state of this.tenants.values()) {
      total += state.queue.length;
    }
    return total;
  }

  /**
   * Returns a snapshot of scheduler state for observability.
   */
  stats(): DrrSchedulerStats {
    const tenants: DrrSchedulerStats['tenants'] = {};
    for (const [id, state] of this.tenants.entries()) {
      tenants[id] = {
        depth: state.queue.length,
        deficit: state.deficit,
        weight: state.weight,
      };
    }
    return {
      totalDepth: this.totalDepth(),
      tenants,
      rounds: this.rounds,
    };
  }

  /**
   * Resets all tenant state. Useful in tests or after a full drain.
   */
  reset(): void {
    this.tenants.clear();
    this.activeOrder = [];
    this.rounds = 0;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Resolves the DRR weight for a tenant tier.
   * Unknown tiers fall back to {@link FALLBACK_WEIGHT}.
   */
  private resolveWeight(tier: TenantTier): number {
    const w = this.tierWeights[tier];
    if (typeof w === 'number' && w > 0) return w;

    logger.debug(
      { tier },
      'drr-scheduler: unknown tier, using fallback weight',
    );
    return FALLBACK_WEIGHT;
  }
}
