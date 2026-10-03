/**
 * Hedged Request Utility (issue #517)
 *
 * A hedged request fires a primary operation and, after a configurable delay
 * (typically p95 latency), fires one or more backup ("hedge") operations.
 * The first response to arrive wins; all outstanding operations are abandoned.
 *
 * This pattern reduces tail latency without the amplification cost of full
 * parallelism: under normal conditions the primary wins and no hedge fires;
 * only when the primary is slow (tail-latency regime) does the hedge activate.
 *
 * ---
 * ## Global concurrency cap
 *
 * Under an outage, every in-flight request could fire a hedge simultaneously,
 * potentially doubling load on the downstream service.  To prevent this, the
 * module maintains a global semaphore (`maxConcurrentHedges`) that caps the
 * number of hedge operations that can be in flight at any moment.  When the
 * cap is reached, additional hedges are *skipped* (the primary is allowed to
 * complete naturally) — we never queue or block.
 *
 * ---
 * ## Usage
 *
 * ```ts
 * import { hedgedRequest } from "./utils/hedged-request.js";
 *
 * const result = await hedgedRequest({
 *   operationName: "simulateTransaction",
 *   primary: () => client.simulateTransaction(tx),
 *   hedge: () => backupClient.simulateTransaction(tx),
 *   hedgeDelayMs: 500,       // p95 latency
 *   signal: abortController.signal,
 * });
 * ```
 *
 * ---
 * ## Metrics
 *
 * - `soroban_hedge_wins_total` (counter, labels: operation): incremented when
 *   the hedge response arrives before the primary.
 * - `soroban_hedge_skipped_total` (counter, labels: operation): incremented
 *   when the hedge is skipped because the global concurrency cap is reached.
 */

import { Counter } from "prom-client";
import { metricsRegistry } from "../metrics.js";

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

export const sorobanHedgeWinsTotal = new Counter({
  name: "soroban_hedge_wins_total",
  help: "Total number of hedged request wins (hedge responded before primary)",
  labelNames: ["operation"] as const,
  registers: [metricsRegistry],
});

export const sorobanHedgeSkippedTotal = new Counter({
  name: "soroban_hedge_skipped_total",
  help: "Total number of hedged requests skipped because the global hedge concurrency cap was reached",
  labelNames: ["operation"] as const,
  registers: [metricsRegistry],
});

// ---------------------------------------------------------------------------
// Global hedge concurrency cap
// ---------------------------------------------------------------------------

/**
 * Maximum number of concurrent hedge operations allowed globally.
 * When this many hedges are already in-flight, additional hedges are skipped.
 *
 * This is intentionally quite low: during an outage we want to limit
 * amplification.  Tune via env var SOROBAN_HEDGE_MAX_CONCURRENT.
 */
const DEFAULT_MAX_CONCURRENT_HEDGES = 5;

let maxConcurrentHedges = DEFAULT_MAX_CONCURRENT_HEDGES;

/**
 * Initialize the global hedge concurrency cap from an optional env override.
 * Reads `SOROBAN_HEDGE_MAX_CONCURRENT` if set, otherwise uses the default.
 * Must be called once at startup (e.g. in `src/index.ts`).
 */
export function initializeHedgeConcurrencyFromEnv(): void {
  const raw = process.env.SOROBAN_HEDGE_MAX_CONCURRENT;
  if (raw) {
    const parsed = Number.parseInt(raw, 10);
    if (Number.isFinite(parsed) && parsed >= 1) {
      maxConcurrentHedges = parsed;
    }
  }
}

/**
 * Set the global hedge concurrency cap.  Useful for reading from config on
 * startup; also used in tests.
 */
export function setMaxConcurrentHedges(n: number): void {
  maxConcurrentHedges = Math.max(1, n);
}

/**
 * Returns the current maximum concurrent hedge limit.
 */
export function getMaxConcurrentHedges(): number {
  return maxConcurrentHedges;
}

/** Number of hedges currently in-flight globally. */
let concurrentHedges = 0;

// ---------------------------------------------------------------------------
// Options & types
// ---------------------------------------------------------------------------

export interface HedgedRequestOptions<T> {
  /**
   * Human-readable operation name for metrics & logging.
   */
  operationName: string;

  /**
   * The primary (preferred) request function.
   */
  primary: () => Promise<T>;

  /**
   * The backup (hedge) request function.  Only called after `hedgeDelayMs`
   * has elapsed and the primary has not yet resolved, and only if the
   * global concurrency cap has not been reached.
   */
  hedge: () => Promise<T>;

  /**
   * How long to wait (milliseconds) before firing the hedge after the
   * primary starts.  Should be set to the p95 latency of the operation.
   * Default: 500 ms.
   */
  hedgeDelayMs?: number;

  /**
   * Optional AbortSignal.  When signalled, both primary and hedge (if
   * started) are abandoned and the promise rejects with an AbortError.
   */
  signal?: AbortSignal;
}

// ---------------------------------------------------------------------------
// Custom errors
// ---------------------------------------------------------------------------

export class AbortError extends Error {
  public readonly code = "ABORT_ERR";
  constructor(message: string) {
    super(message);
    this.name = "AbortError";
  }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Race a primary and (optionally) a hedge request.
 *
 * The primary fires immediately.  After `hedgeDelayMs` (default 500), if the
 * primary hasn't settled AND the global concurrency cap allows it, a hedge
 * request is fired.  The promise resolves (or rejects) with the first
 * settled result.  Losers are silently discarded.
 *
 * If both requests fail, the *primary*'s error is propagated (the hedge
 * error is discarded).
 */
export async function hedgedRequest<T>(
  options: HedgedRequestOptions<T>,
): Promise<T> {
  const {
    operationName,
    primary,
    hedge,
    hedgeDelayMs = 500,
    signal,
  } = options;

  // Check for pre-existing abort
  if (signal?.aborted) {
    throw new AbortError("Hedged request aborted before start");
  }

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let hedgeStarted = false;
    let primaryError: unknown = undefined;
    let primaryDone = false;
    let hedgeTimer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      clearTimeout(hedgeTimer);
      signal?.removeEventListener("abort", onAbort);
    };

    const onSettle = (
      err: unknown | null,
      value: T | null,
    ): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (err) reject(err);
      else resolve(value as T);
    };

    const onAbort = () => {
      onSettle(new AbortError("Hedged request aborted"), null);
    };

    signal?.addEventListener("abort", onAbort, { once: true });

    // ── Start primary ──────────────────────────────────────────────
    primary()
      .then((value) => {
        primaryDone = true;
        onSettle(null, value);
      })
      .catch((err) => {
        primaryDone = true;
        primaryError = err;

        if (!hedgeStarted) {
          // Primary failed before hedge was scheduled — propagate error
          onSettle(err, null);
        } else {
          // Hedge is in-flight; wait for it.  If hedge also fails we'll
          // propagate the primary error (handled in hedge .catch below).
        }
      });

    // ── Schedule hedge ─────────────────────────────────────────────
    hedgeTimer = setTimeout(() => {
      if (settled) return;

      // Check global concurrency cap
      if (concurrentHedges >= maxConcurrentHedges) {
        sorobanHedgeSkippedTotal.inc({ operation: operationName });
        // Can't fire hedge — primary is still running, wait for it
        return;
      }

      hedgeStarted = true;
      concurrentHedges++;

      hedge()
        .then((value) => {
          concurrentHedges--;
          sorobanHedgeWinsTotal.inc({ operation: operationName });
          onSettle(null, value);
        })
        .catch((_hedgeError) => {
          concurrentHedges--;
          // Hedge failed.  If primary already failed, propagate primary error.
          // If primary is still running, wait for it.
          if (primaryDone) {
            onSettle(primaryError, null);
          }
          // Otherwise, do nothing — primary might still succeed.
        });
    }, hedgeDelayMs);
  });
}
