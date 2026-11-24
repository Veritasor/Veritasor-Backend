import { logger } from '../../utils/logger.js';
import { idempotencyKeysCount, idempotencySweepRunsTotal } from '../../metrics.js';
import {
  DEFAULT_SWEEP_INTERVAL_MS,
  MIN_SWEEP_INTERVAL_MS,
  type IdempotencyBackend,
  type IdempotencyStore,
  type SweepResult,
} from './types.js';
import { inMemoryIdempotencyStore } from './memoryStore.js';
import { createRedisIdempotencyStore } from './redisStore.js';

export interface IdempotencySweeperOptions {
  store: IdempotencyStore;
  backend: IdempotencyBackend;
  /** How often the sweeper runs. Defaults to 60s. */
  intervalMs?: number;
  /**
   * When true, `start()` schedules the first sweep on the next tick
   * rather than after one full interval. Defaults to true so that SREs
   * see gauge data immediately after boot.
   */
  runImmediately?: boolean;
  /** Injected for tests. Defaults to the global timer functions. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setIntervalFn?: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  clearIntervalFn?: (handle: any) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setTimeoutFn?: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  clearTimeoutFn?: (handle: any) => void;
  /** Injected for tests. Defaults to the structured `logger`. */
  log?: typeof logger;
}

export interface IdempotencySweeperHandle {
  sweeper: IdempotencySweeper;
  backend: IdempotencyBackend;
  stop: () => Promise<void>;
}

/**
 * Parse the sweep interval from `IDEMPOTENCY_SWEEP_INTERVAL_MS`, applying
 * a hard floor so a misconfigured value cannot turn the sweeper into a
 * tight loop. Returns the resolved interval in milliseconds.
 */
export function resolveSweepIntervalMs(): number {
  const raw = process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS;
  if (raw === undefined || raw === '') return DEFAULT_SWEEP_INTERVAL_MS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return DEFAULT_SWEEP_INTERVAL_MS;
  }
  return Math.max(MIN_SWEEP_INTERVAL_MS, parsed);
}

/**
 * Start the application-wide idempotency sweeper.
 *
 * - When a Redis store is configured, the sweeper runs against it.
 * - Otherwise it runs against the in-memory store.
 *
 * The interval is read from `IDEMPOTENCY_SWEEP_INTERVAL_MS` (default
 * 60s, hard floor 1s). The returned handle exposes `stop()` for
 * graceful shutdown.
 */
export async function startIdempotencySweeper(): Promise<IdempotencySweeperHandle | null> {
  const redisStore = await createRedisIdempotencyStore();
  const intervalMs = resolveSweepIntervalMs();

  if (redisStore) {
    const sweeper = new IdempotencySweeper({
      store: redisStore,
      backend: 'redis',
      intervalMs,
    });
    sweeper.start();
    return {
      sweeper,
      backend: 'redis',
      stop: () => sweeper.stop(),
    };
  }

  // The in-memory store has no external dependencies; we always run a
  // sweeper against it so SREs get the same gauge for single-process
  // deployments as they do for cluster deployments.
  const sweeper = new IdempotencySweeper({
    store: inMemoryIdempotencyStore,
    backend: 'memory',
    intervalMs,
  });
  sweeper.start();
  return {
    sweeper,
    backend: 'memory',
    stop: () => sweeper.stop(),
  };
}

/** Module-scoped handle to the active background sweeper */
let activeSweeperHandle: IdempotencySweeperHandle | null = null;

/**
 * Start the idempotency sweeper if not in test environment and not already running.
 * Stores the returned IdempotencySweeperHandle in module scope.
 * Subsequent calls while running are no-ops.
 */
export async function startIdempotencySweeperIfNeeded(): Promise<IdempotencySweeperHandle | null> {
  if (process.env.NODE_ENV === 'test') {
    return null;
  }
  if (activeSweeperHandle) {
    return activeSweeperHandle;
  }
  activeSweeperHandle = await startIdempotencySweeper();
  return activeSweeperHandle;
}

/**
 * Stop the module-scoped idempotency sweeper handle and clear it.
 * Calling it multiple times is idempotent (no-op when nothing is running).
 */
export async function stopIdempotencySweeper(): Promise<void> {
  if (!activeSweeperHandle) {
    return;
  }
  const handle = activeSweeperHandle;
  activeSweeperHandle = null;
  await handle.stop();
}

/**
 * Cooperative, non-blocking TTL sweeper for the idempotency store.
 */
export class IdempotencySweeper {
  private readonly store: IdempotencyStore;
  private readonly backend: IdempotencyBackend;
  private readonly intervalMs: number;
  private readonly runImmediately: boolean;
  // The global setTimeout/setInterval signatures union DOM and Node
  // overloads; cast at the boundary so the class compiles cleanly.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly setIntervalFn: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly clearIntervalFn: (handle: any) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly setTimeoutFn: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly clearTimeoutFn: (handle: any) => void;
  private readonly log: typeof logger;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private intervalHandle: any = null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private timeoutHandle: any = null;
  private inflight: Promise<SweepResult> | null = null;
  private stopped = false;

  constructor(options: IdempotencySweeperOptions) {
    this.store = options.store;
    this.backend = options.backend;
    const requested = options.intervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
    this.intervalMs = Math.max(MIN_SWEEP_INTERVAL_MS, requested);
    this.runImmediately = options.runImmediately ?? true;
    this.setIntervalFn = options.setIntervalFn ?? setInterval;
    this.clearIntervalFn = options.clearIntervalFn ?? clearInterval;
    this.setTimeoutFn = options.setTimeoutFn ?? setTimeout;
    this.clearTimeoutFn = options.clearTimeoutFn ?? clearTimeout;
    this.log = options.log ?? logger;
  }

  /** Whether the background interval is currently scheduled. */
  isRunning(): boolean {
    return this.intervalHandle !== null;
  }

  /** Schedule the periodic sweep. Safe to call multiple times. */
  start(): void {
    if (this.isRunning()) return;

    this.stopped = false;

    if (this.runImmediately) {
      // Use a setTimeout(0) so we never block the caller (e.g. boot
      // sequence) on a sweep that might be slow on a hot Redis.
      this.timeoutHandle = this.setTimeoutFn(() => {
        this.timeoutHandle = null;
        void this.runOnce();
      }, 0);
      if (typeof this.timeoutHandle.unref === 'function') {
        this.timeoutHandle.unref();
      }
    }

    this.intervalHandle = this.setIntervalFn(() => {
      void this.runOnce();
    }, this.intervalMs);
    // CRITICAL: an unref'd interval does not keep the event loop alive.
    // The sweeper must never block process exit.
    if (typeof this.intervalHandle.unref === 'function') {
      this.intervalHandle.unref();
    }
  }

  /**
   * Cancel future sweeps and wait for any in-flight cycle to finish.
   * Idempotent: calling `stop()` twice is safe and resolves immediately
   * the second time.
   */
  async stop(): Promise<void> {
    if (this.stopped && !this.inflight) return;
    this.stopped = true;

    if (this.timeoutHandle !== null) {
      this.clearTimeoutFn(this.timeoutHandle);
      this.timeoutHandle = null;
    }

    if (this.intervalHandle !== null) {
      this.clearIntervalFn(this.intervalHandle);
      this.intervalHandle = null;
    }

    if (this.inflight) {
      try {
        await this.inflight;
      } catch {
        // runOnce() never throws, but be defensive so a future
        // refactor cannot wedge shutdown.
      }
    }
  }

  /**
   * Run a single sweep cycle. Concurrent callers (e.g. the interval
   * firing while a manual `runOnce()` is still working) share the
   * same in-flight promise — the sweeper never overlaps itself.
   *
   * Never throws. All errors are logged and surfaced as metrics.
   */
  runOnce(): Promise<SweepResult> {
    if (this.inflight) return this.inflight;

    const cycle = this.executeCycle()
      .catch((err: unknown) => {
        // Defensive: executeCycle already swallows everything, but if
        // a future change introduces a path that throws, we still
        // must not reject the in-flight promise (callers rely on it).
        const message = err instanceof Error ? err.message : String(err);
        this.log.error({
          event: 'idempotency_sweep_unexpected_error',
          backend: this.backend,
          error: message,
        });
        idempotencySweepRunsTotal.inc({ backend: this.backend, outcome: 'error' });
        return {
          backend: this.backend,
          evicted: 0,
          keys: -1,
          errored: true,
          durationMs: 0,
        } satisfies SweepResult;
      })
      .finally(() => {
        this.inflight = null;
      });

    this.inflight = cycle;
    return cycle;
  }

  private async executeCycle(): Promise<SweepResult> {
    const start = Date.now();
    let evicted = 0;
    let keys = -1;
    let errored = false;

    try {
      if (typeof this.store.sweepExpired === 'function') {
        evicted = await this.store.sweepExpired();
      }

      if (typeof this.store.count === 'function') {
        keys = await this.store.count();
        if (keys >= 0) {
          idempotencyKeysCount.set({ backend: this.backend }, keys);
        }
      }

      idempotencySweepRunsTotal.inc({ backend: this.backend, outcome: 'ok' });
    } catch (err) {
      errored = true;
      const message = err instanceof Error ? err.message : String(err);
      this.log.warn({
        event: 'idempotency_sweep_failed',
        backend: this.backend,
        error: message,
      });
      idempotencySweepRunsTotal.inc({ backend: this.backend, outcome: 'error' });
    }

    return {
      backend: this.backend,
      evicted,
      keys,
      errored,
      durationMs: Date.now() - start,
    };
  }
}
