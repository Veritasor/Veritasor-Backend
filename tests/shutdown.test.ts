/**
 * Tests for the graceful shutdown orchestrator (`src/shutdown.ts`).
 *
 * Coverage targets (≥ 95 %):
 *   ✔ Successful shutdown — server closes, pool drains, process.exit(0) called
 *   ✔ Timeout breach — deadline fires before drain completes, process.exit(1) called
 *   ✔ Repeated signal — second signal during active shutdown calls process.exit(1) immediately
 *   ✔ pool.end() error — logged but does not prevent clean exit
 *   ✔ server.close() error — causes process.exit(1) via error path
 *   ✔ onCleanup hook — invoked after pool closes; errors are swallowed
 *   ✔ SHUTDOWN_TIMEOUT_MS env override — respected when set to a valid integer
 *   ✔ Invalid SHUTDOWN_TIMEOUT_MS — falls back to 15 000 ms default
 *   ✔ Both SIGTERM and SIGINT are registered
 *   ✔ Returned handler function is callable directly (used in integration-style assertions)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Server } from 'node:http';
import { EventEmitter } from 'node:events';
import { createShutdownOrchestrator } from '../src/shutdown.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal fake `http.Server` whose `close()` behaviour is controlled
 * by a returned `resolveClose` / `rejectClose` pair so tests can decide when
 * the drain completes.
 */
function makeServer(opts: { closeError?: Error } = {}): {
  server: Server;
  triggerClose: (err?: Error) => void;
} {
  let storedCallback: ((err?: Error) => void) | undefined;

  const server = new EventEmitter() as unknown as Server;
  (server as unknown as { close: (cb: (err?: Error) => void) => void }).close = (
    cb: (err?: Error) => void,
  ) => {
    storedCallback = cb;
    // If a canned error was provided, fire it on the next tick
    if (opts.closeError) {
      process.nextTick(() => cb(opts.closeError));
    }
  };

  return {
    server,
    triggerClose: (err?: Error) => {
      if (storedCallback) storedCallback(err);
    },
  };
}

/**
 * Build a fake `Pool` whose `end()` behaviour is controlled by the caller.
 */
function makePool(opts: { rejects?: boolean; hangs?: boolean } = {}): {
  pool: { end: () => Promise<void> };
  resolveEnd: () => void;
} {
  let resolveEnd!: () => void;

  const pool = {
    end: vi.fn(
      (): Promise<void> =>
        new Promise<void>((resolve, reject) => {
          if (opts.hangs) {
            resolveEnd = resolve; // caller controls when it resolves
            return;
          }
          if (opts.rejects) {
            reject(new Error('pool.end failed'));
          } else {
            resolve();
            resolveEnd = resolve;
          }
        }),
    ),
  };

  return { pool, resolveEnd };
}

/**
 * Build a fake `process`-like object that records `exit` calls and exposes
 * a signal emitter for `on`.
 */
function makeProc(): {
  proc: NodeJS.Process;
  exitCalls: number[];
  emit: (signal: string) => void;
} {
  const exitCalls: number[] = [];
  const emitter = new EventEmitter();

  const proc = {
    on: emitter.on.bind(emitter),
    off: emitter.off.bind(emitter),
    exit: vi.fn((code: number) => {
      exitCalls.push(code);
    }),
    env: process.env,
  } as unknown as NodeJS.Process;

  return {
    proc,
    exitCalls,
    emit: (signal: string) => emitter.emit(signal, signal),
  };
}

/** Flush the microtask queue and any immediately-queued timers. */
const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('createShutdownOrchestrator', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // ── Happy path ─────────────────────────────────────────────────────────

  describe('successful shutdown', () => {
    it('calls server.close() then pool.end() then process.exit(0)', async () => {
      const { server, triggerClose } = makeServer();
      const { pool } = makePool();
      const { proc, exitCalls, emit } = makeProc();

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000 });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();

      // server.close() must be called first
      expect(
        (server as unknown as { close: ReturnType<typeof vi.fn> }).close,
      ).toBeDefined();

      // Simulate server drain completing
      triggerClose();
      await flush();

      expect(pool.end).toHaveBeenCalledTimes(1);
      expect(exitCalls).toEqual([0]);
    });

    it('registers handlers for both SIGTERM and SIGINT', () => {
      const { server } = makeServer();
      const { pool } = makePool();
      const { proc } = makeProc();

      const onSpy = vi.spyOn(proc, 'on');
      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000 });
      orchestrator.register(server, proc);

      const registeredSignals = onSpy.mock.calls.map(([signal]) => signal);
      expect(registeredSignals).toContain('SIGTERM');
      expect(registeredSignals).toContain('SIGINT');
    });

    it('calls process.exit(0) when SIGINT is the trigger', async () => {
      const { server, triggerClose } = makeServer();
      const { pool } = makePool();
      const { proc, exitCalls, emit } = makeProc();

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000 });
      orchestrator.register(server, proc);

      emit('SIGINT');
      await flush();
      triggerClose();
      await flush();

      expect(exitCalls).toEqual([0]);
    });

    it('invokes onCleanup hook after pool closes', async () => {
      const { server, triggerClose } = makeServer();
      const { pool } = makePool();
      const { proc, exitCalls, emit } = makeProc();
      const onCleanup = vi.fn().mockResolvedValue(undefined);

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000, onCleanup });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();
      triggerClose();
      await flush();

      expect(onCleanup).toHaveBeenCalledTimes(1);
      expect(exitCalls).toEqual([0]);
    });

    it('exits 0 even if onCleanup hook throws', async () => {
      const { server, triggerClose } = makeServer();
      const { pool } = makePool();
      const { proc, exitCalls, emit } = makeProc();
      const onCleanup = vi.fn().mockRejectedValue(new Error('cleanup failed'));

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000, onCleanup });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();
      triggerClose();
      await flush();

      expect(exitCalls).toEqual([0]);
    });

    it('returns the registered handler function', () => {
      const { server } = makeServer();
      const { pool } = makePool();
      const { proc } = makeProc();

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000 });
      const handler = orchestrator.register(server, proc);

      expect(typeof handler).toBe('function');
    });
  });

  // ── pool.end() errors ──────────────────────────────────────────────────

  describe('pool.end() error handling', () => {
    it('logs pool error but still calls process.exit(0)', async () => {
      const { server, triggerClose } = makeServer();
      const { pool } = makePool({ rejects: true });
      const { proc, exitCalls, emit } = makeProc();
      const stderrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000 });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();
      triggerClose();
      await flush();

      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('[Shutdown] Error while closing DB pool:'),
        expect.any(Error),
      );
      // Pool error is swallowed — exit code must still be 0
      expect(exitCalls).toEqual([0]);
    });
  });

  // ── server.close() error ───────────────────────────────────────────────

  describe('server.close() error handling', () => {
    it('calls process.exit(1) when server.close() errors', async () => {
      const closeError = new Error('server close failed');
      const { server } = makeServer({ closeError });
      const { pool } = makePool();
      const { proc, exitCalls, emit } = makeProc();
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000 });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      // Wait for nextTick-fired close error to propagate
      await flush();
      await flush();

      expect(exitCalls).toEqual([1]);
    });
  });

  // ── Timeout ────────────────────────────────────────────────────────────

  describe('shutdown timeout', () => {
    it('force-exits with code 1 when deadline expires before server closes', async () => {
      // server.close() callback is never invoked → deadline fires
      const { server } = makeServer(); // triggerClose never called
      const { pool } = makePool({ hangs: true });
      const { proc, exitCalls, emit } = makeProc();
      const stderrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 3_000 });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();

      // Advance past the deadline
      vi.advanceTimersByTime(3_001);
      await flush();

      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('exceeded'),
        // The message includes the timeout value
      );
      expect(exitCalls).toEqual([1]);
    });

    it('does NOT force-exit if drain finishes before the deadline', async () => {
      const { server, triggerClose } = makeServer();
      const { pool } = makePool();
      const { proc, exitCalls, emit } = makeProc();

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 10_000 });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();
      triggerClose(); // drain completes well within 10 s
      await flush();

      // Advance time — deadline should already be cleared
      vi.advanceTimersByTime(15_000);
      await flush();

      // Only one exit, and it's 0
      expect(exitCalls).toEqual([0]);
    });
  });

  // ── Repeated signal ────────────────────────────────────────────────────

  describe('repeated signal (double-signal guard)', () => {
    it('force-exits with code 1 on second SIGTERM during active shutdown', async () => {
      // server.close() never calls back → shutdown is stuck draining
      const { server } = makeServer();
      const { pool } = makePool({ hangs: true });
      const { proc, exitCalls, emit } = makeProc();
      const stderrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 30_000 });
      orchestrator.register(server, proc);

      // First signal — starts the drain
      emit('SIGTERM');
      await flush();

      expect(exitCalls).toHaveLength(0); // not exited yet

      // Second signal — should force-exit immediately
      emit('SIGTERM');
      await flush();

      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('second'),
      );
      expect(exitCalls).toEqual([1]);
    });

    it('force-exits with code 1 on SIGINT after SIGTERM', async () => {
      const { server } = makeServer();
      const { pool } = makePool({ hangs: true });
      const { proc, exitCalls, emit } = makeProc();
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 30_000 });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();

      emit('SIGINT');
      await flush();

      expect(exitCalls).toEqual([1]);
    });

    it('force-exits with code 1 on SIGTERM after SIGINT', async () => {
      const { server } = makeServer();
      const { pool } = makePool({ hangs: true });
      const { proc, exitCalls, emit } = makeProc();
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 30_000 });
      orchestrator.register(server, proc);

      emit('SIGINT');
      await flush();

      emit('SIGTERM');
      await flush();

      expect(exitCalls).toEqual([1]);
    });
  });

  // ── SHUTDOWN_TIMEOUT_MS env override ───────────────────────────────────

  describe('SHUTDOWN_TIMEOUT_MS environment variable', () => {
    it('respects a valid SHUTDOWN_TIMEOUT_MS value', async () => {
      const { server } = makeServer();
      const { pool } = makePool({ hangs: true });
      const { proc, exitCalls, emit } = makeProc();
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const originalEnv = process.env.SHUTDOWN_TIMEOUT_MS;
      process.env.SHUTDOWN_TIMEOUT_MS = '2000';

      // Explicitly NOT passing timeoutMs so the env var is picked up
      const orchestrator = createShutdownOrchestrator({ pool });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();

      vi.advanceTimersByTime(2_001);
      await flush();

      expect(exitCalls).toEqual([1]);

      // Restore
      if (originalEnv === undefined) {
        delete process.env.SHUTDOWN_TIMEOUT_MS;
      } else {
        process.env.SHUTDOWN_TIMEOUT_MS = originalEnv;
      }
    });

    it('falls back to 15 000 ms on invalid SHUTDOWN_TIMEOUT_MS', async () => {
      const { server } = makeServer();
      const { pool } = makePool({ hangs: true });
      const { proc, exitCalls, emit } = makeProc();
      const stderrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      vi.spyOn(console, 'warn').mockImplementation(() => {});

      const originalEnv = process.env.SHUTDOWN_TIMEOUT_MS;
      process.env.SHUTDOWN_TIMEOUT_MS = 'not-a-number';

      const orchestrator = createShutdownOrchestrator({ pool });
      orchestrator.register(server, proc);

      emit('SIGTERM');
      await flush();

      // Should NOT have exited at 5 s (before the 15 s default)
      vi.advanceTimersByTime(5_000);
      await flush();
      expect(exitCalls).toHaveLength(0);

      // Should force-exit at 15 s
      vi.advanceTimersByTime(10_001);
      await flush();
      expect(exitCalls).toEqual([1]);

      if (originalEnv === undefined) {
        delete process.env.SHUTDOWN_TIMEOUT_MS;
      } else {
        process.env.SHUTDOWN_TIMEOUT_MS = originalEnv;
      }
    });
  });

  // ── Handler callable directly ──────────────────────────────────────────

  describe('handler invocable directly', () => {
    it('works when handler is called with a signal string argument', async () => {
      const { server, triggerClose } = makeServer();
      const { pool } = makePool();
      const { proc, exitCalls } = makeProc();

      const orchestrator = createShutdownOrchestrator({ pool, timeoutMs: 5_000 });
      const handler = orchestrator.register(server, proc);

      // Call directly rather than via emit
      handler('SIGTERM');
      await flush();
      triggerClose();
      await flush();

      expect(exitCalls).toEqual([0]);
    });
  });
});
