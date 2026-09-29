import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Capture mocks before module imports
const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

vi.mock('../../utils/logger.js', () => ({
  logger: mockLogger,
}));

const mockConfig = {
  statsd: {
    host: '127.0.0.1',
    port: 8125,
    prefix: 'veritasor.',
    dualWriteEnabled: true,
    dualWriteIntervalMs: 10_000,
  },
};

vi.mock('../../config/index.js', () => ({
  config: mockConfig,
}));

vi.mock('../../metrics.js', () => ({
  metricsRegistry: { getMetricsAsJSON: vi.fn().mockReturnValue([]) },
  statsdDualWriteRunsTotal: { inc: vi.fn() },
  statsdDualWriteErrorsTotal: { inc: vi.fn() },
  statsdDualWriteDurationMs: { observe: vi.fn() },
  statsdDualWriteMetricsCount: { set: vi.fn() },
}));

vi.mock('../statsdClient.js', () => ({
  StatsDClient: vi.fn().mockImplementation(() => ({
    gauge: vi.fn(),
    increment: vi.fn(),
    timing: vi.fn(),
    histogram: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  })),
  sanitizeTagValue: vi.fn((v: string) => v.replace(/[^a-zA-Z0-9_.\-]/g, '_')),
}));

vi.mock('../statsdDualWrite.js', () => {
  const handle = {
    stop: vi.fn().mockResolvedValue(undefined),
  };
  return {
    startStatsdDualWrite: vi.fn().mockReturnValue(handle),
    StatsdDualWriteHandle: {} as any,
  };
});

import {
  startStatsdDualWriteIfEnabled,
  stopStatsdDualWriteIfNeeded,
} from '../statsdBootstrap.js';
import { startStatsdDualWrite } from '../statsdDualWrite.js';
import { StatsDClient } from '../statsdClient.js';

describe('statsdBootstrap', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfig.statsd.dualWriteEnabled = true;
  });

  afterEach(async () => {
    // Ensure module-level state is reset between tests
    await stopStatsdDualWriteIfNeeded();
    vi.clearAllMocks();
  });

  describe('startStatsdDualWriteIfEnabled', () => {
    it('creates a StatsD client and starts dual-write when enabled', () => {
      startStatsdDualWriteIfEnabled();

      expect(StatsDClient).toHaveBeenCalledWith({
        host: '127.0.0.1',
        port: 8125,
        prefix: 'veritasor.',
      });
      expect(startStatsdDualWrite).toHaveBeenCalled();
    });

    it('logs a warning and skips if already running', () => {
      startStatsdDualWriteIfEnabled();
      vi.clearAllMocks();

      startStatsdDualWriteIfEnabled();

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'StatsD dual-write already running; ignoring duplicate start',
      );
      // No second client created
      expect(StatsdClient).not.toHaveBeenCalled();
    });

    it('does not start dual-write when the feature flag is disabled', () => {
      mockConfig.statsd.dualWriteEnabled = false;

      startStatsdDualWriteIfEnabled();

      expect(StatsDClient).not.toHaveBeenCalled();
      expect(startStatsdDualWrite).not.toHaveBeenCalled();
    });

    it('respects a disabled flag after a previous start and stop', async () => {
      startStatsdDualWriteIfEnabled();
      await stopStatsdDualWriteIfNeeded();
      vi.clearAllMocks();

      mockConfig.statsd.dualWriteEnabled = false;
      startStatsdDualWriteIfEnabled();

      expect(StatsDClient).not.toHaveBeenCalled();
      expect(startStatsdDualWrite).not.toHaveBeenCalled();
    });
  });

  describe('stopStatsdDualWriteIfNeeded', () => {
    it('is a no-op when nothing is running', async () => {
      await expect(stopStatsdDualWriteIfNeeded()).resolves.toUndefined();
      expect(mockLogger.warn).not.toHaveBeenCalled();
    });

    it('stops the dual-write handle when running', async () => {
      startStatsdDualWriteIfEnabled();
      const handle = (startStatsdDualWrite as ReturnType<typeof vi.fn>).mock
        .results[0].value;

      await stopStatsdDualWriteIfNeeded();

      expect(handle.stop).toHaveBeenCalled();
    });

    it('clears the handle after stopping, making a second stop a no-op', async () => {
      startStatsdDualWriteIfEnabled();

      await stopStatsdDualWriteIfNeeded();
      const handle = (startStatsdDualWrite as ReturnType<typeof vi.fn>).mock
        .results[0].value;
      expect(handle.stop).toHaveBeenCalledTimes(1);

      vi.clearAllMocks();

      // Second stop should not call handle.stop again
      await stopStatsdDualWriteIfNeeded();
      expect(handle.stop).not.toHaveBeenCalled();
    });

    it('logs a warning and clears handle when stop throws', async () => {
      startStatsdDualWriteIfEnabled();
      const handle = (startStatsdDualWrite as ReturnType<typeof vi.fn>).mock
        .results[0].value;
      (handle.stop as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('close failed'),
      );

      await stopStatsdDualWriteIfNeeded();

      expect(mockLogger.warn).toHaveBeenCalledWith(
        { err: 'close failed' },
        'StatsD dual-write stop error',
      );

      // Handle should be cleared even after error
      await stopStatsdDualWriteIfNeeded();
      expect(handle.stop).toHaveBeenCalledTimes(1);
    });

    it('surfaces non-Error rejections with a deterministic warning', async () => {
      startStatsdDualWriteIfEnabled();
      const handle = (startStatsdDualWrite as ReturnType<typeof vi.fn>).mock
        .results[0].value;
      (handle.stop as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        'unexpected failure',
      );

      await stopStatsdDualWriteIfNeeded();

      expect(mockLogger.warn).toHaveBeenCalledWith(
        { err: 'unexpected failure' },
        'StatsD dual-write stop error',
      );
    });
  });

  describe('state transitions', () => {
    it('supports start -> stop -> start with a fresh client each time', async () => {
      startStatsdDualWriteIfEnabled();
      expect(StatsdClient).toHaveBeenCalledTimes(1);

      await stopStatsdDualWriteIfNeeded();

      startStatsdDualWriteIfEnabled();
      expect(StatsDClient).toHaveBeenCalledTimes(2);
      expect(startStatsdDualWrite).toHaveBeenCalledTimes(2);
    });

    it('does not leak the handle across stop and start cycles', async () => {
      startStatsdDualWriteIfEnabled();
      const firstHandle = (startStatsdDualWrite as ReturnType<typeof vi.fn>).mock
        .results[0].value;

      await stopStatsdDualWriteIfNeeded();
      expect(firstHandle.stop).toHaveBeenCalledTimes(1);

      startStatsdDualWriteIfEnabled();
      const secondHandle = (startStatsdDualWrite as ReturnType<typeof vi.fn>).mock
        .results[1].value;

      await stopStatsdDualWriteIfNeeded();
      expect(secondHandle.stop).toHaveBeenCalledTimes(1);
      expect(firstHandle.stop).toHaveBeenCalledTimes(1);
    });
  });
});
