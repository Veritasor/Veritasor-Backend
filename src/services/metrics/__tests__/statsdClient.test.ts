import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('hot-shots', () => {
  const MockStatsD = vi.fn();
  MockStatsD.prototype.gauge = vi.fn();
  MockStatsD.prototype.increment = vi.fn();
  MockStatsD.prototype.timing = vi.fn();
  MockStatsD.prototype.histogram = vi.fn();
  MockStatsD.prototype.close = vi.fn((cb: () => void) => cb());
  return { default: MockStatsD };
});

vi.mock('../../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import StatsD from 'hot-shots';
import { StatsDClient, sanitizeTagValue } from '../statsdClient.js';
import { logger } from '../../../utils/logger.js';

describe('StatsDClient', () => {
  let client: StatsDClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new StatsDClient({
      host: '127.0.0.1',
      port: 8125,
      prefix: 'veritasor.',
      protocol: 'udp',
    });
  });

  afterEach(async () => {
    await client.close();
  });

  it('creates a hot-shots StatsD instance with the provided config', () => {
    expect(StatsD).toHaveBeenCalledWith(
      expect.objectContaining({
        host: '127.0.0.1',
        port: 8125,
        prefix: 'veritasor.',
        protocol: 'udp',
      }),
    );
  });

  it('defaults protocol to udp when not specified', () => {
    new StatsDClient({ host: '10.0.0.1', port: 8125, prefix: 'app.' });
    expect(StatsD).toHaveBeenCalledWith(
      expect.objectContaining({ protocol: 'udp' }),
    );
  });

  describe('gauge', () => {
    it('sends a gauge metric', () => {
      client.gauge('test_metric', 42, { env: 'prod' });
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      expect(instance.gauge).toHaveBeenCalledWith('test_metric', 42, {
        env: 'prod',
      });
    });

    it('sends a gauge without tags', () => {
      client.gauge('test_metric', 99);
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      expect(instance.gauge).toHaveBeenCalledWith('test_metric', 99, undefined);
    });

    it('logs a warning and does not throw when send fails', () => {
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      (instance.gauge as ReturnType<typeof vi.fn>).mockImplementation(() => {
        throw new Error('socket hang up');
      });

      expect(() => client.gauge('fail_metric', 1)).not.toThrow();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ err: 'socket hang up', name: 'fail_metric' }),
        'StatsD gauge send failed',
      );
    });
  });

  describe('increment', () => {
    it('sends an increment (counter)', () => {
      client.increment('requests', 5, { method: 'GET' });
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      expect(instance.increment).toHaveBeenCalledWith('requests', 5, {
        method: 'GET',
      });
    });

    it('logs a warning when send fails', () => {
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      (instance.increment as ReturnType<typeof vi.fn>).mockImplementation(() => {
        throw new Error('ENOTFOUND');
      });

      expect(() => client.increment('r', 1)).not.toThrow();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ err: 'ENOTFOUND' }),
        'StatsD increment send failed',
      );
    });
  });

  describe('timing', () => {
    it('sends a timing metric', () => {
      client.timing('latency', 250, { route: '/api' });
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      expect(instance.timing).toHaveBeenCalledWith('latency', 250, {
        route: '/api',
      });
    });

    it('logs a warning when send fails', () => {
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      (instance.timing as ReturnType<typeof vi.fn>).mockImplementation(() => {
        throw new Error('send failed');
      });

      expect(() => client.timing('lat', 100)).not.toThrow();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ err: 'send failed' }),
        'StatsD timing send failed',
      );
    });
  });

  describe('histogram', () => {
    it('sends a histogram metric', () => {
      client.histogram('bucket_size', 1024, { unit: 'bytes' });
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      expect(instance.histogram).toHaveBeenCalledWith('bucket_size', 1024, {
        unit: 'bytes',
      });
    });

    it('logs a warning when send fails', () => {
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      (instance.histogram as ReturnType<typeof vi.fn>).mockImplementation(() => {
        throw new Error('timeout');
      });

      expect(() => client.histogram('h', 5)).not.toThrow();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ err: 'timeout' }),
        'StatsD histogram send failed',
      );
    });
  });

  describe('close', () => {
    it('closes the underlying StatsD client', async () => {
      await client.close();
      const instance = (StatsD as unknown as ReturnType<typeof vi.fn>).mock
        .instances[0];
      expect(instance.close).toHaveBeenCalled();
    });

    it('can be called multiple times safely', async () => {
      await client.close();
      await client.close();
      // Should not throw
    });
  });
});

describe('sanitizeTagValue', () => {
  it('passes through valid characters', () => {
    expect(sanitizeTagValue('hello_world.123-ABC')).toBe('hello_world.123-ABC');
  });

  it('replaces invalid characters with underscore', () => {
    expect(sanitizeTagValue('hello world!')).toBe('hello_world_');
  });

  it('handles empty string', () => {
    expect(sanitizeTagValue('')).toBe('');
  });

  it('replaces special chars like colons, slashes, and spaces', () => {
    expect(sanitizeTagValue('a:b/c d')).toBe('a_b_c_d');
  });

  it('handles unicode characters', () => {
    expect(sanitizeTagValue('café')).toBe('caf_');
  });
});
