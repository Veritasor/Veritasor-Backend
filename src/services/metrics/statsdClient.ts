import StatsD from 'hot-shots';
import { logger } from '../../utils/logger.js';

export interface StatsDClientConfig {
  host: string;
  port: number;
  prefix: string;
  /** Protocol: 'udp' (default) or 'tcp' */
  protocol?: 'udp' | 'tcp';
}

export class StatsDClient {
  private client: StatsD;

  constructor(config: StatsDClientConfig) {
    this.client = new StatsD({
      host: config.host,
      port: config.port,
      prefix: config.prefix,
      protocol: config.protocol ?? 'udp',
      bufferFlushInterval: 1000,
      cacheDns: false,
      maxBufferSize: 0,
    });
  }

  gauge(name: string, value: number, tags?: Record<string, string>): void {
    try {
      this.client.gauge(name, value, tags);
    } catch (err) {
      logger.warn(
        { err: (err as Error).message, name, value },
        'StatsD gauge send failed',
      );
    }
  }

  increment(name: string, value: number, tags?: Record<string, string>): void {
    try {
      this.client.increment(name, value, tags);
    } catch (err) {
      logger.warn(
        { err: (err as Error).message, name, value },
        'StatsD increment send failed',
      );
    }
  }

  timing(name: string, value: number, tags?: Record<string, string>): void {
    try {
      this.client.timing(name, value, tags);
    } catch (err) {
      logger.warn(
        { err: (err as Error).message, name, value },
        'StatsD timing send failed',
      );
    }
  }

  histogram(name: string, value: number, tags?: Record<string, string>): void {
    try {
      this.client.histogram(name, value, tags);
    } catch (err) {
      logger.warn(
        { err: (err as Error).message, name, value },
        'StatsD histogram send failed',
      );
    }
  }

  async close(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.client.close(() => {
        resolve();
      });
    });
  }
}

/**
 * Sanitize a label value for StatsD tag use.
 * StatsD tags should only contain [a-zA-Z0-9_.-].
 */
export function sanitizeTagValue(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.\-]/g, '_');
}
