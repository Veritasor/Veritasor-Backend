import { config } from '../../config/index.js';
import { logger } from '../../utils/logger.js';
import { metricsRegistry } from '../../metrics.js';
import { StatsDClient } from './statsdClient.js';
import {
  startStatsdDualWrite,
  type StatsdDualWriteHandle,
} from './statsdDualWrite.js';

let dualWriteHandle: StatsdDualWriteHandle | undefined;

/**
 * Start the StatsD dual-write loop when STATSD_DUAL_WRITE_ENABLED is true.
 * Safe to call from app startup; no-op when the feature flag is off.
 */
export function startStatsdDualWriteIfEnabled(): void {
  if (!config.statsd.dualWriteEnabled) {
    return;
  }

  if (dualWriteHandle) {
    logger.warn('StatsD dual-write already running; ignoring duplicate start');
    return;
  }

  const statsdClient = new StatsDClient({
    host: config.statsd.host,
    port: config.statsd.port,
    prefix: config.statsd.prefix,
  });

  dualWriteHandle = startStatsdDualWrite({
    statsdClient,
    registry: metricsRegistry,
    intervalMs: config.statsd.dualWriteIntervalMs,
  });

  logger.info(
    {
      host: config.statsd.host,
      port: config.statsd.port,
      prefix: config.statsd.prefix,
      intervalMs: config.statsd.dualWriteIntervalMs,
    },
    'StatsD dual-write initialised',
  );
}

/**
 * Stop the StatsD dual-write loop if it is running.
 * Safe to call during graceful shutdown; no-op when not running.
 */
export async function stopStatsdDualWriteIfNeeded(): Promise<void> {
  if (!dualWriteHandle) {
    return;
  }

  try {
    await dualWriteHandle.stop();
  } catch (err) {
    logger.warn(
      { err: (err as Error).message },
      'StatsD dual-write stop error',
    );
  } finally {
    dualWriteHandle = undefined;
  }
}
