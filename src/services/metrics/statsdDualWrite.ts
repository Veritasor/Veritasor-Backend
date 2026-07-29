import type { Registry } from 'prom-client';
import { StatsDClient, sanitizeTagValue } from './statsdClient.js';
import { logger } from '../../utils/logger.js';
import {
  statsdDualWriteRunsTotal,
  statsdDualWriteErrorsTotal,
  statsdDualWriteDurationMs,
  statsdDualWriteMetricsCount,
} from '../../metrics.js';

export interface StatsdDualWriteConfig {
  statsdClient: StatsDClient;
  registry: Registry;
  /** Interval in ms between push cycles. Must be >= 1000. */
  intervalMs: number;
}

export interface StatsdDualWriteHandle {
  stop: () => Promise<void>;
}

/**
 * Sanitize a Prometheus metric name for StatsD.
 * Replace non-alphanumeric chars (except underscore) with underscore.
 */
function sanitizeMetricName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_');
}

/**
 * Build StatsD tags from Prometheus label pairs.
 */
function buildTags(labels: Record<string, string | number>): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const [key, value] of Object.entries(labels)) {
    tags[sanitizeTagValue(key)] = sanitizeTagValue(String(value));
  }
  return tags;
}

/** Build a stable key for delta-tracking from metric name + label set. */
function deltaKey(name: string, labels: Record<string, string | number>): string {
  return `${name}:${JSON.stringify(labels)}`;
}

/**
 * Start a periodic dual-write loop that reads all metrics from the
 * prom-client Registry and pushes them to the configured StatsD endpoint.
 *
 * COUNTER handling: Since StatsD counters are incremental and prom-client
 * counters are cumulative, we track the last observed value per
 * (name, labels) key and emit the delta on each cycle.
 *
 * GAUGE handling: The current value is sent as-is each cycle.
 *
 * HISTOGRAM handling: Cumulative bucket counts and a delta-sum timing
 * are emitted per label set.
 */
export function startStatsdDualWrite(
  config: StatsdDualWriteConfig,
): StatsdDualWriteHandle {
  const { statsdClient, registry, intervalMs } = config;

  // Track previous counter values + histogram sums to compute deltas
  const previousCounters = new Map<string, number>();
  const previousSums = new Map<string, number>();

  let timer: ReturnType<typeof setInterval> | null = null;
  let stopped = false;

  const pushMetrics = (): void => {
    const startedAt = Date.now();
    let metricsCount = 0;

    try {
      const metrics = registry.getMetricsAsJSON();

      for (const metric of metrics) {
        const safeName = sanitizeMetricName(metric.name);

        for (const value of metric.values) {
          const tags = buildTags(value.labels);
          metricsCount++;

          switch (metric.type) {
            case 'counter': {
              const key = deltaKey(safeName, value.labels);
              const current = value.value as number;
              const prev = previousCounters.get(key) ?? 0;
              const delta = current - prev;
              if (delta > 0) {
                statsdClient.increment(safeName, delta, tags);
              }
              previousCounters.set(key, current);
              break;
            }

            case 'gauge': {
              statsdClient.gauge(safeName, value.value as number, tags);
              break;
            }

            case 'histogram': {
              const key = deltaKey(safeName, value.labels);
              const currentSum = (value as Record<string, unknown>).sum as number ?? 0;
              const prevSum = previousSums.get(key) ?? 0;
              const deltaSum = currentSum - prevSum;
              previousSums.set(key, currentSum);

              // Emit cumulative bucket counts
              const buckets = (value as Record<string, unknown>).buckets as Record<string, number> | undefined;
              if (buckets) {
                for (const [bucket, count] of Object.entries(buckets)) {
                  statsdClient.histogram(`${safeName}_bucket`, count, {
                    ...tags,
                    le: sanitizeTagValue(String(bucket)),
                  });
                }
              }

              // Emit delta-sum as timing (convert seconds → ms for StatsD)
              if (deltaSum > 0) {
                statsdClient.timing(safeName, deltaSum * 1000, tags);
              }

              break;
            }

            case 'summary': {
              // Summary: emit quantiles as gauges, and count + sum
              const summaryValue = value as Record<string, unknown>;
              const percentiles = summaryValue.percentiles as Record<string, number> | undefined;
              if (percentiles) {
                for (const [quantile, qValue] of Object.entries(percentiles)) {
                  statsdClient.gauge(`${safeName}_quantile`, qValue, {
                    ...tags,
                    quantile: sanitizeTagValue(quantile),
                  });
                }
              }
              const sCount = summaryValue.count as number | undefined;
              const sSum = summaryValue.sum as number | undefined;
              if (sCount !== undefined && sCount > 0) {
                statsdClient.histogram(`${safeName}_count`, sCount, tags);
              }
              if (sSum !== undefined) {
                statsdClient.timing(safeName, sSum * 1000, tags);
              }
              break;
            }
          }
        }
      }

      statsdDualWriteMetricsCount.set(metricsCount);
      statsdDualWriteRunsTotal.inc({ outcome: 'ok' });
    } catch (err) {
      statsdDualWriteRunsTotal.inc({ outcome: 'error' });
      statsdDualWriteErrorsTotal.inc({ reason: 'push_failed' });
      logger.warn(
        { err: (err as Error).message },
        'StatsD dual-write push cycle failed',
      );
    } finally {
      statsdDualWriteDurationMs.observe(Date.now() - startedAt);
    }
  };

  timer = setInterval(pushMetrics, intervalMs);
  // Don't keep the process alive just for the dual-write timer
  if (timer.unref) {
    timer.unref();
  }

  logger.info(
    { intervalMs },
    'StatsD dual-write started',
  );

  return {
    stop: async (): Promise<void> => {
      if (stopped) return;
      stopped = true;

      if (timer) {
        clearInterval(timer);
        timer = null;
      }

      // Final flush of pending deltas
      try {
        pushMetrics();
      } catch {
        // Best-effort; socket may already be gone
      }

      await statsdClient.close();
      logger.info('StatsD dual-write stopped');
    },
  };
}
