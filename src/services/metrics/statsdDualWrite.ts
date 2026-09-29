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

  const pushMetrics = async (): Promise<void> => {
    const startedAt = Date.now();
    let metricsCount = 0;

    try {
      // `getMetricsAsJSON` is asynchronous in prom-client >= 15: it returns a
      // promise that resolves to the JSON snapshot of every registered
      // metric. Awaiting it is required — treating it as a synchronous array
      // throws on iteration and silently disables the whole push loop.
      const metrics = await registry.getMetricsAsJSON();

      for (const metric of metrics) {
        const safeName = sanitizeMetricName(metric.name);

        for (const value of metric.values) {
          // prom-client >= 15 flattens every sample into its own entry and
          // carries the concrete sample name (e.g. `foo_bucket`, `foo_sum`,
          // `foo_count`) on `metricName`. Older revisions exposed a single
          // nested object per label set instead.
          const labels = (value.labels ?? {}) as Record<string, string | number>;
          const tags = buildTags(labels);
          const sampleName = sanitizeMetricName(
            (value as { metricName?: string }).metricName ?? metric.name,
          );
          const sample = typeof value.value === 'number' ? value.value : 0;
          metricsCount++;

          switch (metric.type) {
            case 'counter': {
              const key = deltaKey(sampleName, labels);
              const prev = previousCounters.get(key) ?? 0;
              const delta = sample - prev;
              if (delta > 0) {
                statsdClient.increment(sampleName, delta, tags);
              }
              previousCounters.set(key, sample);
              break;
            }

            case 'gauge': {
              statsdClient.gauge(sampleName, sample, tags);
              break;
            }

            case 'histogram': {
              if (sampleName.endsWith('_bucket')) {
                // Cumulative bucket counters, tagged with the `le` bound.
                statsdClient.histogram(sampleName, sample, tags);
              } else if (sampleName.endsWith('_sum')) {
                const key = deltaKey(sampleName, labels);
                const prevSum = previousSums.get(key) ?? 0;
                const deltaSum = sample - prevSum;
                previousSums.set(key, sample);
                // Emit delta-sum as timing (convert seconds -> ms for StatsD)
                // under the metric's own name, not the `_sum` sample.
                if (deltaSum > 0) {
                  statsdClient.timing(safeName, deltaSum * 1000, tags);
                }
              }
              break;
            }

            case 'summary': {
              const quantile = labels.quantile;
              if (quantile !== undefined) {
                statsdClient.gauge(`${safeName}_quantile`, sample, {
                  ...tags,
                  quantile: sanitizeTagValue(String(quantile)),
                });
              } else if (sampleName.endsWith('_count')) {
                const key = deltaKey(sampleName, labels);
                const prevSum = previousSums.get(key) ?? 0;
                previousSums.set(key, sample);
                if (sample > prevSum) {
                  statsdClient.histogram(sampleName, sample, tags);
                }
              } else if (sampleName.endsWith('_sum')) {
                statsdClient.timing(safeName, sample * 1000, tags);
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

  timer = setInterval(() => {
    // `pushMetrics` handles its own errors; keep the interval callback
    // synchronous so a rejected promise can never become an unhandled
    // rejection that would tear the process down.
    void pushMetrics();
  }, intervalMs);
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
        await pushMetrics();
      } catch {
        // Best-effort; socket may already be gone
      }

      await statsdClient.close();
      logger.info('StatsD dual-write stopped');
    },
  };
}
