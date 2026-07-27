import { randomUUID } from "node:crypto";
import { logger } from "../utils/logger.js";
import {
  jobDurationSeconds,
  jobItemsProcessedTotal,
  jobLastRunTimestamp,
  jobRunsTotal,
} from "../metrics.js";
import { getPushgatewayClient } from "./pushgatewayClient.js";

export interface JobOutcome {
  /** Number of business items this run acted on (0 if none were due). */
  itemsProcessed: number;
  /** Whether the run completed without error. */
  success: boolean;
}

/**
 * Runs `fn`, records duration/outcome/item-count metrics, and pushes them to
 * the Pushgateway (grouped by `jobName` and a per-run id) so a short-lived
 * batch process doesn't lose its metrics before Prometheus can scrape them.
 *
 * The grouping is deleted from the Pushgateway once the run has both pushed
 * successfully and completed without error, so Pushgateway doesn't
 * accumulate one stale time series per run forever. A failed run's grouping
 * is left in place for operator visibility.
 *
 * `fn` is expected to catch its own errors and report them via the returned
 * `success: false` (matching this repo's existing job convention of logging
 * and swallowing rather than throwing). A `fn` that throws anyway is still
 * treated as a failed run with zero items processed, defensively.
 */
export async function runInstrumentedJob(
  jobName: string,
  fn: () => Promise<JobOutcome>,
): Promise<JobOutcome> {
  const runId = randomUUID();
  const start = process.hrtime.bigint();

  let outcome: JobOutcome;
  try {
    outcome = await fn();
  } catch (error) {
    logger.error(`Unhandled error in job "${jobName}"`, error);
    outcome = { itemsProcessed: 0, success: false };
  }

  const durationSeconds = Number(process.hrtime.bigint() - start) / 1e9;
  jobDurationSeconds.labels(jobName).observe(durationSeconds);
  jobRunsTotal.labels(jobName, outcome.success ? "success" : "failure").inc();
  jobItemsProcessedTotal.labels(jobName).inc(outcome.itemsProcessed);
  jobLastRunTimestamp.labels(jobName).set(Date.now() / 1000);

  const pushgateway = getPushgatewayClient();
  await pushgateway.pushJobMetrics(jobName, runId);
  if (outcome.success) {
    await pushgateway.deleteJobGrouping(jobName, runId);
  }

  return outcome;
}
