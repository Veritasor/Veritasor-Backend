import { Pushgateway } from "prom-client";
import { logger } from "../utils/logger.js";
import { metricsRegistry } from "../metrics.js";

/**
 * Minimal Pushgateway surface this module depends on, so tests can inject a
 * fake without mocking Node's `http`/`https` modules (which `prom-client`'s
 * `Pushgateway` uses internally rather than `fetch`).
 */
export interface PushgatewayLike {
  push(params: { jobName: string; groupings?: Record<string, string> }): Promise<unknown>;
  delete(params: { jobName: string; groupings?: Record<string, string> }): Promise<unknown>;
}

export interface PushgatewayClient {
  /** Push this run's current metrics, grouped by job name and run id. */
  pushJobMetrics(jobName: string, runId: string): Promise<void>;
  /** Delete a previously-pushed grouping so it doesn't linger forever. */
  deleteJobGrouping(jobName: string, runId: string): Promise<void>;
}

const MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 500;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** No-op client used when `PUSHGATEWAY_URL` is unset (e.g. local dev, tests). */
class NoopPushgatewayClient implements PushgatewayClient {
  async pushJobMetrics(): Promise<void> {
    // Intentionally a no-op: no Pushgateway is configured.
  }

  async deleteJobGrouping(): Promise<void> {
    // Intentionally a no-op: no Pushgateway is configured.
  }
}

/**
 * Pushes and deletes job groupings against a real Pushgateway, retrying
 * transient failures (e.g. the Pushgateway being temporarily unreachable)
 * with a short linear backoff. A Pushgateway failure is logged and
 * swallowed rather than thrown — losing an observability push must never
 * fail the batch job itself.
 */
export class HttpPushgatewayClient implements PushgatewayClient {
  constructor(private readonly gateway: PushgatewayLike) {}

  async pushJobMetrics(jobName: string, runId: string): Promise<void> {
    await this.withRetries(
      () => this.gateway.push({ jobName, groupings: { run_id: runId } }),
      `push metrics for job="${jobName}" run_id="${runId}"`,
    );
  }

  async deleteJobGrouping(jobName: string, runId: string): Promise<void> {
    await this.withRetries(
      () => this.gateway.delete({ jobName, groupings: { run_id: runId } }),
      `delete grouping for job="${jobName}" run_id="${runId}"`,
    );
  }

  private async withRetries(fn: () => Promise<unknown>, label: string): Promise<void> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        await fn();
        return;
      } catch (error) {
        lastError = error;
        logger.warn(`Pushgateway ${label} failed (attempt ${attempt}/${MAX_ATTEMPTS})`, error);
        if (attempt < MAX_ATTEMPTS) {
          await sleep(RETRY_DELAY_MS * attempt);
        }
      }
    }
    logger.error(`Pushgateway ${label} failed after ${MAX_ATTEMPTS} attempts`, lastError);
  }
}

let cachedClient: PushgatewayClient | undefined;

/**
 * Returns the process-wide {@link PushgatewayClient}, built from
 * `PUSHGATEWAY_URL` on first call and cached thereafter. Returns a no-op
 * client when the variable is unset.
 */
export function getPushgatewayClient(): PushgatewayClient {
  if (!cachedClient) {
    const url = process.env.PUSHGATEWAY_URL;
    cachedClient = url
      ? new HttpPushgatewayClient(new Pushgateway(url, {}, metricsRegistry))
      : new NoopPushgatewayClient();
  }
  return cachedClient;
}

/** Test-only: clears the cached client so a new `PUSHGATEWAY_URL` takes effect. */
export function resetPushgatewayClientForTests(): void {
  cachedClient = undefined;
}
