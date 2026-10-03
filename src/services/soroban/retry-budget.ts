import { config } from "../../config/index.js";
import {
  sorobanRetryBudgetExhaustedTotal,
  sorobanRetryTotal,
} from "../../metrics.js";

export class SorobanRetryBudgetExceededError extends Error {
  public readonly code = "SOROBAN_RETRY_BUDGET_EXCEEDED";
  public readonly currentRetryCount: number;
  public readonly budgetLimit: number;

  constructor(currentRetryCount: number, budgetLimit: number) {
    super(
      `Soroban retry budget exhausted: ${currentRetryCount}/${budgetLimit} retries in the last 60 seconds.`,
    );
    this.name = "SorobanRetryBudgetExceededError";
    this.currentRetryCount = currentRetryCount;
    this.budgetLimit = budgetLimit;
  }
}

/**
 * Backoff configuration for exponential retry delays.
 *
 * Environment variables:
 * - SOROBAN_BACKOFF_BASE_MS: base delay in milliseconds (default: 200)
 * - SOROBAN_BACKOFF_MAX_MS: maximum delay cap in milliseconds (default: 30000)
 */
export interface BackoffConfig {
  /** Base delay in milliseconds */
  baseMs: number;
  /** Maximum delay cap in milliseconds */
  maxMs: number;
}

/**
 * Reads backoff configuration from environment variables.
 * Falls back to sensible defaults if not set.
 */
export function getBackoffConfig(): BackoffConfig {
  const baseMs = parseInt(process.env.SOROBAN_BACKOFF_BASE_MS ?? "200", 10);
  const maxMs = parseInt(process.env.SOROBAN_BACKOFF_MAX_MS ?? "30000", 10);

  if (!Number.isFinite(baseMs) || baseMs <= 0) {
    throw new Error("SOROBAN_BACKOFF_BASE_MS must be a positive number");
  }
  if (!Number.isFinite(maxMs) || maxMs <= 0) {
    throw new Error("SOROBAN_BACKOFF_MAX_MS must be a positive number");
  }
  if (baseMs > maxMs) {
    throw new Error("SOROBAN_BACKOFF_BASE_MS must not exceed SOROBAN_BACKOFF_MAX_MS");
  }

  return { baseMs, maxMs };
}

/**
 * Calculates exponential backoff delay with full jitter.
 *
 * Formula: Math.random() * min(cap, base * 2^attempt)
 *
 * Full jitter prevents thundering herd — concurrent retrying clients do NOT fire
 * simultaneously after a shared failure. Each client independently picks a random
 * delay in [0, cap].
 *
 * Implements the "Full Jitter" algorithm from the AWS Exponential Backoff
 * blog post: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
 *
 * @param attempt - Zero-based attempt number (0 = first retry)
 * @param baseMs - Base delay in milliseconds
 * @param capMs - Maximum delay cap in milliseconds
 * @param random - RNG function (default: Math.random, injectable for tests)
 * @returns Delay in milliseconds before next retry
 *
 * @example
 * fullJitter(0, 200, 30000) // 0–200ms
 * fullJitter(1, 200, 30000) // 0–400ms
 * fullJitter(2, 200, 30000) // 0–800ms
 * fullJitter(7, 200, 30000) // 0–30000ms (capped)
 */
export function fullJitter(
  attempt: number,
  baseMs: number,
  capMs: number,
  random: () => number = Math.random,
): number {
  if (!Number.isFinite(attempt) || attempt < 0) {
    throw new RangeError("attempt must be a non-negative integer");
  }
  if (!Number.isFinite(baseMs) || baseMs <= 0) {
    throw new RangeError("baseMs must be a positive number");
  }
  if (!Number.isFinite(capMs) || capMs <= 0) {
    throw new RangeError("capMs must be a positive number");
  }

  // Exponential growth: base * 2^attempt, capped at capMs
  const exponential = baseMs * Math.pow(2, attempt);
  const capped = Math.min(exponential, capMs);

  // Full jitter: uniform random in [0, capped)
  return Math.floor(random() * capped);
}

/**
 * Retry budget tracker for Soroban operations.
 *
 * Enforces a per-window retry quota using a sliding 60-second window.
 * This prevents retry storms by limiting the total number of retry attempts
 * across all concurrent operations within the window.
 *
 * Combined with exponential backoff (via fullJitter), this provides resilience
 * without overwhelming the backend during recovery from shared failures.
 */
export class SorobanRetryBudget {
  private readonly windowMs = 60_000; // 60-second sliding window
  private readonly attempts: number[] = [];
  private readonly maxRetries: number;

  /**
   * Creates a retry budget with a specified max retry count per 60-second window.
   *
   * @param maxRetries - Maximum number of retries allowed within 60 seconds
   * @throws Error if maxRetries is negative
   */
  constructor(maxRetries: number) {
    if (maxRetries < 0) {
      throw new Error("Soroban retry budget maxRetries must be non-negative");
    }

    this.maxRetries = maxRetries;
  }

  /**
   * Checks if another retry attempt is allowed within the current budget.
   *
   * @returns true if a retry can be performed; false if budget is exhausted
   */
  canRetry(): boolean {
    this.pruneExpiredAttempts();
    const allowed = this.attempts.length < this.maxRetries;
    if (!allowed) {
      sorobanRetryBudgetExhaustedTotal.inc();
    }
    return allowed;
  }

  /**
   * Records a retry attempt and increments retry metrics.
   *
   * @param operation - Name of the Soroban operation being retried
   */
  recordRetry(operation: string): void {
    this.pruneExpiredAttempts();
    sorobanRetryTotal.inc({ operation });
    this.attempts.push(Date.now());
  }

  /**
   * Returns the current count of non-expired retry attempts.
   *
   * @returns Number of retries within the 60-second window
   */
  getRetryCount(): number {
    this.pruneExpiredAttempts();
    return this.attempts.length;
  }

  /**
   * Resets the retry budget for testing purposes.
   * Clears all recorded attempts.
   */
  reset(): void {
    this.attempts.length = 0;
  }

  /**
   * Removes retry attempts older than the 60-second window.
   */
  private pruneExpiredAttempts(): void {
    const cutoff = Date.now() - this.windowMs;
    while (this.attempts.length > 0 && this.attempts[0] < cutoff) {
      this.attempts.shift();
    }
  }
}

export const sorobanRetryBudget = new SorobanRetryBudget(
  config.soroban.retryBudgetMaxRetries,
);
