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

export class SorobanRetryBudget {
  private readonly windowMs = 60_000;
  private readonly attempts: number[] = [];
  private readonly maxRetries: number;

  constructor(maxRetries: number) {
    if (maxRetries < 0) {
      throw new Error("Soroban retry budget maxRetries must be non-negative");
    }

    this.maxRetries = maxRetries;
  }

  canRetry(): boolean {
    this.pruneExpiredAttempts();
    const allowed = this.attempts.length < this.maxRetries;
    if (!allowed) {
      sorobanRetryBudgetExhaustedTotal.inc();
    }
    return allowed;
  }

  recordRetry(operation: string): void {
    this.pruneExpiredAttempts();
    sorobanRetryTotal.inc({ operation });
    this.attempts.push(Date.now());
  }

  getRetryCount(): number {
    this.pruneExpiredAttempts();
    return this.attempts.length;
  }

  reset(): void {
    this.attempts.length = 0;
  }

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
