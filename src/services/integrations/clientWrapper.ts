import {
  globalOutboundRetryBudget,
  GlobalRetryBudgetExceededError,
} from "./retryBudget.js";

export interface RetryOptions {
  provider: string;
  operation: string;
  maxRetries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean;
  shouldRetry?: (response: Response | null, error: unknown) => boolean;
}

const DEFAULT_SHOULD_RETRY = (response: Response | null, error: unknown): boolean => {
  if (error) return true;
  if (!response) return false;
  // Retry 5xx server errors and 429 Too Many Requests
  return response.status >= 500 || response.status === 429;
};

/**
 * Executes an outbound HTTP request (or any async call) with exponential backoff,
 * jitter, and global outbound retry budget enforcement.
 */
export async function executeWithRetry<T = Response>(
  fn: () => Promise<T>,
  options: RetryOptions,
): Promise<T> {
  const {
    provider,
    operation,
    maxRetries = 3,
    baseDelayMs = 100,
    maxDelayMs = 1000,
    jitter = true,
    shouldRetry = DEFAULT_SHOULD_RETRY as unknown as (
      response: T | null,
      error: unknown,
    ) => boolean,
  } = options;

  let attempt = 0;

  while (true) {
    let result: T | null = null;
    let err: unknown = null;

    try {
      result = await fn();
    } catch (e) {
      err = e;
    }

    const isFailure = err !== null || (result !== null && shouldRetry(result, err));

    if (!isFailure) {
      if (err !== null) throw err;
      return result as T;
    }

    if (attempt >= maxRetries) {
      if (err !== null) throw err;
      return result as T;
    }

    // Check global retry budget before attempting retry
    const allowed = await globalOutboundRetryBudget.canRetry(provider, operation);
    if (!allowed) {
      // Record exhaustion and throw budget exceeded error
      await globalOutboundRetryBudget.recordRetry(provider, operation).catch(() => {});
      throw new GlobalRetryBudgetExceededError(
        await globalOutboundRetryBudget.getRetryCount(),
        50,
      );
    }

    // Consume 1 retry unit from the global budget
    await globalOutboundRetryBudget.recordRetry(provider, operation);
    attempt++;

    // Calculate delay with exponential backoff and jitter
    let delay = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
    if (jitter) {
      delay = delay * (0.5 + Math.random() * 0.5);
    }

    await new Promise((resolve) => setTimeout(resolve, delay));
  }
}
