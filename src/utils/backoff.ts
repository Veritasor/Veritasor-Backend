export type BackoffOptions = {
  baseDelayMs: number
  maxDelayMs: number
  maxAttempts: number
}

export const DEFAULT_BACKOFF_OPTIONS: BackoffOptions = {
  baseDelayMs: 200,
  maxDelayMs: 10_000,
  maxAttempts: 3,
}

export type SleepFn = (ms: number) => Promise<void>

export class BackoffError extends Error {
  public readonly attemptCount: number
  public readonly cause: unknown

  constructor(message: string, attemptCount: number, cause: unknown) {
    super(message)
    this.name = 'BackoffError'
    this.attemptCount = attemptCount
    this.cause = cause
  }
}

export function calculateBackoffDelay(
  attemptNumber: number,
  options: BackoffOptions,
  random: () => number = Math.random,
): number {
  const temp = Math.min(options.maxDelayMs, options.baseDelayMs * 2 ** attemptNumber)
  const delay = Math.round(random() * temp)
  return Math.max(1, delay)
}

export async function withBackoff<T>(
  fn: (attempt: number) => Promise<T>,
  options: BackoffOptions = DEFAULT_BACKOFF_OPTIONS,
  onRetry?: (attempt: number, delayMs: number, error: unknown) => void,
  sleep?: SleepFn,
  random?: () => number,
): Promise<T> {
  const sleepFn: SleepFn = sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)))
  const randomFn = random ?? Math.random
  let lastError: unknown

  if (options.maxAttempts <= 0) {
    throw new BackoffError('maxAttempts must be at least 1', 0, undefined)
  }

  for (let attempt = 1; attempt <= options.maxAttempts; attempt++) {
    try {
      return await fn(attempt)
    } catch (error) {
      lastError = error
      if (attempt < options.maxAttempts) {
        const delayMs = calculateBackoffDelay(attempt, options, randomFn)
        onRetry?.(attempt, delayMs, error)
        await sleepFn(delayMs)
      }
    }
  }

  if (options.maxAttempts <= 1) {
    throw lastError
  }

  throw new BackoffError(
    `Operation failed after ${options.maxAttempts} attempts`,
    options.maxAttempts,
    lastError,
  )
}
