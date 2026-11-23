/**
 * Calculate a delay time for rate limiting based on failed attempts.
 * Uses exponential backoff to deter brute force attacks.
 *
 * @param failedAttempts - Number of failed attempts
 * @param baseDelayMs - Base delay in milliseconds
 * @param maxDelayMs - Maximum delay in milliseconds
 * @returns Delay time in milliseconds
 */
export function calculateBackoffDelay(
  failedAttempts: number,
  baseDelayMs: number = 1000,
  maxDelayMs: number = 30000,
): number {
  if (failedAttempts <= 0) return 0;

  // Exponential backoff with jitter
  const delay = Math.min(
    baseDelayMs * Math.pow(2, failedAttempts - 1),
    maxDelayMs,
  );

  // Add 10% jitter to prevent thundering herd
  const jitter = delay * 0.1 * Math.random();

  return Math.floor(delay + jitter);
}

/**
 * Create a timing-safe comparison for sensitive strings.
 * Helps prevent timing attacks when comparing tokens or hashed values.
 *
 * @param a - First string to compare
 * @param b - Second string to compare
 * @returns True if strings are equal
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Add a constant-time delay to prevent timing attacks.
 * Useful for operations that should take a consistent amount of time
 * regardless of whether they succeed or fail.
 *
 * @param targetTimeMs - Target time in milliseconds for the operation
 * @param startTime - Start time (from performance.now() or Date.now())
 */
export async function addTimingDelay(
  targetTimeMs: number,
  startTime: number,
): Promise<void> {
  const elapsed = Date.now() - startTime;
  const remaining = targetTimeMs - elapsed;

  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}
