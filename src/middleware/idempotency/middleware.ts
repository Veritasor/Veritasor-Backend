import type { Request, Response, NextFunction } from 'express';
import { logger } from '../../utils/logger.js';
import { ExternalServiceError } from '../../types/errors.js';
import {
  DEFAULT_TTL_MS,
  IDEMPOTENCY_KEY_HEADER,
  MAX_KEY_LENGTH,
  MIN_KEY_LENGTH,
  type IdempotencyEntry,
  type IdempotencyOptions,
} from './types.js';
import { inMemoryIdempotencyStore } from './memoryStore.js';
import {
  generateRequestHash,
  generateStoreKey,
  getStrictKeyFormatMessage,
  isValidKeyFormat,
} from './keys.js';

/**
 * Creates idempotency middleware for protecting API endpoints
 *
 * @example
 * ```typescript
 * // Basic usage
 * app.post('/api/attestations',
 *   requireAuth,
 *   idempotencyMiddleware({ scope: 'attestations' }),
 *   handleAttestation
 * );
 *
 * // With custom options
 * app.post('/api/payments',
 *   idempotencyMiddleware({
 *     scope: 'payments',
 *     ttlMs: 3600000, // 1 hour
 *     strictKeyFormat: true,
 *     getUserKey: (req) => req.user?.id ?? req.ip ?? 'anonymous',
 *   }),
 *   handlePayment
 * );
 * ```
 *
 * @param options - Middleware configuration options
 * @returns Express middleware function
 */
export function idempotencyMiddleware(options: IdempotencyOptions) {
  const store = options.store ?? inMemoryIdempotencyStore;
  const scope = options.scope;
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const getUserKey = options.getUserKey ?? ((req: Request) => {
    // Try to get user ID from authenticated request
    if (req.user && typeof req.user === 'object' && 'id' in req.user) {
      return (req.user as { id: string }).id;
    }
    return req.ip ?? 'anonymous';
  });
  const strictKeyFormat = options.strictKeyFormat ?? false;
  const validateKey = options.validateKey ?? ((key: string) => isValidKeyFormat(key, strictKeyFormat));
  const skipIf = options.skipIf ?? (() => false);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Check if we should skip idempotency processing
    if (skipIf(req)) {
      next();
      return;
    }

    // Extract and validate idempotency key
    const rawKey = req.headers[IDEMPOTENCY_KEY_HEADER];
    const keyValue = typeof rawKey === 'string'
      ? rawKey.trim()
      : Array.isArray(rawKey)
        ? rawKey[0]?.trim()
        : undefined;

    try {
      // Validate key presence
      if (!keyValue) {
        res.status(400).json({
          error: 'Bad Request',
          message: `Missing ${IDEMPOTENCY_KEY_HEADER} header`,
          code: 'IDEMPOTENCY_KEY_REQUIRED',
        });
        return;
      }

      // Validate key format
      if (!validateKey(keyValue)) {
        res.status(400).json({
          error: 'Bad Request',
          message: `Invalid ${IDEMPOTENCY_KEY_HEADER} format. Key must be between ${MIN_KEY_LENGTH} and ${MAX_KEY_LENGTH} characters${getStrictKeyFormatMessage(strictKeyFormat)}`,
          code: 'IDEMPOTENCY_KEY_INVALID',
        });
        return;
      }

      // Generate unique key for this user + scope + key combination
      const userKey = getUserKey(req);
      const storeKey = generateStoreKey(scope, userKey, keyValue);
      const currentRequestHash = generateRequestHash(req.body);

      // Check for cached response
      const cached = await store.get(storeKey);
      if (cached) {
        // Verify body integrity to prevent key collisions with different payloads
        if (cached.requestHash !== currentRequestHash) {
          logger.warn(`[idempotency] Key collision detected for key: ${keyValue}. Payloads do not match.`);
          res.status(422).json({
            error: 'Unprocessable Entity',
            message: 'Idempotency key already used with a different request body',
            code: 'IDEMPOTENCY_KEY_COLLISION',
          });
          return;
        }

        logger.info(`[idempotency] Returning cached response for key: ${keyValue}`);
        // Return cached response
        res.status(cached.status).json(cached.body);
        return;
      }

      // If store supports atomic reservation, reserve the key for this in-flight request
      if (typeof store.reserve === 'function') {
        const acquired = await store.reserve(storeKey, ttlMs);
        if (!acquired) {
          // Another concurrent request holds the reservation or completed the request
          logger.warn(`[idempotency] Concurrent duplicate request detected for key: ${keyValue}`);
          res.setHeader('Retry-After', '1');
          res.status(409).json({
            error: 'Conflict',
            message: 'A request with this idempotency key is currently in progress',
            code: 'IDEMPOTENCY_IN_PROGRESS',
          });
          return;
        }
      }

      // Store original methods
      const originalJson = res.json.bind(res);
      const originalStatus = res.status.bind(res);
      let statusCode = 200;
      let finalized = false;

      // Safe release helper
      const releaseReservation = () => {
        if (finalized) return;
        finalized = true;
        if (typeof store.delete === 'function') {
          store.delete(storeKey).catch((err) => {
            logger.error('[idempotency] Failed to release reservation:', err);
          });
        }
      };

      // If the request closes or finishes prematurely without a successful 2xx response
      res.once('close', () => {
        if (!finalized && (res.statusCode < 200 || res.statusCode >= 300)) {
          releaseReservation();
        }
      });

      // Override status to track the actual status code
      res.status = function (code: number): Response {
        statusCode = code;
        return originalStatus(code);
      };

      // Override json to cache or release the response
      res.json = function (body: unknown): Response {
        // Only cache successful responses (2xx)
        if (statusCode >= 200 && statusCode < 300) {
          finalized = true;
          const entry: IdempotencyEntry = {
            status: statusCode,
            body,
            requestHash: currentRequestHash,
            createdAt: Date.now(),
          };
          store.set(storeKey, entry, ttlMs).catch((err) => {
            logger.error('[idempotency] Failed to cache response:', err);
          });
        } else {
          // Non-2xx response: release reservation so client can retry
          releaseReservation();
        }
        return originalJson(body);
      };

      // Continue to route handler
      next();
    } catch (err) {
      logger.error('[idempotency] Middleware store error, failing closed:', err);
      // Fail closed with 503 ExternalServiceError
      if (err instanceof ExternalServiceError) {
        next(err);
      } else {
        next(new ExternalServiceError('Idempotency store error', 503, {
          cause: err instanceof Error ? err.message : String(err),
        }));
      }
    }
  };
}
