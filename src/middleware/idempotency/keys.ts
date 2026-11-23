import { createHash } from 'node:crypto';
import {
  DEFAULT_TTL_MS,
  IDEMPOTENCY_KEY_HEADER,
  MAX_KEY_LENGTH,
  MIN_KEY_LENGTH,
  UUID_PATTERN,
} from './types.js';

/**
 * Validate idempotency key format
 * @param key - The key to validate
 * @param strict - Whether to require UUID format
 * @returns True if valid
 */
export function isValidKeyFormat(key: string, strict: boolean): boolean {
  // Check length constraints
  if (key.length < MIN_KEY_LENGTH || key.length > MAX_KEY_LENGTH) {
    return false;
  }

  // In strict mode, require UUID format
  if (strict && !UUID_PATTERN.test(key)) {
    return false;
  }

  return true;
}

/**
 * Generate store key from components
 * @param scope - Operation scope
 * @param userKey - User identifier
 * @param keyValue - Client-provided idempotency key
 * @returns Full store key
 */
export function generateStoreKey(scope: string, userKey: string, keyValue: string): string {
  // If userKey looks like a stable tenant/business identifier (alphanumeric, hyphen, underscore),
  // wrap it in a Redis cluster hash tag so keys for the same tenant land on the same slot.
  const TENANT_RE = /^[a-zA-Z0-9\-_]{1,100}$/;
  const tenantTag = TENANT_RE.test(userKey) ? `{${userKey}}` : userKey;
  return `idempotency:${scope}:${tenantTag}:${keyValue}`;
}

/**
 * Generate a hash of the request body for integrity checking
 * @param body - Request body
 * @returns SHA-256 hash
 */
export function generateRequestHash(body: unknown): string {
  const content = body ? JSON.stringify(body) : '';
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Helper to generate the strict format message
 */
export function getStrictKeyFormatMessage(strict: boolean): string {
  return strict ? ' and must be a valid UUID' : '';
}

/**
 * Get the default TTL value
 * @returns Default TTL in milliseconds
 */
export function getDefaultTtl(): number {
  return DEFAULT_TTL_MS;
}

/**
 * Get the header name for idempotency key
 * @returns Header name
 */
export function getIdempotencyHeaderName(): string {
  return IDEMPOTENCY_KEY_HEADER;
}
