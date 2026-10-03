import { z } from "zod";

// ---------------------------------------------------------------------------
// Event Filter DSL
// ---------------------------------------------------------------------------
//
// The filter DSL is a JSON object where each key is an event type pattern
// (e.g. "attestation.created", "business.*") and the value is either:
//
//   - `true`  → deliver all events of this type
//   - `false` → suppress all events of this type
//   - `{ … }` → deliver only when the event payload matches all key/value pairs
//
// Examples:
//   { "attestation.created": true, "business.updated": false }
//   { "attestation.*": { "status": "completed" } }
//
// Wildcards (*) match any single segment. Double-wildcards (**) match any
// number of segments including zero.

/** Maximum number of filter rules per subscription. */
export const MAX_FILTER_RULES = 50;

/** Maximum length of an event-type key in characters. */
const MAX_EVENT_TYPE_LENGTH = 200;

/** Maximum length of a single filter value in characters. */
const MAX_FILTER_VALUE_LENGTH = 500;

/** Maximum depth of a filter object's nested paths (prevents deeply-nested DoS). */
const MAX_FILTER_DEPTH = 5;

/**
 * Validates that an event-type string is safe:
 * - Contains only alphanumeric, dots, hyphens, underscores, and wildcards.
 * - Is within the allowed length.
 * - Does not start or end with a dot.
 */
function isValidEventType(value: string): boolean {
  if (value.length === 0 || value.length > MAX_EVENT_TYPE_LENGTH) return false;
  if (value.startsWith(".") || value.endsWith(".")) return false;
  // Allow: letters, numbers, ., -, _, *, **
  return /^[a-zA-Z0-9._*-]+$/.test(value);
}

/**
 * Recursively check the depth of a value to prevent deeply-nested filter
 * objects from causing stack overflows during evaluation.
 */
function getDepth(val: unknown): number {
  if (val === null || val === undefined) return 0;
  if (typeof val !== "object" || Array.isArray(val)) return 0;
  const obj = val as Record<string, unknown>;
  let maxDepth = 0;
  for (const v of Object.values(obj)) {
    maxDepth = Math.max(maxDepth, getDepth(v));
  }
  return maxDepth + 1;
}

/**
 * Schema for a single filter value.
 *
 * A filter value can be:
 * - `true` / `false`: enable or suppress events of that type entirely
 * - An object with string key/value pairs for field-level matching
 */
const filterValueSchema: z.ZodType<boolean | Record<string, string>> = z.lazy(() =>
  z.union([
    z.boolean(),
    z.record(
      z.string().min(1).max(100),
      z.string().min(0).max(MAX_FILTER_VALUE_LENGTH),
    ).refine(
      (obj) => getDepth(obj) <= MAX_FILTER_DEPTH,
      `Filter depth must not exceed ${MAX_FILTER_DEPTH} levels`,
    ),
  ]),
);

/**
 * Schema for the complete event-filters map.
 *
 * Each key must be a valid event-type string; each value is a filterValue.
 */
export const eventFiltersSchema = z
  .record(
    z.string().refine(isValidEventType, {
      message:
        "Event type must contain only alphanumeric, dots, hyphens, underscores, and wildcards",
    }),
    filterValueSchema,
  )
  .refine(
    (filters) => Object.keys(filters).length <= MAX_FILTER_RULES,
    `Maximum ${MAX_FILTER_RULES} filter rules allowed per subscription`,
  )
  .default({});

export type EventFilters = z.infer<typeof eventFiltersSchema>;

// ---------------------------------------------------------------------------
// Subscription CRUD schemas
// ---------------------------------------------------------------------------

const URL_MAX_LENGTH = 2048;

/** Blocked URL schemes for security. */
const BLOCKED_SCHEMES = new Set(["javascript", "data", "vbscript", "file", "ftp"]);

function hasBlockedScheme(url: string): boolean {
  const lower = url.toLowerCase();
  if (lower.startsWith("//")) return true;
  return [...BLOCKED_SCHEMES].some(
    (s) => lower.startsWith(`${s}:`) || lower.startsWith(`${s}%3a`),
  );
}

function isValidUrl(value: string): boolean {
  if (value.length > URL_MAX_LENGTH) return false;
  if (hasBlockedScheme(value)) return false;
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

const urlField = z
  .string()
  .min(1, "URL is required")
  .max(URL_MAX_LENGTH, `URL must not exceed ${URL_MAX_LENGTH} characters`)
  .refine(isValidUrl, "URL must be a valid HTTPS endpoint");

const secretField = z
  .string()
  .min(32, "Secret must be at least 32 characters for cryptographic security")
  .max(512, "Secret must not exceed 512 characters");

const maxPayloadSizeField = z
  .number()
  .int("maxPayloadSize must be an integer")
  .min(1024, "maxPayloadSize must be at least 1024 bytes")
  .max(10 * 1024 * 1024, "maxPayloadSize must not exceed 10 MB")
  .optional();

const enabledField = z.boolean().optional().default(true);

/**
 * Schema for creating a new webhook subscription.
 */
export const createWebhookSubscriptionSchema = z.object({
  url: urlField,
  secret: secretField,
  eventFilters: eventFiltersSchema.optional(),
  maxPayloadSize: maxPayloadSizeField,
  enabled: enabledField,
}).strict();

export type CreateWebhookSubscriptionInput = z.infer<
  typeof createWebhookSubscriptionSchema
>;

/**
 * Schema for updating an existing webhook subscription.
 *
 * All fields are optional for partial updates.
 */
export const updateWebhookSubscriptionSchema = z.object({
  url: urlField.optional(),
  secret: secretField.optional(),
  eventFilters: eventFiltersSchema.optional(),
  enabled: z.boolean().optional(),
  maxPayloadSize: maxPayloadSizeField,
}).strict();

export type UpdateWebhookSubscriptionInput = z.infer<
  typeof updateWebhookSubscriptionSchema
>;

/**
 * Schema for querying webhook subscriptions (list endpoint).
 */
export const listWebhookSubscriptionsQuerySchema = z.object({
  businessId: z.string().min(1).max(255).optional(),
  enabled: z
    .preprocess(
      (val) => {
        if (val === "true" || val === "1") return true;
        if (val === "false" || val === "0") return false;
        return val;
      },
      z.boolean().optional(),
    )
    .optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
}).strict();

export type ListWebhookSubscriptionsQuery = z.infer<
  typeof listWebhookSubscriptionsQuerySchema
>;

// ---------------------------------------------------------------------------
// Filter evaluation (applied at dispatch time)
// ---------------------------------------------------------------------------

/**
 * Check whether an event should be delivered based on a subscription's
 * event-filters map.
 *
 * Resolution order (first match wins):
 * 1. Exact match on event type (e.g. "attestation.created")
 * 2. Segment-level wildcard (e.g. "attestation.*")
 * 3. Recursive wildcard (e.g. "**" matches everything)
 *
 * When a filter object is matched, every key in the filter must exist as a
 * field in the event payload with the same value. Nested payload fields are
 * traversed with dot-separated keys (e.g. "data.status").
 *
 * @param eventType  - The event type string (e.g. "attestation.created").
 * @param eventPayload - The event payload to match against filter objects.
 * @param filters    - The subscription's eventFilters map.
 * @returns `true` when the event should be delivered, `false` otherwise.
 */
export function evaluateEventFilter(
  eventType: string,
  eventPayload: Record<string, unknown>,
  filters: EventFilters,
): boolean {
  if (!filters || Object.keys(filters).length === 0) {
    // No filters configured — deliver everything
    return true;
  }

  // 1. Exact match
  const exact = filters[eventType];
  if (typeof exact === "boolean") return exact;
  if (typeof exact === "object" && exact !== null) {
    return matchesFilterObject(exact, eventPayload);
  }

  // 2. Segment-level wildcard (e.g. "attestation.*")
  const segments = eventType.split(".");
  for (let i = 0; i < segments.length; i++) {
    const wildcardPattern = [...segments.slice(0, i), "*"].join(".");
    const match = filters[wildcardPattern];
    if (typeof match === "boolean") return match;
    if (typeof match === "object" && match !== null) {
      return matchesFilterObject(match, eventPayload);
    }
  }

  // 3. Recursive wildcard
  const recursive = filters["**"];
  if (typeof recursive === "boolean") return recursive;
  if (typeof recursive === "object" && recursive !== null) {
    return matchesFilterObject(recursive, eventPayload);
  }

  // No matching rule — default to delivering
  return true;
}

/**
 * Check that every key/value in the filter object exists in the event payload.
 *
 * Keys may contain dots for nested access (e.g. "data.status" resolves to
 * `eventPayload.data.status`).
 */
function matchesFilterObject(
  filter: Record<string, string>,
  payload: Record<string, unknown>,
): boolean {
  for (const [key, expectedValue] of Object.entries(filter)) {
    const actualValue = resolveNestedValue(payload, key);
    if (actualValue === undefined) return false;
    if (String(actualValue) !== expectedValue) return false;
  }
  return true;
}

function resolveNestedValue(
  obj: Record<string, unknown>,
  path: string,
): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
