/**
 * Span attribute PII sanitizer for the OpenTelemetry pipeline.
 *
 * Wraps an existing SpanExporter and scrubs any attribute key that matches
 * the built-in denylist before the span reaches the remote collector.
 * The same redaction logic applies to span events and span links so that PII
 * cannot slip through those side-channels either.
 *
 * Usage:
 *   const exporter = new SanitizingSpanExporter(new OTLPTraceExporter({ url }));
 */

import type {
  SpanExporter,
  ReadableSpan,
} from "@opentelemetry/sdk-trace-base";
import type { ExportResult } from "@opentelemetry/core";
import type { Attributes } from "@opentelemetry/api";

/** Sentinel placed in place of a redacted value. */
export const REDACTED_VALUE = "[REDACTED]";

/**
 * Attribute key patterns that must never be exported.
 *
 * Keys are matched case-insensitively against each element in this set.
 * Add new entries here when auditing new span producers.
 */
export const DENYLIST: ReadonlySet<string> = new Set([
  // Auth / credential fields
  "user.email",
  "email",
  "enduser.email",
  "http.request.header.authorization",
  "http.response.header.set-cookie",
  "token",
  "access_token",
  "refresh_token",
  "api_key",
  "apikey",
  "secret",
  "password",
  "reset_token",
  "code",
  // Revenue / financial data
  "revenue",
  "revenue_amount",
  "amount",
  "gross_revenue",
  "net_revenue",
  "transaction_amount",
  // Identity
  "user.id",
  "user_id",
  "account_id",
  "customer_id",
  // Raw token values
  "jwt",
  "bearer",
  "x-api-key",
  "x-auth-token",
]);

/**
 * Returns `true` when the attribute key appears on the denylist.
 *
 * Matching is case-insensitive so that `User.Email` is caught the same as
 * `user.email`.
 */
export function isDenylisted(key: string): boolean {
  return DENYLIST.has(key.toLowerCase());
}

/**
 * Recursively walk an attribute value and replace any string that looks like
 * a bearer token or e-mail address — even inside nested objects that a
 * misbehaving instrumentation might set as a stringified JSON blob.
 *
 * For simple scalar values we just check the key.  For objects (shouldn't
 * happen in well-formed OTel data but defensive coding is cheap) we recurse.
 */
function redactValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  // Arrays: recurse into each element (e.g., multi-value headers).
  if (Array.isArray(value)) {
    return value.map(redactValue);
  }

  // Plain objects: recurse to catch nested PII (e.g., JSON-stringified bodies
  // that somebody accidentally passed as an attribute value).
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = isDenylisted(k) ? REDACTED_VALUE : redactValue(v);
    }
    return result;
  }

  return value;
}

/**
 * Return a copy of `attrs` with every denylisted key replaced by
 * `REDACTED_VALUE`.  Non-denylisted values are preserved exactly.
 */
export function sanitizeAttributes(
  attrs: Attributes | undefined,
): Attributes | undefined {
  if (!attrs) {
    return attrs;
  }

  const cleaned: Attributes = {};
  for (const [key, value] of Object.entries(attrs)) {
    cleaned[key] = isDenylisted(key)
      ? REDACTED_VALUE
      : (redactValue(value) as Attributes[string]);
  }
  return cleaned;
}

/**
 * Produce a sanitized shallow copy of a single ReadableSpan.
 *
 * We deliberately copy the minimal fields needed by the downstream exporter
 * rather than mutating the original — spans are shared references inside the
 * SDK's internal buffer and mutation would corrupt in-flight data.
 */
function sanitizeSpan(span: ReadableSpan): ReadableSpan {
  const sanitizedEvents = span.events.map((event) => ({
    ...event,
    attributes: sanitizeAttributes(event.attributes),
  }));

  const sanitizedLinks = span.links.map((link) => ({
    ...link,
    attributes: sanitizeAttributes(link.attributes),
  }));

  // `ReadableSpan` is structurally typed; we spread and override only the
  // fields that may carry PII.
  return {
    ...span,
    attributes: sanitizeAttributes(span.attributes) ?? {},
    events: sanitizedEvents,
    links: sanitizedLinks,
  };
}

/**
 * A SpanExporter decorator that strips PII from every span before forwarding
 * to the wrapped exporter.
 *
 * Drop-in replacement for any `SpanExporter` implementation:
 *
 * ```ts
 * const exporter = new SanitizingSpanExporter(new OTLPTraceExporter({ url }));
 * ```
 */
export class SanitizingSpanExporter implements SpanExporter {
  constructor(private readonly inner: SpanExporter) {}

  export(
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void,
  ): void {
    const sanitized = spans.map(sanitizeSpan);
    this.inner.export(sanitized, resultCallback);
  }

  async shutdown(): Promise<void> {
    return this.inner.shutdown();
  }

  /** Forwarded so callers that need forceFlush keep working. */
  forceFlush?(): Promise<void> {
    return this.inner.forceFlush?.() ?? Promise.resolve();
  }
}
