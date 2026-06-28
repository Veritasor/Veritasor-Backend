import {
  context,
  createContextKey,
  isSpanContextValid,
  trace,
} from "@opentelemetry/api";

/**
 * Structured logger utility with request-scoped context.
 *
 * Security considerations:
 * - Sensitive fields are redacted recursively before output.
 * - Control characters are stripped from string values to prevent log injection.
 * - Error objects are reduced to non-secret operational fields.
 *
 * @module logger
 */

export type LogContext = Record<string, unknown>;
type LogLevel = "info" | "warn" | "error";

const REDACTED = "[REDACTED]";
const LOGGER_CONTEXT_KEY = createContextKey("veritasor.logger.context");
const loggerContextStack: LogContext[] = [];

export const SENSITIVE_LOG_FIELDS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "password",
  "passwordhash",
  "token",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
  "resettoken",
  "reset_token",
  "resetlink",
  "secret",
  "apikey",
  "api_key",
  "x-api-key",
  "x-auth-token",
  "email",
]);

export function runWithLoggerContext<T>(
  logContext: LogContext,
  callback: () => T,
): T {
  const parentContext = context.active();
  const currentLogContext = getLoggerContext(parentContext);
  const mergedLogContext = {
    ...currentLogContext,
    ...(sanitizeLogValue(logContext) as LogContext),
  };

  loggerContextStack.push(mergedLogContext);

  try {
    return context.with(
      parentContext.setValue(LOGGER_CONTEXT_KEY, mergedLogContext),
      callback,
    );
  } finally {
    loggerContextStack.pop();
  }
}

export function getLoggerContext(activeContext = context.active()): LogContext {
  return (
    (activeContext.getValue(LOGGER_CONTEXT_KEY) as LogContext | undefined) ??
    loggerContextStack[loggerContextStack.length - 1] ??
    {}
  );
}

export const logger = {
  info: (...args: unknown[]) => writeLog("info", args),
  warn: (...args: unknown[]) => writeLog("warn", args),
  error: (...args: unknown[]) => writeLog("error", args),
};

function writeLog(level: LogLevel, args: unknown[]): void {
  const entry = buildLogEntry(level, args);
  const output = JSON.stringify(entry);

  if (level === "error") {
    console.error(output);
    return;
  }

  if (level === "warn") {
    console.warn(output);
    return;
  }

  console.log(output);
}

export function buildLogEntry(level: LogLevel, args: unknown[]): LogContext {
  const { message, context: entryContext } = normalizeLogArgs(args);
  const scopedContext = sanitizeLogValue(getLoggerContext()) as LogContext;
  const traceContext = getActiveTraceCorrelation();
  const structuredContext = sanitizeLogValue(entryContext) as LogContext;

  const entry = {
    ...scopedContext,
    ...traceContext,
    ...structuredContext,
    ...(message ? { message: sanitizeString(message) } : {}),
    timestamp: new Date().toISOString(),
    level,
  };

  assertTraceCorrelation(entry, traceContext);

  return entry;
}

function normalizeLogArgs(args: unknown[]): {
  message?: string;
  context: LogContext;
} {
  const context: LogContext = {};
  const messages: string[] = [];

  for (const arg of args) {
    if (arg === undefined) {
      continue;
    }

    if (typeof arg === "string") {
      const parsed = tryParseJsonObject(arg);
      if (parsed) {
        Object.assign(context, parsed);
      } else {
        messages.push(arg);
      }
      continue;
    }

    if (isPlainRecord(arg)) {
      Object.assign(context, arg);
      continue;
    }

    if (arg instanceof Error) {
      context.err = {
        name: arg.name,
        message: arg.message,
        stack: arg.stack,
      };
      continue;
    }

    messages.push(String(arg));
  }

  return {
    message: messages.length > 0 ? messages.join(" ") : undefined,
    context,
  };
}

function tryParseJsonObject(value: string): LogContext | undefined {
  try {
    const parsed = JSON.parse(value);
    return isPlainRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function getActiveTraceCorrelation(): LogContext {
  const activeSpan = trace.getActiveSpan();
  const spanContext = activeSpan?.spanContext();

  if (!spanContext || !isSpanContextValid(spanContext)) {
    return {};
  }

  return {
    trace_id: spanContext.traceId,
    span_id: spanContext.spanId,
  };
}

function assertTraceCorrelation(
  entry: LogContext,
  traceContext: LogContext,
): void {
  if (process.env.NODE_ENV !== "test") {
    return;
  }

  if (!traceContext.trace_id || !traceContext.span_id) {
    return;
  }

  if (
    entry.trace_id !== traceContext.trace_id ||
    entry.span_id !== traceContext.span_id
  ) {
    throw new Error(
      "Log entry is missing active OpenTelemetry trace correlation fields while a span is active.",
    );
  }
}

function sanitizeLogValue(value: unknown, key?: string): unknown {
  if (key && SENSITIVE_LOG_FIELDS.has(normalizeFieldName(key))) {
    return REDACTED;
  }

  if (typeof value === "string") {
    return sanitizeString(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeLogValue(item));
  }

  if (value instanceof Error) {
    return {
      name: sanitizeString(value.name),
      message: sanitizeString(value.message),
      stack: value.stack ? sanitizeString(value.stack) : undefined,
    };
  }

  if (isPlainRecord(value)) {
    const sanitized: LogContext = {};
    for (const [entryKey, entryValue] of Object.entries(value)) {
      sanitized[entryKey] = sanitizeLogValue(entryValue, entryKey);
    }
    return sanitized;
  }

  return value;
}

function sanitizeString(value: string): string {
  return value.replace(/[\r\n\t\u0000-\u001f\u007f]+/g, " ");
}

function normalizeFieldName(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9_-]/g, "");
}

function isPlainRecord(value: unknown): value is LogContext {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Date) &&
    !(value instanceof Error)
  );
}
