import { AsyncLocalStorage } from "node:async_hooks";

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
const loggerContext = new AsyncLocalStorage<LogContext>();

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

export function runWithLoggerContext<T>(context: LogContext, callback: () => T): T {
  return loggerContext.run(sanitizeLogValue(context) as LogContext, callback);
}

export function getLoggerContext(): LogContext {
  return loggerContext.getStore() ?? {};
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
  const { message, context } = normalizeLogArgs(args);
  const scopedContext = sanitizeLogValue(getLoggerContext()) as LogContext;
  const structuredContext = sanitizeLogValue(context) as LogContext;

  return {
    ...scopedContext,
    ...structuredContext,
    ...(message ? { message: sanitizeString(message) } : {}),
    timestamp: new Date().toISOString(),
    level,
  };
}

function normalizeLogArgs(args: unknown[]): { message?: string; context: LogContext } {
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
