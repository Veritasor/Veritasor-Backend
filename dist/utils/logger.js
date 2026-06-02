import { AsyncLocalStorage } from "node:async_hooks";
const REDACTED = "[REDACTED]";
const loggerContext = new AsyncLocalStorage();
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
export function runWithLoggerContext(context, callback) {
    return loggerContext.run(sanitizeLogValue(context), callback);
}
export function getLoggerContext() {
    return loggerContext.getStore() ?? {};
}
export const logger = {
    info: (...args) => writeLog("info", args),
    warn: (...args) => writeLog("warn", args),
    error: (...args) => writeLog("error", args),
};
function writeLog(level, args) {
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
export function buildLogEntry(level, args) {
    const { message, context } = normalizeLogArgs(args);
    const scopedContext = sanitizeLogValue(getLoggerContext());
    const structuredContext = sanitizeLogValue(context);
    return {
        ...scopedContext,
        ...structuredContext,
        ...(message ? { message: sanitizeString(message) } : {}),
        timestamp: new Date().toISOString(),
        level,
    };
}
function normalizeLogArgs(args) {
    const context = {};
    const messages = [];
    for (const arg of args) {
        if (arg === undefined) {
            continue;
        }
        if (typeof arg === "string") {
            const parsed = tryParseJsonObject(arg);
            if (parsed) {
                Object.assign(context, parsed);
            }
            else {
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
function tryParseJsonObject(value) {
    try {
        const parsed = JSON.parse(value);
        return isPlainRecord(parsed) ? parsed : undefined;
    }
    catch {
        return undefined;
    }
}
function sanitizeLogValue(value, key) {
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
        const sanitized = {};
        for (const [entryKey, entryValue] of Object.entries(value)) {
            sanitized[entryKey] = sanitizeLogValue(entryValue, entryKey);
        }
        return sanitized;
    }
    return value;
}
function sanitizeString(value) {
    return value.replace(/[\r\n\t\u0000-\u001f\u007f]+/g, " ");
}
function normalizeFieldName(key) {
    return key.toLowerCase().replace(/[^a-z0-9_-]/g, "");
}
function isPlainRecord(value) {
    return (typeof value === "object" &&
        value !== null &&
        !Array.isArray(value) &&
        !(value instanceof Date) &&
        !(value instanceof Error));
}
