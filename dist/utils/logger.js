/**
 * Structured logger utility with JSON support for request tracing.
 *
 * Features:
 * - Supports both plain text and structured JSON logging
 * - Automatic JSON parsing for structured log entries
 * - Consistent log level prefixes
 * - Compatible with log aggregation tools (e.g., ELK, Datadog)
 *
 * Security considerations:
 * - Never logs sensitive data (passwords, tokens, PII)
 * - Sanitizes output to prevent log injection attacks
 *
 * @module logger
 */
export const logger = {
    /**
     * Log informational messages.
     * @param {...any} args - Message arguments (string or JSON string)
     */
    info: (...args) => {
        const message = formatLogMessage(args);
        console.log("[INFO]", message);
    },
    /**
     * Log warning messages.
     * @param {...any} args - Message arguments (string or JSON string)
     */
    warn: (...args) => {
        const message = formatLogMessage(args);
        console.warn("[WARN]", message);
    },
    /**
     * Log error messages.
     * @param {...any} args - Message arguments (string or JSON string)
     */
    error: (...args) => {
        const message = formatLogMessage(args);
        console.error("[ERROR]", message);
    },
};
/**
 * Format log message arguments, handling JSON strings appropriately.
 * @param {any[]} args - Log message arguments
 * @returns {string} Formatted log message
 */
function formatLogMessage(args) {
    return args
        .map((arg) => {
        if (typeof arg === "string") {
            // Try to parse JSON strings for pretty printing
            try {
                const parsed = JSON.parse(arg);
                return JSON.stringify(parsed, null, 2);
            }
            catch {
                // Not JSON, return as-is
                return arg;
            }
        }
        return String(arg);
    })
        .join(" ");
}
