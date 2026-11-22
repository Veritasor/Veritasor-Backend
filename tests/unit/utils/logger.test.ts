import { describe, expect, it } from "vitest";
import {
  buildLogEntry,
  runWithLoggerContext,
  SENSITIVE_LOG_FIELDS,
} from "../../../src/utils/logger.js";

describe("logger structured fields", () => {
  it("merges request-scoped correlation id into log entries", () => {
    const entry = runWithLoggerContext({ correlationId: "corr-test-123" }, () =>
      buildLogEntry("info", ["auth_event", { event: "AUTH_SUCCESS" }]),
    );

    expect(entry).toMatchObject({
      level: "info",
      correlationId: "corr-test-123",
      event: "AUTH_SUCCESS",
      message: "auth_event",
    });
  });

  it("redacts every listed sensitive field at the top level", () => {
    const context = Object.fromEntries(
      [...SENSITIVE_LOG_FIELDS].map((key) => [key, `secret-${key}`]),
    );
    const entry = buildLogEntry("warn", ["sensitive_event", context]);

    for (const key of SENSITIVE_LOG_FIELDS) {
      expect(entry[key], `top-level ${key}`).toBe("[REDACTED]");
    }
  });

  it("matches sensitive field names case-insensitively", () => {
    const entry = buildLogEntry("warn", [
      "case_insensitive_event",
      {
        PASSWORD: "secret",
        AccessToken: "access-secret",
        X_API_KEY: "api-secret",
        safeField: "kept",
      },
    ]);

    expect(entry.PASSWORD).toBe("[REDACTED]");
    expect(entry.AccessToken).toBe("[REDACTED]");
    expect(entry.X_API_KEY).toBe("[REDACTED]");
    expect(entry.safeField).toBe("kept");
  });

  it("redacts nested objects and arrays of objects without touching safe fields", () => {
    const entry = buildLogEntry("warn", [
      "nested_sensitive_event",
      {
        request: {
          password: "nested-secret",
          safe: "nested-kept",
        },
        users: [
          { email: "one@example.com", name: "One" },
          { access_token: "array-secret", name: "Two" },
        ],
        safeTopLevel: "still-kept",
      },
    ]);

    expect(entry.request).toMatchObject({
      password: "[REDACTED]",
      safe: "nested-kept",
    });
    expect(entry.users).toEqual([
      { email: "[REDACTED]", name: "One" },
      { access_token: "[REDACTED]", name: "Two" },
    ]);
    expect(entry.safeTopLevel).toBe("still-kept");
  });

  it("redacts sensitive properties on Error objects", () => {
    const error = Object.assign(new Error("operation failed"), {
      password: "error-secret",
      safeDetail: "error-kept",
    });

    const entry = buildLogEntry("error", ["error_event", error]);

    expect(entry.err).toMatchObject({
      name: "Error",
      message: "operation failed",
      password: "[REDACTED]",
      safeDetail: "error-kept",
    });
  });

  it("strips control characters from messages to prevent log injection", () => {
    const entry = buildLogEntry("error", ["first line\nsecond line\twith tab"]);

    expect(entry.message).toBe("first line second line with tab");
  });
});
