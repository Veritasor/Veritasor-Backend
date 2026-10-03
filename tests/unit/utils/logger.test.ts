import { describe, expect, it } from "vitest";
import { buildLogEntry, runWithLoggerContext } from "../../../src/utils/logger.js";

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

  it("redacts sensitive fields from structured context", () => {
    const entry = buildLogEntry("warn", [
      "sensitive_event",
      {
        email: "user@example.com",
        password: "super-secret",
        nested: {
          accessToken: "access-token",
          safe: "kept",
        },
      },
    ]);

    expect(entry.email).toBe("[REDACTED]");
    expect(entry.password).toBe("[REDACTED]");
    expect(entry.nested).toMatchObject({
      accessToken: "[REDACTED]",
      safe: "kept",
    });
  });

  it("strips control characters from messages to prevent log injection", () => {
    const entry = buildLogEntry("error", ["first line\nsecond line\twith tab"]);

    expect(entry.message).toBe("first line second line with tab");
  });
});
