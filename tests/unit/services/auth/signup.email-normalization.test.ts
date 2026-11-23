/**
 * Regression tests for the stored-form email normalization contract.
 *
 * Signup persists the trimmed + lowercased address with plus tags intact;
 * login and forgot-password must use the same helper so the address a user
 * typed always finds their account. Plus-stripped forms remain the canonical
 * identity for rate limiting.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import express, { type Express } from "express";
import { authRouter } from "../../../../src/routes/auth.js";
import { errorHandler } from "../../../../src/middleware/errorHandler.js";
import { resetRateLimiterStore } from "../../../../src/middleware/rateLimiter.js";
import {
  clearAllUsers,
  findUserByEmail,
} from "../../../../src/repositories/userRepository.js";
import { signup } from "../../../../src/services/auth/signup.js";
import { forgotPassword } from "../../../../src/services/auth/forgotPassword.js";
import {
  createSignupRateLimitStore,
  resetSignupRateLimitStore,
} from "../../../../src/utils/signupRateLimiter.js";

vi.mock("../../../../src/utils/logger.js", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock("../../../../src/services/email/sendReset.js", () => ({
  sendPasswordResetEmail: vi.fn().mockResolvedValue({ retryable: false }),
}));

const PASSWORD = "S3cure!Passw0rd";
const NO_DELAY = { minOperationTimeMs: 0 };

function createTestApp(): Express {
  const app = express();
  app.use(express.json());
  app.use("/api/auth", authRouter);
  app.use(errorHandler);
  return app;
}

beforeEach(() => {
  clearAllUsers();
  resetSignupRateLimitStore();
  resetRateLimiterStore();
});

afterEach(() => {
  clearAllUsers();
  resetSignupRateLimitStore();
  resetRateLimiterStore();
});

describe("stored-form email normalization", () => {
  it("signs up and logs in with the same plus-tagged address", async () => {
    const app = createTestApp();
    const email = "a+x@b.com";

    const signupResponse = await request(app)
      .post("/api/auth/signup")
      .send({ email, password: PASSWORD });

    expect(signupResponse.status).toBe(201);
    expect(signupResponse.body.user.email).toBe(email);
    expect((await findUserByEmail(email))?.email).toBe(email);

    const loginResponse = await request(app)
      .post("/api/auth/login")
      .send({ email, password: PASSWORD });

    expect(loginResponse.status).toBe(200);
    expect(loginResponse.body.user.email).toBe(email);
  });

  it("finds the plus-tagged account for password reset", async () => {
    const email = "a+x@b.com";

    await signup(
      { email, password: PASSWORD, ipAddress: "10.0.0.1" },
      NO_DELAY,
    );

    const response = await forgotPassword({ email });

    expect(response.message).toBe(
      "If an account with this email exists, a reset link has been sent.",
    );
    expect((await findUserByEmail(email))?.resetToken).toBeTruthy();
  });

  it("does not persist the plus-stripped address", async () => {
    await signup(
      { email: "v+1@b.com", password: PASSWORD, ipAddress: "10.0.0.2" },
      NO_DELAY,
    );

    expect(await findUserByEmail("v+1@b.com")).not.toBeNull();
    expect(await findUserByEmail("v@b.com")).toBeNull();
  });

  it("does not let a plus-tag signup block the canonical mailbox owner", async () => {
    await signup(
      { email: "victim+attacker@b.com", password: PASSWORD, ipAddress: "10.0.0.4" },
      NO_DELAY,
    );
    await signup(
      { email: "victim@b.com", password: PASSWORD, ipAddress: "10.0.0.5" },
      NO_DELAY,
    );

    expect(await findUserByEmail("victim+attacker@b.com")).not.toBeNull();
    expect(await findUserByEmail("victim@b.com")).not.toBeNull();
  });

  it("still treats plus-tag variants as one rate-limit identity", () => {
    const store = createSignupRateLimitStore({
      windowMs: 60_000,
      maxAttemptsPerIp: 100,
      maxAttemptsPerEmail: 2,
      maxGlobalAttempts: 100,
      blockDurationMs: 300_000,
      progressiveDelayThreshold: 100,
      enableProgressiveDelay: false,
    });

    store.recordAttempt("10.0.0.3", "a+1@b.com");
    const result = store.checkLimit("10.0.0.3", "a+2@b.com");

    expect(result.remainingAttempts).toBeLessThan(2);
  });
});
