import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import { authRouter, signupErrorToAppError } from "../../../src/routes/auth.js";
import { errorHandler } from "../../../src/middleware/errorHandler.js";
import {
  AppError,
  AuthenticationError,
  ConflictError,
  RateLimitError,
} from "../../../src/types/errors.js";
import { SignupError } from "../../../src/services/auth/signup.js";
import * as loginModule from "../../../src/services/auth/login.js";
import * as refreshModule from "../../../src/services/auth/refresh.js";
import * as resetPasswordModule from "../../../src/services/auth/resetPassword.js";

vi.mock("../../../src/services/auth/login.js", () => ({ login: vi.fn() }));
vi.mock("../../../src/services/auth/refresh.js", () => ({ refresh: vi.fn() }));
vi.mock("../../../src/services/auth/resetPassword.js", () => ({
  resetPassword: vi.fn(),
}));
vi.mock("../../../src/middleware/rateLimiter.js", () => ({
  rateLimiter: () => (_req: express.Request, _res: express.Response, next: express.NextFunction) =>
    next(),
}));

function createAuthTestApp() {
  const app = express();
  app.use(express.json());
  app.use("/api/auth", authRouter);
  app.use(errorHandler);
  return app;
}

describe("signupErrorToAppError", () => {
  it("maps RATE_LIMITED to RateLimitError", () => {
    const err = new SignupError("Too many attempts", "RATE_LIMITED", 429);
    expect(signupErrorToAppError(err)).toBeInstanceOf(RateLimitError);
  });

  it("maps EMAIL_EXISTS to ConflictError", () => {
    const err = new SignupError("Email taken", "EMAIL_EXISTS", 409);
    expect(signupErrorToAppError(err)).toBeInstanceOf(ConflictError);
  });

  it("maps EMAIL_INVALID to AppError with signup type code", () => {
    const err = new SignupError("Bad email", "EMAIL_INVALID", 400);
    const mapped = signupErrorToAppError(err);
    expect(mapped).toBeInstanceOf(AppError);
    expect(mapped.code).toBe("EMAIL_INVALID");
  });
});

describe("auth routes — central errorHandler", () => {
  const app = createAuthTestApp();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns validation envelope for invalid login body", async () => {
    const res = await request(app).post("/api/auth/login").send({ password: "x" });

    expect(res.status).toBe(400);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("VALIDATION_ERROR");
    expect(res.body.message).toBe("Validation Error");
    expect(res.body.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: ["email"] }),
      ]),
    );
  });

  it("returns authentication envelope for invalid credentials", async () => {
    vi.mocked(loginModule.login).mockRejectedValue(
      new AuthenticationError("Invalid email or password"),
    );

    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "user@example.com", password: "wrong" });

    expect(res.status).toBe(401);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("AUTHENTICATION_ERROR");
    expect(res.body.message).toMatch(/invalid email or password/i);
  });

  it("does not leak internal messages for unknown login errors", async () => {
    vi.mocked(loginModule.login).mockRejectedValue(
      new Error("postgres connection secret-host:5432"),
    );

    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "user@example.com", password: "secret" });

    expect(res.status).toBe(500);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("INTERNAL_SERVER_ERROR");
    expect(res.body.message).toBe("An unexpected error occurred");
    expect(res.body.message).not.toMatch(/postgres/i);
  });

  it("passes AppError through refresh route", async () => {
    vi.mocked(refreshModule.refresh).mockRejectedValue(
      new AuthenticationError("Invalid or expired refresh token"),
    );

    const res = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: "bad" });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("AUTHENTICATION_ERROR");
  });

  it("returns INVALID_RESET_TOKEN envelope from reset-password service", async () => {
    vi.mocked(resetPasswordModule.resetPassword).mockRejectedValue(
      new AppError("Invalid or expired reset token", 400, "INVALID_RESET_TOKEN"),
    );

    const res = await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: "a".repeat(64),
        newPassword: "SecureP@ss123",
      });

    expect(res.status).toBe(400);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("INVALID_RESET_TOKEN");
    expect(res.body.message).toMatch(/invalid or expired/i);
  });
});
