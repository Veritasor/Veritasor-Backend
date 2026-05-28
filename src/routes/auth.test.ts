import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import { authRouter } from "./auth.js";
import { errorHandler } from "../middleware/errorHandler.js";
import * as loginModule from "../services/auth/login.js";
import { AuthenticationError } from "../types/errors.js";

vi.mock("../services/auth/login.js", () => ({
  login: vi.fn(),
}));

vi.mock("../middleware/rateLimiter.js", () => ({
  rateLimiter: () => (_req: express.Request, _res: express.Response, next: express.NextFunction) =>
    next(),
}));

const app = express();
app.use(express.json());
app.use("/api/v1/auth", authRouter);
app.use(errorHandler);

describe("POST /api/v1/auth/login", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 400 when email is missing", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ password: "secret123" });

    expect(res.status).toBe(400);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("VALIDATION_ERROR");
    expect(res.body.message).toBe("Validation Error");
    expect(res.body.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["email"],
          message: expect.stringMatching(/required/i),
        }),
      ]),
    );
  });

  it("returns 400 when password is missing", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "user@example.com" });

    expect(res.status).toBe(400);
    expect(res.body.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["password"],
          message: expect.stringMatching(/required/i),
        }),
      ]),
    );
  });

  it("returns 400 when email is not a string", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: 12345, password: "secret123" });

    expect(res.status).toBe(400);
    expect(res.body.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["email"],
          message: expect.stringMatching(/string/i),
        }),
      ]),
    );
  });

  it("returns 400 when email format is invalid", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "not-an-email", password: "secret123" });

    expect(res.status).toBe(400);
    expect(res.body.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["email"],
          message: expect.stringMatching(/email/i),
        }),
      ]),
    );
  });

  it("returns 400 when password exceeds max length", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "user@example.com", password: "a".repeat(129) });

    expect(res.status).toBe(400);
    expect(res.body.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: ["password"],
          message: expect.stringMatching(/128/i),
        }),
      ]),
    );
  });

  it("normalizes email to lowercase and trims whitespace", async () => {
    vi.mocked(loginModule.login).mockResolvedValue({
      accessToken: "token",
      refreshToken: "refresh",
      user: { id: "1", email: "user@example.com" },
    });

    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "  USER@EXAMPLE.COM  ", password: "secret123" });

    expect(res.status).toBe(200);
    expect(loginModule.login).toHaveBeenCalledWith({
      email: "user@example.com",
      password: "secret123",
    });
  });

  it("returns 401 envelope for invalid credentials", async () => {
    vi.mocked(loginModule.login).mockRejectedValue(
      new AuthenticationError("Invalid email or password"),
    );

    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "user@example.com", password: "wrongpassword" });

    expect(res.status).toBe(401);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("AUTHENTICATION_ERROR");
    expect(res.body.message).toMatch(/invalid/i);
  });

  it("returns 200 with tokens for valid login", async () => {
    vi.mocked(loginModule.login).mockResolvedValue({
      accessToken: "access_token_123",
      refreshToken: "refresh_token_456",
      user: { id: "user-1", email: "user@example.com" },
    });

    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({ email: "user@example.com", password: "correctpassword" });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      accessToken: "access_token_123",
      refreshToken: "refresh_token_456",
      user: { id: "user-1", email: "user@example.com" },
    });
  });
});
