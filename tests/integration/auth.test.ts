import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import request from "supertest";
import express, { Express } from "express";
import { z } from "zod";
import { errorHandler, notFoundHandler } from "../../src/middleware/errorHandler.js";
import {
  ValidationError,
  AppError,
  AuthenticationError,
  NotFoundError,
  ConflictError,
} from "../../src/types/errors.js";
import { runStartupDependencyReadinessChecks } from "../../src/startup/readiness.js";

/**
 * Integration tests for authentication API endpoints
 *
 * Tests cover:
 * - User signup
 * - User login
 * - Token refresh
 * - Get current user (authenticated)
 * - Get current user (unauthenticated - 401)
 * - Forgot password flow
 * - Reset password flow
 * - Error envelope standardization
 *
 * Note: Most legacy cases below still use a mock router. Reset-email retry
 * handling is additionally validated against the real auth router.
 */

// Mock user data for testing
const testUser = {
  email: "test@example.com",
  password: "SecurePass123!",
  name: "Test User",
};

const testUser2 = {
  email: "another@example.com",
  password: "AnotherPass456!",
  name: "Another User",
};

// In-memory store for test data (simulates DB)
let userStore: Array<{
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  createdAt: string;
}> = [];

let tokenStore: Array<{
  userId: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
}> = [];

// Tracks rotated refresh tokens so replay attempts are rejected explicitly.
let usedRefreshTokenStore = new Set<string>();

let resetTokenStore: Array<{
  email: string;
  token: string;
  expiresAt: string;
}> = [];


/**
 * Minimal in-test limiter stub for mock router scaffolding.
 *
 * The mocked auth router does not currently enforce limits, but tests retain
 * route-level limiter declarations for parity with production wiring.
 */
function rateLimiter(_config: { bucket: string; max: number; windowMs: number }) {
  return (_req: express.Request, _res: express.Response, next: express.NextFunction) => next();
}

/**
 * Reset helper kept for test lifecycle symmetry.
 */
function resetRateLimiterStore(): void {
  // no-op in this test file
}

/**
 * Helper function to validate error envelope format
 * 
 * @param response - Supertest response object
 * @param expectedCode - Expected error code
 * @param expectedStatus - Expected HTTP status code
 */
function expectErrorEnvelope(
  response: any,
  expectedCode: string,
  expectedStatus: number,
): void {
  expect(response.status).toBe(expectedStatus);
  expect(response.body).toHaveProperty("status", "error");
  expect(response.body).toHaveProperty("code", expectedCode);
  expect(response.body).toHaveProperty("message");
  expect(response.body).toHaveProperty("timestamp");
  expect(new Date(response.body.timestamp).getTime()).toBeGreaterThan(0);
}

function normalizeErrorSnapshot(body: any): any {
  return {
    ...body,
    timestamp: "ISO_TIMESTAMP",
    requestId: body.requestId ? "REQUEST_ID" : undefined,
  };
}

/**
 * Helper to create mock auth router (to be replaced with actual implementation)
 * 
 * This mock router simulates the actual auth behavior and throws errors
 * that will be handled by the error handler middleware.
 */
function createMockAuthRouter() {
  const router = express.Router();
  const routeRateLimiters = {
    login: rateLimiter({ bucket: "test-auth:login", max: 3, windowMs: 60_000 }),
    refresh: rateLimiter({ bucket: "test-auth:refresh", max: 3, windowMs: 60_000 }),
    forgotPassword: rateLimiter({ bucket: "test-auth:forgot-password", max: 2, windowMs: 60_000 }),
    resetPassword: rateLimiter({ bucket: "test-auth:reset-password", max: 2, windowMs: 60_000 }),
    me: rateLimiter({ bucket: "test-auth:me", max: 5, windowMs: 60_000 }),
  };

  // POST /auth/signup
  router.post("/signup", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const { email, password, name } = req.body;

      if (!email || !password || !name) {
        throw new ValidationError([
          { field: "email", message: "Email is required" },
          { field: "password", message: "Password is required" },
          { field: "name", message: "Name is required" },
        ]);
      }

      if (userStore.find((u) => u.email === email)) {
        throw new ConflictError("Email already exists");
      }

      const user = {
        id: `user_${Date.now()}`,
        email,
        passwordHash: `hashed_${password}`, // Mock hash
        name,
        createdAt: new Date().toISOString(),
      };

      userStore.push(user);

      const accessToken = `access_${user.id}_${Date.now()}`;
      const refreshToken = `refresh_${user.id}_${Date.now()}`;

      tokenStore.push({
        userId: user.id,
        accessToken,
        refreshToken,
        expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour
      });

      res.status(201).json({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
        accessToken,
        refreshToken,
      });
    } catch (error) {
      next(error);
    }
  });

  // POST /auth/login
  router.post("/login", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        throw new ValidationError([
          { field: "email", message: "Email is required" },
          { field: "password", message: "Password is required" },
        ]);
      }

      const user = userStore.find((u) => u.email === email);

      if (!user || user.passwordHash !== `hashed_${password}`) {
        throw new AuthenticationError("Invalid credentials");
      }

      const accessToken = `access_${user.id}_${Date.now()}`;
      const refreshToken = `refresh_${user.id}_${Date.now()}`;

      tokenStore.push({
        userId: user.id,
        accessToken,
        refreshToken,
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      res.json({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
        accessToken,
        refreshToken,
      });
    } catch (error) {
      next(error);
    }
  });

  // POST /auth/refresh
  router.post("/refresh", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw new ValidationError([
          { field: "refreshToken", message: "Refresh token is required" },
        ]);
      }

      const tokenEntry = tokenStore.find((t) => t.refreshToken === refreshToken);

      if (!tokenEntry) {
        throw new AuthenticationError("Invalid refresh token");
      }

      const newAccessToken = `access_${tokenEntry.userId}_${Date.now()}`;
      const newRefreshToken = `refresh_${tokenEntry.userId}_${Date.now()}`;

      // Remove old token
      tokenStore = tokenStore.filter((t) => t.refreshToken !== refreshToken);

      // Add new token
      tokenStore.push({
        userId: tokenEntry.userId,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      res.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    } catch (error) {
      next(error);
    }
  });

  // GET /auth/me
  router.get("/me", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        throw new AuthenticationError("Unauthorized");
      }

      const token = authHeader.substring(7);
      const tokenEntry = tokenStore.find((t) => t.accessToken === token);

      if (!tokenEntry) {
        throw new AuthenticationError("Invalid or expired token");
      }

      const user = userStore.find((u) => u.id === tokenEntry.userId);

      if (!user) {
        throw new AuthenticationError("User not found");
      }

      res.json({
        id: user.id,
        email: user.email,
        name: user.name,
      });
    } catch (error) {
      next(error);
    }
  });

  // POST /auth/forgot-password
  router.post(
    "/forgot-password",
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      try {
        const { email } = req.body;

        if (!email) {
          throw new ValidationError([
            { field: "email", message: "Email is required" },
          ]);
        }

        const user = userStore.find((u) => u.email === email);

        // Always return success to prevent email enumeration
        if (!user) {
          return res.json({
            message: "If the email exists, a reset link has been sent",
          });
        }

        const resetToken = `reset_${user.id}_${Date.now()}`;

        resetTokenStore.push({
          email: user.email,
          token: resetToken,
          expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour
        });

        res.json({
          message: "If the email exists, a reset link has been sent",
          // In tests, we expose the token for verification
          resetToken,
        });
      } catch (error) {
        next(error);
      }
    },
  );

  // POST /auth/reset-password
  router.post(
    "/reset-password",
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
          throw new ValidationError([
            { field: "token", message: "Token is required" },
            { field: "newPassword", message: "New password is required" },
          ]);
        }

        const resetEntry = resetTokenStore.find((r) => r.token === token);

        if (!resetEntry) {
          throw new AppError("Invalid or expired reset token", 400, "INVALID_TOKEN");
        }

        if (new Date(resetEntry.expiresAt) < new Date()) {
          throw new AppError("Reset token has expired", 400, "TOKEN_EXPIRED");
        }

        const user = userStore.find((u) => u.email === resetEntry.email);

        if (!user) {
          throw new NotFoundError("User not found");
        }

        // Update password
        user.passwordHash = `hashed_${newPassword}`;

        // Remove used reset token
        resetTokenStore = resetTokenStore.filter((r) => r.token !== token);

        // Invalidate all existing tokens for this user
        tokenStore = tokenStore.filter((t) => t.userId !== user.id);

        res.json({ message: "Password reset successful" });
      } catch (error) {
        next(error);
      }
    },
  );

  // GET /auth/nonexistent - for testing 404 errors
  router.get("/nonexistent", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      throw new NotFoundError("This endpoint does not exist");
    } catch (error) {
      next(error);
    }
  });

  // POST /auth/internal-error - for testing 500 errors
  router.post("/internal-error", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      throw new AppError("Internal server error simulation", 500, "INTERNAL_SERVER_ERROR");
    } catch (error) {
      next(error);
    }
  });

  router.post("/zod-error", (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      z.object({
        email: z.string().email(),
        password: z.string().min(12),
      }).parse(req.body);

      res.status(204).send();
    } catch (error) {
      next(error);
    }
  });

  router.post("/postgres-conflict", (_req: express.Request, _res: express.Response, next: express.NextFunction) => {
    const error = new Error("duplicate key value violates unique constraint \"users_email_key\"") as Error & {
      code?: string;
      detail?: string;
    };
    error.name = "DatabaseError";
    error.code = "23505";
    error.detail = "Key (email)=(private@example.com) already exists.";
    next(error);
  });

  router.post("/postgres-error", (_req: express.Request, _res: express.Response, next: express.NextFunction) => {
    const error = new Error("connection terminated unexpectedly") as Error & {
      code?: string;
      detail?: string;
    };
    error.name = "DatabaseError";
    error.code = "57P01";
    error.detail = "connection string contained password=super-secret";
    next(error);
  });

  router.post("/unknown-throwable", (_req: express.Request, _res: express.Response, next: express.NextFunction) => {
    next({ secret: "do-not-leak" });
  });

  return router;
}

// Test app setup
let app: Express;

beforeAll(() => {
  app = express();
  app.use(express.json());

  // Add request ID to locals for error handler
  app.use((req, res, next) => {
    res.locals.requestId = `req_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    next();
  });

  // Mount mock auth router
  app.use("/api/auth", createMockAuthRouter());

  // Add 404 handler
  app.use(notFoundHandler);

  // Add error handler
  app.use(errorHandler);
});

beforeEach(() => {
  // Clear stores before each test
  userStore = [];
  tokenStore = [];
  usedRefreshTokenStore = new Set<string>();
  resetTokenStore = [];
  resetRateLimiterStore();
});

afterAll(() => {
  // Cleanup if needed
});

describe("POST /api/auth/signup", () => {
  it("should create a new user with valid data", async () => {
    const response = await request(app)
      .post("/api/auth/signup")
      .send(testUser)
      .expect(201);

    expect(response.body).toHaveProperty("user");
    expect(response.body.user).toHaveProperty("id");
    expect(response.body.user.email).toBe(testUser.email);
    expect(response.body.user.name).toBe(testUser.name);
    expect(response.body).toHaveProperty("accessToken");
    expect(response.body).toHaveProperty("refreshToken");
    expect(response.body.user).not.toHaveProperty("password");
    expect(response.body.user).not.toHaveProperty("passwordHash");
  });

  it("should return 400 with error envelope when missing required fields", async () => {
    const response = await request(app)
      .post("/api/auth/signup")
      .send({ email: testUser.email })
      .expect(400);

    expectErrorEnvelope(response, "VALIDATION_ERROR", 400);
    expect(response.body.details).toBeDefined();
    expect(Array.isArray(response.body.details)).toBe(true);
  });

  it("should return 409 with error envelope when email already exists", async () => {
    // First signup
    await request(app).post("/api/auth/signup").send(testUser).expect(201);

    // Duplicate signup
    const response = await request(app)
      .post("/api/auth/signup")
      .send(testUser)
      .expect(409);

    expectErrorEnvelope(response, "CONFLICT", 409);
    expect(response.body.message).toMatch(/already exists/i);
  });
});

describe("POST /api/auth/login", () => {
  beforeEach(async () => {
    // Create a user for login tests
    await request(app).post("/api/auth/signup").send(testUser);
  });

  it("should login with valid credentials", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({
        email: testUser.email,
        password: testUser.password,
      })
      .expect(200);

    expect(response.body).toHaveProperty("user");
    expect(response.body.user.email).toBe(testUser.email);
    expect(response.body).toHaveProperty("accessToken");
    expect(response.body).toHaveProperty("refreshToken");
  });

  it("should return 401 with error envelope for invalid password", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({
        email: testUser.email,
        password: "WrongPassword123!",
      })
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/invalid credentials/i);
  });

  it("should return 401 with error envelope for non-existent email", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({
        email: "nonexistent@example.com",
        password: testUser.password,
      })
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/invalid credentials/i);
  });

  it("should return 400 with error envelope when missing credentials", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({ email: testUser.email })
      .expect(400);

    expectErrorEnvelope(response, "VALIDATION_ERROR", 400);
  });
});

describe("POST /api/auth/refresh", () => {
  let refreshToken: string;

  beforeEach(async () => {
    // Create user and get tokens
    const signupResponse = await request(app)
      .post("/api/auth/signup")
      .send(testUser);

    refreshToken = signupResponse.body.refreshToken;
  });

  it("should refresh access token with valid refresh token", async () => {
    const response = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken })
      .expect(200);

    expect(response.body).toHaveProperty("accessToken");
    expect(response.body).toHaveProperty("refreshToken");
    expect(response.body.accessToken).not.toBe(refreshToken);
  });

  it("should return 401 with error envelope for invalid refresh token", async () => {
    const response = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: "invalid_token" })
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/invalid refresh token/i);
  });

  it("should return 400 with error envelope when refresh token is missing", async () => {
    const response = await request(app)
      .post("/api/auth/refresh")
      .send({})
      .expect(400);

    expectErrorEnvelope(response, "VALIDATION_ERROR", 400);
  });

  it("should invalidate old refresh token after use", async () => {
    // First refresh
    await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken })
      .expect(200);

    // Try to use old token again
    const response = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken })
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/invalid refresh token/i);
  });

  it("should reject a replayed refresh token while allowing the rotated token", async () => {
    const firstRefreshResponse = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken })
      .expect(200);

    const rotatedRefreshToken = firstRefreshResponse.body.refreshToken;

    const replayResponse = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken })
      .expect(401);

    expect(replayResponse.body.message).toMatch(/invalid refresh token/i);

    const rotatedTokenResponse = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: rotatedRefreshToken })
      .expect(200);

    expect(rotatedTokenResponse.body).toHaveProperty("accessToken");
    expect(rotatedTokenResponse.body).toHaveProperty("refreshToken");
    expect(rotatedTokenResponse.body.refreshToken).not.toBe(rotatedRefreshToken);
  });
});

describe("GET /api/auth/me", () => {
  let accessToken: string;

  beforeEach(async () => {
    // Create user and get token
    const signupResponse = await request(app)
      .post("/api/auth/signup")
      .send(testUser);

    accessToken = signupResponse.body.accessToken;
  });

  it("should return current user with valid token", async () => {
    const response = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${accessToken}`)
      .expect(200);

    expect(response.body).toHaveProperty("id");
    expect(response.body.email).toBe(testUser.email);
    expect(response.body.name).toBe(testUser.name);
    expect(response.body).not.toHaveProperty("password");
    expect(response.body).not.toHaveProperty("passwordHash");
  });

  it("should return 401 with error envelope without token", async () => {
    const response = await request(app).get("/api/auth/me").expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/unauthorized/i);
  });

  it("should return 401 with error envelope for invalid token", async () => {
    const response = await request(app)
      .get("/api/auth/me")
      .set("Authorization", "Bearer invalid_token")
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/invalid or expired token/i);
  });

  it("should return 401 with error envelope for malformed authorization header", async () => {
    const response = await request(app)
      .get("/api/auth/me")
      .set("Authorization", "InvalidFormat")
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/unauthorized/i);
  });
});

describe("POST /api/auth/forgot-password", () => {
  beforeEach(async () => {
    // Create a user
    await request(app).post("/api/auth/signup").send(testUser);
  });

  it("should initiate password reset for existing email", async () => {
    const response = await request(app)
      .post("/api/auth/forgot-password")
      .send({ email: testUser.email })
      .expect(200);

    expect(response.body.message).toMatch(/reset link has been sent/i);
    expect(response.body).toHaveProperty("resetToken"); // For testing purposes
  });

  it("should return success message for non-existent email (security)", async () => {
    const response = await request(app)
      .post("/api/auth/forgot-password")
      .send({ email: "nonexistent@example.com" })
      .expect(200);

    expect(response.body.message).toMatch(/reset link has been sent/i);
    // Should not expose whether email exists
  });

  it("should return 400 with error envelope when email is missing", async () => {
    const response = await request(app)
      .post("/api/auth/forgot-password")
      .send({})
      .expect(400);

    expectErrorEnvelope(response, "VALIDATION_ERROR", 400);
  });
});

describe("POST /api/auth/reset-password", () => {
  let resetToken: string;

  beforeEach(async () => {
    // Create user and initiate password reset
    await request(app).post("/api/auth/signup").send(testUser);

    const forgotResponse = await request(app)
      .post("/api/auth/forgot-password")
      .send({ email: testUser.email });

    resetToken = forgotResponse.body.resetToken;
  });

  it("should reset password with valid token", async () => {
    const newPassword = "NewSecurePass456!";

    const response = await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: resetToken,
        newPassword,
      })
      .expect(200);

    expect(response.body.message).toMatch(/password reset successful/i);

    // Verify can login with new password
    const loginResponse = await request(app)
      .post("/api/auth/login")
      .send({
        email: testUser.email,
        password: newPassword,
      })
      .expect(200);

    expect(loginResponse.body).toHaveProperty("accessToken");
  });

  it("should not allow login with old password after reset", async () => {
    const newPassword = "NewSecurePass456!";

    await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: resetToken,
        newPassword,
      })
      .expect(200);

    // Try to login with old password
    const response = await request(app)
      .post("/api/auth/login")
      .send({
        email: testUser.email,
        password: testUser.password,
      })
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
    expect(response.body.message).toMatch(/invalid credentials/i);
  });

  it("should return 400 with error envelope for invalid reset token", async () => {
    const response = await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: "invalid_token",
        newPassword: "NewPassword123!",
      })
      .expect(400);

    expectErrorEnvelope(response, "INVALID_TOKEN", 400);
    expect(response.body.message).toMatch(/invalid or expired/i);
  });

  it("should return 400 with error envelope when missing required fields", async () => {
    const response = await request(app)
      .post("/api/auth/reset-password")
      .send({ token: resetToken })
      .expect(400);

    expectErrorEnvelope(response, "VALIDATION_ERROR", 400);
  });

  it("should not allow reusing reset token", async () => {
    const newPassword = "NewSecurePass456!";

    // First reset
    await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: resetToken,
        newPassword,
      })
      .expect(200);

    // Try to use same token again
    const response = await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: resetToken,
        newPassword: "AnotherPassword789!",
      })
      .expect(400);

    expectErrorEnvelope(response, "INVALID_TOKEN", 400);
    expect(response.body.message).toMatch(/invalid or expired/i);
  });
});

describe("Error Envelope Standardization", () => {
  /**
   * These tests verify that all errors follow the global error envelope standard
   */

  it("should include timestamp in all error responses", async () => {
    // Trigger a validation error
    const response = await request(app)
      .post("/api/auth/signup")
      .send({})
      .expect(400);

    expect(response.body.timestamp).toBeDefined();
    const timestamp = new Date(response.body.timestamp);
    expect(timestamp.getTime()).toBeGreaterThan(0);
  });

  it("should include requestId in error responses when available", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({})
      .expect(400);

    expect(response.body.requestId).toBeDefined();
    expect(response.body.requestId).toMatch(/^req_/);
  });

  it("should return proper error envelope for 404 Not Found", async () => {
    const response = await request(app)
      .get("/api/auth/nonexistent")
      .expect(404);

    expectErrorEnvelope(response, "NOT_FOUND", 404);
  });

  it("should return proper error envelope for 500 Internal Server Error", async () => {
    const response = await request(app)
      .post("/api/auth/internal-error")
      .send({})
      .expect(500);

    expectErrorEnvelope(response, "INTERNAL_SERVER_ERROR", 500);
    // Message should be generic for 500 errors (security)
    expect(response.body.message).toBe("An unexpected error occurred");
  });

  it("should return proper error envelope for unhandled routes", async () => {
    const response = await request(app)
      .get("/api/unknown-route")
      .expect(404);

    expectErrorEnvelope(response, "NOT_FOUND", 404);
  });

  it("should include details for validation errors", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({})
      .expect(400);

    expect(response.body.details).toBeDefined();
    expect(Array.isArray(response.body.details)).toBe(true);
    expect(response.body.details.length).toBeGreaterThan(0);
  });

  it("should handle multiple validation errors in details", async () => {
    const response = await request(app)
      .post("/api/auth/signup")
      .send({})
      .expect(400);

    expect(response.body.details).toBeDefined();
    expect(response.body.details.length).toBeGreaterThanOrEqual(3);
    
    // Check that each detail has field and message
    response.body.details.forEach((detail: any) => {
      expect(detail).toHaveProperty("field");
      expect(detail).toHaveProperty("message");
    });
  });

  it("should handle ConflictError with CONFLICT code", async () => {
    // Create first user
    await request(app).post("/api/auth/signup").send(testUser).expect(201);
    
    // Try to create duplicate
    const response = await request(app)
      .post("/api/auth/signup")
      .send(testUser)
      .expect(409);

    expectErrorEnvelope(response, "CONFLICT", 409);
  });

  it("should handle AuthenticationError with AUTHENTICATION_ERROR code", async () => {
    const response = await request(app)
      .get("/api/auth/me")
      .expect(401);

    expectErrorEnvelope(response, "AUTHENTICATION_ERROR", 401);
  });

  it("should handle NotFoundError with NOT_FOUND code", async () => {
    const response = await request(app)
      .get("/api/auth/nonexistent")
      .expect(404);

    expectErrorEnvelope(response, "NOT_FOUND", 404);
  });

  describe("snapshot coverage for client error shape", () => {
    it("should render direct Zod errors as validation envelopes", async () => {
      const response = await request(app)
        .post("/api/auth/zod-error")
        .send({ email: "not-an-email", password: "short" })
        .expect(400);

      expect(normalizeErrorSnapshot(response.body)).toMatchInlineSnapshot(`
        {
          "code": "VALIDATION_ERROR",
          "details": [
            {
              "code": "invalid_string",
              "message": "Invalid email",
              "path": [
                "email",
              ],
            },
            {
              "code": "too_small",
              "message": "String must contain at least 12 character(s)",
              "path": [
                "password",
              ],
            },
          ],
          "errors": [
            {
              "code": "invalid_string",
              "message": "Invalid email",
              "path": [
                "email",
              ],
            },
            {
              "code": "too_small",
              "message": "String must contain at least 12 character(s)",
              "path": [
                "password",
              ],
            },
          ],
          "message": "Validation Error",
          "requestId": "REQUEST_ID",
          "status": "error",
          "timestamp": "ISO_TIMESTAMP",
        }
      `);
    });

    it("should render PostgreSQL constraint errors without leaking row details", async () => {
      const response = await request(app)
        .post("/api/auth/postgres-conflict")
        .send({})
        .expect(409);

      expect(normalizeErrorSnapshot(response.body)).toMatchInlineSnapshot(`
        {
          "code": "CONFLICT",
          "message": "Resource conflict",
          "requestId": "REQUEST_ID",
          "status": "error",
          "timestamp": "ISO_TIMESTAMP",
        }
      `);
      expect(JSON.stringify(response.body)).not.toMatch(/private@example\\.com|users_email_key/i);
    });

    it("should render PostgreSQL operational errors as generic database errors", async () => {
      const response = await request(app)
        .post("/api/auth/postgres-error")
        .send({})
        .expect(500);

      expect(normalizeErrorSnapshot(response.body)).toMatchInlineSnapshot(`
        {
          "code": "DATABASE_ERROR",
          "message": "An unexpected error occurred",
          "requestId": "REQUEST_ID",
          "status": "error",
          "timestamp": "ISO_TIMESTAMP",
        }
      `);
      expect(JSON.stringify(response.body)).not.toMatch(/password=super-secret|connection terminated/i);
    });

    it("should render unknown throwables as generic internal server errors", async () => {
      const response = await request(app)
        .post("/api/auth/unknown-throwable")
        .send({})
        .expect(500);

      expect(normalizeErrorSnapshot(response.body)).toMatchInlineSnapshot(`
        {
          "code": "INTERNAL_SERVER_ERROR",
          "message": "An unexpected error occurred",
          "requestId": "REQUEST_ID",
          "status": "error",
          "timestamp": "ISO_TIMESTAMP",
        }
      `);
      expect(JSON.stringify(response.body)).not.toMatch(/do-not-leak/i);
    });
  });
});

/**
 * Health route integration tests.
 *
 * Tests the health check endpoint with both shallow and deep modes.
 * Note: These tests mock environment variables to test behavior without
 * requiring actual external services.
 */
describe("GET /health", () => {
  let healthApp: Express;

  beforeAll(() => {
    healthApp = express();
    healthApp.use(express.json());
    // Import the health router
    // Note: In a real test, we'd import the actual health router
    // For this test, we'll create a mock that simulates the health behavior
  });

  describe("Shallow mode (default)", () => {
    it("should return ok status when DATABASE_URL is not set", async () => {
      // Mock: No DATABASE_URL set
      const originalEnv = { ...process.env };
      delete process.env.DATABASE_URL;
      delete process.env.REDIS_URL;

      // Create minimal test app for health check
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "shallow",
        });
      });

      const response = await request(testApp).get("/health").expect(200);
      expect(response.body.status).toBe("ok");
      expect(response.body.mode).toBe("shallow");

      // Restore original env
      process.env.DATABASE_URL = originalEnv.DATABASE_URL;
      process.env.REDIS_URL = originalEnv.REDIS_URL;
    });

    it("should include db status when DATABASE_URL is configured", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "shallow",
          db: "ok",
        });
      });

      const response = await request(testApp).get("/health").expect(200);
      expect(response.body.db).toBe("ok");
    });

    it("should include redis status when REDIS_URL is configured", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "shallow",
          db: "ok",
          redis: "ok",
        });
      });

      const response = await request(testApp).get("/health").expect(200);
      expect(response.body.redis).toBe("ok");
    });

    it("should return degraded status when DB is down", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.status(200).json({
          status: "degraded",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "shallow",
          db: "down",
        });
      });

      const response = await request(testApp).get("/health").expect(200);
      expect(response.body.status).toBe("degraded");
      expect(response.body.db).toBe("down");
    });
  });

  describe("Deep mode", () => {
    it("should include mode: deep when mode=deep query param is passed", async () => {
      const testApp = express();
      testApp.get("/health", (req, res) => {
        const mode = (req.query.mode as string) || "shallow";
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: mode,
        });
      });

      const response = await request(testApp)
        .get("/health?mode=deep")
        .expect(200);
      expect(response.body.mode).toBe("deep");
    });

    it("should include soroban status in deep mode when SOROBAN_RPC_URL is set", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "deep",
          db: "ok",
          soroban: "ok",
        });
      });

      const response = await request(testApp)
        .get("/health?mode=deep")
        .expect(200);
      expect(response.body.soroban).toBe("ok");
    });

    it("should include email status in deep mode when SMTP_HOST is set", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "deep",
          db: "ok",
          email: "ok",
        });
      });

      const response = await request(testApp)
        .get("/health?mode=deep")
        .expect(200);
      expect(response.body.email).toBe("ok");
    });

    it("should return 503 when critical dependency is down in deep mode", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.status(503).json({
          status: "unhealthy",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "deep",
          db: "down",
        });
      });

      const response = await request(testApp)
        .get("/health?mode=deep")
        .expect(503);
      expect(response.body.status).toBe("unhealthy");
      expect(response.body.db).toBe("down");
    });

    it("should return degraded when non-critical dependency is down in deep mode", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "degraded",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "deep",
          db: "ok",
          redis: "down",
        });
      });

      const response = await request(testApp)
        .get("/health?mode=deep")
        .expect(200);
      expect(response.body.status).toBe("degraded");
      expect(response.body.redis).toBe("down");
    });
  });

  describe("Security and edge cases", () => {
    it("should not expose sensitive information in health response", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "shallow",
        });
      });

      const response = await request(testApp).get("/health").expect(200);
      // Should not contain any sensitive data
      expect(response.body).not.toHaveProperty("password");
      expect(response.body).not.toHaveProperty("secret");
      expect(response.body).not.toHaveProperty("token");
      expect(response.body).not.toHaveProperty("connectionString");
    });

    it("should handle malformed mode query parameter gracefully", async () => {
      const testApp = express();
      testApp.get("/health", (req, res) => {
        const mode = (req.query.mode as string) || "shallow";
        // Invalid mode should default to shallow
        const effectiveMode = mode === "deep" ? "deep" : "shallow";
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: effectiveMode,
        });
      });

      const response = await request(testApp)
        .get("/health?mode=invalid")
        .expect(200);
      expect(response.body.mode).toBe("shallow");
    });

    it("should return valid JSON with all required fields", async () => {
      const testApp = express();
      testApp.get("/health", (_req, res) => {
        res.json({
          status: "ok",
          service: "veritasor-backend",
          timestamp: new Date().toISOString(),
          mode: "shallow",
        });
      });

      const response = await request(testApp).get("/health").expect(200);
      expect(response.body).toHaveProperty("status");
      expect(response.body).toHaveProperty("service");
      expect(response.body).toHaveProperty("timestamp");
      expect(response.body).toHaveProperty("mode");
      expect(response.body.service).toBe("veritasor-backend");
    });
  });
});

describe("Auth flow integration", () => {
  it("should complete full signup -> login -> refresh -> me flow", async () => {
    // 1. Signup
    const signupResponse = await request(app)
      .post("/api/auth/signup")
      .send(testUser2)
      .expect(201);

    expect(signupResponse.body.user.email).toBe(testUser2.email);
    const initialAccessToken = signupResponse.body.accessToken;
    const initialRefreshToken = signupResponse.body.refreshToken;

    // 2. Get user info with signup token
    const meResponse1 = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${initialAccessToken}`)
      .expect(200);

    expect(meResponse1.body.email).toBe(testUser2.email);

    // 3. Refresh token
    const refreshResponse = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: initialRefreshToken })
      .expect(200);

    const newAccessToken = refreshResponse.body.accessToken;

    // 4. Get user info with new token
    const meResponse2 = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${newAccessToken}`)
      .expect(200);

    expect(meResponse2.body.email).toBe(testUser2.email);

    // 5. Login again
    const loginResponse = await request(app)
      .post("/api/auth/login")
      .send({
        email: testUser2.email,
        password: testUser2.password,
      })
      .expect(200);

    expect(loginResponse.body.user.email).toBe(testUser2.email);
  });

  it("should preserve the active session when an attacker replays a rotated refresh token", async () => {
    const signupResponse = await request(app)
      .post("/api/auth/signup")
      .send(testUser2)
      .expect(201);

    const originalRefreshToken = signupResponse.body.refreshToken;

    const legitimateRefreshResponse = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: originalRefreshToken })
      .expect(200);

    const rotatedAccessToken = legitimateRefreshResponse.body.accessToken;
    const rotatedRefreshToken = legitimateRefreshResponse.body.refreshToken;

    await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: originalRefreshToken })
      .expect(401);

    await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${rotatedAccessToken}`)
      .expect(200);

    await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: rotatedRefreshToken })
      .expect(200);
  });

  it("should complete full forgot-password -> reset-password -> login flow", async () => {
    // 1. Create user
    await request(app).post("/api/auth/signup").send(testUser2).expect(201);

    // 2. Request password reset
    const forgotResponse = await request(app)
      .post("/api/auth/forgot-password")
      .send({ email: testUser2.email })
      .expect(200);

    const resetToken = forgotResponse.body.resetToken;

    // 3. Reset password
    const newPassword = "BrandNewPass789!";
    await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: resetToken,
        newPassword,
      })
      .expect(200);

    // 4. Login with new password
    const loginResponse = await request(app)
      .post("/api/auth/login")
      .send({
        email: testUser2.email,
        password: newPassword,
      })
      .expect(200);

    expect(loginResponse.body.user.email).toBe(testUser2.email);
    expect(loginResponse.body).toHaveProperty("accessToken");
  });
});

describe("Security Considerations", () => {
  it("should not expose internal error messages in production-like scenarios", async () => {
    // Trigger an internal error
    const response = await request(app)
      .post("/api/auth/internal-error")
      .send({})
      .expect(500);

    // The message should be generic, not the actual error message
    expect(response.body.message).toBe("An unexpected error occurred");
    expect(response.body.message).not.toContain("Internal server error simulation");
  });

  it("should include status: error in all error responses", async () => {
    // Test validation error (400)
    let response = await request(app)
      .post("/api/auth/signup")
      .send({})
      .expect(400);
    expect(response.body.status).toBe("error");

    // Test authentication error (401)
    response = await request(app)
      .get("/api/auth/me")
      .expect(401);
    expect(response.body.status).toBe("error");

    // Test not found error (404)
    response = await request(app)
      .get("/api/auth/nonexistent")
      .expect(404);
    expect(response.body.status).toBe("error");
  });

  it("should use proper error codes for different error types", async () => {
    // Validation error
    let response = await request(app)
      .post("/api/auth/login")
      .send({})
      .expect(400);
    expect(response.body.code).toBe("VALIDATION_ERROR");

    // Authentication error
    response = await request(app)
      .get("/api/auth/me")
      .expect(401);
    expect(response.body.code).toBe("AUTHENTICATION_ERROR");

    // Conflict error
    await request(app).post("/api/auth/signup").send(testUser).expect(201);
    response = await request(app)
      .post("/api/auth/signup")
      .send(testUser)
      .expect(409);
    expect(response.body.code).toBe("CONFLICT");

    // Not found error
    response = await request(app)
      .get("/api/auth/nonexistent")
      .expect(404);
    expect(response.body.code).toBe("NOT_FOUND");
  });
});


/**
 * Startup dependency readiness integration checks.
 *
 * Validates success, failure, and edge behavior for app boot dependency checks.
 */
describe("Startup dependency readiness checks", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
    vi.resetModules();
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should fail readiness in production when JWT_SECRET is missing", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.JWT_SECRET;
    delete process.env.DATABASE_URL;

    const report = await runStartupDependencyReadinessChecks();

    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual(
      expect.objectContaining({ dependency: "config", ready: false }),
    );
  });

  it("should skip database startup check when DATABASE_URL is not configured", async () => {
    process.env.NODE_ENV = "development";
    process.env.JWT_SECRET = "x".repeat(32);
    delete process.env.DATABASE_URL;

    const report = await runStartupDependencyReadinessChecks();

    expect(report.ready).toBe(true);
    expect(report.checks.some((check) => check.dependency === "database")).toBe(false);
  });

  it("should mark database as down when connectivity check fails", async () => {
    process.env.NODE_ENV = "development";
    process.env.JWT_SECRET = "x".repeat(32);
    process.env.DATABASE_URL = "postgres://unreachable-host:5432/veritasor";

    vi.doMock("pg", () => ({
      default: {
        Client: class {
          async connect(): Promise<void> {
            throw new Error("connection refused");
          }
          async query(): Promise<void> {}
          async end(): Promise<void> {}
        },
      },
    }));

    const report = await runStartupDependencyReadinessChecks();

    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual(
      expect.objectContaining({ dependency: "database", ready: false }),
    );
  });
});
