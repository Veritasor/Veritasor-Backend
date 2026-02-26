import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import express, { Express } from "express";

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
 *
 * Note: Auth routes are not yet implemented. These tests are ready
 * for when the auth router is added to the application.
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

let resetTokenStore: Array<{
  email: string;
  token: string;
  expiresAt: string;
}> = [];

// Helper to create mock auth router (to be replaced with actual implementation)
function createMockAuthRouter() {
  const router = express.Router();

  // POST /auth/signup
  router.post("/signup", (req: express.Request, res: express.Response) => {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (userStore.find((u) => u.email === email)) {
      return res.status(409).json({ error: "Email already exists" });
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
  });

  // POST /auth/login
  router.post("/login", (req: express.Request, res: express.Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Missing email or password" });
    }

    const user = userStore.find((u) => u.email === email);

    if (!user || user.passwordHash !== `hashed_${password}`) {
      return res.status(401).json({ error: "Invalid credentials" });
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
  });

  // POST /auth/refresh
  router.post("/refresh", (req: express.Request, res: express.Response) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: "Missing refresh token" });
    }

    const tokenEntry = tokenStore.find((t) => t.refreshToken === refreshToken);

    if (!tokenEntry) {
      return res.status(401).json({ error: "Invalid refresh token" });
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
  });

  // GET /auth/me
  router.get("/me", (req: express.Request, res: express.Response) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.substring(7);
    const tokenEntry = tokenStore.find((t) => t.accessToken === token);

    if (!tokenEntry) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const user = userStore.find((u) => u.id === tokenEntry.userId);

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
    });
  });

  // POST /auth/forgot-password
  router.post(
    "/forgot-password",
    (req: express.Request, res: express.Response) => {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ error: "Missing email" });
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
    },
  );

  // POST /auth/reset-password
  router.post(
    "/reset-password",
    (req: express.Request, res: express.Response) => {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({ error: "Missing token or new password" });
      }

      const resetEntry = resetTokenStore.find((r) => r.token === token);

      if (!resetEntry) {
        return res
          .status(400)
          .json({ error: "Invalid or expired reset token" });
      }

      if (new Date(resetEntry.expiresAt) < new Date()) {
        return res.status(400).json({ error: "Reset token has expired" });
      }

      const user = userStore.find((u) => u.email === resetEntry.email);

      if (!user) {
        return res.status(400).json({ error: "User not found" });
      }

      // Update password
      user.passwordHash = `hashed_${newPassword}`;

      // Remove used reset token
      resetTokenStore = resetTokenStore.filter((r) => r.token !== token);

      // Invalidate all existing tokens for this user
      tokenStore = tokenStore.filter((t) => t.userId !== user.id);

      res.json({ message: "Password reset successful" });
    },
  );

  return router;
}

// Test app setup
let app: Express;

beforeAll(() => {
  app = express();
  app.use(express.json());

  // Mount mock auth router
  // TODO: Replace with actual auth router when implemented
  app.use("/api/auth", createMockAuthRouter());
});

beforeEach(() => {
  // Clear stores before each test
  userStore = [];
  tokenStore = [];
  resetTokenStore = [];
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

  it("should return 400 when missing required fields", async () => {
    const response = await request(app)
      .post("/api/auth/signup")
      .send({ email: testUser.email })
      .expect(400);

    expect(response.body).toHaveProperty("error");
  });

  it("should return 409 when email already exists", async () => {
    // First signup
    await request(app).post("/api/auth/signup").send(testUser).expect(201);

    // Duplicate signup
    const response = await request(app)
      .post("/api/auth/signup")
      .send(testUser)
      .expect(409);

    expect(response.body.error).toMatch(/already exists/i);
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

  it("should return 401 with invalid password", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({
        email: testUser.email,
        password: "WrongPassword123!",
      })
      .expect(401);

    expect(response.body.error).toMatch(/invalid credentials/i);
  });

  it("should return 401 with non-existent email", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({
        email: "nonexistent@example.com",
        password: testUser.password,
      })
      .expect(401);

    expect(response.body.error).toMatch(/invalid credentials/i);
  });

  it("should return 400 when missing credentials", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({ email: testUser.email })
      .expect(400);

    expect(response.body).toHaveProperty("error");
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

  it("should return 401 with invalid refresh token", async () => {
    const response = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: "invalid_token" })
      .expect(401);

    expect(response.body.error).toMatch(/invalid refresh token/i);
  });

  it("should return 400 when refresh token is missing", async () => {
    const response = await request(app)
      .post("/api/auth/refresh")
      .send({})
      .expect(400);

    expect(response.body).toHaveProperty("error");
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

    expect(response.body.error).toMatch(/invalid refresh token/i);
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

  it("should return 401 without token", async () => {
    const response = await request(app).get("/api/auth/me").expect(401);

    expect(response.body.error).toMatch(/unauthorized/i);
  });

  it("should return 401 with invalid token", async () => {
    const response = await request(app)
      .get("/api/auth/me")
      .set("Authorization", "Bearer invalid_token")
      .expect(401);

    expect(response.body.error).toMatch(/invalid or expired token/i);
  });

  it("should return 401 with malformed authorization header", async () => {
    const response = await request(app)
      .get("/api/auth/me")
      .set("Authorization", "InvalidFormat")
      .expect(401);

    expect(response.body.error).toMatch(/unauthorized/i);
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

  it("should return 400 when email is missing", async () => {
    const response = await request(app)
      .post("/api/auth/forgot-password")
      .send({})
      .expect(400);

    expect(response.body).toHaveProperty("error");
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

    expect(response.body.error).toMatch(/invalid credentials/i);
  });

  it("should return 400 with invalid reset token", async () => {
    const response = await request(app)
      .post("/api/auth/reset-password")
      .send({
        token: "invalid_token",
        newPassword: "NewPassword123!",
      })
      .expect(400);

    expect(response.body.error).toMatch(/invalid or expired/i);
  });

  it("should return 400 when missing required fields", async () => {
    const response = await request(app)
      .post("/api/auth/reset-password")
      .send({ token: resetToken })
      .expect(400);

    expect(response.body).toHaveProperty("error");
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

    expect(response.body.error).toMatch(/invalid or expired/i);
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
