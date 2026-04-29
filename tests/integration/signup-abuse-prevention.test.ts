/**
 * Integration tests for Signup Abuse Prevention
 *
 * Tests cover:
 * - Email validation (disposable, format, suspicious patterns)
 * - Password strength requirements
 * - Rate limiting (per IP, per email, global)
 * - Honeypot detection
 * - Timing attack prevention
 * - Complete signup flows with abuse prevention
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import request from "supertest";
import express, { Express } from "express";
import {
  signup,
  SignupError,
  checkSignupAvailability,
  getSignupRateLimitHeaders,
} from "../../src/services/auth/signup.js";
import {
  resetSignupRateLimitStore,
  getSignupRateLimitStore,
  createSignupRateLimitStore,
} from "../../src/utils/signupRateLimiter.js";
import {
  deleteUser,
  findUserByEmail,
} from "../../src/repositories/userRepository.js";
import { authRouter } from "../../src/routes/auth.js";

/**
 * Helper to create a test express app with auth router
 */
function createTestApp(): Express {
  const app = express();
  app.use(express.json());
  app.use("/api/auth", authRouter);
  return app;
}

/**
 * Valid test credentials that pass all abuse prevention checks
 */
const validUser = {
  email: "valid@example.com",
  password: "SecureP@ssw0rd123",
};

const validUser2 = {
  email: "another@example.com",
  password: "AnotherP@ss456!",
};

describe("Signup Service - Abuse Prevention", () => {
  beforeEach(() => {
    resetSignupRateLimitStore();
  });

  afterEach(async () => {
    const user = await findUserByEmail(validUser.email);
    if (user) await deleteUser(user.id);
    const user2 = await findUserByEmail(validUser2.email);
    if (user2) await deleteUser(user2.id);
    resetSignupRateLimitStore();
  });

  describe("Email Validation", () => {
    it("should accept valid email addresses", async () => {
      const result = await signup({
        email: "valid.user+tag@example.com",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
      });

      expect(result).toBeDefined();
      expect(result.user.email).toBe("valid.user@example.com");

      await deleteUser(result.user.id);
    });

    it("should reject invalid email formats", async () => {
      await expect(
        signup({
          email: "invalid-email",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow(SignupError);
    });

    it("should reject email without domain", async () => {
      await expect(
        signup({
          email: "user@",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow(SignupError);
    });

    it("should reject email without TLD", async () => {
      await expect(
        signup({
          email: "user@example",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow(SignupError);
    });

    it("should normalize email to lowercase", async () => {
      const result = await signup({
        email: "UPPERCASE@EXAMPLE.COM",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
      });

      expect(result.user.email).toBe("uppercase@example.com");
      await deleteUser(result.user.id);
    });

    it("should trim whitespace from email", async () => {
      const result = await signup({
        email: "  trimmed@example.com  ",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
      });

      expect(result.user.email).toBe("trimmed@example.com");
      await deleteUser(result.user.id);
    });
  });

  describe("Disposable Email Blocking", () => {
    it("should reject known disposable email domains", async () => {
      const disposableDomains = [
        "user@10minutemail.com",
        "user@tempmail.com",
        "user@guerrillamail.com",
        "user@mailinator.com",
      ];

      for (const email of disposableDomains) {
        await expect(
          signup({
            email,
            password: "SecureP@ss123!",
            ipAddress: "192.168.1.1",
          }),
        ).rejects.toThrow("Disposable email addresses are not allowed");
      }
    });

    it("should reject disposable email with case variations", async () => {
      await expect(
        signup({
          email: "User@10MINUTEMAIL.COM",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow("Disposable email addresses are not allowed");
    });
  });

  describe("Password Strength", () => {
    it("should accept strong passwords", async () => {
      const strongPasswords = [
        "SecureP@ssw0rd123!",
        "MyV3ry$tr0ngP@ss",
        "C0mpl3x!Pass#2024",
      ];

      for (const pwd of strongPasswords) {
        const result = await signup({
          email: `user${Date.now()}@example.com`,
          password: pwd,
          ipAddress: "192.168.1.1",
        });
        expect(result).toBeDefined();
        await deleteUser(result.user.id);
      }
    });

    it("should reject short passwords", async () => {
      await expect(
        signup({
          email: "user@example.com",
          password: "Short1!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow("Password does not meet security requirements");
    });

    it("should reject passwords without uppercase", async () => {
      await expect(
        signup({
          email: "user@example.com",
          password: "lowercase123!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow("Password does not meet security requirements");
    });

    it("should reject passwords without lowercase", async () => {
      await expect(
        signup({
          email: "user@example.com",
          password: "UPPERCASE123!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow("Password does not meet security requirements");
    });

    it("should reject passwords without numbers", async () => {
      await expect(
        signup({
          email: "user@example.com",
          password: "NoNumbers!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow("Password does not meet security requirements");
    });

    it("should reject passwords without special characters", async () => {
      await expect(
        signup({
          email: "user@example.com",
          password: "NoSpecialChars123",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow("Password does not meet security requirements");
    });

    it("should reject common weak passwords", async () => {
      // SignupError message is generic; the "too common" reason is in .details
      await expect(
        signup({
          email: "user@example.com",
          password: "Password123!",
          ipAddress: "192.168.1.1",
        }),
      ).rejects.toThrow("Password does not meet security requirements");
    });
  });

  describe("Rate Limiting", () => {
    it("should track signup attempts per IP", async () => {
      const ip = "192.168.1.100";
      const rateLimiter = createSignupRateLimitStore({ maxAttemptsPerIp: 3 });

      for (let i = 0; i < 3; i++) {
        const result = await signup(
          {
            email: `user${i}@example.com`,
            password: "SecureP@ss123!",
            ipAddress: ip,
          },
          { rateLimit: { maxAttemptsPerIp: 3 } },
        );
        await deleteUser(result.user.id);
      }

      const availability = checkSignupAvailability(ip, "user4@example.com", {
        maxAttemptsPerIp: 3,
      });
      expect(availability.available).toBe(false);
    });

    it("should track signup attempts per email", async () => {
      const ip = "192.168.1.101";
      const email = "test@example.com";

      await signup(
        {
          email,
          password: "SecureP@ss123!",
          ipAddress: ip,
        },
        { rateLimit: { maxAttemptsPerEmail: 1 } },
      ).catch(() => {});

      const user = await findUserByEmail(email);
      if (user) await deleteUser(user.id);

      const availability = checkSignupAvailability("192.168.1.102", email, {
        maxAttemptsPerEmail: 1,
      });
      expect(availability.available).toBe(false);
    });

    it("should return rate limit headers", () => {
      const ip = "192.168.1.1";
      const email = "test@example.com";

      const headers = getSignupRateLimitHeaders(ip, email);

      expect(headers).toHaveProperty("X-RateLimit-Limit");
      expect(headers).toHaveProperty("X-RateLimit-Remaining");
      expect(headers).toHaveProperty("X-RateLimit-Reset");
    });
  });

  describe("Honeypot Detection", () => {
    it("should reject requests with filled honeypot field", async () => {
      await expect(
        signup({
          email: "user@example.com",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
          website: "spam-bot-value", // Honeypot filled
        }),
      ).rejects.toThrow(SignupError);
    });

    it("should accept requests with empty honeypot field", async () => {
      const result = await signup({
        email: "honeypot@example.com",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
        website: "", // Empty honeypot - OK
      });

      expect(result).toBeDefined();
      await deleteUser(result.user.id);
    });
  });

  describe("Duplicate Email Handling", () => {
    it("should reject duplicate email registration", async () => {
      const result = await signup({
        email: "duplicate@example.com",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
      });

      await expect(
        signup({
          email: "duplicate@example.com",
          password: "DifferentP@ss456!",
          ipAddress: "192.168.1.2",
        }),
      ).rejects.toThrow(SignupError);

      await deleteUser(result.user.id);
    });

    it("should use generic error message for duplicate email (no enumeration)", async () => {
      const result = await signup({
        email: "enum@example.com",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
      });

      try {
        await signup({
          email: "enum@example.com",
          password: "DifferentP@ss456!",
          ipAddress: "192.168.1.2",
        });
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(SignupError);
        const signupError = error as SignupError;
        expect(signupError.message).not.toContain("already exists");
        expect(signupError.statusCode).toBe(400);
      }

      await deleteUser(result.user.id);
    });
  });

  describe("Signup Error Types", () => {
    it("should return correct error type for invalid email", async () => {
      try {
        await signup({
          email: "invalid",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
        });
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(SignupError);
        expect((error as SignupError).type).toBe("EMAIL_INVALID");
      }
    });

    it("should return correct error type for disposable email", async () => {
      try {
        await signup({
          email: "user@10minutemail.com",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
        });
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(SignupError);
        expect((error as SignupError).type).toBe("EMAIL_DISPOSABLE");
      }
    });

    it("should return correct error type for weak password", async () => {
      try {
        await signup({
          email: "user@example.com",
          password: "weak",
          ipAddress: "192.168.1.1",
        });
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(SignupError);
        expect((error as SignupError).type).toBe("PASSWORD_WEAK");
      }
    });

    it("should return correct error type for honeypot trigger", async () => {
      try {
        await signup({
          email: "user@example.com",
          password: "SecureP@ss123!",
          ipAddress: "192.168.1.1",
          website: "bot",
        });
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(SignupError);
        expect((error as SignupError).type).toBe("HONEYPOT_TRIGGERED");
      }
    });
  });

  describe("Full Signup Flow", () => {
    it("should complete successful signup with all validations", async () => {
      const result = await signup({
        email: "success@example.com",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
      });

      expect(result).toBeDefined();
      expect(result.user).toBeDefined();
      expect(result.user.email).toBe("success@example.com");
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.user).not.toHaveProperty("passwordHash");

      await deleteUser(result.user.id);
    });

    it("should create user in repository", async () => {
      const email = "repo@example.com";
      const result = await signup({
        email,
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.1",
      });

      const foundUser = await findUserByEmail(email);
      expect(foundUser).toBeDefined();
      expect(foundUser!.email).toBe(email);

      await deleteUser(result.user.id);
    });
  });
});

describe("Auth Router - Signup Endpoint", () => {
  let app: Express;

  beforeEach(() => {
    app = createTestApp();
    resetSignupRateLimitStore();
  });

  afterEach(() => {
    resetSignupRateLimitStore();
  });

  describe("POST /api/auth/signup", () => {
    it("should return 201 for successful signup", async () => {
      const response = await request(app)
        .post("/api/auth/signup")
        .set("X-Forwarded-For", "192.168.1.1")
        .send({
          email: "router@example.com",
          password: "SecureP@ss123!",
        });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty("accessToken");
      expect(response.body).toHaveProperty("refreshToken");
      expect(response.body.user.email).toBe("router@example.com");

      const user = await findUserByEmail("router@example.com");
      if (user) await deleteUser(user.id);
    });

    it("should return rate limit headers", async () => {
      const response = await request(app)
        .post("/api/auth/signup")
        .set("X-Forwarded-For", "192.168.1.2")
        .send({
          email: "headers@example.com",
          password: "SecureP@ss123!",
        });

      expect(response.headers["x-ratelimit-limit"]).toBeDefined();
      expect(response.headers["x-ratelimit-remaining"]).toBeDefined();
      expect(response.headers["x-ratelimit-reset"]).toBeDefined();

      const user = await findUserByEmail("headers@example.com");
      if (user) await deleteUser(user.id);
    });

    it("should return 400 for invalid email", async () => {
      const response = await request(app).post("/api/auth/signup").send({
        email: "invalid-email",
        password: "SecureP@ss123!",
      });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty("error");
      expect(response.body).toHaveProperty("type", "EMAIL_INVALID");
    });

    it("should return 400 for disposable email", async () => {
      const response = await request(app).post("/api/auth/signup").send({
        email: "user@10minutemail.com",
        password: "SecureP@ss123!",
      });

      expect(response.status).toBe(400);
      expect(response.body.type).toBe("EMAIL_DISPOSABLE");
    });

    it("should return 400 for weak password", async () => {
      const response = await request(app).post("/api/auth/signup").send({
        email: "user@example.com",
        password: "weak",
      });

      expect(response.status).toBe(400);
      expect(response.body.type).toBe("PASSWORD_WEAK");
    });

    it("should return 400 for honeypot trigger", async () => {
      const response = await request(app).post("/api/auth/signup").send({
        email: "user@example.com",
        password: "SecureP@ss123!",
        website: "spam-bot",
      });

      expect(response.status).toBe(400);
      expect(response.body.type).toBe("HONEYPOT_TRIGGERED");
    });

    it("should use client IP from X-Forwarded-For", async () => {
      const response = await request(app)
        .post("/api/auth/signup")
        .set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
        .send({
          email: "proxy@example.com",
          password: "SecureP@ss123!",
        });

      expect(response.status).toBe(201);

      const user = await findUserByEmail("proxy@example.com");
      if (user) await deleteUser(user.id);
    });
  });

  describe("GET /api/auth/signup/availability", () => {
    it("should return availability status", async () => {
      const response = await request(app)
        .get("/api/auth/signup/availability")
        .set("X-Forwarded-For", "192.168.1.50")
        .query({ email: "check@example.com" });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("available");
      expect(response.body).toHaveProperty("remainingAttempts");
      expect(response.body).toHaveProperty("resetIn");
    });

    it("should show limited availability after max attempts", async () => {
      const ip = "192.168.1.51";

      const rateLimiter = getSignupRateLimitStore({ maxAttemptsPerIp: 2 });

      rateLimiter.recordAttempt(ip, "user1@example.com");
      rateLimiter.recordAttempt(ip, "user2@example.com");

      const availability = checkSignupAvailability(ip, "user3@example.com", {
        maxAttemptsPerIp: 2,
      });
      expect(availability.available).toBe(false);
    });
  });
});

describe("Schema Validation Edge Cases", () => {
  beforeEach(() => {
    resetSignupRateLimitStore();
  });

  it("should reject missing email with VALIDATION_ERROR and details", async () => {
    try {
      await signup({
        // @ts-expect-error - intentionally omitting email
        email: undefined,
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.10",
      });
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SignupError);
      const e = error as SignupError;
      expect(e.type).toBe("VALIDATION_ERROR");
      expect(e.statusCode).toBe(400);
      expect(e.details).toBeDefined();
      expect(e.details!.some((d) => d.includes("email"))).toBe(true);
    }
  });

  it("should reject missing password with VALIDATION_ERROR and details", async () => {
    try {
      await signup({
        email: "valid@example.com",
        // @ts-expect-error - intentionally omitting password
        password: undefined,
        ipAddress: "192.168.1.11",
      });
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SignupError);
      const e = error as SignupError;
      expect(e.type).toBe("VALIDATION_ERROR");
      expect(e.details!.some((d) => d.includes("password"))).toBe(true);
    }
  });

  it("should reject null email with VALIDATION_ERROR", async () => {
    await expect(
      signup({
        // @ts-expect-error - testing runtime null
        email: null,
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.12",
      }),
    ).rejects.toMatchObject({ type: "VALIDATION_ERROR" });
  });

  it("should reject empty-string email with VALIDATION_ERROR", async () => {
    await expect(
      signup({
        email: "",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.13",
      }),
    ).rejects.toMatchObject({ type: "VALIDATION_ERROR" });
  });

  it("should reject empty-string password with VALIDATION_ERROR", async () => {
    await expect(
      signup({
        email: "user@example.com",
        password: "",
        ipAddress: "192.168.1.14",
      }),
    ).rejects.toMatchObject({ type: "VALIDATION_ERROR" });
  });

  it("should reject non-string email with VALIDATION_ERROR", async () => {
    await expect(
      signup({
        // @ts-expect-error - simulating malformed JSON body
        email: 12345,
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.15",
      }),
    ).rejects.toMatchObject({ type: "VALIDATION_ERROR" });
  });

  it("should reject non-string password with VALIDATION_ERROR", async () => {
    await expect(
      signup({
        email: "user@example.com",
        // @ts-expect-error - simulating malformed JSON body
        password: { not: "a string" },
        ipAddress: "192.168.1.16",
      }),
    ).rejects.toMatchObject({ type: "VALIDATION_ERROR" });
  });

  it("should reject whitespace-only email with VALIDATION_ERROR", async () => {
    await expect(
      signup({
        email: "    ",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.17",
      }),
    ).rejects.toMatchObject({ type: "VALIDATION_ERROR" });
  });

  it("should report all missing fields together when both email and password are absent", async () => {
    try {
      await signup({
        // @ts-expect-error - both missing
        email: undefined,
        // @ts-expect-error - both missing
        password: undefined,
        ipAddress: "192.168.1.18",
      });
      expect.fail("Should have thrown");
    } catch (error) {
      const e = error as SignupError;
      expect(e.type).toBe("VALIDATION_ERROR");
      expect(e.details!.length).toBeGreaterThanOrEqual(2);
    }
  });

  it("should reject email exceeding RFC 5321 max length", async () => {
    const longLocal = "a".repeat(250);
    const tooLongEmail = `${longLocal}@example.com`;
    await expect(
      signup({
        email: tooLongEmail,
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.19",
      }),
    ).rejects.toMatchObject({ type: "EMAIL_INVALID" });
  });

  it("should populate details on EMAIL_INVALID errors for client diagnostics", async () => {
    try {
      await signup({
        email: "not-an-email",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.20",
      });
      expect.fail("Should have thrown");
    } catch (error) {
      const e = error as SignupError;
      expect(e.type).toBe("EMAIL_INVALID");
      expect(e.details).toBeDefined();
      expect(e.details!.length).toBeGreaterThan(0);
    }
  });

  it("should populate details on PASSWORD_WEAK errors for client diagnostics", async () => {
    try {
      await signup({
        email: "weakpw@example.com",
        password: "short",
        ipAddress: "192.168.1.21",
      });
      expect.fail("Should have thrown");
    } catch (error) {
      const e = error as SignupError;
      expect(e.type).toBe("PASSWORD_WEAK");
      expect(e.details).toBeDefined();
      expect(e.details!.length).toBeGreaterThan(0);
    }
  });

  it("should populate details on HONEYPOT_TRIGGERED errors", async () => {
    try {
      await signup({
        email: "user@example.com",
        password: "SecureP@ss123!",
        ipAddress: "192.168.1.22",
        website: "spam",
      });
      expect.fail("Should have thrown");
    } catch (error) {
      const e = error as SignupError;
      expect(e.type).toBe("HONEYPOT_TRIGGERED");
      expect(e.details).toBeDefined();
    }
  });
});

describe("Idempotency Expectations", () => {
  beforeEach(() => {
    resetSignupRateLimitStore();
  });

  it("should produce a single user when concurrent signups race the same email", async () => {
    const email = "idempotent@example.com";
    const password = "SecureP@ss123!";

    const results = await Promise.allSettled([
      signup({ email, password, ipAddress: "192.168.2.1" }),
      signup({ email, password, ipAddress: "192.168.2.2" }),
      signup({ email, password, ipAddress: "192.168.2.3" }),
    ]);

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");

    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(2);

    for (const r of rejected) {
      const reason = (r as PromiseRejectedResult).reason as SignupError;
      expect(reason).toBeInstanceOf(SignupError);
      expect(reason.type).toBe("EMAIL_EXISTS");
      // Generic message: must NOT leak that the address is already registered
      expect(reason.message).not.toMatch(/already exists|registered/i);
    }

    const user = await findUserByEmail(email);
    expect(user).not.toBeNull();
    if (user) await deleteUser(user.id);
  });

  it("should treat second sequential signup with same email as duplicate", async () => {
    const email = "sequential@example.com";
    const first = await signup({
      email,
      password: "SecureP@ss123!",
      ipAddress: "192.168.2.10",
    });

    try {
      await signup({
        email,
        password: "SecureP@ss123!",
        ipAddress: "192.168.2.11",
      });
      expect.fail("Should have thrown");
    } catch (error) {
      const e = error as SignupError;
      expect(e.type).toBe("EMAIL_EXISTS");
      expect(e.statusCode).toBe(400);
    }

    await deleteUser(first.user.id);
  });
});

describe("Timing Attack Prevention", () => {
  it("should take consistent time for existing vs non-existing email", async () => {
    const existingEmail = "timing-test@example.com";
    const nonExistingEmail = "nonexistent@example.com";

    const result = await signup({
      email: existingEmail,
      password: "SecureP@ss123!",
      ipAddress: "192.168.1.1",
    });

    const start1 = Date.now();
    try {
      await signup({
        email: existingEmail,
        password: "DifferentP@ss456!",
        ipAddress: "192.168.1.2",
      });
    } catch {}
    const time1 = Date.now() - start1;

    const start2 = Date.now();
    try {
      await signup({
        email: nonExistingEmail,
        password: "DifferentP@ss456!",
        ipAddress: "192.168.1.3",
      });
    } catch {}
    const time2 = Date.now() - start2;

    expect(Math.abs(time1 - time2)).toBeLessThan(100);

    await deleteUser(result.user.id);
  });
});
