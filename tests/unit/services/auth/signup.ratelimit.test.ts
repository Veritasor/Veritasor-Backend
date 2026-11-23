import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import request from "supertest";
import express from "express";
import {
  signup,
  SignupError,
  type SignupRequest,
} from "../../../../src/services/auth/signup.js";
import {
  clearAllUsers,
} from "../../../../src/repositories/userRepository.js";
import {
  resetSignupRateLimitStore,
  getSignupRateLimitStore,
} from "../../../../src/utils/signupRateLimiter.js";
import { authRouter } from "../../../../src/routes/auth.js";
import { errorHandler } from "../../../../src/middleware/errorHandler.js";
import { resetRateLimiterStore } from "../../../../src/middleware/rateLimiter.js";

// Silence logger output during tests
vi.mock("../../../../src/utils/logger.js", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

function validRequest(overrides: Partial<SignupRequest> = {}): SignupRequest {
  return {
    email: "test@example.com",
    password: "SecureP@ss123",
    ipAddress: "198.51.100.1",
    ...overrides,
  };
}

describe("Signup rate limiting and timing", () => {
  let app: express.Express;

  beforeEach(() => {
    vi.useFakeTimers();
    clearAllUsers();
    resetSignupRateLimitStore();
    resetRateLimiterStore();

    app = express();
    app.use(express.json());
    app.use("/api/auth", authRouter);
    app.use(errorHandler);
  });

  afterEach(() => {
    vi.useRealTimers();
    clearAllUsers();
    resetSignupRateLimitStore();
    resetRateLimiterStore();
  });

  it("resolves within 1 s of simulated time with status 429 and Retry-After header", async () => {
    const rateLimitConfig = {
      rateLimit: {
        maxAttemptsPerIp: 1,
        windowMs: 60 * 60 * 1000, // 1 hour
      },
    };
    const ip = "198.51.100.42";

    // First attempt succeeds
    await signup(validRequest({ email: "user1@example.com", ipAddress: ip }), rateLimitConfig);

    // Second attempt should be rate limited immediately without sleeping for the whole window
    const startTime = Date.now();
    let thrownError: SignupError | undefined;

    try {
      await signup(validRequest({ email: "user2@example.com", ipAddress: ip }), rateLimitConfig);
    } catch (err) {
      thrownError = err as SignupError;
    }

    const elapsed = Date.now() - startTime;

    expect(thrownError).toBeInstanceOf(SignupError);
    expect(thrownError?.statusCode).toBe(429);
    expect(thrownError?.type).toBe("RATE_LIMITED");
    expect(elapsed).toBeLessThanOrEqual(1000);
    expect(typeof thrownError?.retryAfterMs).toBe("number");
    expect(thrownError!.retryAfterMs!).toBeGreaterThan(0);
  });

  it("Retry-After equals ceil(suggestedDelayMs/1000)", async () => {
    const windowMs = 60 * 60 * 1000;
    const rateLimitConfig = {
      rateLimit: {
        maxAttemptsPerIp: 1,
        windowMs,
      },
    };
    const ip = "198.51.100.43";

    await signup(validRequest({ email: "user1@example.com", ipAddress: ip }), rateLimitConfig);

    // Advance 500ms
    vi.advanceTimersByTime(500);

    const check = getSignupRateLimitStore(rateLimitConfig.rateLimit).checkLimit(ip, "user2@example.com");
    expect(check.allowed).toBe(false);

    let thrownError: SignupError | undefined;
    try {
      await signup(validRequest({ email: "user2@example.com", ipAddress: ip }), rateLimitConfig);
    } catch (err) {
      thrownError = err as SignupError;
    }

    expect(thrownError).toBeDefined();
    expect(thrownError?.retryAfterMs).toBe(check.suggestedDelayMs);

    const expectedRetryAfter = Math.ceil(thrownError!.retryAfterMs! / 1000);
    const retryAfterHeader = check.headers["Retry-After"];
    expect(retryAfterHeader).toBe(String(expectedRetryAfter));
  });

  it("burst over route limiter threshold on /signup gets 429 from middleware without calling signup()", async () => {
    // Route limiter threshold is 10 requests per sliding window for authRouteRateLimiters.signup
    const requests = [];
    for (let i = 0; i < 10; i++) {
      const res = await request(app)
        .post("/api/auth/signup")
        .set("X-Forwarded-For", "203.0.113.50")
        .send({
          email: `burst${i}@example.com`,
          password: "SecureP@ss123",
        });
      // Requests within max limit pass through middleware (and may succeed or fail validation)
      expect(res.status).not.toBe(429);
    }

    // 11th request exceeds route limiter threshold (max = 10)
    const burstRes = await request(app)
      .post("/api/auth/signup")
      .set("X-Forwarded-For", "203.0.113.50")
      .send({
        email: "burst11@example.com",
        password: "SecureP@ss123",
      });

    expect(burstRes.status).toBe(429);
    expect(burstRes.body).toHaveProperty("error", "Too many requests, please try again later.");
    expect(burstRes.headers).toHaveProperty("retry-after");
    expect(burstRes.headers["x-ratelimit-bucket"]).toBe("auth:signup");
  });
});
