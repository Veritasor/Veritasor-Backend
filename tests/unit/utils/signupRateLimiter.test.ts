/**
 * Unit tests for Signup Rate Limiter
 *
 * Tests cover:
 * - Rate limiting per IP
 * - Rate limiting per email
 * - Global rate limiting
 * - Progressive delays
 * - Blocking/unblocking
 * - Cleanup and expiration
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  createSignupRateLimitStore,
  resetSignupRateLimitStore,
  getSignupRateLimitStore,
  DEFAULT_SIGNUP_RATE_LIMIT_CONFIG,
  type SignupRateLimitConfig,
} from "../../../src/utils/signupRateLimiter.js";

describe("SignupRateLimitStore", () => {
  const testConfig: Partial<SignupRateLimitConfig> = {
    windowMs: 60000, // 1 minute for testing
    maxAttemptsPerIp: 3,
    maxAttemptsPerEmail: 2,
    maxGlobalAttempts: 100,
    blockDurationMs: 300000, // 5 minutes
    progressiveDelayThreshold: 2,
    enableProgressiveDelay: true,
  };

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    resetSignupRateLimitStore();
  });

  describe("checkLimit", () => {
    it("should allow signup when under limits", () => {
      const store = createSignupRateLimitStore(testConfig);
      const result = store.checkLimit("192.168.1.1", "test@example.com");

      expect(result.allowed).toBe(true);
      expect(result.remainingAttempts).toBeGreaterThan(0);
      expect(result.isBlocked).toBe(false);
    });

    it("should return rate limit headers", () => {
      const store = createSignupRateLimitStore(testConfig);
      const result = store.checkLimit("192.168.1.1", "test@example.com");

      expect(result.headers).toHaveProperty("X-RateLimit-Limit");
      expect(result.headers).toHaveProperty("X-RateLimit-Remaining");
      expect(result.headers).toHaveProperty("X-RateLimit-Reset");
    });

    it("should deny signup when IP limit exceeded", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      // Record attempts up to limit
      store.recordAttempt(ip, email);
      store.recordAttempt(ip, email);
      store.recordAttempt(ip, email);

      const result = store.checkLimit(ip, "another@example.com");
      expect(result.allowed).toBe(false);
      expect(result.blockReason).toContain("IP");
    });

    it("should deny signup when email limit exceeded", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      // Record attempts up to limit
      store.recordAttempt(ip, email);
      store.recordAttempt(ip, email);

      const result = store.checkLimit("192.168.1.2", email);
      expect(result.allowed).toBe(false);
      expect(result.blockReason).toContain("email");
    });

    it("should deny when global limit exceeded", () => {
      const smallConfig: Partial<SignupRateLimitConfig> = {
        ...testConfig,
        maxGlobalAttempts: 5,
      };
      const store = createSignupRateLimitStore(smallConfig);

      // Simulate multiple signups from different IPs
      for (let i = 0; i < 5; i++) {
        store.recordAttempt(`192.168.1.${i}`, `user${i}@example.com`);
      }

      const result = store.checkLimit("192.168.2.1", "newuser@example.com");
      expect(result.allowed).toBe(false);
      expect(result.blockReason).toContain("Global");
    });

    it("should calculate progressive delay after failures", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      // Record failures to trigger progressive delay
      store.recordFailure(ip, email);
      store.recordFailure(ip, email);

      const result = store.checkLimit(ip, email);
      expect(result.suggestedDelayMs).toBeGreaterThan(0);
    });
  });

  describe("recordAttempt", () => {
    it("should increment attempt count for IP", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      store.recordAttempt(ip, email);
      store.recordAttempt(ip, email);

      const result = store.checkLimit(ip, "another@example.com");
      expect(result.remainingAttempts).toBeLessThan(
        testConfig.maxAttemptsPerIp!,
      );
    });

    it("should increment attempt count for email", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      store.recordAttempt(ip, email);

      const result = store.checkLimit("192.168.1.2", email);
      expect(result.remainingAttempts).toBeLessThan(
        testConfig.maxAttemptsPerEmail!,
      );
    });

    it("should update global count", () => {
      const store = createSignupRateLimitStore(testConfig);

      store.recordAttempt("192.168.1.1", "user1@example.com");
      store.recordAttempt("192.168.1.2", "user2@example.com");

      const stats = store.getStats();
      expect(stats.globalAttempts).toBe(2);
    });
  });

  describe("recordFailure", () => {
    it("should track failed attempts", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      store.recordFailure(ip, email);

      const stats = store.getStats();
      expect(stats.globalFailedAttempts).toBe(1);
    });

    it("should block IP after excessive failures when enabled", () => {
      const store = createSignupRateLimitStore({
        ...testConfig,
        maxAttemptsPerIp: 1,
      });
      const ip = "192.168.1.1";
      const email = "test@example.com";

      // Trigger multiple failures
      for (let i = 0; i < 4; i++) {
        store.recordFailure(ip, `email${i}@example.com`, true);
      }

      const result = store.checkLimit(ip, "new@example.com");
      expect(result.isBlocked).toBe(true);
    });
  });

  describe("recordSuccess", () => {
    it("should reset failure count on success", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      store.recordFailure(ip, email);
      store.recordFailure(ip, email);
      store.recordSuccess(ip, email);

      const result = store.checkLimit(ip, email);
      expect(result.suggestedDelayMs).toBe(0);
    });

    it("should not reset attempt count", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      store.recordAttempt(ip, email);
      store.recordSuccess(ip, email);

      const stats = store.getStats();
      expect(stats.globalAttempts).toBe(1);
    });
  });

  describe("block/unblock", () => {
    it("should block an IP", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";

      store.block("ip", ip, "Suspicious activity");

      const result = store.checkLimit(ip, "test@example.com");
      expect(result.isBlocked).toBe(true);
      // The block reason comes from the store's internal formatting
      expect(result.blockReason).toBeDefined();
    });

    it("should block an email", () => {
      const store = createSignupRateLimitStore(testConfig);
      const email = "spam@example.com";

      store.block("email", email, "Abuse detected");

      const result = store.checkLimit("192.168.1.1", email);
      expect(result.isBlocked).toBe(true);
    });

    it("should unblock an IP", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";

      store.block("ip", ip, "Test block");
      store.unblock("ip", ip);

      const result = store.checkLimit(ip, "test@example.com");
      expect(result.isBlocked).toBe(false);
    });
  });

  describe("getStats", () => {
    it("should return store statistics", () => {
      const store = createSignupRateLimitStore(testConfig);

      store.recordAttempt("192.168.1.1", "user1@example.com");
      store.recordAttempt("192.168.1.2", "user2@example.com");
      store.recordFailure("192.168.1.1", "user1@example.com");
      store.block("ip", "192.168.1.3", "Test");

      const stats = store.getStats();
      expect(stats.ipRecords).toBe(3);
      expect(stats.emailRecords).toBe(2);
      expect(stats.globalAttempts).toBe(2);
      expect(stats.globalFailedAttempts).toBe(1);
      expect(stats.blockedIps).toBe(1);
    });
  });

  describe("cleanup", () => {
    it("should reset limits after window expires", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";
      const email = "test@example.com";

      // Exhaust the limit
      store.recordAttempt(ip, email);
      store.recordAttempt(ip, email);
      store.recordAttempt(ip, email);

      let result = store.checkLimit(ip, "another@example.com");
      expect(result.allowed).toBe(false);

      // Advance time past the window
      vi.advanceTimersByTime(testConfig.windowMs! + 1000);

      // Should be allowed again
      result = store.checkLimit(ip, "another@example.com");
      expect(result.allowed).toBe(true);
    });

    it("should expire blocks after block duration", () => {
      const store = createSignupRateLimitStore(testConfig);
      const ip = "192.168.1.1";

      store.block("ip", ip, "Test block", testConfig.blockDurationMs);

      let result = store.checkLimit(ip, "test@example.com");
      expect(result.isBlocked).toBe(true);

      // Advance time past block duration
      vi.advanceTimersByTime(testConfig.blockDurationMs! + 1000);

      result = store.checkLimit(ip, "test@example.com");
      expect(result.isBlocked).toBe(false);
    });
  });

  describe("reset", () => {
    it("should clear all records", () => {
      const store = createSignupRateLimitStore(testConfig);

      store.recordAttempt("192.168.1.1", "user1@example.com");
      store.recordAttempt("192.168.1.2", "user2@example.com");
      store.block("ip", "192.168.1.3", "Test");

      store.reset();

      const stats = store.getStats();
      expect(stats.ipRecords).toBe(0);
      expect(stats.emailRecords).toBe(0);
      expect(stats.globalAttempts).toBe(0);
      expect(stats.blockedIps).toBe(0);
    });
  });

  describe("stop", () => {
    it("should clear cleanup interval", () => {
      const store = createSignupRateLimitStore(testConfig);
      expect(() => store.stop()).not.toThrow();
    });
  });
});

describe("getSignupRateLimitStore (singleton)", () => {
  afterEach(() => {
    resetSignupRateLimitStore();
  });

  it("should return the same instance on multiple calls", () => {
    const store1 = getSignupRateLimitStore();
    const store2 = getSignupRateLimitStore();
    expect(store1).toBe(store2);
  });

  it("should create new instance after reset", () => {
    const store1 = getSignupRateLimitStore();
    resetSignupRateLimitStore();
    const store2 = getSignupRateLimitStore();
    expect(store1).not.toBe(store2);
  });

  it("should use config on first call only", () => {
    const customConfig: Partial<SignupRateLimitConfig> = {
      maxAttemptsPerIp: 100,
    };
    const store = getSignupRateLimitStore(customConfig);
    expect(store).toBeDefined();
  });
});

describe("createSignupRateLimitStore", () => {
  it("should create independent instances", () => {
    const store1 = createSignupRateLimitStore({ maxAttemptsPerIp: 5 });
    const store2 = createSignupRateLimitStore({ maxAttemptsPerIp: 10 });
    expect(store1).not.toBe(store2);
  });
});
