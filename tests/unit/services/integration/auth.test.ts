/**
 * @file auth.test.ts
 * @description Integration tests for config validation. Verifies that the
 * app fails fast with clear error messages when critical env vars are missing,
 * and starts successfully when all required vars are present.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { sendPasswordResetEmail } from "../../../src/services/email/sendReset.js";
import { getMailTransport } from "../../../src/services/email/client.js";

vi.mock("../../../src/services/email/client.js", () => ({
  getMailTransport: vi.fn(),
}));

vi.mock("../../../src/utils/logger.js", () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Store original env so we can restore it after each test
const ORIGINAL_ENV = { ...process.env };

/**
 * Dynamically re-imports the config module with a fresh module cache,
 * so each test gets a clean validation run against the current process.env.
 */
async function loadConfig() {
  // Clear module cache to force re-execution of validateConfig()
  const mod = await import("../../src/config/index.js?" + Date.now());
  return mod.config;
}

describe("Config Validation", () => {
  beforeEach(() => {
    // Reset env to a known valid state before each test
    process.env = {
      ...ORIGINAL_ENV,
      NODE_ENV: "test",
      PORT: "3000",
      DATABASE_URL: "postgresql://user:pass@localhost:5432/veritasor_test",
      JWT_SECRET: "supersecretjwttokenthatisfortycharacterslong!!",
      RAZORPAY_KEY_ID: "rzp_test_abc123",
      RAZORPAY_KEY_SECRET: "test_secret_xyz",
      RAZORPAY_WEBHOOK_SECRET: "webhook_secret_abc",
    };
  });

  afterEach(() => {
    // Restore original env after each test
    process.env = ORIGINAL_ENV;
  });

  // ── Happy path ────────────────────────────────────────────────────────────

  it("should load config successfully when all required env vars are present", async () => {
    const config = await loadConfig();
    expect(config.DATABASE_URL).toBe(
      "postgresql://user:pass@localhost:5432/veritasor_test"
    );
    expect(config.JWT_SECRET).toBeDefined();
    expect(config.RAZORPAY_KEY_ID).toBe("rzp_test_abc123");
    expect(config.PORT).toBe(3000); // Should be coerced to number
    expect(config.NODE_ENV).toBe("test");
  });

  // ── Missing vars ──────────────────────────────────────────────────────────

  it("should throw when DATABASE_URL is missing", async () => {
    delete process.env.DATABASE_URL;
    await expect(loadConfig()).rejects.toThrow("DATABASE_URL");
  });

  it("should throw when JWT_SECRET is missing", async () => {
    delete process.env.JWT_SECRET;
    await expect(loadConfig()).rejects.toThrow("JWT_SECRET");
  });

  it("should throw when RAZORPAY_KEY_ID is missing", async () => {
    delete process.env.RAZORPAY_KEY_ID;
    await expect(loadConfig()).rejects.toThrow("RAZORPAY_KEY_ID");
  });

  it("should throw when RAZORPAY_KEY_SECRET is missing", async () => {
    delete process.env.RAZORPAY_KEY_SECRET;
    await expect(loadConfig()).rejects.toThrow("RAZORPAY_KEY_SECRET");
  });

  it("should throw when RAZORPAY_WEBHOOK_SECRET is missing", async () => {
    delete process.env.RAZORPAY_WEBHOOK_SECRET;
    await expect(loadConfig()).rejects.toThrow("RAZORPAY_WEBHOOK_SECRET");
  });

  // ── Invalid values ────────────────────────────────────────────────────────

  it("should throw when JWT_SECRET is shorter than 32 characters", async () => {
    process.env.JWT_SECRET = "tooshort";
    await expect(loadConfig()).rejects.toThrow(
      "JWT_SECRET must be at least 32 characters"
    );
  });

  it("should throw when NODE_ENV is an invalid value", async () => {
    process.env.NODE_ENV = "staging"; // not in enum
    await expect(loadConfig()).rejects.toThrow();
  });

  // ── Defaults ──────────────────────────────────────────────────────────────

  it("should default PORT to 3000 when not set", async () => {
    delete process.env.PORT;
    const config = await loadConfig();
    expect(config.PORT).toBe(3000);
  });

  it("should default NODE_ENV to development when not set", async () => {
    delete process.env.NODE_ENV;
    const config = await loadConfig();
    expect(config.NODE_ENV).toBe("development");
  });

  // ── Error message quality ─────────────────────────────────────────────────

  it("should report ALL missing vars in a single error, not just the first", async () => {
    delete process.env.DATABASE_URL;
    delete process.env.JWT_SECRET;
    delete process.env.RAZORPAY_KEY_ID;

    try {
      await loadConfig();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.message).toContain("DATABASE_URL");
      expect(err.message).toContain("JWT_SECRET");
      expect(err.message).toContain("RAZORPAY_KEY_ID");
    }
  });
});

describe("Email Service: sendPasswordResetEmail", () => {
  const mockSendMail = vi.fn();
  
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getMailTransport).mockReturnValue({
      sendMail: mockSendMail,
    } as any);
  });

  it("should send email with valid inputs", async () => {
    mockSendMail.mockResolvedValueOnce({});
    const result = await sendPasswordResetEmail(
      "user@example.com",
      "https://veritasor.com/reset?token=123"
    );
    
    expect(result.error).toBeUndefined();
    expect(mockSendMail).toHaveBeenCalledWith(expect.objectContaining({
      to: "user@example.com",
      subject: "Reset your password",
    }));
  });

  it("should reject invalid email format", async () => {
    const result = await sendPasswordResetEmail(
      "not-an-email",
      "https://veritasor.com/reset"
    );
    
    expect(result.error?.message).toBe("Invalid input");
    expect(mockSendMail).not.toHaveBeenCalled();
  });

  it("should reject unsafe URL protocols", async () => {
    const result = await sendPasswordResetEmail(
      "user@example.com",
      "javascript:alert(1)"
    );
    
    expect(result.error?.message).toBe("Invalid input");
    expect(mockSendMail).not.toHaveBeenCalled();
  });

  it("should escape HTML characters in the reset link", async () => {
    mockSendMail.mockResolvedValueOnce({});
    const maliciousLink = "https://example.com/reset?token=123&<b>tag</b>";
    
    await sendPasswordResetEmail("user@example.com", maliciousLink);
    
    const callArgs = mockSendMail.mock.calls[0][0];
    expect(callArgs.html).toContain("https://example.com/reset?token=123&amp;&lt;b&gt;tag&lt;/b&gt;");
    expect(callArgs.html).not.toContain("<b>");
  });

  it("should return retryable: true on temporary SMTP errors", async () => {
    const timeoutError: any = new Error("Connection timeout");
    timeoutError.code = "ETIMEDOUT";
    mockSendMail.mockRejectedValueOnce(timeoutError);
    
    const result = await sendPasswordResetEmail(
      "user@example.com",
      "https://example.com/reset"
    );
    
    expect(result.retryable).toBe(true);
  });
});