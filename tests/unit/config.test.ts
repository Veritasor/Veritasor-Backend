import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

/**
 * Unit tests for the configuration module.
 * 
 * These tests verify:
 * - Fail fast on missing DATABASE_URL
 * - Fail fast on invalid URL for DATABASE_URL
 * - Fail fast on missing ALLOWED_ORIGINS in production
 * - Fail fast on weak JWT_SECRET in production
 * - Fallback to default dev secret in development
 * - Correct enum validation for STELLAR_NETWORK
 */

describe("Config Module Validation", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    // Clear relevant env vars
    delete process.env.DATABASE_URL;
    delete process.env.NODE_ENV;
    delete process.env.JWT_SECRET;
    delete process.env.ALLOWED_ORIGINS;
    delete process.env.STELLAR_NETWORK;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  async function loadConfig() {
    return await import("../../src/config/index.js");
  }

  it("should throw ConfigValidationError when DATABASE_URL is missing", async () => {
    process.env.NODE_ENV = "development";
    // DATABASE_URL is missing
    
    await expect(loadConfig()).rejects.toThrow("Invalid environment configuration");
  });

  it("should throw when DATABASE_URL is not a valid URL", async () => {
    process.env.NODE_ENV = "development";
    process.env.DATABASE_URL = "not-a-url";
    
    await expect(loadConfig()).rejects.toThrow("Invalid environment configuration");
  });

  it("should succeed in development with a valid DATABASE_URL and missing JWT_SECRET", async () => {
    process.env.NODE_ENV = "development";
    process.env.DATABASE_URL = "postgres://localhost:5432/db";
    
    const { config } = await loadConfig();
    expect(config.databaseUrl).toBe("postgres://localhost:5432/db");
    expect(config.jwtSecret).toBe("default_dev_secret_for_local_testing_only");
  });

  it("should throw in production if ALLOWED_ORIGINS is missing", async () => {
    process.env.NODE_ENV = "production";
    process.env.DATABASE_URL = "postgres://localhost:5432/db";
    process.env.JWT_SECRET = "a-very-long-and-secure-secret-that-is-over-32-chars";
    
    await expect(loadConfig()).rejects.toThrow("Invalid environment configuration");
  });

  it("should throw in production if JWT_SECRET is less than 32 chars", async () => {
    process.env.NODE_ENV = "production";
    process.env.DATABASE_URL = "postgres://localhost:5432/db";
    process.env.ALLOWED_ORIGINS = "https://example.com";
    process.env.JWT_SECRET = "too-short";
    
    await expect(loadConfig()).rejects.toThrow("Invalid environment configuration");
  });

  it("should throw if STELLAR_NETWORK is invalid", async () => {
    process.env.NODE_ENV = "development";
    process.env.DATABASE_URL = "postgres://localhost:5432/db";
    process.env.STELLAR_NETWORK = "invalid-network";
    
    await expect(loadConfig()).rejects.toThrow("Invalid environment configuration");
  });

  it("should accept valid STELLAR_NETWORK values", async () => {
    process.env.NODE_ENV = "development";
    process.env.DATABASE_URL = "postgres://localhost:5432/db";
    process.env.STELLAR_NETWORK = "public";
    
    const { config } = await loadConfig();
    expect(config.stellar.network).toBe("public");
  });
});
