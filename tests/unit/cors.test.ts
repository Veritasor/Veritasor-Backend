import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

/**
 * Unit tests for getAllowedOrigins() in src/config/index.ts.
 *
 * These tests verify the origin resolution logic in isolation:
 * - ALLOWED_ORIGINS set → parsed array
 * - ALLOWED_ORIGINS unset + production → []
 * - ALLOWED_ORIGINS unset + development → "*"
 * - Edge cases: extra spaces, trailing commas, empty segments
 */

describe("getAllowedOrigins", () => {
  beforeEach(() => {
    vi.resetModules();
    process.env.DATABASE_URL = "postgres://localhost:5432/db";
  });

  afterEach(() => {
    delete process.env.ALLOWED_ORIGINS;
    delete process.env.NODE_ENV;
  });

  async function loadGetAllowedOrigins() {
    const mod = await import("../../src/config/index.js") as typeof import("../../src/config/index.js");
    return mod.getAllowedOrigins;
  }

  it("should return parsed array when ALLOWED_ORIGINS is set", async () => {
    process.env.ALLOWED_ORIGINS = "https://a.com,https://b.com";
    const getAllowedOrigins = await loadGetAllowedOrigins();
    const result = getAllowedOrigins();

    expect(result).toEqual(["https://a.com", "https://b.com"]);
  });

  it("should trim whitespace from origins", async () => {
    process.env.ALLOWED_ORIGINS = "  https://a.com , https://b.com  ";
    const getAllowedOrigins = await loadGetAllowedOrigins();
    const result = getAllowedOrigins();

    expect(result).toEqual(["https://a.com", "https://b.com"]);
  });

  it("should filter out empty segments from trailing commas", async () => {
    process.env.ALLOWED_ORIGINS = "https://a.com,,https://b.com,";
    const getAllowedOrigins = await loadGetAllowedOrigins();
    const result = getAllowedOrigins();

    expect(result).toEqual(["https://a.com", "https://b.com"]);
  });

  it("should fail in production when ALLOWED_ORIGINS is unset", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.ALLOWED_ORIGINS;
    process.env.JWT_SECRET = "a-very-long-and-secure-secret-that-is-over-32-chars";
    
    await expect(loadGetAllowedOrigins()).rejects.toThrow("Invalid environment configuration");
  });

  it('should return "*" in development when ALLOWED_ORIGINS is unset', async () => {
    process.env.NODE_ENV = "development";
    delete process.env.ALLOWED_ORIGINS;
    const getAllowedOrigins = await loadGetAllowedOrigins();
    const result = getAllowedOrigins();

    expect(result).toBe("*");
  });

  it("should return parsed array even in development if ALLOWED_ORIGINS is set", async () => {
    process.env.NODE_ENV = "development";
    process.env.ALLOWED_ORIGINS = "http://localhost:3001";
    const getAllowedOrigins = await loadGetAllowedOrigins();
    const result = getAllowedOrigins();

    expect(result).toEqual(["http://localhost:3001"]);
  });

  it("should handle a single origin", async () => {
    process.env.ALLOWED_ORIGINS = "https://only-one.com";
    const getAllowedOrigins = await loadGetAllowedOrigins();
    const result = getAllowedOrigins();

    expect(result).toEqual(["https://only-one.com"]);
  });
});
