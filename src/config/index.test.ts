import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { envSchema, ConfigValidationError } from "./index.js";

describe("src/config/index.ts", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("ConfigValidationError", () => {
    it("should create an error with the correct name and message", async () => {
      const { ConfigValidationError } = await import("./index.js");
      const err = new ConfigValidationError("test error");
      expect(err).toBeInstanceOf(Error);
      expect(err.name).toBe("ConfigValidationError");
      expect(err.message).toBe("test error");
    });
  });

  describe("envSchema", () => {
    it("should successfully parse a valid development environment", () => {
      const env = {
        DATABASE_URL: "postgres://user:pass@localhost:5432/db",
      };
      const parsed = envSchema.parse(env);
      expect(parsed.NODE_ENV).toBe("development");
    });

    it("should throw if DATABASE_URL is missing or invalid", () => {
      expect(() => envSchema.parse({})).toThrow(/DATABASE_URL environment variable is required/);
      expect(() => envSchema.parse({ DATABASE_URL: "not-a-url" })).toThrow(/must be a valid URL/);
    });

    describe("production rules", () => {
      it("should throw if ALLOWED_ORIGINS is not set in production", () => {
        const env = {
          NODE_ENV: "production",
          DATABASE_URL: "postgres://user:pass@localhost:5432/db",
        };
        const result = envSchema.safeParse(env);
        expect(result.success).toBe(false);
        if (!result.success) {
          const issues = result.error.issues;
          expect(issues).toEqual(expect.arrayContaining([
            expect.objectContaining({ path: ["ALLOWED_ORIGINS"], message: "ALLOWED_ORIGINS must be set in production" })
          ]));
        }
      });

      it("should throw if JWT_SECRET is short in production with env loader", () => {
        const env = {
          NODE_ENV: "production",
          DATABASE_URL: "postgres://user:pass@localhost:5432/db",
          ALLOWED_ORIGINS: "https://app.example.com",
          SECRET_LOADER: "env",
          JWT_SECRET: "short",
        };
        const result = envSchema.safeParse(env);
        expect(result.success).toBe(false);
        if (!result.success) {
           expect(result.error.issues).toEqual(expect.arrayContaining([
             expect.objectContaining({ path: ["JWT_SECRET"] })
           ]));
        }
      });

      it("should throw if SECRET_FILE_PATH is missing with file loader", () => {
        const env = {
          NODE_ENV: "production",
          DATABASE_URL: "postgres://user:pass@localhost:5432/db",
          ALLOWED_ORIGINS: "https://app.example.com",
          SECRET_LOADER: "file",
        };
        const result = envSchema.safeParse(env);
        expect(result.success).toBe(false);
        if (!result.success) {
           expect(result.error.issues).toEqual(expect.arrayContaining([
             expect.objectContaining({ path: ["SECRET_FILE_PATH"] })
           ]));
        }
      });

      it("should throw if VAULT_BASE_URL or VAULT_SECRET_PATH are missing with vault loader", () => {
        const env = {
          NODE_ENV: "production",
          DATABASE_URL: "postgres://user:pass@localhost:5432/db",
          ALLOWED_ORIGINS: "https://app.example.com",
          SECRET_LOADER: "vault",
        };
        const result = envSchema.safeParse(env);
        expect(result.success).toBe(false);
        if (!result.success) {
           expect(result.error.issues).toEqual(expect.arrayContaining([
             expect.objectContaining({ path: ["VAULT_BASE_URL"] }),
             expect.objectContaining({ path: ["VAULT_SECRET_PATH"] })
           ]));
        }
      });
    });
  });

  describe("getAllowedOrigins", () => {
    it("should return array of origins when ALLOWED_ORIGINS is set", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.ALLOWED_ORIGINS = "https://a.com, https://b.com ";
      const { getAllowedOrigins } = await import("./index.js");
      expect(getAllowedOrigins()).toEqual(["https://a.com", "https://b.com"]);
    });

    it("should return '*' in development if ALLOWED_ORIGINS is unset", async () => {
      process.env.NODE_ENV = "development";
      process.env.DATABASE_URL = "postgres://localhost/db";
      delete process.env.ALLOWED_ORIGINS;
      const { getAllowedOrigins } = await import("./index.js");
      expect(getAllowedOrigins()).toBe("*");
    });
  });

  describe("Module initialization invalid inputs and primary state transitions", () => {
    it("should throw ConfigValidationError for invalid process.env on load", async () => {
      delete process.env.DATABASE_URL;
      await expect(import("./index.js")).rejects.toThrow(ConfigValidationError);
    });

    it("should set a default JWT_SECRET in development if missing", async () => {
      process.env.NODE_ENV = "development";
      process.env.DATABASE_URL = "postgres://localhost/db";
      delete process.env.JWT_SECRET;
      const { config } = await import("./index.js");
      expect(config.jwtSecret).toBe("default_dev_secret_for_local_testing_only");
    });

    it("should throw ConfigValidationError for invalid boolean env var", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.REDIS_TLS = "maybe";
      await expect(import("./index.js")).rejects.toThrow(ConfigValidationError);
    });

    it("should parse valid boolean env var correctly", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.REDIS_TLS = "yes";
      const { config } = await import("./index.js");
      expect(config.redis.tls).toBe(true);
    });

    it("should throw ConfigValidationError for invalid positive integer env var", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.PGPOOL_MAX = "-5";
      await expect(import("./index.js")).rejects.toThrow(ConfigValidationError);
    });

    it("should parse valid positive integer env var correctly", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.PGPOOL_MAX = "15";
      const { config } = await import("./index.js");
      expect(config.db.poolMax).toBe(15);
    });

    it("should throw ConfigValidationError for invalid decimal env var", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA = "5.0"; // Max is 1.0
      await expect(import("./index.js")).rejects.toThrow(ConfigValidationError);
    });

    it("should parse valid decimal env var correctly", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA = "0.5";
      const { config } = await import("./index.js");
      expect(config.soroban.adaptiveBatch.ewmaAlpha).toBe(0.5);
    });

    it("should throw ConfigValidationError if SPIFFE_TRUST_DOMAIN is missing when MTLS_SPIFFE_ENABLED=true", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_SPIFFE_ENABLED = "true";
      delete process.env.SPIFFE_TRUST_DOMAIN;
      await expect(import("./index.js")).rejects.toThrow(ConfigValidationError);
    });

    it("should throw ConfigValidationError if MTLS paths are missing when MTLS_ENABLED=true and SPIFFE is not true", async () => {
      process.env.DATABASE_URL = "postgres://localhost/db";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_SPIFFE_ENABLED = "false";
      delete process.env.MTLS_CA_PATH;
      await expect(import("./index.js")).rejects.toThrow(ConfigValidationError);
    });
  });
});
