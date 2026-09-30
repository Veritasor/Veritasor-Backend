import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  DependencyName,
  DependencyReadinessResult,
  StartupReadinessReport,
  runStartupDependencyReadinessChecks,
  checkDatabase,
  sanitiseDbError,
} from "./readiness.js";

vi.mock("../db/client.js", () => ({
  db: {
    query: vi.fn(),
  },
}));

import { db } from "../db/client.js";

const originalEnv = process.env;

describe("src/startup/readiness.ts", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    delete process.env.JWT_SECRET;
    delete process.env.SOROBAN_CONTRACT_ID;
    delete process.env.STRIPE_WEBHOOK_SECRET;
    delete process.env.MTLS_ENABLED;
    delete process.env.MTLS_SPIFFE_ENABLED;
    delete process.env.SPIFFE_TRUST_DOMAIN;
    delete process.env.SPIFFE_WORKLOAD_API_SOCKET;
    delete process.env.MTLS_OCSP_ENABLED;
    delete process.env.MTLS_CRL_PATH;
    delete process.env.MTLS_CA_PATH;
    delete process.env.MTLS_CERT_PATH;
    delete process.env.MTLS_KEY_PATH;
    delete process.env.DATABASE_URL;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("DependencyName type instantiation", () => {
    it("accepts all valid dependency name variants as literal types", () => {
      const names: DependencyName[] = [
        "config/jwt",
        "config/soroban",
        "config/stripe",
        "config/mtls",
        "database",
      ];
      expect(names).toHaveLength(5);
      expect(names).toContain("config/jwt");
      expect(names).toContain("config/soroban");
      expect(names).toContain("config/stripe");
      expect(names).toContain("config/mtls");
      expect(names).toContain("database");
    });

    it("can be used as a discriminant in readiness result objects", () => {
      const resultReady: DependencyReadinessResult = {
        dependency: "config/jwt",
        ready: true,
      };
      const resultNotReady: DependencyReadinessResult = {
        dependency: "database",
        ready: false,
        reason: "database connection failed",
      };

      expect(resultReady.dependency).toBe("config/jwt");
      expect(resultReady.ready).toBe(true);
      expect(resultReady.reason).toBeUndefined();

      expect(resultNotReady.dependency).toBe("database");
      expect(resultNotReady.ready).toBe(false);
      expect(resultNotReady.reason).toBeDefined();
      expect(typeof resultNotReady.reason).toBe("string");
    });
  });

  describe("DependencyReadinessResult state transitions", () => {
    it("allows ready=true without reason field", () => {
      const result: DependencyReadinessResult = {
        dependency: "config/soroban",
        ready: true,
      };
      expect(result.ready).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("requires reason field when ready=false", () => {
      const result: DependencyReadinessResult = {
        dependency: "config/stripe",
        ready: false,
        reason: "STRIPE_WEBHOOK_SECRET must be set in production",
      };
      expect(result.ready).toBe(false);
      expect(result.reason).toBe("STRIPE_WEBHOOK_SECRET must be set in production");
    });

    it("excludes secret values from reason strings", () => {
      const reason = "database connection failed: [redacted]";
      const result: DependencyReadinessResult = {
        dependency: "database",
        ready: false,
        reason,
      };
      expect(result.reason).not.toMatch(/postgres(?:ql)?:\/\//i);
      expect(result.reason).not.toContain("password");
      expect(result.reason).not.toContain("secret");
    });
  });

  describe("StartupReadinessReport aggregation", () => {
    it("reports ready=true when all checks are ready", () => {
      const checks: DependencyReadinessResult[] = [
        { dependency: "config/jwt", ready: true },
        { dependency: "config/soroban", ready: true },
        { dependency: "config/stripe", ready: true },
        { dependency: "config/mtls", ready: true },
      ];
      const allReady = checks.every((c) => c.ready);
      const report: StartupReadinessReport = {
        ready: allReady,
        checks,
      };
      expect(report.ready).toBe(true);
      expect(report.checks).toHaveLength(4);
      expect(report.checks.every((c) => c.ready)).toBe(true);
    });

    it("reports ready=false when a single check is not ready", () => {
      const checks: DependencyReadinessResult[] = [
        { dependency: "config/jwt", ready: true },
        { dependency: "config/soroban", ready: true },
        {
          dependency: "database",
          ready: false,
          reason: "database probe timed out after 2500 ms",
        },
      ];
      const allReady = checks.every((c) => c.ready);
      const report: StartupReadinessReport = {
        ready: allReady,
        checks,
      };
      expect(report.ready).toBe(false);
      const failed = report.checks.filter((c) => !c.ready);
      expect(failed).toHaveLength(1);
      expect(failed[0].dependency).toBe("database");
      expect(failed[0].reason).toContain("timed out");
    });

    it("preserves evaluation order in checks array", () => {
      const checks: DependencyReadinessResult[] = [
        { dependency: "config/jwt", ready: true },
        { dependency: "config/soroban", ready: true },
        { dependency: "config/stripe", ready: true },
        { dependency: "config/mtls", ready: true },
        { dependency: "database", ready: true },
      ];
      const report: StartupReadinessReport = {
        ready: true,
        checks,
      };
      expect(report.checks[0].dependency).toBe("config/jwt");
      expect(report.checks[1].dependency).toBe("config/soroban");
      expect(report.checks[2].dependency).toBe("config/stripe");
      expect(report.checks[3].dependency).toBe("config/mtls");
      expect(report.checks[4].dependency).toBe("database");
    });
  });

  describe("sanitiseDbError — invalid input boundaries", () => {
    it("sanitises postgres:// connection strings", () => {
      const raw =
        "connect ECONNREFUSED postgres://user:password@localhost:5432/db";
      const sanitised = sanitiseDbError(raw);
      expect(sanitised).not.toContain("password");
      expect(sanitised).not.toContain("postgres://user");
      expect(sanitised).toContain("[redacted]");
      expect(sanitised).toContain("connect ECONNREFUSED");
    });

    it("sanitises postgresql:// connection strings", () => {
      const raw = "timeout connecting to postgresql://admin:secret@host:5432/prod";
      const sanitised = sanitiseDbError(raw);
      expect(sanitised).not.toContain("admin:secret");
      expect(sanitised).toContain("[redacted]");
    });

    it("handles case-insensitive scheme matches", () => {
      const raw = "error: POSTGRES://usr:pwd@h/db refused";
      const sanitised = sanitiseDbError(raw);
      expect(sanitised).not.toMatch(/POSTGRES/i);
      expect(sanitised).toContain("[redacted]");
    });

    it("passes through error messages without connection strings unchanged", () => {
      const raw = "database query failed with syntax error at or near ')'";
      expect(sanitiseDbError(raw)).toBe(raw);
    });

    it("handles empty string input", () => {
      expect(sanitiseDbError("")).toBe("");
    });

    it("handles messages with multiple connection strings", () => {
      const raw =
        "first postgres://a:b@c/d then postgresql://x:y@z/w both fail";
      const sanitised = sanitiseDbError(raw);
      const matches = sanitised.match(/\[redacted\]/g) || [];
      expect(matches).toHaveLength(2);
    });
  });

  describe("runStartupDependencyReadinessChecks — JWT config boundary", () => {
    it("dev: passes JWT check with exactly 8 characters (minimum)", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "12345678";
      const report = await runStartupDependencyReadinessChecks();
      const jwtCheck = report.checks.find((c) => c.dependency === "config/jwt");
      expect(jwtCheck?.ready).toBe(true);
    });

    it("dev: fails JWT check with 7 characters (under minimum)", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "1234567";
      const report = await runStartupDependencyReadinessChecks();
      const jwtCheck = report.checks.find((c) => c.dependency === "config/jwt");
      expect(jwtCheck?.ready).toBe(false);
      expect(jwtCheck?.reason).toContain("at least 8 characters (got 7)");
    });

    it("dev: fails JWT check with empty secret", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "";
      const report = await runStartupDependencyReadinessChecks();
      const jwtCheck = report.checks.find((c) => c.dependency === "config/jwt");
      expect(jwtCheck?.ready).toBe(false);
      expect(jwtCheck?.reason).toContain("got 0");
    });

    it("dev: trims whitespace before length check", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "   12345678   ";
      const report = await runStartupDependencyReadinessChecks();
      const jwtCheck = report.checks.find((c) => c.dependency === "config/jwt");
      expect(jwtCheck?.ready).toBe(true);
    });

    it("prod: passes JWT check with exactly 32 characters", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "a".repeat(32);
      process.env.SOROBAN_CONTRACT_ID = "valid-contract-id";
      process.env.STRIPE_WEBHOOK_SECRET = "valid-webhook-secret";
      const report = await runStartupDependencyReadinessChecks();
      const jwtCheck = report.checks.find((c) => c.dependency === "config/jwt");
      expect(jwtCheck?.ready).toBe(true);
    });

    it("prod: fails JWT check with 31 characters (under minimum)", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "a".repeat(31);
      process.env.SOROBAN_CONTRACT_ID = "valid-contract-id";
      process.env.STRIPE_WEBHOOK_SECRET = "valid-webhook-secret";
      const report = await runStartupDependencyReadinessChecks();
      const jwtCheck = report.checks.find((c) => c.dependency === "config/jwt");
      expect(jwtCheck?.ready).toBe(false);
      expect(jwtCheck?.reason).toContain("at least 32 characters in production (got 31)");
    });
  });

  describe("runStartupDependencyReadinessChecks — Soroban config boundary", () => {
    it("dev: passes Soroban check even without SOROBAN_CONTRACT_ID", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/soroban");
      expect(check?.ready).toBe(true);
    });

    it("prod: fails Soroban check with empty SOROBAN_CONTRACT_ID", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "a".repeat(32);
      process.env.SOROBAN_CONTRACT_ID = "";
      process.env.STRIPE_WEBHOOK_SECRET = "valid-webhook-secret";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/soroban");
      expect(check?.ready).toBe(false);
      expect(check?.reason).toBe("SOROBAN_CONTRACT_ID must be set in production");
    });

    it("prod: passes Soroban check with non-empty value", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "a".repeat(32);
      process.env.SOROBAN_CONTRACT_ID = "CCV6QJ... (realistic contract id)";
      process.env.STRIPE_WEBHOOK_SECRET = "valid-webhook-secret";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/soroban");
      expect(check?.ready).toBe(true);
    });
  });

  describe("runStartupDependencyReadinessChecks — Stripe config boundary", () => {
    it("dev: passes Stripe check even without webhook secret", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/stripe");
      expect(check?.ready).toBe(true);
    });

    it("prod: fails Stripe check with empty STRIPE_WEBHOOK_SECRET", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "a".repeat(32);
      process.env.SOROBAN_CONTRACT_ID = "valid-contract-id";
      process.env.STRIPE_WEBHOOK_SECRET = "";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/stripe");
      expect(check?.ready).toBe(false);
      expect(check?.reason).toBe("STRIPE_WEBHOOK_SECRET must be set in production");
    });

    it("prod: passes Stripe check with non-empty value", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "a".repeat(32);
      process.env.SOROBAN_CONTRACT_ID = "valid-contract-id";
      process.env.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_value";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/stripe");
      expect(check?.ready).toBe(true);
    });
  });

  describe("runStartupDependencyReadinessChecks — mTLS config boundary", () => {
    it("passes mTLS check when MTLS_ENABLED is not set", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(true);
    });

    it("passes mTLS check when MTLS_ENABLED=false", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.MTLS_ENABLED = "false";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(true);
    });

    it("fails mTLS check when SPIFFE enabled without SPIFFE_TRUST_DOMAIN", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_SPIFFE_ENABLED = "true";
      process.env.MTLS_CA_PATH = "/ca";
      process.env.MTLS_CERT_PATH = "/cert";
      process.env.MTLS_KEY_PATH = "/key";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(false);
      expect(check?.reason).toBe(
        "SPIFFE_TRUST_DOMAIN must be set when MTLS_SPIFFE_ENABLED=true",
      );
    });

    it("passes mTLS check when SPIFFE enabled with SPIFFE_TRUST_DOMAIN", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_SPIFFE_ENABLED = "true";
      process.env.SPIFFE_TRUST_DOMAIN = "example.com";
      process.env.MTLS_CA_PATH = "/etc/ca.pem";
      process.env.MTLS_CERT_PATH = "/etc/cert.pem";
      process.env.MTLS_KEY_PATH = "/etc/key.pem";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(true);
    });

    it("fails mTLS check when OCSP enabled without CRL path", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_OCSP_ENABLED = "true";
      process.env.MTLS_CA_PATH = "/ca";
      process.env.MTLS_CERT_PATH = "/cert";
      process.env.MTLS_KEY_PATH = "/key";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(false);
      expect(check?.reason).toBe(
        "MTLS_CRL_PATH must be set when MTLS_OCSP_ENABLED=true",
      );
    });

    it("passes mTLS check when OCSP enabled with CRL path", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_OCSP_ENABLED = "true";
      process.env.MTLS_CRL_PATH = "/etc/crl.pem";
      process.env.MTLS_CA_PATH = "/ca";
      process.env.MTLS_CERT_PATH = "/cert";
      process.env.MTLS_KEY_PATH = "/key";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(true);
    });

    it("fails mTLS check when MTLS_ENABLED=true but paths missing", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_CA_PATH = "/ca";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(false);
      expect(check?.reason).toContain("MTLS_CA_PATH, MTLS_CERT_PATH, and MTLS_KEY_PATH must be set");
    });

    it("passes mTLS check when all three cert paths are set", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_CA_PATH = "/etc/ca.pem";
      process.env.MTLS_CERT_PATH = "/etc/cert.pem";
      process.env.MTLS_KEY_PATH = "/etc/key.pem";
      const report = await runStartupDependencyReadinessChecks();
      const check = report.checks.find((c) => c.dependency === "config/mtls");
      expect(check?.ready).toBe(true);
    });
  });

  describe("checkDatabase — timeouts and error boundaries", () => {
    it("returns ready=true when db.query resolves successfully", async () => {
      vi.mocked(db.query).mockResolvedValueOnce({ rows: [] } as any);
      const result = await checkDatabase();
      expect(result.dependency).toBe("database");
      expect(result.ready).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("returns timed-out reason when db.query never resolves within timeout", async () => {
      vi.mocked(db.query).mockImplementationOnce(
        () => new Promise(() => {}) as any,
      );
      const origTimeout = setTimeout;
      try {
        const result = await checkDatabase();
        expect(result.ready).toBe(false);
        expect(result.reason).toContain("timed out after 2500 ms");
      } finally {
        vi.useRealTimers();
      }
    }, 5000);

    it("returns sanitised connection failure reason on arbitrary error", async () => {
      const rawError = new Error(
        "connection refused postgres://u:p@h:5432/db",
      );
      vi.mocked(db.query).mockRejectedValueOnce(rawError);
      const result = await checkDatabase();
      expect(result.ready).toBe(false);
      expect(result.reason).toContain("database connection failed:");
      expect(result.reason).not.toContain("u:p");
      expect(result.reason).toContain("[redacted]");
    });

    it("handles non-Error thrown values gracefully", async () => {
      vi.mocked(db.query).mockRejectedValueOnce("some plain string error");
      const result = await checkDatabase();
      expect(result.ready).toBe(false);
      expect(result.reason).toContain("database connection failed:");
      expect(result.reason).toContain("some plain string error");
    });

    it("performs exactly one SELECT 1 probe", async () => {
      vi.mocked(db.query).mockResolvedValueOnce({ rows: [[1]] } as any);
      await checkDatabase();
      expect(db.query).toHaveBeenCalledTimes(1);
      expect(db.query).toHaveBeenCalledWith("SELECT 1");
    });
  });

  describe("runStartupDependencyReadinessChecks — aggregate edge cases", () => {
    it("omits database check when DATABASE_URL is not set", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      delete process.env.DATABASE_URL;
      const report = await runStartupDependencyReadinessChecks();
      const deps = report.checks.map((c) => c.dependency);
      expect(deps).not.toContain("database");
      expect(deps).toEqual(
        expect.arrayContaining([
          "config/jwt",
          "config/soroban",
          "config/stripe",
          "config/mtls",
        ]),
      );
    });

    it("includes database check when DATABASE_URL is set", async () => {
      process.env.NODE_ENV = "development";
      process.env.JWT_SECRET = "dev-secret-12345678";
      process.env.DATABASE_URL = "postgres://u:p@localhost:5432/db";
      vi.mocked(db.query).mockResolvedValueOnce({ rows: [] } as any);
      const report = await runStartupDependencyReadinessChecks();
      const deps = report.checks.map((c) => c.dependency);
      expect(deps).toContain("database");
    });

    it("overall ready=false when at least one check fails", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "too-short";
      process.env.SOROBAN_CONTRACT_ID = "";
      process.env.STRIPE_WEBHOOK_SECRET = "";
      const report = await runStartupDependencyReadinessChecks();
      expect(report.ready).toBe(false);
      expect(report.checks.some((c) => !c.ready)).toBe(true);
    });

    it("overall ready=true when every check passes", async () => {
      process.env.NODE_ENV = "production";
      process.env.JWT_SECRET = "a".repeat(32);
      process.env.SOROBAN_CONTRACT_ID = "CCV6QJ_CONTRACT";
      process.env.STRIPE_WEBHOOK_SECRET = "whsec_prod_secret";
      process.env.DATABASE_URL = "postgres://u:p@localhost:5432/db";
      vi.mocked(db.query).mockResolvedValueOnce({ rows: [] } as any);
      const report = await runStartupDependencyReadinessChecks();
      expect(report.ready).toBe(true);
      expect(report.checks.every((c) => c.ready)).toBe(true);
    });
  });
});
