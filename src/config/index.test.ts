import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigValidationError, envSchema, rawEnvSchema } from "./index.js";

const currentDir = path.dirname(fileURLToPath(import.meta.url));

describe("mTLS and Redis Config Validation", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    process.env = {
      ...originalEnv,
      NODE_ENV: "test",
      DATABASE_URL: "postgres://localhost:5432/test_db",
    };
    // Clean up mTLS and Redis environment variables
    delete process.env.MTLS_ENABLED;
    delete process.env.MTLS_SPIFFE_ENABLED;
    delete process.env.SPIFFE_TRUST_DOMAIN;
    delete process.env.MTLS_CA_PATH;
    delete process.env.MTLS_CERT_PATH;
    delete process.env.MTLS_KEY_PATH;
    delete process.env.MTLS_CN_ALLOWLIST;
    delete process.env.MTLS_SPIFFE_ID_ALLOWLIST;
    delete process.env.SPIFFE_WORKLOAD_API_SOCKET;
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
    delete process.env.REDIS_TLS;
    delete process.env.REDIS_FORCE_SINGLE_NODE;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  async function loadConfig() {
    return await import("./index.js");
  }

  describe("mTLS configuration", () => {
    it("populates config.mtls and sets enabled=true when MTLS_ENABLED=true and cert paths are provided", async () => {
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_CA_PATH = "/certs/ca.pem";
      process.env.MTLS_CERT_PATH = "/certs/server.pem";
      process.env.MTLS_KEY_PATH = "/certs/server-key.pem";
      process.env.MTLS_CN_ALLOWLIST = "client1.internal, client2.internal";
      process.env.MTLS_SPIFFE_ID_ALLOWLIST = "spiffe://example.org/ns/prod/sa/app";

      const { config } = await loadConfig();

      expect(config.mtls.enabled).toBe(true);
      expect(config.mtls.caPath).toBe("/certs/ca.pem");
      expect(config.mtls.certPath).toBe("/certs/server.pem");
      expect(config.mtls.keyPath).toBe("/certs/server-key.pem");
      expect(config.mtls.cnAllowlist).toEqual(["client1.internal", "client2.internal"]);
      expect(config.mtls.spiffeIdAllowlist).toEqual(["spiffe://example.org/ns/prod/sa/app"]);
      expect(config.mtls.spiffe.enabled).toBe(false);
    });

    it("throws ConfigValidationError at import time when MTLS_ENABLED=true without cert paths", async () => {
      process.env.MTLS_ENABLED = "true";
      // No MTLS_CA_PATH, MTLS_CERT_PATH, or MTLS_KEY_PATH

      await expect(loadConfig()).rejects.toThrow(ConfigValidationError);
      await expect(loadConfig()).rejects.toThrow(
        "MTLS_CA_PATH, MTLS_CERT_PATH, and MTLS_KEY_PATH must be set when MTLS_ENABLED=true and MTLS_SPIFFE_ENABLED is not true",
      );
    });

    it("throws ConfigValidationError when MTLS_ENABLED=true and MTLS_SPIFFE_ENABLED=true without SPIFFE_TRUST_DOMAIN", async () => {
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_SPIFFE_ENABLED = "true";
      // No SPIFFE_TRUST_DOMAIN

      await expect(loadConfig()).rejects.toThrow(ConfigValidationError);
      await expect(loadConfig()).rejects.toThrow(
        "SPIFFE_TRUST_DOMAIN must be set when MTLS_SPIFFE_ENABLED=true",
      );
    });

    it("succeeds when MTLS_ENABLED=true and MTLS_SPIFFE_ENABLED=true with SPIFFE_TRUST_DOMAIN", async () => {
      process.env.MTLS_ENABLED = "true";
      process.env.MTLS_SPIFFE_ENABLED = "true";
      process.env.SPIFFE_TRUST_DOMAIN = "veritasor.internal";
      process.env.SPIFFE_WORKLOAD_API_SOCKET = "unix:///run/spire/sockets/agent.sock";

      const { config } = await loadConfig();

      expect(config.mtls.enabled).toBe(true);
      expect(config.mtls.spiffe.enabled).toBe(true);
      expect(config.mtls.spiffe.trustDomain).toBe("veritasor.internal");
      expect(config.mtls.spiffe.workloadApiSocket).toBe("unix:///run/spire/sockets/agent.sock");
    });

    it("defaults mtls.enabled to false when MTLS_ENABLED is unset", async () => {
      const { config } = await loadConfig();
      expect(config.mtls.enabled).toBe(false);
    });
  });

  describe("Redis configuration", () => {
    it("populates REDIS_URL, REDIS_CLUSTER_NODES, REDIS_TLS=1 and REDIS_FORCE_SINGLE_NODE=true in config.redis", async () => {
      process.env.REDIS_URL = "redis://127.0.0.1:6379";
      process.env.REDIS_CLUSTER_NODES = "node1:7000,node2:7001";
      process.env.REDIS_TLS = "1";
      process.env.REDIS_FORCE_SINGLE_NODE = "true";

      const { config } = await loadConfig();

      expect(config.redis.url).toBe("redis://127.0.0.1:6379");
      expect(config.redis.clusterNodes).toBe("node1:7000,node2:7001");
      expect(config.redis.tls).toBe(true);
      expect(config.redis.forceSingleNode).toBe(true);
    });

    it("accepts rediss:// URLs for REDIS_URL", async () => {
      process.env.REDIS_URL = "rediss://secure-redis.internal:6380";

      const { config } = await loadConfig();
      expect(config.redis.url).toBe("rediss://secure-redis.internal:6380");
    });

    it("rejects non-redis protocol URLs for REDIS_URL", async () => {
      process.env.REDIS_URL = "http://localhost:6379";

      await expect(loadConfig()).rejects.toThrow(ConfigValidationError);
    });

    it("rejects malformed URLs for REDIS_URL", async () => {
      process.env.REDIS_URL = "not-a-valid-url";

      await expect(loadConfig()).rejects.toThrow(ConfigValidationError);
    });
  });

  describe("Hardening against schema drift", () => {
    it("ensures every parsedEnv.X access in src/config/index.ts is declared in envSchema", () => {
      const configSource = fs.readFileSync(path.join(currentDir, "index.ts"), "utf-8");
      const matches = [...configSource.matchAll(/parsedEnv\.([A-Z0-9_]+)/g)];
      const accessedKeys = new Set(matches.map((m) => m[1]));
      const declaredKeys = new Set(Object.keys(rawEnvSchema.shape));

      for (const key of accessedKeys) {
        expect(
          declaredKeys.has(key),
          `parsedEnv.${key} is accessed in src/config/index.ts but not declared in envSchema`,
        ).toBe(true);
      }
    });
  });
});
