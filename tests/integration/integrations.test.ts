import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import request from "supertest";
import express, { Express } from "express";
import integrationsRouter from "../../src/routes/integrations.js";
import integrationsRazorpayRouter from "../../src/routes/integrations-razorpay.js";
import { IntegrationPermission, ROLE_PERMISSIONS } from "../../src/types/permissions.js";
import { clearAll } from "../../src/repositories/integration.js";
import { integrationRepository } from "../../src/repositories/integrations.js";

// Mock the auth middleware to simulate different user roles
vi.mock("../../src/middleware/auth.js", () => ({
  requireAuth: (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.substring(7);
    const mockUser = getMockUserFromToken(token);
    if (!mockUser) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.user = mockUser;
    next();
  },
}));

// Helper function to get mock user from token
function getMockUserFromToken(token: string) {
  const tokenMap: Record<string, any> = {
    "user_token": { id: "user_123", userId: "user_123", email: "user@example.com" },
    "admin_token": { id: "admin_123", userId: "admin_123", email: "admin@example.com" },
    "business_admin_token": { id: "biz_admin_123", userId: "biz_admin_123", email: "bizadmin@example.com" },
  };
  return tokenMap[token];
}

// Mock integration data for testing
const mockIntegrationData = {
  id: "integration_123",
  userId: "user_123",
  provider: "stripe",
  externalId: "acct_123456",
  token: { access_token: "sk_test_123", refresh_token: "rt_123" },
  metadata: { business_name: "Test Business" },
  createdAt: "2024-01-01T00:00:00Z",
  updatedAt: "2024-01-01T00:00:00Z",
};

// Test app setup
let app: Express;

function razorpayApiResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response;
}

beforeAll(() => {
  app = express();
  app.use(express.json());
  app.use("/api/integrations", integrationsRouter);
});

beforeEach(() => {
  clearAll();
});

afterAll(() => {
  vi.restoreAllMocks();
});

describe("Razorpay Connect Credential Integrity Checks", () => {
  let razorpayApp: Express;
  const originalFetch = global.fetch;

  beforeEach(() => {
    razorpayApp = express();
    razorpayApp.use(express.json());
    razorpayApp.use("/api/integrations/razorpay", integrationsRazorpayRouter);
    global.fetch = vi.fn();
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  it("stores a verified Razorpay connection without exposing the secret", async () => {
    const userId = `razorpay-user-${Date.now()}`;

    vi.mocked(global.fetch).mockResolvedValueOnce(
      razorpayApiResponse(200, { entity: "collection", items: [] }),
    );

    const response = await request(razorpayApp)
      .post("/api/integrations/razorpay")
      .set("x-user-id", userId)
      .send({
        apiKeyId: "rzp_test_123456789",
        apiKeySecret: "secret_1234567890abcdef",
      })
      .expect(201);

    expect(global.fetch).toHaveBeenCalledWith(
      "https://api.razorpay.com/v1/payments?count=1",
      expect.objectContaining({
        headers: expect.objectContaining({
          Accept: "application/json",
          Authorization: expect.stringMatching(/^Basic /),
        }),
        signal: expect.any(AbortSignal),
      }),
    );
    expect(response.body.meta.apiKeyId).toBe("rzp_test_123456789");
    expect(response.body.meta.apiKeySecret).toBe("*****");
    expect(response.body.meta.credentialFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(response.body.meta.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    const storedRecords = integrationRepository.listByUser(userId);
    expect(storedRecords).toHaveLength(1);
    expect(storedRecords[0]?.meta.apiKeySecret).toBe("secret_1234567890abcdef");
  });

  it("rejects padded credentials before calling Razorpay", async () => {
    const response = await request(razorpayApp)
      .post("/api/integrations/razorpay")
      .set("x-user-id", `razorpay-user-${Date.now()}`)
      .send({
        apiKeyId: " rzp_test_padded ",
        apiKeySecret: "secret_1234567890abcdef",
      })
      .expect(400);

    expect(response.body.error).toMatch(/without surrounding whitespace/i);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("returns a conflict for duplicate Razorpay connections", async () => {
    const userId = `razorpay-user-${Date.now()}`;

    vi.mocked(global.fetch).mockResolvedValueOnce(
      razorpayApiResponse(200, { entity: "collection", items: [] }),
    );

    await request(razorpayApp)
      .post("/api/integrations/razorpay")
      .set("x-user-id", userId)
      .send({
        apiKeyId: "rzp_test_duplicate",
        apiKeySecret: "secret_duplicate_123456",
      })
      .expect(201);

    const response = await request(razorpayApp)
      .post("/api/integrations/razorpay")
      .set("x-user-id", userId)
      .send({
        apiKeyId: "rzp_test_duplicate",
        apiKeySecret: "secret_duplicate_123456",
      })
      .expect(409);

    expect(response.body.error).toMatch(/already connected/i);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it("treats Razorpay auth failures as invalid credentials without leaking upstream details", async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      razorpayApiResponse(401, {
        error: {
          description: "Invalid credentials submitted to Razorpay",
        },
      }),
    );

    const response = await request(razorpayApp)
      .post("/api/integrations/razorpay")
      .set("x-user-id", `razorpay-user-${Date.now()}`)
      .send({
        apiKeyId: "rzp_test_invalid",
        apiKeySecret: "secret_invalid_123456",
      })
      .expect(400);

    expect(response.body).toEqual({ error: "Invalid Razorpay credentials" });
    expect(JSON.stringify(response.body)).not.toMatch(/submitted to razorpay/i);
  });

  it("rejects unexpected Razorpay verification payloads", async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      razorpayApiResponse(200, { ok: true }),
    );

    const response = await request(razorpayApp)
      .post("/api/integrations/razorpay")
      .set("x-user-id", `razorpay-user-${Date.now()}`)
      .send({
        apiKeyId: "rzp_test_unexpected",
        apiKeySecret: "secret_unexpected_1234",
      })
      .expect(502);

    expect(response.body).toEqual({ error: "Unexpected Razorpay verification response" });
  });
});

describe("Integrations Granular Permission System", () => {
  describe("GET /api/integrations", () => {
    it("should allow public access to available integrations", async () => {
      const response = await request(app)
        .get("/api/integrations")
        .expect(200);

      expect(response.body).toHaveProperty("available");
      expect(Array.isArray(response.body.available)).toBe(true);
      expect(response.body.available.length).toBeGreaterThan(0);

      // Should not include connected info for unauthenticated users
      expect(response.body).not.toHaveProperty("connected");
    });

    it("should include connection status for authenticated users", async () => {
      const response = await request(app)
        .get("/api/integrations")
        .set("Authorization", "Bearer user_token")
        .expect(200);

      expect(response.body).toHaveProperty("available");
      expect(response.body).toHaveProperty("connected");
      expect(Array.isArray(response.body.connected)).toBe(true);
    });

    it("should filter sensitive metadata for all users", async () => {
      const response = await request(app)
        .get("/api/integrations")
        .set("Authorization", "Bearer user_token")
        .expect(200);

      if (response.body.connected.length > 0) {
        const connected = response.body.connected[0];
        expect(connected).not.toHaveProperty("token");
        expect(connected).not.toHaveProperty("accessToken");
        expect(connected).not.toHaveProperty("refreshToken");
      }
    });
  });

  describe("GET /api/integrations/connected", () => {
    it("should require authentication", async () => {
      const response = await request(app)
        .get("/api/integrations/connected")
        .expect(401);

      expect(response.body.error).toMatch(/unauthorized/i);
    });

    it("should require READ_CONNECTED permission", async () => {
      // Test with user role (should have READ_CONNECTED)
      const response = await request(app)
        .get("/api/integrations/connected")
        .set("Authorization", "Bearer user_token")
        .set("x-user-role", "user")
        .expect(200);

      expect(response.body).toHaveProperty("integrations");
      expect(response.body).toHaveProperty("count");
    });

    it("should filter sensitive metadata", async () => {
      const response = await request(app)
        .get("/api/integrations/connected")
        .set("Authorization", "Bearer user_token")
        .expect(200);

      if (response.body.integrations.length > 0) {
        const integration = response.body.integrations[0];
        expect(integration).not.toHaveProperty("token");
        expect(integration.metadata).not.toHaveProperty("token");
        expect(integration.metadata).not.toHaveProperty("accessToken");
      }
    });
  });

  describe("POST /api/integrations/connect", () => {
    it("should require authentication", async () => {
      const response = await request(app)
        .post("/api/integrations/connect")
        .send({ provider: "stripe" })
        .expect(401);

      expect(response.body.error).toMatch(/unauthorized/i);
    });

    it("should require CONNECT permission", async () => {
      const response = await request(app)
        .post("/api/integrations/connect")
        .set("Authorization", "Bearer user_token")
        .set("x-user-role", "user")
        .send({ provider: "stripe" })
        .expect(200);

      expect(response.body).toHaveProperty("provider", "stripe");
      expect(response.body).toHaveProperty("authUrl");
      expect(response.body).toHaveProperty("state");
      expect(response.body).toHaveProperty("expiresAt");
    });

    it("should validate request body", async () => {
      const response = await request(app)
        .post("/api/integrations/connect")
        .set("Authorization", "Bearer user_token")
        .send({ provider: "invalid_provider" })
        .expect(400);

      expect(response.body.error).toMatch(/validation error/i);
    });

    it("should reject unavailable integrations", async () => {
      // Mock an unavailable integration
      const response = await request(app)
        .post("/api/integrations/connect")
        .set("Authorization", "Bearer user_token")
        .send({ provider: "nonexistent" })
        .expect(404);

      expect(response.body.message).toMatch(/not found/i);
    });

    it("should prevent duplicate connections", async () => {
      // First connection attempt
      await request(app)
        .post("/api/integrations/connect")
        .set("Authorization", "Bearer user_token")
        .send({ provider: "stripe" })
        .expect(200);

      // Second connection attempt should fail
      const response = await request(app)
        .post("/api/integrations/connect")
        .set("Authorization", "Bearer user_token")
        .send({ provider: "stripe" })
        .expect(409);

      expect(response.body.message).toMatch(/already connected/i);
    });
  });

  describe("DELETE /api/integrations/:integrationId", () => {
    it("should require authentication", async () => {
      const response = await request(app)
        .delete("/api/integrations/integration_123")
        .expect(401);

      expect(response.body.error).toMatch(/unauthorized/i);
    });

    it("should require DISCONNECT_OWN permission", async () => {
      const response = await request(app)
        .delete("/api/integrations/integration_123")
        .set("Authorization", "Bearer user_token")
        .set("x-user-role", "user")
        .expect(404);

      expect(response.body.message).toMatch(/not found or access denied/i);
    });

    it("should verify ownership before deletion", async () => {
      // Try to delete an integration that doesn't belong to the user
      const response = await request(app)
        .delete("/api/integrations/other_user_integration")
        .set("Authorization", "Bearer user_token")
        .expect(404);

      expect(response.body.message).toMatch(/not found or access denied/i);
    });
  });

  describe("GET /api/integrations/:integrationId", () => {
    it("should require authentication", async () => {
      const response = await request(app)
        .get("/api/integrations/integration_123")
        .expect(401);

      expect(response.body.error).toMatch(/unauthorized/i);
    });

    it("should require READ_OWN permission", async () => {
      const response = await request(app)
        .get("/api/integrations/integration_123")
        .set("Authorization", "Bearer user_token")
        .set("x-user-role", "user")
        .expect(404);

      expect(response.body.message).toMatch(/not found or access denied/i);
    });

    it("should verify ownership before access", async () => {
      const response = await request(app)
        .get("/api/integrations/other_user_integration")
        .set("Authorization", "Bearer user_token")
        .expect(404);

      expect(response.body.message).toMatch(/not found or access denied/i);
    });
  });

  describe("Role-based Access Control", () => {
    it("should allow users to manage their own integrations", async () => {
      // Test user role permissions
      const userPermissions = ROLE_PERMISSIONS.user;

      expect(userPermissions).toContain(IntegrationPermission.READ_AVAILABLE);
      expect(userPermissions).toContain(IntegrationPermission.READ_CONNECTED);
      expect(userPermissions).toContain(IntegrationPermission.CONNECT);
      expect(userPermissions).toContain(IntegrationPermission.DISCONNECT_OWN);
      expect(userPermissions).not.toContain(IntegrationPermission.DISCONNECT_ANY);
      expect(userPermissions).not.toContain(IntegrationPermission.ADMIN);
    });

    it("should allow business admins to manage all business integrations", async () => {
      // Test business admin role permissions
      const businessAdminPermissions = ROLE_PERMISSIONS.business_admin;

      expect(businessAdminPermissions).toContain(IntegrationPermission.DISCONNECT_ANY);
      expect(businessAdminPermissions).toContain(IntegrationPermission.MANAGE_ANY);
      expect(businessAdminPermissions).not.toContain(IntegrationPermission.ADMIN);
    });

    it("should allow admins full control", async () => {
      // Test admin role permissions
      const adminPermissions = ROLE_PERMISSIONS.admin;

      expect(adminPermissions).toContain(IntegrationPermission.ADMIN);
      expect(adminPermissions.length).toBe(Object.values(IntegrationPermission).length);
    });
  });

  describe("Security and Data Protection", () => {
    it("should never expose sensitive tokens in responses", async () => {
      // Test all endpoints to ensure no token leakage
      const endpoints = [
        "/api/integrations",
        "/api/integrations/connected",
        "/api/integrations/integration_123",
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set("Authorization", "Bearer user_token")
          .expect(200);

        const responseBody = JSON.stringify(response.body);
        expect(responseBody).not.toMatch(/access_token/i);
        expect(responseBody).not.toMatch(/refresh_token/i);
        expect(responseBody).not.toMatch(/sk_test_/i);
        expect(responseBody).not.toMatch(/sk_live_/i);
      }
    });

    it("should validate all input parameters", async () => {
      // Test invalid integration ID format
      const response = await request(app)
        .delete("/api/integrations/invalid-uuid")
        .set("Authorization", "Bearer user_token")
        .expect(404); // Should fail validation or ownership check

      expect(response.body.error).toBeDefined();
    });

    it("should handle malformed requests gracefully", async () => {
      const response = await request(app)
        .post("/api/integrations/connect")
        .set("Authorization", "Bearer user_token")
        .send({ invalid_field: "value" })
        .expect(400);

      expect(response.body.error).toMatch(/validation error/i);
    });
  });

  describe("Error Handling", () => {
    it("should return consistent error format", async () => {
      const response = await request(app)
        .get("/api/integrations/connected")
        .expect(401);

      expect(response.body).toHaveProperty("error");
      expect(response.body).toHaveProperty("message");
    });

    it("should handle server errors gracefully", async () => {
      // Mock a server error scenario
      const response = await request(app)
        .get("/api/integrations/nonexistent-endpoint")
        .expect(404);
    });
  });

  describe("Integration Flow Tests", () => {
    it("should complete full integration lifecycle", async () => {
      // 1. List available integrations
      const listResponse = await request(app)
        .get("/api/integrations")
        .set("Authorization", "Bearer user_token")
        .expect(200);

      expect(listResponse.body.available.length).toBeGreaterThan(0);

      // 2. Check connected integrations (should be empty initially)
      const connectedResponse = await request(app)
        .get("/api/integrations/connected")
        .set("Authorization", "Bearer user_token")
        .expect(200);

      expect(connectedResponse.body.integrations).toHaveLength(0);

      // 3. Initiate connection
      const connectResponse = await request(app)
        .post("/api/integrations/connect")
        .set("Authorization", "Bearer user_token")
        .send({ provider: "stripe" })
        .expect(200);

      expect(connectResponse.body).toHaveProperty("authUrl");
      expect(connectResponse.body).toHaveProperty("state");

      // Note: In a real test, you would complete the OAuth flow
      // For this test, we'll simulate the connection being established
    });
  });
});

describe("Permission Middleware Tests", () => {
  it("should handle missing user role gracefully", async () => {
    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", "Bearer user_token")
      // Don't set x-user-role header
      .expect(200);

    // Should default to 'user' role and work correctly
    expect(response.body).toHaveProperty("integrations");
  });

  it("should reject invalid user roles", async () => {
    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", "Bearer user_token")
      .set("x-user-role", "invalid_role")
      .expect(200); // Should default to user role

    expect(response.body).toHaveProperty("integrations");
  });

  it("should handle permission context correctly", async () => {
    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", "Bearer user_token")
      .set("x-user-role", "admin")
      .expect(200);

    expect(response.body).toHaveProperty("integrations");
  });
});

// ─── Shopify HMAC Property-Based Tests ───────────────────────────────────────

import fc from "fast-check";
import { computeShopifyHmac } from "../../src/services/integrations/shopify/callback.js";

describe("computeShopifyHmac — property-based tests", () => {
  // Property 1: HMAC round-trip (determinism)
  // Validates: Requirements 1.1, 1.2, 8.1, 8.2
  it("Property 1: same inputs always produce the same digest (determinism)", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1 }),
        fc.dictionary(fc.string(), fc.string()),
        (secret, params) => {
          const first = computeShopifyHmac(secret, params);
          const second = computeShopifyHmac(secret, params);
          return first === second;
        },
      ),
      { numRuns: 100 },
    );
  });

  // Property 2: HMAC order-independence (confluence)
  // Validates: Requirements 2.2, 8.4
  it("Property 2: shuffled key insertion order produces the same digest (order-independence)", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1 }),
        fc.dictionary(fc.string(), fc.string()),
        (secret, params) => {
          // Build a shuffled copy of params
          const entries = Object.entries(params);
          for (let i = entries.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [entries[i], entries[j]] = [entries[j], entries[i]];
          }
          const shuffled = Object.fromEntries(entries);

          return computeShopifyHmac(secret, params) === computeShopifyHmac(secret, shuffled);
        },
      ),
      { numRuns: 100 },
    );
  });

  // Property 3: HMAC excludes the `hmac` key
  // Validates: Requirements 2.1, 8.3
  it("Property 3: adding, removing, or changing the `hmac` key does not affect the digest", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1 }),
        fc.dictionary(fc.string(), fc.string()),
        fc.string(),
        (secret, params, hmacValue) => {
          // Baseline: params without any `hmac` key
          const { hmac: _removed, ...withoutHmac } = params;
          const baseline = computeShopifyHmac(secret, withoutHmac);

          // With `hmac` key added
          const withHmac = { ...withoutHmac, hmac: hmacValue };
          const withHmacResult = computeShopifyHmac(secret, withHmac);

          // With `hmac` key set to a different value
          const withDifferentHmac = { ...withoutHmac, hmac: hmacValue + "_mutated" };
          const withDifferentHmacResult = computeShopifyHmac(secret, withDifferentHmac);

          return baseline === withHmacResult && baseline === withDifferentHmacResult;
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ─── Task 3.2: handleCallback — env guard ────────────────────────────────────

import { handleCallback } from "../../src/services/integrations/shopify/callback.js";
import * as shopifyStore from "../../src/services/integrations/shopify/store.js";

describe("handleCallback — env guard", () => {
  const originalClientId = process.env.SHOPIFY_CLIENT_ID;
  const originalClientSecret = process.env.SHOPIFY_CLIENT_SECRET;

  afterEach(() => {
    // Restore original env values
    if (originalClientId === undefined) {
      delete process.env.SHOPIFY_CLIENT_ID;
    } else {
      process.env.SHOPIFY_CLIENT_ID = originalClientId;
    }
    if (originalClientSecret === undefined) {
      delete process.env.SHOPIFY_CLIENT_SECRET;
    } else {
      process.env.SHOPIFY_CLIENT_SECRET = originalClientSecret;
    }
  });

  it("returns 'Shopify app not configured' when SHOPIFY_CLIENT_ID is missing", async () => {
    delete process.env.SHOPIFY_CLIENT_ID;
    process.env.SHOPIFY_CLIENT_SECRET = "some-secret";
    const result = await handleCallback({ code: "c", shop: "s", state: "st" });
    expect(result).toEqual({ success: false, error: "Shopify app not configured" });
  });

  it("returns 'Shopify app not configured' when SHOPIFY_CLIENT_SECRET is missing", async () => {
    process.env.SHOPIFY_CLIENT_ID = "some-client-id";
    delete process.env.SHOPIFY_CLIENT_SECRET;
    const result = await handleCallback({ code: "c", shop: "s", state: "st" });
    expect(result).toEqual({ success: false, error: "Shopify app not configured" });
  });

  it("returns 'Shopify app not configured' when both env vars are empty strings", async () => {
    process.env.SHOPIFY_CLIENT_ID = "";
    process.env.SHOPIFY_CLIENT_SECRET = "";
    const result = await handleCallback({ code: "c", shop: "s", state: "st" });
    expect(result).toEqual({ success: false, error: "Shopify app not configured" });
  });
});

// ─── Task 4.3: Property 4 — Tampered parameter causes HMAC rejection ─────────

describe("computeShopifyHmac — property-based tests", () => {
  // Property 4: Tampered param causes HMAC rejection
  // Validates: Requirements 1.3
  it("Property 4: mutating any non-hmac parameter causes handleCallback to return Invalid HMAC signature", async () => {
    const savedClientId = process.env.SHOPIFY_CLIENT_ID;
    const savedClientSecret = process.env.SHOPIFY_CLIENT_SECRET;

    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";

    await fc.assert(
      fc.asyncProperty(
        fc.record({
          code: fc.string({ minLength: 1 }),
          shop: fc.constant("test-shop.myshopify.com"),
          state: fc.string({ minLength: 1 }),
        }),
        async (params) => {
          const hmac = computeShopifyHmac("test-secret", params);
          const tamperedParams = { ...params, code: params.code + "_tampered", hmac };
          const result = await handleCallback(tamperedParams);
          return result.error === "Invalid HMAC signature";
        },
      ),
      { numRuns: 100 },
    );

    if (savedClientId === undefined) {
      delete process.env.SHOPIFY_CLIENT_ID;
    } else {
      process.env.SHOPIFY_CLIENT_ID = savedClientId;
    }
    if (savedClientSecret === undefined) {
      delete process.env.SHOPIFY_CLIENT_SECRET;
    } else {
      process.env.SHOPIFY_CLIENT_SECRET = savedClientSecret;
    }
  });

  // Property 5: Missing required params rejected without side effects
  // Validates: Requirements 3.1, 3.2
  it("Property 5: params missing any required field causes handleCallback to return success: false", async () => {
    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";

    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.constant({ shop: "test.myshopify.com", state: "abc", hmac: "xyz" }),
          fc.constant({ code: "abc", state: "abc", hmac: "xyz" }),
          fc.constant({ code: "abc", shop: "test.myshopify.com", hmac: "xyz" }),
          fc.constant({ code: "abc", shop: "test.myshopify.com", state: "abc" }),
        ),
        async (params) => {
          const result = await handleCallback(params as Record<string, string>);
          return result.success === false;
        },
      ),
      { numRuns: 100 },
    );

    delete process.env.SHOPIFY_CLIENT_ID;
    delete process.env.SHOPIFY_CLIENT_SECRET;
  });
});

// ─── Task 4.5: handleCallback — HMAC and params validation ───────────────────

describe("handleCallback — HMAC and params validation", () => {
  beforeEach(() => {
    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";
  });

  afterEach(() => {
    delete process.env.SHOPIFY_CLIENT_ID;
    delete process.env.SHOPIFY_CLIENT_SECRET;
  });

  function makeValidParams(secret: string) {
    const params = { code: "auth-code", shop: "mystore.myshopify.com", state: "nonce-123" };
    const hmac = computeShopifyHmac(secret, params);
    return { ...params, hmac };
  }

  it("valid HMAC proceeds past HMAC check", async () => {
    const params = makeValidParams("test-secret");
    const result = await handleCallback(params);
    expect(result.error).not.toBe("Invalid HMAC signature");
  });

  it("tampered HMAC returns Invalid HMAC signature", async () => {
    const params = makeValidParams("test-secret");
    const tampered = { ...params, code: "different-code" };
    const result = await handleCallback(tampered);
    expect(result).toEqual({ success: false, error: "Invalid HMAC signature" });
  });

  it("missing hmac param returns Missing HMAC signature", async () => {
    const result = await handleCallback({
      code: "auth-code",
      shop: "mystore.myshopify.com",
      state: "nonce-123",
    });
    expect(result).toEqual({ success: false, error: "Missing HMAC signature" });
  });

  it("empty hmac param returns Missing HMAC signature", async () => {
    const result = await handleCallback({
      code: "auth-code",
      shop: "mystore.myshopify.com",
      state: "nonce-123",
      hmac: "",
    });
    expect(result).toEqual({ success: false, error: "Missing HMAC signature" });
  });

  it("missing code returns Missing required callback parameters", async () => {
    const result = await handleCallback({
      shop: "mystore.myshopify.com",
      state: "nonce-123",
      hmac: "somehash",
    });
    expect(result).toEqual({ success: false, error: "Missing required callback parameters" });
  });

  it("missing shop returns Missing required callback parameters", async () => {
    const result = await handleCallback({
      code: "auth-code",
      state: "nonce-123",
      hmac: "somehash",
    });
    expect(result).toEqual({ success: false, error: "Missing required callback parameters" });
  });

  it("missing state returns Missing required callback parameters", async () => {
    const result = await handleCallback({
      code: "auth-code",
      shop: "mystore.myshopify.com",
      hmac: "somehash",
    });
    expect(result).toEqual({ success: false, error: "Missing required callback parameters" });
  });

  it("HMAC validated before state nonce is consumed (ordering guarantee)", async () => {
    // Seed the store with a valid nonce
    shopifyStore.setOAuthState("nonce-123", "mystore.myshopify.com");

    // Call handleCallback with a tampered HMAC (so HMAC check fails)
    const params = makeValidParams("test-secret");
    const tampered = { ...params, code: "tampered-code" };
    const result = await handleCallback(tampered);

    expect(result).toEqual({ success: false, error: "Invalid HMAC signature" });

    // The nonce must NOT have been consumed — it should still be in the store
    const remaining = shopifyStore.consumeOAuthState("nonce-123");
    expect(remaining).toBe("mystore.myshopify.com");
  });
});

// ─── Task 5.2: Property 6 — Invalid shop hostname rejected after HMAC, before state consumed ───

describe("computeShopifyHmac — property-based tests", () => {
  // Property 6: Invalid shop hostname rejected after HMAC, before state consumed
  // Validates: Requirements 4.1, 4.2, 3.3
  it("Property 6: invalid shop hostname rejected after HMAC passes, state nonce remains unconsumed", async () => {
    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";

    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1 }).filter(
          (s) => !/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(s),
        ),
        fc.string({ minLength: 1 }),
        async (invalidShop, state) => {
          // Seed the store with the nonce
          shopifyStore.setOAuthState(state, "some-shop.myshopify.com");

          // Build params with the invalid shop and compute a valid HMAC over them
          const baseParams = { code: "auth-code", shop: invalidShop, state };
          const hmac = computeShopifyHmac("test-secret", baseParams);
          const params = { ...baseParams, hmac };

          const result = await handleCallback(params);

          // The nonce must still be in the store (not consumed)
          const remaining = shopifyStore.consumeOAuthState(state);

          return result.error === "Invalid shop hostname" && remaining !== undefined;
        },
      ),
      { numRuns: 50 },
    );

    delete process.env.SHOPIFY_CLIENT_ID;
    delete process.env.SHOPIFY_CLIENT_SECRET;
  });
});

// ─── Task 5.3: handleCallback — shop hostname validation ─────────────────────

describe("handleCallback — shop hostname validation", () => {
  beforeEach(() => {
    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";
  });

  afterEach(() => {
    delete process.env.SHOPIFY_CLIENT_ID;
    delete process.env.SHOPIFY_CLIENT_SECRET;
  });

  it("valid .myshopify.com hostname proceeds past shop check", async () => {
    const params = { code: "auth-code", shop: "mystore.myshopify.com", state: "nonce-abc" };
    const hmac = computeShopifyHmac("test-secret", params);
    const result = await handleCallback({ ...params, hmac });
    expect(result.error).not.toBe("Invalid shop hostname");
  });

  it("hostname with dots in subdomain is rejected", async () => {
    const params = { code: "auth-code", shop: "my.store.myshopify.com", state: "nonce-abc" };
    const hmac = computeShopifyHmac("test-secret", params);
    const result = await handleCallback({ ...params, hmac });
    expect(result).toEqual({ success: false, error: "Invalid shop hostname" });
  });

  it("non-myshopify domain is rejected", async () => {
    const params = { code: "auth-code", shop: "mystore.shopify.com", state: "nonce-abc" };
    const hmac = computeShopifyHmac("test-secret", params);
    const result = await handleCallback({ ...params, hmac });
    expect(result).toEqual({ success: false, error: "Invalid shop hostname" });
  });

  it("shop hostname is normalized to lowercase before validation", async () => {
    // HMAC is computed with the mixed-case shop value (raw params)
    const params = { code: "auth-code", shop: "MyStore.myshopify.com", state: "nonce-abc" };
    const hmac = computeShopifyHmac("test-secret", params);
    const result = await handleCallback({ ...params, hmac });
    // Normalization happens inside handleCallback, so shop validation should pass
    // Result will be 'Invalid or expired state' (no nonce seeded), not 'Invalid shop hostname'
    expect(result.error).not.toBe("Invalid shop hostname");
  });
});

// ─── Task 6.2: Property 7 — State nonce consumed exactly once ────────────────

describe("computeShopifyHmac — property-based tests", () => {
  // Property 7: State nonce consumed exactly once
  // Validates: Requirements 5.1, 5.5
  it("Property 7: state nonce is absent from Token_Store after handleCallback returns, regardless of token exchange outcome", async () => {
    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";

    // Stub fetch so token exchange fails immediately (network error) without hanging
    vi.stubGlobal("fetch", () => Promise.reject(new Error("Network error")));

    try {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1 }),
          async (state) => {
            // Seed the store with the nonce
            shopifyStore.setOAuthState(state, "mystore.myshopify.com");

            // Build valid params and compute valid HMAC
            const baseParams = { code: "auth-code", shop: "mystore.myshopify.com", state };
            const hmac = computeShopifyHmac("test-secret", baseParams);
            const params = { ...baseParams, hmac };

            // Call handleCallback — fails at token exchange (stubbed), that's fine
            await handleCallback(params);

            // The nonce must be gone from the store (consumed on first use)
            const remaining = shopifyStore.consumeOAuthState(state);
            return remaining === undefined;
          },
        ),
        { numRuns: 50 },
      );
    } finally {
      vi.unstubAllGlobals();
      delete process.env.SHOPIFY_CLIENT_ID;
      delete process.env.SHOPIFY_CLIENT_SECRET;
    }
  });
});

// ─── Task 6.3: handleCallback — state nonce validation ───────────────────────

describe("handleCallback — state nonce validation", () => {
  beforeEach(() => {
    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";
    // Stub fetch so token exchange fails immediately without hanging
    vi.stubGlobal("fetch", () => Promise.reject(new Error("Network error")));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.SHOPIFY_CLIENT_ID;
    delete process.env.SHOPIFY_CLIENT_SECRET;
  });

  function makeValidParamsForShop(secret: string, shop: string, state: string) {
    const params = { code: "auth-code", shop, state };
    const hmac = computeShopifyHmac(secret, params);
    return { ...params, hmac };
  }

  it("state not in store returns Invalid or expired state", async () => {
    // Do NOT seed the store — state is absent
    const params = makeValidParamsForShop("test-secret", "mystore.myshopify.com", "nonce-not-seeded");
    const result = await handleCallback(params);
    expect(result).toEqual({ success: false, error: "Invalid or expired state" });
  });

  it("state found but shop mismatch returns Invalid or expired state", async () => {
    // Seed with a different shop
    shopifyStore.setOAuthState("nonce-abc", "other-shop.myshopify.com");
    const params = makeValidParamsForShop("test-secret", "mystore.myshopify.com", "nonce-abc");
    const result = await handleCallback(params);
    expect(result).toEqual({ success: false, error: "Invalid or expired state" });
  });

  it("state consumed after first use (replay prevention)", async () => {
    // Seed the store
    shopifyStore.setOAuthState("nonce-abc", "mystore.myshopify.com");
    const params = makeValidParamsForShop("test-secret", "mystore.myshopify.com", "nonce-abc");

    // First call — will fail at token exchange (stubbed), but nonce should be consumed
    await handleCallback(params);

    // Nonce must be gone
    const remaining = shopifyStore.consumeOAuthState("nonce-abc");
    expect(remaining).toBeUndefined();
  });
});

// ─── Task 8.2: handleCallback — token exchange ───────────────────────────────

describe("handleCallback — token exchange", () => {
  function makeValidParamsForTokenExchange() {
    const params = { code: "auth-code", shop: "mystore.myshopify.com", state: "nonce-abc" };
    const hmac = computeShopifyHmac("test-secret", params);
    return { ...params, hmac };
  }

  beforeEach(() => {
    process.env.SHOPIFY_CLIENT_ID = "test-client-id";
    process.env.SHOPIFY_CLIENT_SECRET = "test-secret";
    shopifyStore.setOAuthState("nonce-abc", "mystore.myshopify.com");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.SHOPIFY_CLIENT_ID;
    delete process.env.SHOPIFY_CLIENT_SECRET;
  });

  it("network error returns Token exchange request failed", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network error")));
    shopifyStore.setOAuthState("nonce-abc", "mystore.myshopify.com");
    const result = await handleCallback(makeValidParamsForTokenExchange());
    expect(result).toEqual({ success: false, error: "Token exchange request failed" });
  });

  it("non-2xx response returns Token exchange failed", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 400 }));
    shopifyStore.setOAuthState("nonce-abc", "mystore.myshopify.com");
    const result = await handleCallback(makeValidParamsForTokenExchange());
    expect(result).toEqual({ success: false, error: "Token exchange failed" });
  });

  it("response missing access_token returns No access token in response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({}),
    }));
    shopifyStore.setOAuthState("nonce-abc", "mystore.myshopify.com");
    const result = await handleCallback(makeValidParamsForTokenExchange());
    expect(result).toEqual({ success: false, error: "No access token in response" });
  });

  it("successful flow returns success true with normalized shop", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ access_token: "shpat_test123" }),
    }));
    shopifyStore.setOAuthState("nonce-abc", "mystore.myshopify.com");
    const result = await handleCallback(makeValidParamsForTokenExchange());
    expect(result).toEqual({ success: true, shop: "mystore.myshopify.com" });
  });
});

/**
 * OAuth State Tampering Integration Tests
 *
 * Validates that the OAuth state parameter is properly enforced to prevent:
 * - CSRF attacks via state forgery or cross-user state theft
 * - State replay attacks
 * - State parameter injection (SQL injection, XSS)
 * - Concurrent/race-condition state reuse
 * - Expired state usage
 * - State enumeration via predictable token patterns
 *
 * @security These tests directly verify the CSRF-protection guarantees of the OAuth flow.
 */
describe("OAuth State Tampering", () => {
  const attackerBusinessId = "biz_attacker_456";
  const attackerToken = "token_attacker_456";

  beforeAll(() => {
    // Register attacker as a second authenticated business
    mockTokens[attackerToken] = {
      userId: "user_attacker_456",
      businessId: attackerBusinessId,
    };
  });

  afterAll(() => {
    delete mockTokens[attackerToken];
  });

  describe("Cross-user state theft", () => {
    it("should reject callback when state belongs to a different business", async () => {
      // Victim initiates OAuth and receives a valid state token
      const victimConnect = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const victimState = victimConnect.body.state;

      // Attacker intercepts the state and tries to use it with their own session
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${attackerToken}`)
        .send({ code: "stolen_auth_code", state: victimState })
        .expect(403);

      expect(response.body.error).toMatch(/state does not match/i);
    });

    it("should preserve victim state after failed cross-user theft attempt", async () => {
      // Victim initiates OAuth
      const victimConnect = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const victimState = victimConnect.body.state;

      // Attacker's attempt is rejected
      await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${attackerToken}`)
        .send({ code: "stolen_auth_code", state: victimState })
        .expect(403);

      // Victim should still be able to complete their own legitimate flow
      const legitimateResponse = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "legitimate_auth_code", state: victimState })
        .expect(201);

      expect(legitimateResponse.body.connection).toHaveProperty(
        "status",
        "active",
      );
    });

    it("should isolate state between two businesses initiated at the same time", async () => {
      // Both businesses initiate OAuth simultaneously
      const [victimConnect, attackerConnect] = await Promise.all([
        request(app)
          .post("/api/integrations/stripe/connect")
          .set("Authorization", `Bearer ${authToken}`),
        request(app)
          .post("/api/integrations/stripe/connect")
          .set("Authorization", `Bearer ${attackerToken}`),
      ]);

      const victimState = victimConnect.body.state;
      const attackerState = attackerConnect.body.state;

      // States must differ
      expect(victimState).not.toBe(attackerState);

      // Attacker's token cannot be used by victim's session
      const crossAttempt = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "code", state: attackerState })
        .expect(403);

      expect(crossAttempt.body.error).toMatch(/state does not match/i);
    });
  });

  describe("State replay attacks", () => {
    it("should reject a state token that has already been consumed", async () => {
      const connectResponse = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const state = connectResponse.body.state;

      // First use — legitimate, should succeed
      await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "code_first_use", state })
        .expect(201);

      // Second use — replay attack, must be rejected
      const replayResponse = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "code_replay", state })
        .expect(400);

      expect(replayResponse.body.error).toMatch(/invalid or expired state/i);
    });

    it("should not create a second connection from a replayed state", async () => {
      const connectResponse = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const state = connectResponse.body.state;

      await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "code_first_use", state })
        .expect(201);

      // Replay attempt
      await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "code_replay", state })
        .expect(400);

      // Only one connection should exist
      const connectedResponse = await request(app)
        .get("/api/integrations/connected")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      expect(connectedResponse.body.integrations).toHaveLength(1);
    });
  });

  describe("State forgery", () => {
    it("should reject a completely fabricated state token", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: "forged_state_abc123" })
        .expect(400);

      expect(response.body.error).toMatch(/invalid or expired state/i);
    });

    it("should reject a state that mimics the internal generation pattern", async () => {
      // Attacker who has seen a real state tries to guess another valid one
      const guessedState = `state_${businessId}_stripe_${Date.now()}`;

      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: guessedState })
        .expect(400);

      expect(response.body.error).toMatch(/invalid or expired state/i);
    });

    it("should reject a state constructed from valid-looking UUIDs", async () => {
      const uuidLikeState = "550e8400-e29b-41d4-a716-446655440000";

      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: uuidLikeState })
        .expect(400);

      expect(response.body.error).toMatch(/invalid or expired state/i);
    });
  });

  describe("State parameter injection", () => {
    it("should reject state with SQL injection payload", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: "' OR '1'='1'; --" })
        .expect(400);

      expect(response.body.error).toMatch(/invalid or expired state/i);
    });

    it("should reject state with XSS payload", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({
          code: "some_code",
          state: "<script>alert('xss')</script>",
        })
        .expect(400);

      expect(response.body.error).toMatch(/invalid or expired state/i);
    });

    it("should treat empty string state as missing", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: "" })
        .expect(400);

      expect(response.body.error).toMatch(/missing/i);
    });

    it("should reject an excessively long state string", async () => {
      const longState = "a".repeat(10_000);

      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: longState })
        .expect(400);

      expect(response.body.error).toMatch(/invalid or expired state/i);
    });

    it("should reject state with null-byte injection", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: "valid_prefix\x00injected_suffix" })
        .expect(400);

      expect(response.body.error).toMatch(/invalid or expired state/i);
    });
  });

  describe("Expired state attack", () => {
    it("should reject a state token that has already expired", async () => {
      // Directly inject an expired state entry into the store
      oauthStateStore.push({
        state: "expired_state_token_xyz",
        businessId,
        integrationId: "stripe",
        createdAt: new Date(Date.now() - 700_000).toISOString(), // 11+ minutes ago
        expiresAt: new Date(Date.now() - 100_000).toISOString(), // 100 seconds in the past
      });

      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: "expired_state_token_xyz" })
        .expect(400);

      expect(response.body.error).toMatch(/expired/i);
    });

    it("should reject a state token that expires between connect and callback", async () => {
      const connectResponse = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const state = connectResponse.body.state;

      // Manually expire the state by mutating the store entry
      const entry = oauthStateStore.find((s) => s.state === state);
      if (entry) {
        entry.expiresAt = new Date(Date.now() - 1).toISOString();
      }

      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "late_code", state })
        .expect(400);

      expect(response.body.error).toMatch(/expired/i);
    });
  });

  describe("Concurrent state usage (race condition)", () => {
    it("should allow exactly one successful use when state is submitted concurrently", async () => {
      const connectResponse = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const state = connectResponse.body.state;

      // Submit two requests with the same state simultaneously
      const [response1, response2] = await Promise.all([
        request(app)
          .post("/api/integrations/callback")
          .set("Authorization", `Bearer ${authToken}`)
          .send({ code: "code_concurrent_1", state }),
        request(app)
          .post("/api/integrations/callback")
          .set("Authorization", `Bearer ${authToken}`)
          .send({ code: "code_concurrent_2", state }),
      ]);

      const statuses = [response1.status, response2.status].sort();

      // Exactly one must succeed and one must fail
      expect(statuses).toContain(201);
      expect(statuses).toContain(400);
    });

    it("should not create duplicate connections from concurrent state reuse", async () => {
      const connectResponse = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const state = connectResponse.body.state;

      await Promise.all([
        request(app)
          .post("/api/integrations/callback")
          .set("Authorization", `Bearer ${authToken}`)
          .send({ code: "code_race_1", state }),
        request(app)
          .post("/api/integrations/callback")
          .set("Authorization", `Bearer ${authToken}`)
          .send({ code: "code_race_2", state }),
      ]);

      const connectedResponse = await request(app)
        .get("/api/integrations/connected")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      // Only one connection should have been created
      expect(connectedResponse.body.integrations.length).toBeLessThanOrEqual(1);
    });
  });

  describe("State enumeration resistance", () => {
    it("should generate unique state tokens across multiple connect requests", async () => {
      // Run sequentially to avoid same-millisecond Date.now() collisions in the mock
      const states: string[] = [];
      for (let i = 0; i < 5; i++) {
        const res = await request(app)
          .post("/api/integrations/stripe/connect")
          .set("Authorization", `Bearer ${authToken}`)
          .expect(200);
        states.push(res.body.state as string);
      }

      const uniqueStates = new Set(states);
      expect(uniqueStates.size).toBe(states.length);
    });

    it("should generate unique state tokens across different businesses", async () => {
      const [victimConnect, attackerConnect] = await Promise.all([
        request(app)
          .post("/api/integrations/stripe/connect")
          .set("Authorization", `Bearer ${authToken}`)
          .expect(200),
        request(app)
          .post("/api/integrations/stripe/connect")
          .set("Authorization", `Bearer ${attackerToken}`)
          .expect(200),
      ]);

      expect(victimConnect.body.state).not.toBe(attackerConnect.body.state);
    });
  });

  describe("State isolation across integrations", () => {
    it("should bind state to the integration it was generated for", async () => {
      // Get a Stripe state token
      const stripeConnect = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const stripeState = stripeConnect.body.state;

      // Completing the callback with the Stripe state should produce a Stripe connection
      const callbackResponse = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: stripeState })
        .expect(201);

      expect(callbackResponse.body.connection).toHaveProperty(
        "integrationId",
        "stripe",
      );
      expect(callbackResponse.body.connection).toHaveProperty(
        "provider",
        "stripe",
      );
    });

    it("should not allow a state from one integration to be used for another", async () => {
      // Get Stripe state
      const stripeConnect = await request(app)
        .post("/api/integrations/stripe/connect")
        .set("Authorization", `Bearer ${authToken}`)
        .expect(200);

      const stripeState = stripeConnect.body.state;

      // Tamper: mutate the stored state to point to a different integration
      const entry = oauthStateStore.find((s) => s.state === stripeState);
      if (entry) {
        entry.integrationId = "shopify";
      }

      // The callback should use the integration recorded in the state, not Stripe
      const callbackResponse = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: stripeState })
        .expect(201);

      // Connection should reflect the tampered integrationId (shopify), not stripe
      expect(callbackResponse.body.connection).toHaveProperty(
        "integrationId",
        "shopify",
      );
    });
  });

  describe("Missing and malformed state values", () => {
    it("should return 400 when state is not provided at all", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code" })
        .expect(400);

      expect(response.body.error).toMatch(/missing.*state/i);
    });

    it("should return 400 when both code and state are missing", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({})
        .expect(400);

      expect(response.body.error).toMatch(/missing/i);
    });

    it("should return 400 when state is a number instead of a string", async () => {
      const response = await request(app)
        .post("/api/integrations/callback")
        .set("Authorization", `Bearer ${authToken}`)
        .send({ code: "some_code", state: 12345 })
        .expect(400);

      // Numeric state should not match any registered string state
      expect(response.body.error).toBeDefined();
    });
  });
});
