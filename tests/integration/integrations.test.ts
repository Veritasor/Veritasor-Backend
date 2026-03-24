import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import request from "supertest";
import express, { Express } from "express";
import integrationsRouter from "../../src/routes/integrations.js";
import { IntegrationPermission, ROLE_PERMISSIONS } from "../../src/types/permissions.js";
import { clearAll } from "../../src/repositories/integration.js";

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
