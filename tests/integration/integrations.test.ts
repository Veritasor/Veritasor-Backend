import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import express, { Express } from "express";

/**
 * Integration tests for integrations API endpoints
 *
 * Tests cover:
 * - List available integrations
 * - List connected integrations for a business
 * - Stripe OAuth connect flow
 * - Disconnect integration
 * - Protected routes return 401 when unauthenticated
 *
 * Note: Integrations routes are not yet implemented. These tests are ready
 * for when the integrations router is added to the application.
 */

// Mock integration data
const availableIntegrations = [
  {
    id: "stripe",
    name: "Stripe",
    description: "Connect your Stripe account to attest payment data",
    provider: "stripe",
    authType: "oauth2",
    status: "available",
  },
  {
    id: "shopify",
    name: "Shopify",
    description: "Connect your Shopify store to attest sales data",
    provider: "shopify",
    authType: "oauth2",
    status: "available",
  },
  {
    id: "quickbooks",
    name: "QuickBooks",
    description: "Connect QuickBooks to attest accounting data",
    provider: "quickbooks",
    authType: "oauth2",
    status: "coming_soon",
  },
];

// In-memory stores for test data
let connectedIntegrationsStore: Array<{
  id: string;
  businessId: string;
  integrationId: string;
  provider: string;
  accountId: string;
  accountName: string;
  connectedAt: string;
  status: "active" | "disconnected" | "error";
  metadata?: Record<string, unknown>;
}> = [];

let oauthStateStore: Array<{
  state: string;
  businessId: string;
  integrationId: string;
  createdAt: string;
  expiresAt: string;
}> = [];

// Mock user tokens for authentication
let mockTokens: Record<string, { userId: string; businessId: string }> = {};

// Helper to create mock integrations router
function createMockIntegrationsRouter() {
  const router = express.Router();

  // Middleware to check authentication
  const requireAuth = (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.substring(7);
    const tokenData = mockTokens[token];

    if (!tokenData) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    req.user = { id: tokenData.userId };
    res.locals.businessId = tokenData.businessId;
    next();
  };

  // GET /integrations/available - List all available integrations
  router.get("/available", (_req: express.Request, res: express.Response) => {
    res.json({
      integrations: availableIntegrations,
    });
  });

  // GET /integrations/connected - List connected integrations for authenticated business
  router.get(
    "/connected",
    requireAuth,
    (_req: express.Request, res: express.Response) => {
      const businessId = res.locals.businessId as string;

      const connected = connectedIntegrationsStore
        .filter(
          (conn) => conn.businessId === businessId && conn.status === "active",
        )
        .map((conn) => ({
          id: conn.id,
          integrationId: conn.integrationId,
          provider: conn.provider,
          accountId: conn.accountId,
          accountName: conn.accountName,
          connectedAt: conn.connectedAt,
          status: conn.status,
        }));

      res.json({
        integrations: connected,
      });
    },
  );

  // POST /integrations/:integrationId/connect - Initiate OAuth connection
  router.post(
    "/:integrationId/connect",
    requireAuth,
    (req: express.Request, res: express.Response) => {
      const { integrationId } = req.params;
      const businessId = res.locals.businessId as string;

      // Check if integration exists
      const integration = availableIntegrations.find(
        (i) => i.id === integrationId,
      );

      if (!integration) {
        return res.status(404).json({ error: "Integration not found" });
      }

      if (integration.status !== "available") {
        return res.status(400).json({ error: "Integration is not available" });
      }

      // Generate OAuth state
      const state = `state_${businessId}_${integrationId}_${Date.now()}`;

      oauthStateStore.push({
        state,
        businessId,
        integrationId,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 600000).toISOString(), // 10 minutes
      });

      // Return OAuth URL (mock)
      const redirectUri =
        req.body.redirectUri || "http://localhost:3000/integrations/callback";
      const authUrl = `https://connect.${integration.provider}.com/oauth/authorize?client_id=mock_client_id&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;

      res.json({
        authUrl,
        state,
      });
    },
  );

  // POST /integrations/callback - Handle OAuth callback
  router.post(
    "/callback",
    requireAuth,
    (req: express.Request, res: express.Response) => {
      const { code, state } = req.body;

      if (!code || !state) {
        return res.status(400).json({ error: "Missing code or state" });
      }

      // Verify state
      const stateEntry = oauthStateStore.find((s) => s.state === state);

      if (!stateEntry) {
        return res.status(400).json({ error: "Invalid or expired state" });
      }

      if (new Date(stateEntry.expiresAt) < new Date()) {
        return res.status(400).json({ error: "State has expired" });
      }

      const businessId = res.locals.businessId as string;

      if (stateEntry.businessId !== businessId) {
        return res.status(403).json({ error: "State does not match business" });
      }

      // Mock: Exchange code for access token and create connection
      const integration = availableIntegrations.find(
        (i) => i.id === stateEntry.integrationId,
      );

      if (!integration) {
        return res.status(404).json({ error: "Integration not found" });
      }

      const connectionId = `conn_${Date.now()}`;

      const connection = {
        id: connectionId,
        businessId,
        integrationId: integration.id,
        provider: integration.provider,
        accountId: `acct_${Date.now()}`,
        accountName: `${integration.name} Account`,
        connectedAt: new Date().toISOString(),
        status: "active" as const,
        metadata: {
          accessToken: `mock_access_token_${Date.now()}`,
          refreshToken: `mock_refresh_token_${Date.now()}`,
        },
      };

      connectedIntegrationsStore.push(connection);

      // Remove used state
      oauthStateStore = oauthStateStore.filter((s) => s.state !== state);

      res.status(201).json({
        connection: {
          id: connection.id,
          integrationId: connection.integrationId,
          provider: connection.provider,
          accountId: connection.accountId,
          accountName: connection.accountName,
          connectedAt: connection.connectedAt,
          status: connection.status,
        },
      });
    },
  );

  // DELETE /integrations/:connectionId - Disconnect integration
  router.delete(
    "/:connectionId",
    requireAuth,
    (req: express.Request, res: express.Response) => {
      const { connectionId } = req.params;
      const businessId = res.locals.businessId as string;

      const connection = connectedIntegrationsStore.find(
        (conn) => conn.id === connectionId && conn.businessId === businessId,
      );

      if (!connection) {
        return res.status(404).json({ error: "Connection not found" });
      }

      // Mark as disconnected
      connection.status = "disconnected";

      res.json({
        message: "Integration disconnected successfully",
        connectionId: connection.id,
      });
    },
  );

  return router;
}

// Test app setup
let app: Express;
let authToken: string;
let businessId: string;

beforeAll(() => {
  app = express();
  app.use(express.json());

  // Mount mock integrations router
  // TODO: Replace with actual integrations router when implemented
  app.use("/api/integrations", createMockIntegrationsRouter());

  // Setup mock authentication
  businessId = "biz_test_123";
  authToken = "token_test_123";
  mockTokens[authToken] = {
    userId: "user_test_123",
    businessId,
  };
});

beforeEach(() => {
  // Clear stores before each test
  connectedIntegrationsStore = [];
  oauthStateStore = [];
});

afterAll(() => {
  // Cleanup
  mockTokens = {};
});

describe("GET /api/integrations/available", () => {
  it("should list all available integrations without authentication", async () => {
    const response = await request(app)
      .get("/api/integrations/available")
      .expect(200);

    expect(response.body).toHaveProperty("integrations");
    expect(Array.isArray(response.body.integrations)).toBe(true);
    expect(response.body.integrations.length).toBeGreaterThan(0);

    const stripeIntegration = response.body.integrations.find(
      (i: { id: string }) => i.id === "stripe",
    );
    expect(stripeIntegration).toBeDefined();
    expect(stripeIntegration).toHaveProperty("name", "Stripe");
    expect(stripeIntegration).toHaveProperty("provider", "stripe");
    expect(stripeIntegration).toHaveProperty("authType", "oauth2");
    expect(stripeIntegration).toHaveProperty("status", "available");
  });

  it("should include integration metadata", async () => {
    const response = await request(app)
      .get("/api/integrations/available")
      .expect(200);

    const integration = response.body.integrations[0];
    expect(integration).toHaveProperty("id");
    expect(integration).toHaveProperty("name");
    expect(integration).toHaveProperty("description");
    expect(integration).toHaveProperty("provider");
    expect(integration).toHaveProperty("authType");
    expect(integration).toHaveProperty("status");
  });
});

describe("GET /api/integrations/connected", () => {
  it("should return 401 when not authenticated", async () => {
    const response = await request(app)
      .get("/api/integrations/connected")
      .expect(401);

    expect(response.body.error).toMatch(/unauthorized/i);
  });

  it("should return empty array when no integrations connected", async () => {
    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(response.body).toHaveProperty("integrations");
    expect(Array.isArray(response.body.integrations)).toBe(true);
    expect(response.body.integrations).toHaveLength(0);
  });

  it("should list connected integrations for authenticated business", async () => {
    // Add a connected integration
    connectedIntegrationsStore.push({
      id: "conn_1",
      businessId,
      integrationId: "stripe",
      provider: "stripe",
      accountId: "acct_123",
      accountName: "My Stripe Account",
      connectedAt: new Date().toISOString(),
      status: "active",
    });

    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(response.body.integrations).toHaveLength(1);
    expect(response.body.integrations[0]).toHaveProperty("id", "conn_1");
    expect(response.body.integrations[0]).toHaveProperty(
      "integrationId",
      "stripe",
    );
    expect(response.body.integrations[0]).toHaveProperty("provider", "stripe");
    expect(response.body.integrations[0]).toHaveProperty(
      "accountId",
      "acct_123",
    );
    expect(response.body.integrations[0]).toHaveProperty("status", "active");
  });

  it("should not include disconnected integrations", async () => {
    connectedIntegrationsStore.push(
      {
        id: "conn_1",
        businessId,
        integrationId: "stripe",
        provider: "stripe",
        accountId: "acct_123",
        accountName: "Active Account",
        connectedAt: new Date().toISOString(),
        status: "active",
      },
      {
        id: "conn_2",
        businessId,
        integrationId: "shopify",
        provider: "shopify",
        accountId: "acct_456",
        accountName: "Disconnected Account",
        connectedAt: new Date().toISOString(),
        status: "disconnected",
      },
    );

    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(response.body.integrations).toHaveLength(1);
    expect(response.body.integrations[0].id).toBe("conn_1");
  });

  it("should not expose sensitive metadata like tokens", async () => {
    connectedIntegrationsStore.push({
      id: "conn_1",
      businessId,
      integrationId: "stripe",
      provider: "stripe",
      accountId: "acct_123",
      accountName: "My Account",
      connectedAt: new Date().toISOString(),
      status: "active",
      metadata: {
        accessToken: "secret_token",
        refreshToken: "secret_refresh",
      },
    });

    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(response.body.integrations[0]).not.toHaveProperty("metadata");
    expect(response.body.integrations[0]).not.toHaveProperty("accessToken");
    expect(response.body.integrations[0]).not.toHaveProperty("refreshToken");
  });
});

describe("POST /api/integrations/:integrationId/connect", () => {
  it("should return 401 when not authenticated", async () => {
    const response = await request(app)
      .post("/api/integrations/stripe/connect")
      .expect(401);

    expect(response.body.error).toMatch(/unauthorized/i);
  });

  it("should initiate OAuth flow for Stripe", async () => {
    const response = await request(app)
      .post("/api/integrations/stripe/connect")
      .set("Authorization", `Bearer ${authToken}`)
      .send({ redirectUri: "http://localhost:3000/callback" })
      .expect(200);

    expect(response.body).toHaveProperty("authUrl");
    expect(response.body).toHaveProperty("state");
    expect(response.body.authUrl).toContain("connect.stripe.com");
    expect(response.body.authUrl).toContain("state=");
    expect(response.body.authUrl).toContain("redirect_uri=");
  });

  it("should return 404 for non-existent integration", async () => {
    const response = await request(app)
      .post("/api/integrations/nonexistent/connect")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(404);

    expect(response.body.error).toMatch(/not found/i);
  });

  it("should return 400 for unavailable integration", async () => {
    const response = await request(app)
      .post("/api/integrations/quickbooks/connect")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(400);

    expect(response.body.error).toMatch(/not available/i);
  });

  it("should generate unique state for each request", async () => {
    const response1 = await request(app)
      .post("/api/integrations/stripe/connect")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    const response2 = await request(app)
      .post("/api/integrations/stripe/connect")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(response1.body.state).not.toBe(response2.body.state);
  });
});

describe("POST /api/integrations/callback", () => {
  let oauthState: string;

  beforeEach(async () => {
    // Initiate OAuth flow to get state
    const connectResponse = await request(app)
      .post("/api/integrations/stripe/connect")
      .set("Authorization", `Bearer ${authToken}`);

    oauthState = connectResponse.body.state;
  });

  it("should return 401 when not authenticated", async () => {
    const response = await request(app)
      .post("/api/integrations/callback")
      .send({
        code: "auth_code_123",
        state: oauthState,
      })
      .expect(401);

    expect(response.body.error).toMatch(/unauthorized/i);
  });

  it("should complete OAuth flow and create connection", async () => {
    const response = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "auth_code_123",
        state: oauthState,
      })
      .expect(201);

    expect(response.body).toHaveProperty("connection");
    expect(response.body.connection).toHaveProperty("id");
    expect(response.body.connection).toHaveProperty("integrationId", "stripe");
    expect(response.body.connection).toHaveProperty("provider", "stripe");
    expect(response.body.connection).toHaveProperty("accountId");
    expect(response.body.connection).toHaveProperty("accountName");
    expect(response.body.connection).toHaveProperty("connectedAt");
    expect(response.body.connection).toHaveProperty("status", "active");
  });

  it("should return 400 when missing code", async () => {
    const response = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({ state: oauthState })
      .expect(400);

    expect(response.body.error).toMatch(/missing code/i);
  });

  it("should return 400 when missing state", async () => {
    const response = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({ code: "auth_code_123" })
      .expect(400);

    expect(response.body.error).toMatch(/missing.*state/i);
  });

  it("should return 400 with invalid state", async () => {
    const response = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "auth_code_123",
        state: "invalid_state",
      })
      .expect(400);

    expect(response.body.error).toMatch(/invalid or expired state/i);
  });

  it("should invalidate state after use", async () => {
    // First callback - should succeed
    await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "auth_code_123",
        state: oauthState,
      })
      .expect(201);

    // Second callback with same state - should fail
    const response = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "auth_code_456",
        state: oauthState,
      })
      .expect(400);

    expect(response.body.error).toMatch(/invalid or expired state/i);
  });

  it("should not expose sensitive tokens in response", async () => {
    const response = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "auth_code_123",
        state: oauthState,
      })
      .expect(201);

    expect(response.body.connection).not.toHaveProperty("metadata");
    expect(response.body.connection).not.toHaveProperty("accessToken");
    expect(response.body.connection).not.toHaveProperty("refreshToken");
  });
});

describe("DELETE /api/integrations/:connectionId", () => {
  let connectionId: string;

  beforeEach(async () => {
    // Create a connection
    const connectResponse = await request(app)
      .post("/api/integrations/stripe/connect")
      .set("Authorization", `Bearer ${authToken}`);

    const callbackResponse = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "auth_code_123",
        state: connectResponse.body.state,
      });

    connectionId = callbackResponse.body.connection.id;
  });

  it("should return 401 when not authenticated", async () => {
    const response = await request(app)
      .delete(`/api/integrations/${connectionId}`)
      .expect(401);

    expect(response.body.error).toMatch(/unauthorized/i);
  });

  it("should disconnect integration successfully", async () => {
    const response = await request(app)
      .delete(`/api/integrations/${connectionId}`)
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(response.body.message).toMatch(/disconnected successfully/i);
    expect(response.body).toHaveProperty("connectionId", connectionId);
  });

  it("should return 404 for non-existent connection", async () => {
    const response = await request(app)
      .delete("/api/integrations/conn_nonexistent")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(404);

    expect(response.body.error).toMatch(/not found/i);
  });

  it("should not show disconnected integration in connected list", async () => {
    // Disconnect
    await request(app)
      .delete(`/api/integrations/${connectionId}`)
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    // Check connected list
    const response = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(response.body.integrations).toHaveLength(0);
  });
});

describe("Integrations flow integration", () => {
  it("should complete full connect -> list -> disconnect flow", async () => {
    // 1. List available integrations
    const availableResponse = await request(app)
      .get("/api/integrations/available")
      .expect(200);

    expect(availableResponse.body.integrations.length).toBeGreaterThan(0);

    // 2. Check no connections initially
    const emptyConnectedResponse = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(emptyConnectedResponse.body.integrations).toHaveLength(0);

    // 3. Initiate Stripe connection
    const connectResponse = await request(app)
      .post("/api/integrations/stripe/connect")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(connectResponse.body).toHaveProperty("authUrl");
    expect(connectResponse.body).toHaveProperty("state");

    // 4. Complete OAuth callback
    const callbackResponse = await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "auth_code_123",
        state: connectResponse.body.state,
      })
      .expect(201);

    const connectionId = callbackResponse.body.connection.id;

    // 5. Verify connection appears in connected list
    const connectedResponse = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(connectedResponse.body.integrations).toHaveLength(1);
    expect(connectedResponse.body.integrations[0].id).toBe(connectionId);

    // 6. Disconnect integration
    await request(app)
      .delete(`/api/integrations/${connectionId}`)
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    // 7. Verify connection no longer in connected list
    const finalConnectedResponse = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(finalConnectedResponse.body.integrations).toHaveLength(0);
  });

  it("should handle multiple integrations for same business", async () => {
    // Connect Stripe
    const stripeConnectResponse = await request(app)
      .post("/api/integrations/stripe/connect")
      .set("Authorization", `Bearer ${authToken}`);

    await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "stripe_code",
        state: stripeConnectResponse.body.state,
      })
      .expect(201);

    // Connect Shopify
    const shopifyConnectResponse = await request(app)
      .post("/api/integrations/shopify/connect")
      .set("Authorization", `Bearer ${authToken}`);

    await request(app)
      .post("/api/integrations/callback")
      .set("Authorization", `Bearer ${authToken}`)
      .send({
        code: "shopify_code",
        state: shopifyConnectResponse.body.state,
      })
      .expect(201);

    // Verify both connections
    const connectedResponse = await request(app)
      .get("/api/integrations/connected")
      .set("Authorization", `Bearer ${authToken}`)
      .expect(200);

    expect(connectedResponse.body.integrations).toHaveLength(2);

    const providers = connectedResponse.body.integrations.map(
      (i: { provider: string }) => i.provider,
    );
    expect(providers).toContain("stripe");
    expect(providers).toContain("shopify");
  });
});
