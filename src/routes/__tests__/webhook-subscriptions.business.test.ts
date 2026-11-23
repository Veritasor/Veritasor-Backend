import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import express, { type Express } from "express";
import request from "supertest";
import { webhookSubscriptionsRouter } from "../webhook-subscriptions.js";
import { errorHandler } from "../../middleware/errorHandler.js";
import * as jwt from "../../utils/jwt.js";
import * as userRepository from "../../repositories/userRepository.js";
import { businessRepository } from "../../repositories/business.js";
import * as subscriptionRepository from "../../repositories/webhookSubscriptionRepository.js";

const USER = {
  id: "user-1",
  userId: "user-1",
  email: "merchant@example.com",
  passwordHash: "password-hash",
  createdAt: new Date("2026-01-01T00:00:00Z"),
  updatedAt: new Date("2026-01-01T00:00:00Z"),
  role: "user" as const,
};

const BUSINESS_A = {
  id: "business-a",
  userId: USER.id,
  name: "Business A",
  email: USER.email,
  industry: null,
  description: null,
  website: null,
  reportingPeriod: "monthly" as const,
  reportingTimezone: "UTC",
  lastReminderSentAt: null,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const BUSINESS_B = {
  ...BUSINESS_A,
  id: "business-b",
  name: "Business B",
};

function buildApp(): Express {
  const app = express();
  app.use(express.json());
  app.use("/api/v1/webhook-subscriptions", webhookSubscriptionsRouter);
  app.use(errorHandler);
  return app;
}

describe("webhook subscription business context", () => {
  beforeEach(() => {
    vi.spyOn(jwt, "verifyToken").mockReturnValue({
      userId: USER.id,
      email: USER.email,
    });
    vi.spyOn(userRepository, "findUserById").mockResolvedValue(USER);
    vi.spyOn(businessRepository, "getById").mockImplementation(async (id) => {
      if (id === BUSINESS_A.id) return BUSINESS_A;
      if (id === BUSINESS_B.id) return BUSINESS_B;
      return null;
    });
    vi.spyOn(subscriptionRepository, "countByBusiness").mockResolvedValue(0);
    vi.spyOn(subscriptionRepository, "create").mockImplementation(
      async (businessId, input) =>
        ({
          id: "subscription-1",
          businessId,
          url: input.url,
          secret: input.secret,
          eventFilters: input.eventFilters ?? {},
          enabled: input.enabled,
          maxPayloadSize: input.maxPayloadSize ?? null,
          secretVersion: 1,
          mtlsConfig: input.mtlsConfig ?? null,
          createdAt: new Date(),
          updatedAt: new Date(),
        }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("creates a subscription under the explicitly selected owned business", async () => {
    const app = buildApp();
    const response = await request(app)
      .post("/api/v1/webhook-subscriptions")
      .set("Authorization", "Bearer valid-token")
      .set("x-business-id", BUSINESS_B.id)
      .send({ url: "https://example.com/webhook", secret: "a-secure-test-secret" });

    expect(response.status).toBe(201);
    expect(subscriptionRepository.create).toHaveBeenCalledWith(
      BUSINESS_B.id,
      expect.objectContaining({ url: "https://example.com/webhook" }),
    );
  });

  it("rejects a business the authenticated user does not own", async () => {
    const app = buildApp();
    const response = await request(app)
      .post("/api/v1/webhook-subscriptions")
      .set("Authorization", "Bearer valid-token")
      .set("x-business-id", "business-other")
      .send({ url: "https://example.com/webhook", secret: "a-secure-test-secret" });

    expect(response.status).toBe(403);
    expect(subscriptionRepository.create).not.toHaveBeenCalled();
  });

  it("requires an explicit business context when no header is supplied", async () => {
    const app = buildApp();
    const response = await request(app)
      .post("/api/v1/webhook-subscriptions")
      .set("Authorization", "Bearer valid-token")
      .send({ url: "https://example.com/webhook", secret: "a-secure-test-secret" });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe("MISSING_BUSINESS_ID");
    expect(subscriptionRepository.create).not.toHaveBeenCalled();
  });
});
