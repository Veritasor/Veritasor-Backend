/**
 * Webhook Subscription CRUD API
 *
 * REST endpoints for managing webhook subscriptions with per-event
 * filter DSL. All endpoints are scoped to the authenticated user's business.
 *
 * Routes:
 *   POST   /api/v1/webhook-subscriptions          - Create a subscription
 *   GET    /api/v1/webhook-subscriptions          - List subscriptions
 *   GET    /api/v1/webhook-subscriptions/:id      - Get a subscription
 *   PATCH  /api/v1/webhook-subscriptions/:id      - Update a subscription
 *   DELETE /api/v1/webhook-subscriptions/:id      - Delete a subscription
 *
 * @module routes/webhook-subscriptions
 */

import { Router } from "express";
import { requireAuth } from "../middleware/requireAuth.js";
import { validateBody, validateQuery } from "../middleware/validate.js";
import { asyncErrorHandler } from "../middleware/errorHandler.js";
import { NotFoundError, ConflictError } from "../types/errors.js";
import {
  createWebhookSubscriptionSchema,
  updateWebhookSubscriptionSchema,
  listWebhookSubscriptionsQuerySchema,
} from "../schemas/webhookSubscription.js";
import * as repo from "../repositories/webhookSubscriptionRepository.js";
import { resolveBusinessIdForUser } from "../services/business/resolveBusiness.js";

const MAX_SUBSCRIPTIONS_PER_BUSINESS = 10;

export const webhookSubscriptionsRouter = Router();

/**
 * GET /api/v1/webhook-subscriptions
 *
 * List webhook subscriptions for the authenticated user's business.
 * Supports optional cursor pagination and enabled/disabled filtering.
 */
webhookSubscriptionsRouter.get(
  "/",
  requireAuth,
  validateQuery(listWebhookSubscriptionsQuerySchema),
  asyncErrorHandler(async (req, res) => {
    const businessId = await resolveBusinessIdForUser(req.user!.id);
    if (!businessId) {
      throw new NotFoundError("Business not found for the authenticated user");
    }

    const query = listWebhookSubscriptionsQuerySchema.parse(req.query);
    query.businessId = businessId;

    const result = await repo.list(query);

    res.status(200).json({
      status: "success",
      data: result.data,
      ...(result.nextCursor ? { nextCursor: result.nextCursor } : {}),
    });
  }),
);

/**
 * GET /api/v1/webhook-subscriptions/:id
 *
 * Get a single webhook subscription by ID.
 */
webhookSubscriptionsRouter.get(
  "/:id",
  requireAuth,
  asyncErrorHandler(async (req, res) => {
    const businessId = await resolveBusinessIdForUser(req.user!.id);
    if (!businessId) {
      throw new NotFoundError("Business not found for the authenticated user");
    }

    const subscription = await repo.getById(req.params.id, businessId);
    if (!subscription) {
      throw new NotFoundError("Webhook subscription not found");
    }

    res.status(200).json({ status: "success", data: subscription });
  }),
);

/**
 * POST /api/v1/webhook-subscriptions
 *
 * Create a new webhook subscription for the authenticated user's business.
 *
 * Validates the URL, secret, event filters (Zod DSL), and enforces
 * per-business subscription limits.
 */
webhookSubscriptionsRouter.post(
  "/",
  requireAuth,
  validateBody(createWebhookSubscriptionSchema),
  asyncErrorHandler(async (req, res) => {
    const businessId = await resolveBusinessIdForUser(req.user!.id);
    if (!businessId) {
      throw new NotFoundError("Business not found for the authenticated user");
    }

    // Enforce per-business subscription capacity
    const existingCount = await repo.countByBusiness(businessId);
    if (existingCount >= MAX_SUBSCRIPTIONS_PER_BUSINESS) {
      throw new ConflictError(
        `Maximum of ${MAX_SUBSCRIPTIONS_PER_BUSINESS} webhook subscriptions allowed per business`,
      );
    }

    const subscription = await repo.create(businessId, req.body);

    res.status(201).json({ status: "success", data: subscription });
  }),
);

/**
 * PATCH /api/v1/webhook-subscriptions/:id
 *
 * Update an existing webhook subscription. Supports partial updates —
 * only the provided fields are changed. Secret rotation increments
 * the secretVersion counter automatically.
 */
webhookSubscriptionsRouter.patch(
  "/:id",
  requireAuth,
  validateBody(updateWebhookSubscriptionSchema),
  asyncErrorHandler(async (req, res) => {
    const businessId = await resolveBusinessIdForUser(req.user!.id);
    if (!businessId) {
      throw new NotFoundError("Business not found for the authenticated user");
    }

    const input = req.body;

    const updated = await repo.update(req.params.id, businessId, input);
    if (!updated) {
      throw new NotFoundError("Webhook subscription not found");
    }

    res.status(200).json({ status: "success", data: updated });
  }),
);

/**
 * DELETE /api/v1/webhook-subscriptions/:id
 *
 * Delete a webhook subscription.
 */
webhookSubscriptionsRouter.delete(
  "/:id",
  requireAuth,
  asyncErrorHandler(async (req, res) => {
    const businessId = await resolveBusinessIdForUser(req.user!.id);
    if (!businessId) {
      throw new NotFoundError("Business not found for the authenticated user");
    }

    const deleted = await repo.remove(req.params.id, businessId);
    if (!deleted) {
      throw new NotFoundError("Webhook subscription not found");
    }

    res.status(200).json({ status: "success", message: "Webhook subscription deleted" });
  }),
);

export default webhookSubscriptionsRouter;
