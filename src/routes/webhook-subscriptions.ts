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
 *   GET    /api/v1/webhook-subscriptions/:id/deliveries
 *                                                 - List a subscription's delivery receipts
 *   PATCH  /api/v1/webhook-subscriptions/:id      - Update a subscription
 *   DELETE /api/v1/webhook-subscriptions/:id      - Delete a subscription
 *
 * @module routes/webhook-subscriptions
 */

import { Router } from "express";
import { requireBusinessAuth } from "../middleware/requireBusinessAuth.js";
import { validateBody, validateQuery } from "../middleware/validate.js";
import { asyncErrorHandler } from "../middleware/errorHandler.js";
import { NotFoundError, ConflictError } from "../types/errors.js";
import {
  createWebhookSubscriptionSchema,
  updateWebhookSubscriptionSchema,
  listWebhookSubscriptionsQuerySchema,
  listWebhookDeliveriesQuerySchema,
} from "../schemas/webhookSubscription.js";
import * as repo from "../repositories/webhookSubscriptionRepository.js";
import type { DeliveryReceipt } from "../repositories/deliveryReceiptRepository.js";

const MAX_SUBSCRIPTIONS_PER_BUSINESS = 10;

/**
 * Maximum length of `responseBody` in the public delivery receipt view.
 * Stored bodies are truncated at this length so the public API never echoes
 * unbounded payload data back to the business.
 */
export const MAX_PUBLIC_RESPONSE_BODY_LENGTH = 500;

/**
 * Public (business-facing) view of a delivery receipt.
 *
 * Omits the stored `signature` (the delivery HMAC) entirely, and truncates
 * `responseBody` to {@link MAX_PUBLIC_RESPONSE_BODY_LENGTH} characters.
 */
export interface PublicDeliveryReceipt {
  id: string;
  deliveryId: string;
  attemptNumber: number;
  subscriptionId: string;
  businessId: string;
  url: string;
  statusCode: number;
  latencyMs: number;
  signatureVersion: number;
  responseBody?: string;
  createdAt: string;
}

function truncateResponseBody(responseBody: string): string {
  return responseBody.length > MAX_PUBLIC_RESPONSE_BODY_LENGTH
    ? responseBody.slice(0, MAX_PUBLIC_RESPONSE_BODY_LENGTH)
    : responseBody;
}

function toPublicDeliveryReceipt(receipt: DeliveryReceipt): PublicDeliveryReceipt {
  const publicReceipt: PublicDeliveryReceipt = {
    id: receipt.id,
    deliveryId: receipt.deliveryId,
    attemptNumber: receipt.attemptNumber,
    subscriptionId: receipt.subscriptionId,
    businessId: receipt.businessId,
    url: receipt.url,
    statusCode: receipt.statusCode,
    latencyMs: receipt.latencyMs,
    signatureVersion: receipt.signatureVersion,
    createdAt: receipt.createdAt,
  };
  if (receipt.responseBody !== undefined && receipt.responseBody !== null) {
    publicReceipt.responseBody = truncateResponseBody(receipt.responseBody);
  }
  return publicReceipt;
}

export const webhookSubscriptionsRouter = Router();

/**
 * GET /api/v1/webhook-subscriptions
 *
 * List webhook subscriptions for the authenticated user's business.
 * Supports optional cursor pagination and enabled/disabled filtering.
 */
webhookSubscriptionsRouter.get(
  "/",
  requireBusinessAuth,
  validateQuery(listWebhookSubscriptionsQuerySchema),
  asyncErrorHandler(async (req, res) => {
    const businessId = req.business!.id;

    const query = listWebhookSubscriptionsQuerySchema.parse(req.query);
    query.businessId = businessId;

    const result = await repo.list(query);
    const publicSubscriptions = result.data.map(repo.toPublicSubscription);

    res.status(200).json({
      status: "success",
      data: publicSubscriptions,
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
  requireBusinessAuth,
  asyncErrorHandler(async (req, res) => {
    const businessId = req.business!.id;

    const subscription = await repo.getById(req.params.id, businessId);
    if (!subscription) {
      throw new NotFoundError("Webhook subscription not found");
    }

    res.status(200).json({ status: "success", data: repo.toPublicSubscription(subscription) });
  }),
);

/**
 * GET /api/v1/webhook-subscriptions/:id/deliveries
 *
 * List webhook delivery receipts for a subscription owned by the
 * authenticated business. Cursor-paginated (`limit`, `cursor`). The public
 * view omits the stored `signature` and truncates `responseBody`.
 */
webhookSubscriptionsRouter.get(
  "/:id/deliveries",
  requireBusinessAuth,
  validateQuery(listWebhookDeliveriesQuerySchema),
  asyncErrorHandler(async (req, res) => {
    const businessId = req.business!.id;

    const subscription = await repo.getById(req.params.id, businessId);
    if (!subscription) {
      throw new NotFoundError("Webhook subscription not found");
    }

    const query = listWebhookDeliveriesQuerySchema.parse(req.query);
    const { queryDeliveryReceipts } = await import(
      "../repositories/deliveryReceiptRepository.js"
    );
    const result = await queryDeliveryReceipts({
      businessId,
      subscriptionId: req.params.id,
      limit: query.limit,
      cursor: query.cursor,
    });

    res.status(200).json({
      status: "success",
      data: result.data.map(toPublicDeliveryReceipt),
      ...(result.nextCursor ? { nextCursor: result.nextCursor } : {}),
    });
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
  requireBusinessAuth,
  validateBody(createWebhookSubscriptionSchema),
  asyncErrorHandler(async (req, res) => {
    const businessId = req.business!.id;

    // Enforce per-business subscription capacity
    const existingCount = await repo.countByBusiness(businessId);
    if (existingCount >= MAX_SUBSCRIPTIONS_PER_BUSINESS) {
      throw new ConflictError(
        `Maximum of ${MAX_SUBSCRIPTIONS_PER_BUSINESS} webhook subscriptions allowed per business`,
      );
    }

    const subscription = await repo.create(businessId, req.body);
    const publicSubscription = repo.toPublicSubscription(subscription);

    res.status(201).json({
      status: "success",
      data: { ...publicSubscription, secret: subscription.secret },
    });
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
  requireBusinessAuth,
  validateBody(updateWebhookSubscriptionSchema),
  asyncErrorHandler(async (req, res) => {
    const businessId = req.business!.id;

    const input = req.body;

    const updated = await repo.update(req.params.id, businessId, input);
    if (!updated) {
      throw new NotFoundError("Webhook subscription not found");
    }

    res.status(200).json({ status: "success", data: repo.toPublicSubscription(updated) });
  }),
);

/**
 * DELETE /api/v1/webhook-subscriptions/:id
 *
 * Delete a webhook subscription.
 */
webhookSubscriptionsRouter.delete(
  "/:id",
  requireBusinessAuth,
  asyncErrorHandler(async (req, res) => {
    const businessId = req.business!.id;

    const deleted = await repo.remove(req.params.id, businessId);
    if (!deleted) {
      throw new NotFoundError("Webhook subscription not found");
    }

    res.status(200).json({ status: "success", message: "Webhook subscription deleted" });
  }),
);

export default webhookSubscriptionsRouter;
