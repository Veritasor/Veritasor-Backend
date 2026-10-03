/**
 * Business Routes
 *
 * HTTP route handlers for business entity operations.
 * All routes requiring authentication use the requireAuth middleware.
 *
 * Routes:
 * - POST /   - Create a new business (requires auth)
 * - GET /me  - Get authenticated user's business (requires auth)
 * - PATCH /me - Update authenticated user's business (requires auth)
 * - GET /:id - Get business by ID (public read)
 *
 * @module routes/businesses
 */

import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { z } from 'zod';
import { validateBody, validateQuery } from '../middleware/validate.js';
import { asyncErrorHandler } from '../middleware/errorHandler.js';
import { createBusiness } from '../services/business/create.js';
import { updateBusiness } from '../services/business/update.js';
import { getMyBusiness, getBusinessById, listBusinesses } from '../services/business/get.js';
import {
  createBusinessInputSchema,
  updateBusinessInputSchema,
  businessListQuerySchema,
} from '../services/business/schemas.js'
import type { WebhookSubscription } from '../services/webhooks/dispatcher.js';
import crypto from 'node:crypto';

const router = Router();
export const webhookRouter = Router({ mergeParams: true });

const webhookRegistrationSchema = z.object({
  url: z.string().url(),
  secret: z.string().min(32), // Mandate cryptographically strong secrets
});

// Mock database repository storage array layer
// TODO: Replace with a persistent repository implementation
const subscriptionsDb: WebhookSubscription[] = [];

/**
 * POST /
 * Create a new business
 *
 * Requires authentication. One business per user is enforced.
 * Input is validated and normalized using Zod schema.
 *
 * @route POST /api/businesses
 * @auth required
 * @param {string} name - Business name (required, max 255 chars)
 * @param {string} [industry] - Industry classification (optional, max 100 chars)
 * @param {string} [description] - Business description (optional, max 2000 chars)
 * @param {string} [website] - Business website URL (optional, max 2048 chars)
 *
 * @returns {object} 201 - Created business object
 * @returns {error} 400 - Validation error
 * @returns {error} 401 - Unauthorized
 * @returns {error} 409 - Business already exists for user
 * @returns {error} 500 - Server error
 */
router.post(
  '/',
  requireAuth,
  validateBody(createBusinessInputSchema),
  asyncErrorHandler(createBusiness),
);

/**
 * GET /me
 * Get authenticated user's business
 *
 * Requires authentication. Returns the business associated
 * with the authenticated user.
 *
 * @route GET /api/businesses/me
 * @auth required
 *
 * @returns {object} 200 - Business object
 * @returns {error} 401 - Unauthorized
 * @returns {error} 404 - Not found
 * @returns {error} 500 - Server error
 */
router.get('/me', requireAuth, asyncErrorHandler(getMyBusiness));

/**
 * PATCH /me
 * Update authenticated user's business
 *
 * Requires authentication. Supports partial updates - only
 * provided fields are updated. Input is validated and normalized.
 *
 * @route PATCH /api/businesses/me
 * @auth required
 * @param {string} [name] - Business name (optional, max 255 chars)
 * @param {string} [industry] - Industry classification (optional, max 100 chars)
 * @param {string} [description] - Business description (optional, max 2000 chars)
 * @param {string} [website] - Business website URL (optional, max 2048 chars)
 *
 * @returns {object} 200 - Updated business object
 * @returns {error} 400 - Validation error
 * @returns {error} 401 - Unauthorized
 * @returns {error} 404 - Not found
 * @returns {error} 500 - Server error
 */
router.patch(
  '/me',
  requireAuth,
  validateBody(updateBusinessInputSchema),
  asyncErrorHandler(updateBusiness),
);

/**
 * GET /
 * List businesses
 *
 * Public endpoint - no authentication required.
 * Supports keyset pagination and filtering.
 *
 * @route GET /api/businesses
 * @param {number} [limit] - Number of items to return (default 20, max 100)
 * @param {string} [cursor] - Keyset pagination cursor
 * @param {string} [sortBy] - Sort column (createdAt, name)
 * @param {string} [sortOrder] - Sort order (asc, desc)
 * @param {string} [industry] - Filter by industry
 *
 * @returns {object} 200 - Paginated list of businesses
 * @returns {error} 400 - Validation error
 * @returns {error} 500 - Server error
 */
router.get('/', validateQuery(businessListQuerySchema), asyncErrorHandler(listBusinesses));

/**
 * GET /:id
 * Get business by ID
 *
 * Public endpoint - no authentication required.
 * Returns business information by ID.
 *
 * @route GET /api/businesses/:id
 * @param {string} id - Business UUID (required)
 *
 * @returns {object} 200 - Business object
 * @returns {error} 404 - Not found
 * @returns {error} 500 - Server error
 */
router.get('/:id', asyncErrorHandler(getBusinessById));

webhookRouter.post("/", requireAuth, validateBody(webhookRegistrationSchema), async (req, res) => {
  try {
    const businessId = req.params.id;
    const validatedBody = webhookRegistrationSchema.parse(req.body);

    // Limit bounded fan-out count capacity rules
    const existingCount = subscriptionsDb.filter(sub => sub.businessId === businessId).length;
    if (existingCount >= 5) {
      return res.status(400).json({ error: "Maximum webhook endpoint subscription capacity reached." });
    }

    const newSubscription: WebhookSubscription = {
      id: crypto.randomUUID(),
      businessId,
      url: validatedBody.url,
      secret: validatedBody.secret,
    };

    subscriptionsDb.push(newSubscription);
    return res.status(201).json(newSubscription);
  } catch (err) {
    // This will be caught by the asyncErrorHandler, but for clarity:
    return res.status(400).json({ error: "Invalid registration payload context validation error." });
  }
});

router.use('/:id/webhooks', webhookRouter);

export default router;