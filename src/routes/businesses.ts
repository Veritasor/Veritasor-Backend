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
import { validateBody } from '../middleware/validate.js';
import { createBusiness } from '../services/business/create.js';
import { updateBusiness } from '../services/business/update.js';
import { getMyBusiness, getBusinessById } from '../services/business/get.js';
import {
  createBusinessInputSchema,
  updateBusinessInputSchema,
} from '../services/business/schemas.js';

const router = Router();

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
  createBusiness,
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
router.get('/me', requireAuth, getMyBusiness);

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
  updateBusiness,
);

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
router.get('/:id', getBusinessById);

export default router;