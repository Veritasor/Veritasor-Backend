/**
 * Business Service - Update
 *
 * Handles the updating of existing business entities with comprehensive input
 * validation and normalization. Supports partial updates of business attributes.
 *
 * Features:
 * - Input validation using Zod schemas
 * - Automatic string normalization (name, URL, country code)
 * - Partial update support (only provided fields are updated)
 * - Structured error logging for observability
 * - User ownership verification
 * - NatSpec-style documentation
 *
 * Security Considerations:
 * - Validates all user inputs before database operations
 * - Verifies business ownership (user can only update their own business)
 * - Normalizes inputs to prevent injection attacks
 * - Enforces maximum field lengths
 * - Validates URL and pattern formats
 * - Validates ISO 3166-1 alpha-2 country codes
 * - Prevents unauthorized access to businesses
 *
 * Error Codes (stable, machine-readable):
 * - VALIDATION_ERROR – 400, input failed schema validation
 * - UNAUTHORIZED     – 401, no authenticated user in request
 * - NOT_FOUND        – 404, no business for this user
 * - INTERNAL_ERROR   – 500, unexpected server failure
 *
 * @module services/business/update
 */

import { Request, Response } from 'express';
import { z } from 'zod';
import { businessRepository } from '../../repositories/business.js';
import {
  parseUpdateBusinessInput,
  UpdateBusinessInput,
} from './schemas.js';
import { formatForStorage } from './normalize.js';

/**
 * Update Business Handler
 *
 * NatSpec-style documentation for the business update handler.
 *
 * @notice This function requires the user to be authenticated (via req.user).
 *         The authentication middleware is responsible for validating the JWT.
 *
 * @dev The authenticated user can only update their own business.
 *      Attempting to update another user's business will result in a 404 error.
 *
 * @dev Updates are partial - only provided fields are modified.
 *      Omitted fields are left unchanged.
 *
 * @param req Express request object containing:
 *   - req.user.id: Authenticated user ID (required)
 *   - req.body: Business updates (any fields can be provided)
 *
 * @param res Express response object for sending responses
 *
 * @returns Response with:
 *   - 200: Successfully updated business with full business object
 *   - 400: Invalid input or validation error
 *   - 401: Unauthenticated (no user in request)
 *   - 404: Business not found for this user
 *   - 500: Server error during business update
 *
 * @throws Will not throw; all errors are handled and returned as HTTP responses
 *
 * @example
 * ```
 * PATCH /api/businesses/me
 * Authorization: Bearer <token>
 * Content-Type: application/json
 *
 * {
 *   "name": "Updated Acme Corp",
 *   "website": "https://newsite.acme.com"
 * }
 *
 * Response (200):
 * {
 *   "id": "uuid-123",
 *   "userId": "user-uuid",
 *   "name": "Updated Acme Corp",
 *   "industry": "Technology",
 *   "description": "We make quality products",
 *   "website": "https://newsite.acme.com",
 *   "createdAt": "2026-03-25T10:00:00Z",
 *   "updatedAt": "2026-03-25T10:30:00Z"
 * }
 * ```
 */
export async function updateBusiness(req: Request, res: Response) {
  try {
    // @dev Verify user authentication
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'User authentication required',
      });
    }

    // @dev Find business for this user
    const business = await businessRepository.getByUserId(userId);
    if (!business) {
      // @dev Return 404 instead of revealing whether business exists
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Business not found',
      });
    }

    // @dev Parse and validate input with Zod schema
    let validatedInput: UpdateBusinessInput;
    try {
      validatedInput = await parseUpdateBusinessInput(req.body);
    } catch (validationError) {
      // @dev Return structured Zod issues so callers know exactly which fields failed
      const details =
        validationError instanceof z.ZodError
          ? validationError.issues
          : validationError instanceof Error
            ? validationError.message
            : 'Unknown validation error';

      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'Invalid input provided',
        details,
      });
    }

    // @dev Format input for storage (additional normalization)
    const normalizedData = formatForStorage({
      name: validatedInput.name,
      industry: validatedInput.industry,
      description: validatedInput.description,
      website: validatedInput.website,
      countryCode: validatedInput.countryCode,
    });

    // @dev Update business in repository with only provided fields
    const updated = await businessRepository.update(business.id, {
      name: normalizedData.name,
      industry: normalizedData.industry,
      description: normalizedData.description,
      website: normalizedData.website,
    });

    // @dev Return updated business with 200 status
    if (!updated) {
      // @dev Fallback error in case update fails unexpectedly
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update business',
      });
    }

    return res.status(200).json(updated);
  } catch (error) {
    // @dev Structured log: emit a JSON-serialisable object so log aggregators
    //      (e.g. Datadog, Cloud Logging) can index fields individually.
    console.error(JSON.stringify({
      event: 'business.update.error',
      userId: req.user?.id ?? null,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    }));

    return res.status(500).json({
      error: 'INTERNAL_ERROR',
      message: 'Failed to update business',
    });
  }
}
