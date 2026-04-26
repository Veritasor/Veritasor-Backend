/**
 * Business Service - Create
 *
 * Handles the creation of new business entities with comprehensive input
 * validation and normalization. Ensures only one business per user.
 *
 * Features:
 * - Input validation using Zod schemas
 * - Automatic string normalization (name, URL, country code)
 * - Duplicate business prevention with stable error codes
 * - Structured error logging for observability
 * - NatSpec-style documentation
 *
 * Security Considerations:
 * - Validates all user inputs before database operations
 * - Prevents duplicate business creation per user
 * - Normalizes inputs to prevent injection attacks
 * - Enforces maximum field lengths
 * - Validates URL and pattern formats
 * - Validates ISO 3166-1 alpha-2 country codes
 *
 * Error Codes (stable, machine-readable):
 * - BUSINESS_ALREADY_EXISTS – 409, user already has a business
 * - VALIDATION_ERROR        – 400, input failed schema validation
 * - UNAUTHORIZED            – 401, no authenticated user in request
 * - INTERNAL_ERROR          – 500, unexpected server failure
 *
 * @module services/business/create
 */

import { Request, Response } from 'express';
import { z } from 'zod';
import { businessRepository } from '../../repositories/business.js';
import {
  parseCreateBusinessInput,
  CreateBusinessInput,
} from './schemas.js';
import { formatForStorage } from './normalize.js';

/**
 * Create Business Handler
 *
 * NatSpec-style documentation for the main business creation handler.
 *
 * @notice This function requires the user to be authenticated (via req.user).
 *         The authentication middleware is responsible for validating the JWT.
 *
 * @dev The input is automatically validated by the validateBody middleware
 *      before reaching this function, but we defensively validate again
 *      to ensure type safety and consistent normalization.
 *
 * @param req Express request object containing:
 *   - req.user.id: Authenticated user ID (required)
 *   - req.body: Business data (name, industry, description, website)
 *
 * @param res Express response object for sending responses
 *
 * @returns Response with:
 *   - 201: Successfully created business with full business object
 *   - 400: Invalid input or validation error
 *   - 401: Unauthenticated (no user in request)
 *   - 409: Business already exists for this user
 *   - 500: Server error during business creation
 *
 * @throws Will not throw; all errors are handled and returned as HTTP responses
 *
 * @example
 * ```
 * POST /api/businesses
 * Authorization: Bearer <token>
 * Content-Type: application/json
 *
 * {
 *   "name": "Acme Corp",
 *   "industry": "Technology",
 *   "description": "We make quality products",
 *   "website": "https://acme.com"
 * }
 *
 * Response (201):
 * {
 *   "id": "uuid-123",
 *   "userId": "user-uuid",
 *   "name": "Acme Corp",
 *   "industry": "Technology",
 *   "description": "We make quality products",
 *   "website": "https://acme.com",
 *   "createdAt": "2026-03-25T10:00:00Z",
 *   "updatedAt": "2026-03-25T10:00:00Z"
 * }
 * ```
 */
export async function createBusiness(req: Request, res: Response) {
  try {
    // @dev Verify user authentication
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'User authentication required',
      });
    }

    // @dev Check for existing business (one per user policy)
    const existing = await businessRepository.getByUserId(userId);
    if (existing) {
      return res.status(409).json({
        // @dev Stable machine-readable code so clients can branch without
        //      string-matching the human message.
        error: 'BUSINESS_ALREADY_EXISTS',
        message: 'A business already exists for this user',
      });
    }

    // @dev Parse and validate input with Zod schema
    let validatedInput: CreateBusinessInput;
    try {
      validatedInput = await parseCreateBusinessInput(req.body);
    } catch (validationError) {
      // @dev Surface structured Zod issues so callers know exactly which
      //      fields failed without parsing the human message.
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

    // @dev Format input for storage (additional normalization layer)
    const normalizedData = formatForStorage({
      name: validatedInput.name,
      industry: validatedInput.industry,
      description: validatedInput.description,
      website: validatedInput.website,
      countryCode: validatedInput.countryCode,
    });

    // @dev Create business in repository
    // @dev email is taken from the authenticated user context (set by auth middleware)
    const business = await businessRepository.create({
      userId,
      email: req.user?.email ?? '',
      name: normalizedData.name!,
      industry: normalizedData.industry,
      description: normalizedData.description,
      website: normalizedData.website,
    });

    // @dev Return created business with 201 status
    return res.status(201).json(business);
  } catch (error) {
    // @dev Structured log: emit a JSON-serialisable object so log aggregators
    //      (e.g. Datadog, Cloud Logging) can index fields individually.
    console.error(JSON.stringify({
      event: 'business.create.error',
      userId: req.user?.id ?? null,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    }));

    return res.status(500).json({
      error: 'INTERNAL_ERROR',
      message: 'Failed to create business',
    });
  }
}
