/**
 * Business Service - Update
 *
 * Handles the updating of existing business entities with comprehensive input
 * validation and normalization. Supports partial updates of business attributes.
 *
 * Features:
 * - Input validation using Zod schemas
 * - Automatic string normalization
 * - Partial update support (only provided fields are updated)
 * - Comprehensive error handling
 * - User ownership verification
 * - NatSpec-style documentation
 *
 * Security Considerations:
 * - Validates all user inputs before database operations
 * - Verifies business ownership (user can only update their own business)
 * - Normalizes inputs to prevent injection attacks
 * - Enforces maximum field lengths
 * - Validates URL and pattern formats
 * - Prevents unauthorized access to businesses
 *
 * @module services/business/update
 */
import { businessRepository } from '../../repositories/business.js';
import { parseUpdateBusinessInput, } from './schemas.js';
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
export async function updateBusiness(req, res) {
    try {
        // @dev Verify user authentication
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'User authentication required',
            });
        }
        // @dev Find business for this user
        const business = await businessRepository.getByUserId(userId);
        if (!business) {
            // @dev Return 404 instead of revealing whether business exists
            return res.status(404).json({
                error: 'Not Found',
                message: 'Business not found',
            });
        }
        // @dev Parse and validate input with Zod schema
        let validatedInput;
        try {
            validatedInput = await parseUpdateBusinessInput(req.body);
        }
        catch (validationError) {
            // @dev Return detailed validation errors to client
            return res.status(400).json({
                error: 'Validation Error',
                message: 'Invalid input provided',
                details: validationError instanceof Error ? validationError.message : 'Unknown validation error',
            });
        }
        // @dev Format input for storage (additional normalization)
        const normalizedData = formatForStorage({
            name: validatedInput.name,
            industry: validatedInput.industry,
            description: validatedInput.description,
            website: validatedInput.website,
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
    }
    catch (error) {
        // @dev Log unexpected errors for debugging
        console.error('Error updating business:', error);
        // @dev Return generic server error to client
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to update business',
        });
    }
}
