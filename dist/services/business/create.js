/**
 * Business Service - Create
 *
 * Handles the creation of new business entities with comprehensive input
 * validation and normalization. Ensures only one business per user.
 *
 * Features:
 * - Input validation using Zod schemas
 * - Automatic string normalization
 * - Duplicate business prevention
 * - Comprehensive error handling
 * - NatSpec-style documentation
 *
 * Security Considerations:
 * - Validates all user inputs before database operations
 * - Prevents duplicate business creation per user
 * - Normalizes inputs to prevent injection attacks
 * - Enforces maximum field lengths
 * - Validates URL and pattern formats
 *
 * @module services/business/create
 */
import { businessRepository } from '../../repositories/business.js';
import { parseCreateBusinessInput, } from './schemas.js';
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
export async function createBusiness(req, res) {
    try {
        // @dev Verify user authentication
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'User authentication required',
            });
        }
        // @dev Check for existing business (one per user policy)
        const existing = await businessRepository.getByUserId(userId);
        if (existing) {
            return res.status(409).json({
                error: 'Conflict',
                message: 'Business already exists for this user',
            });
        }
        // @dev Parse and validate input with Zod schema
        let validatedInput;
        try {
            validatedInput = await parseCreateBusinessInput(req.body);
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
        // @dev Create business in repository
        const business = await businessRepository.create({
            userId,
            name: normalizedData.name,
            industry: normalizedData.industry,
            description: normalizedData.description,
            website: normalizedData.website,
        });
        // @dev Return created business with 201 status
        return res.status(201).json(business);
    }
    catch (error) {
        // @dev Log unexpected errors for debugging
        console.error('Error creating business:', error);
        // @dev Return generic server error to client
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to create business',
        });
    }
}
