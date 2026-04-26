import { verifyToken } from "../utils/jwt.js";
import { findUserById } from "../repositories/userRepository.js";
import { businessRepository } from "../repositories/business.js";
/**
 * Validates JWT token and extracts user information
 * @param token - JWT token from Authorization header
 * @returns User payload or null if invalid
 */
async function validateUserToken(token) {
    try {
        const payload = verifyToken(token);
        if (!payload) {
            return null;
        }
        // Verify user still exists in database
        const user = await findUserById(payload.userId);
        if (!user) {
            return null;
        }
        return {
            id: payload.userId,
            userId: payload.userId,
            email: payload.email,
        };
    }
    catch (error) {
        return null;
    }
}
/**
 * Validates business access for a given user
 * @param businessId - Business ID to validate
 * @param userId - User ID requesting access
 * @returns Business object if valid, null otherwise
 */
async function validateBusinessAccess(businessId, userId) {
    try {
        const business = await businessRepository.getById(businessId);
        if (!business) {
            return null;
        }
        // Ensure user owns the business (authorization boundary)
        if (business.userId !== userId) {
            return null;
        }
        return business;
    }
    catch (error) {
        return null;
    }
}
/**
 * Extracts business ID from various sources with validation
 * @param req - Express request object
 * @returns Business ID or null if invalid/missing
 */
function extractBusinessId(req) {
    // Priority 1: x-business-id header (explicit business context)
    const businessIdHeader = req.header('x-business-id');
    if (businessIdHeader && businessIdHeader.trim().length > 0) {
        const trimmed = businessIdHeader.trim();
        // Basic UUID format validation (adjust based on your ID format)
        if (/^[a-zA-Z0-9\-_]{1,50}$/.test(trimmed)) {
            return trimmed;
        }
    }
    // Priority 2: business_id from request body (for POST/PUT requests)
    if (req.body && typeof req.body.business_id === 'string') {
        const bodyBusinessId = req.body.business_id.trim();
        if (bodyBusinessId.length > 0 && /^[a-zA-Z0-9\-_]{1,50}$/.test(bodyBusinessId)) {
            return bodyBusinessId;
        }
    }
    // Priority 3: businessId from request body (alternative field name)
    if (req.body && typeof req.body.businessId === 'string') {
        const bodyBusinessId = req.body.businessId.trim();
        if (bodyBusinessId.length > 0 && /^[a-zA-Z0-9\-_]{1,50}$/.test(bodyBusinessId)) {
            return bodyBusinessId;
        }
    }
    return null;
}
/**
 * Comprehensive business authorization boundary check
 *
 * This middleware enforces strict business authorization boundaries by:
 * 1. Validating JWT token authentication
 * 2. Verifying user existence in database
 * 3. Extracting and validating business ID from multiple sources
 * 4. Ensuring business exists and user has ownership rights
 * 5. Attaching user and business objects to request for downstream use
 *
 * Security features:
 * - JWT token validation with user existence check
 * - Business ownership verification (authorization boundary)
 * - Input validation for business ID format
 * - Multiple business ID source support with priority ordering
 * - Detailed error responses for debugging (in development)
 *
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Express next function
 */
export async function requireBusinessAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    // Step 1: Validate Authorization header
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({
            error: "Business authentication required",
            message: "Missing or invalid authorization header. Format: 'Bearer <token>'",
            code: "MISSING_AUTH"
        });
        return;
    }
    const token = authHeader.slice(7); // Remove 'Bearer ' prefix
    // Step 2: Validate user token and existence
    const user = await validateUserToken(token);
    if (!user) {
        res.status(401).json({
            error: "Invalid authentication",
            message: "Token is invalid, expired, or user not found",
            code: "INVALID_TOKEN"
        });
        return;
    }
    // Step 3: Extract and validate business ID
    const businessId = extractBusinessId(req);
    if (!businessId) {
        res.status(400).json({
            error: "Business context required",
            message: "Business ID is required. Provide via 'x-business-id' header or 'business_id'/'businessId' in request body",
            code: "MISSING_BUSINESS_ID"
        });
        return;
    }
    // Step 4: Validate business access and ownership
    const business = await validateBusinessAccess(businessId, user.id);
    if (!business) {
        res.status(403).json({
            error: "Business access denied",
            message: "Business not found or access denied. User must own the business.",
            code: "BUSINESS_NOT_FOUND"
        });
        return;
    }
    // Step 5: Attach authenticated context to request
    req.user = user;
    req.business = business;
    // Step 6: Log successful authentication (for security auditing)
    if (process.env.NODE_ENV !== 'test') {
        console.log(`Business auth success: user=${user.id}, business=${business.id}, business_name=${business.name}`);
    }
    next();
}
/**
 * Legacy middleware for backward compatibility
 * @deprecated Use requireBusinessAuth instead
 */
export const requireBusinessAuthLegacy = (req, res, next) => {
    const parseBusinessId = (authorization, businessIdHeader) => {
        if (!authorization || !authorization.startsWith('Bearer ')) {
            return null;
        }
        const businessId = businessIdHeader?.trim();
        return businessId ? businessId : null;
    };
    const businessId = parseBusinessId(req.header('authorization'), req.header('x-business-id'));
    if (!businessId) {
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Bearer token and x-business-id header are required',
        });
        return;
    }
    res.locals.businessId = businessId;
    next();
};
