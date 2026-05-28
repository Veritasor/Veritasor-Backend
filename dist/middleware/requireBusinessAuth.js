import { verifyToken } from "../utils/jwt.js";
import { findUserById } from "../repositories/userRepository.js";
import { businessRepository } from "../repositories/business.js";
import { logger } from "../utils/logger.js";
/**
 * Validates JWT token and returns the user, or null on any failure.
 * Catches all errors so callers never see an unhandled rejection.
 */
async function validateUserToken(token) {
    try {
        const payload = verifyToken(token);
        if (!payload)
            return null;
        const user = await findUserById(payload.userId);
        if (!user)
            return null;
        return { id: payload.userId, userId: payload.userId, email: payload.email };
    }
    catch {
        return null;
    }
}
/**
 * Extracts and validates the business ID from the request.
 *
 * Priority order (matches documented API contract):
 *   1. x-business-id header
 *   2. body.business_id
 *   3. body.businessId
 *
 * Uses req.headers directly (lowercase, per Node.js HTTP spec) so the
 * function works correctly with plain mock objects in tests as well as
 * real Express requests.
 */
function extractBusinessId(req) {
    const ID_RE = /^[a-zA-Z0-9\-_]{1,50}$/;
    // Priority 1: x-business-id header
    const headerVal = req.headers['x-business-id'];
    const headerStr = Array.isArray(headerVal) ? headerVal[0] : headerVal;
    if (headerStr) {
        const trimmed = headerStr.trim();
        if (trimmed && ID_RE.test(trimmed))
            return trimmed;
    }
    // Priority 2 & 3: request body
    if (req.body) {
        for (const field of ['business_id', 'businessId']) {
            const val = req.body[field];
            if (typeof val === 'string') {
                const trimmed = val.trim();
                if (trimmed && ID_RE.test(trimmed))
                    return trimmed;
            }
        }
    }
    return null;
}
/**
 * requireBusinessAuth
 *
 * Enforces business-scoped authentication on every request:
 *   1. Validates the Bearer JWT and confirms the user still exists in the DB.
 *   2. Extracts the business ID from x-business-id header or request body.
 *   3. Fetches the business and verifies the authenticated user owns it.
 *   4. Rejects suspended businesses with 403 BUSINESS_SUSPENDED.
 *   5. Attaches req.user and req.business for downstream handlers.
 *
 * Error codes (stable contract):
 *   401 MISSING_AUTH        – missing / malformed Authorization header
 *   401 INVALID_TOKEN       – expired, invalid, or revoked JWT; user not found
 *   400 MISSING_BUSINESS_ID – no business ID in header or body
 *   403 BUSINESS_NOT_FOUND  – business absent or owned by a different user
 *   403 BUSINESS_SUSPENDED  – business exists but is suspended
 */
export async function requireBusinessAuth(req, res, next) {
    // ── Step 1: Authorization header ──────────────────────────────────────────
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({
            error: "Business authentication required",
            message: "Missing or invalid authorization header. Format: 'Bearer <token>'",
            code: "MISSING_AUTH",
        });
        return;
    }
    const token = authHeader.slice(7);
    // ── Step 2: Token + user validation ───────────────────────────────────────
    const user = await validateUserToken(token);
    if (!user) {
        res.status(401).json({
            error: "Invalid authentication",
            message: "Token is invalid, expired, or user not found",
            code: "INVALID_TOKEN",
        });
        return;
    }
    // ── Step 3: Business ID extraction ────────────────────────────────────────
    const businessId = extractBusinessId(req);
    if (!businessId) {
        res.status(400).json({
            error: "Business context required",
            message: "Business ID is required. Provide via 'x-business-id' header or 'business_id'/'businessId' in request body",
            code: "MISSING_BUSINESS_ID",
        });
        return;
    }
    // ── Step 4: Business ownership check ──────────────────────────────────────
    let business;
    try {
        business = await businessRepository.getById(businessId);
    }
    catch {
        business = null;
    }
    if (!business || business.userId !== user.id) {
        res.status(403).json({
            error: "Business access denied",
            message: "Business not found or access denied. User must own the business.",
            code: "BUSINESS_NOT_FOUND",
        });
        return;
    }
    // ── Step 5: Suspended business check ──────────────────────────────────────
    if (business.suspended === true) {
        logger.warn(JSON.stringify({
            event: "business_auth.suspended",
            userId: user.id,
            businessId: business.id,
        }));
        res.status(403).json({
            error: "Business suspended",
            message: "This business account has been suspended.",
            code: "BUSINESS_SUSPENDED",
        });
        return;
    }
    // ── Step 6: Attach context and proceed ────────────────────────────────────
    req.user = user;
    req.business = business;
    logger.info(JSON.stringify({
        event: "business_auth.success",
        userId: user.id,
        businessId: business.id,
    }));
    next();
}
/**
 * Legacy middleware for backward compatibility.
 * @deprecated Use requireBusinessAuth instead.
 */
export const requireBusinessAuthLegacy = (req, res, next) => {
    const auth = req.headers.authorization;
    const businessIdHeader = req.headers['x-business-id'];
    const businessId = Array.isArray(businessIdHeader)
        ? businessIdHeader[0]?.trim()
        : businessIdHeader?.trim();
    if (!auth || !auth.startsWith('Bearer ') || !businessId) {
        res.status(401).json({
            error: 'Unauthorized',
            message: 'Bearer token and x-business-id header are required',
        });
        return;
    }
    res.locals.businessId = businessId;
    next();
};
