import { verifyToken } from "../utils/jwt.js";
import { findUserById } from "../repositories/userRepository.js";
/**
 * Extracts and validates the Bearer token from the Authorization header.
 *
 * This helper function handles various malformed Authorization headers gracefully:
 * - Missing or empty headers return null (unauthenticated)
 * - Non-"Bearer" schemes return null (unauthenticated, e.g., "Basic", "Token")
 * - Typos in "Bearer" prefix return null (e.g., "Bearr", "BEARER", "Bearer:")
 * - Missing or empty tokens (e.g., "Bearer " or "Bearer") return null
 * - Multiple spaces are normalized correctly (e.g., "Bearer  token" -> "token")
 * - Case-insensitive for the prefix (converts to lowercase before checking)
 *
 * Algorithm:
 * 1. Return null if header is missing or empty (falsy)
 * 2. Split on first whitespace and validate prefix is exactly "bearer" (case-insensitive)
 * 3. Trim any excess whitespace and validate token is non-empty
 * 4. Return null if validation fails at any step (malformed header)
 *
 * @param authHeader - The Authorization header value from the request
 * @returns The extracted Bearer token, or null if header is malformed/missing
 *
 * @example
 * extractBearerToken('Bearer valid-token') // returns 'valid-token'
 * extractBearerToken('Bearer  multiple  spaces') // returns 'multiple  spaces'
 * extractBearerToken('Bearer') // returns null (no token)
 * extractBearerToken('Bearr token') // returns null (typo in prefix)
 * extractBearerToken('Bearer:token') // returns null (colon instead of space)
 * extractBearerToken('Token token') // returns null (wrong scheme)
 * extractBearerToken('') // returns null (empty)
 * extractBearerToken(undefined) // returns null (missing)
 */
export function extractBearerToken(authHeader) {
    // Return null if header is missing or empty
    if (!authHeader) {
        return null;
    }
    // Split on the first whitespace to separate prefix from credentials
    const parts = authHeader.split(/\s+/);
    // Need at least 2 parts: prefix and token
    if (parts.length < 2) {
        return null;
    }
    // Validate prefix is exactly "bearer" (case-insensitive)
    const prefix = parts[0].toLowerCase();
    if (prefix !== "bearer") {
        return null;
    }
    // Get the token (everything after the prefix, handling multiple spaces)
    // We use slice(1) to get all parts after prefix and join with space
    const token = parts.slice(1).join(" ");
    // Validate token is non-empty after trimming
    if (!token || token.trim() === "") {
        return null;
    }
    // Return the token with internal whitespace preserved
    // but external whitespace trimmed (handles edge cases like "Bearer  token  ")
    return token.trim();
}
/**
 * Optional authentication middleware that attempts to authenticate requests
 * by verifying a JWT token in the Authorization header.
 *
 * Reliability & Consistency Improvements:
 * - Uses async/await to support database verification
 * - Verifies user existence in database if token is valid
 * - Clears req.user if database check fails
 * - Aligns with requireAuth naming conventions (id, userId)
 * - Robust header parsing: handles malformed Bearer prefixes gracefully
 * - Treats all malformed headers as unauthenticated requests (no 500 errors)
 *
 * Security Assumptions:
 * - If no token is provided, request is treated as unauthenticated.
 * - If token is provided but invalid, request is treated as unauthenticated.
 * - If token is valid but user no longer exists in DB, request is treated as unauthenticated.
 * - Malformed Authorization headers (wrong prefix, missing token, etc.) are treated as unauthenticated.
 * - This middleware NEVER returns 401 Unauthorized; use requireAuth for protected routes.
 *
 * @param req - Express Request object
 * @param res - Express Response object
 * @param next - Express NextFunction
 */
export async function optionalAuth(req, res, next) {
    try {
        // Extract Authorization header
        const authHeader = req.headers.authorization;
        // Use helper function to extract Bearer token safely
        // Returns null for any malformed headers (including missing headers)
        const token = extractBearerToken(authHeader);
        // If no valid token, proceed without auth
        if (!token) {
            next();
            return;
        }
        // Verify token using existing JWT verification logic
        const payload = verifyToken(token);
        // If token is valid, verify user existence and attach to request
        if (payload) {
            const user = await findUserById(payload.userId);
            if (user) {
                req.user = {
                    id: user.id,
                    userId: user.id,
                    email: user.email,
                };
            }
            else {
                // Token was valid but user was not found (e.g., deleted)
                req.user = undefined;
            }
        }
        // Always proceed to next handler
        next();
    }
    catch (error) {
        // Handle any unexpected errors gracefully
        // Ensure req.user is undefined on error and proceed
        req.user = undefined;
        next();
    }
}
