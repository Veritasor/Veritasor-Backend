/**
 * Refresh token rotation service.
 *
 * Security model
 * ──────────────
 * Each refresh token carries a unique `jti` (JWT ID). On a successful refresh
 * the old JTI is written to the used-token store before the new token pair is
 * returned. Any subsequent attempt to use the same JTI is rejected with an
 * AuthenticationError, regardless of which instance handles the request or
 * whether the process has restarted.
 *
 * The store is injected via `getUsedTokenStore()` so the implementation can be
 * swapped between environments:
 *   - Tests:       InMemoryUsedTokenStore  (reset via clearUsedRefreshTokens)
 *   - Production:  DbUsedTokenStore        (PostgreSQL, shared, TTL-aware)
 *
 * Failure mode
 * ────────────
 * If the store is unavailable (e.g. DB down) the refresh is rejected rather
 * than allowed through. Failing closed is the safe default for auth operations.
 *
 * @module refresh
 */
import { findUserById } from '../../repositories/userRepository.js';
import { generateToken, generateRefreshToken, verifyRefreshToken, } from '../../utils/jwt.js';
import { AuthenticationError } from '../../types/errors.js';
import { getUsedTokenStore, InMemoryUsedTokenStore, setUsedTokenStore, } from './usedTokenStore.js';
import jwt from 'jsonwebtoken';
// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------
/**
 * Resets the used-token store to a fresh InMemoryUsedTokenStore.
 * @internal For test isolation only — do not call in production code.
 */
export function clearUsedRefreshTokens() {
    setUsedTokenStore(new InMemoryUsedTokenStore());
}
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
/**
 * Extracts the `jti` and `exp` claims from a JWT without re-verifying the
 * signature. The token has already been verified by verifyRefreshToken() at
 * this point, so decoding is safe.
 */
function extractJtiAndExp(token) {
    const decoded = jwt.decode(token);
    if (!decoded?.jti || !decoded?.exp) {
        throw new AuthenticationError('Refresh token is missing required claims');
    }
    return { jti: decoded.jti, exp: decoded.exp };
}
// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------
/**
 * Validates a refresh token, prevents replay, and rotates the token pair.
 *
 * Steps:
 *   1. Verify the token is structurally valid and not expired.
 *   2. Check the JTI against the shared used-token store (replay detection).
 *   3. Look up the user to confirm the account still exists.
 *   4. Atomically mark the old JTI as consumed.
 *   5. Issue a new access + refresh token pair.
 *
 * @throws AuthenticationError on any validation or replay failure.
 */
export async function refresh(request) {
    const { refreshToken } = request;
    if (!refreshToken) {
        throw new AuthenticationError('Refresh token is required');
    }
    // Step 1 — cryptographic verification (signature, expiry, iss, aud)
    const payload = verifyRefreshToken(refreshToken);
    if (!payload) {
        throw new AuthenticationError('Invalid or expired refresh token');
    }
    // Step 2 — extract JTI for replay detection
    const { jti, exp } = extractJtiAndExp(refreshToken);
    const store = getUsedTokenStore();
    const alreadyUsed = await store.has(jti);
    if (alreadyUsed) {
        throw new AuthenticationError('Invalid refresh token');
    }
    // Step 3 — confirm the user account still exists
    const user = await findUserById(payload.userId);
    if (!user) {
        throw new AuthenticationError('User not found');
    }
    // Step 4 — mark old JTI as consumed (TTL = token expiry)
    // Failing here means the store is unavailable; fail closed.
    const expiresAt = new Date(exp * 1000);
    await store.mark(jti, user.id, expiresAt);
    // Step 5 — issue new token pair
    const accessToken = generateToken({
        userId: user.id,
        email: user.email,
    });
    const newRefreshToken = generateRefreshToken({
        userId: user.id,
        email: user.email,
    });
    return {
        accessToken,
        refreshToken: newRefreshToken,
    };
}
