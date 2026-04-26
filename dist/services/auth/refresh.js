import { findUserById } from '../../repositories/userRepository.js';
import { generateToken, generateRefreshToken, verifyRefreshToken, } from '../../utils/jwt.js';
// Simple in-memory store for used tokens (rotation protection)
const usedRefreshTokens = new Set();
/**
 * Unified Auth Session Rotation Policy:
 * - validates refresh token
 * - prevents reuse
 * - rotates tokens
 */
export async function refresh(request) {
    const { refreshToken } = request;
    if (!refreshToken) {
        throw new Error('Refresh token is required');
    }
    // 🚨 prevent reuse (IMPORTANT for rotation)
    if (usedRefreshTokens.has(refreshToken)) {
        throw new Error('Invalid refresh token');
    }
    const payload = verifyRefreshToken(refreshToken);
    if (!payload) {
        throw new Error('Invalid or expired refresh token');
    }
    const user = await findUserById(payload.userId);
    if (!user) {
        throw new Error('User not found');
    }
    // mark old token as used
    usedRefreshTokens.add(refreshToken);
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
