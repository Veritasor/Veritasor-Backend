import { findUserByResetToken, updateUserPassword, } from '../../repositories/userRepository.js';
import { hashPassword } from '../../utils/password.js';
/**
 * Resets a user's password using a valid reset token.
 *
 * Security checks:
 * - requires both token and new password
 * - enforces a minimum password length
 * - rejects invalid or expired reset tokens
 * - expects the successful password reset path to consume the reset token,
 *   preventing token reuse
 */
export async function resetPassword(request) {
    const { token, newPassword } = request;
    if (!token || !newPassword) {
        throw new Error('Token and new password are required');
    }
    if (newPassword.length < 6) {
        throw new Error('Password must be at least 6 characters');
    }
    const user = await findUserByResetToken(token);
    if (!user) {
        throw new Error('Invalid or expired reset token');
    }
    const passwordHash = await hashPassword(newPassword);
    await updateUserPassword(user.id, passwordHash);
    return {
        message: 'Password has been reset successfully',
    };
}
