import { findUserByEmail, setResetToken, updateUser, } from '../../repositories/userRepository.js';
import { randomBytes } from 'crypto';
import { sendPasswordResetEmail } from '../email/sendReset.js';
import { AppError } from '../../types/errors.js';
/**
 * Generate a password reset token and send it via the email service.
 * Retryable delivery failures are surfaced so callers can ask the client to retry.
 */
export async function forgotPassword(request) {
    const { email } = request;
    if (!email) {
        throw new Error('Email is required');
    }
    const user = await findUserByEmail(email);
    if (!user) {
        // Don't reveal whether email exists for security
        return {
            message: 'If an account with this email exists, a reset link has been sent',
        };
    }
    // Generate reset token
    const resetToken = randomBytes(32).toString('hex');
    await setResetToken(user.id, resetToken, 30); // 30 minute expiry
    const resetLink = `${process.env.RESET_PASSWORD_URL ?? 'http://localhost:3000/reset-password'}?token=${resetToken}`;
    const emailResult = await sendPasswordResetEmail(user.email, resetLink);
    if (emailResult.error) {
        await updateUser(user.id, {
            resetToken: null,
            resetTokenExpiry: null,
        });
        if (emailResult.retryable) {
            throw new AppError('Unable to send reset email right now. Please try again shortly.', 503, 'RESET_EMAIL_RETRYABLE_FAILURE');
        }
        throw new AppError('Password reset email is currently unavailable.', 500, 'RESET_EMAIL_UNAVAILABLE');
    }
    // Return reset link only in development
    const isDev = process.env.NODE_ENV !== 'production';
    return {
        message: 'If an account with this email exists, a reset link has been sent',
        ...(isDev && { resetLink }),
    };
}
