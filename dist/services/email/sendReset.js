import { getMailTransport } from './client.js';
const MAIL_FROM = process.env.MAIL_FROM ?? process.env.SMTP_USER ?? 'noreply@veritasor.local';
const IS_DEV = process.env.NODE_ENV !== 'production';
const RETRYABLE_EMAIL_ERROR_CODES = new Set([
    'ECONNECTION',
    'ECONNREFUSED',
    'ECONNRESET',
    'EAI_AGAIN',
    'ESOCKET',
    'ETIMEDOUT',
]);
export function isRetryableEmailError(error) {
    if (!(error instanceof Error)) {
        return false;
    }
    const emailError = error;
    if (typeof emailError.responseCode === 'number') {
        return emailError.responseCode >= 400 && emailError.responseCode < 500;
    }
    if (emailError.code && RETRYABLE_EMAIL_ERROR_CODES.has(emailError.code)) {
        return true;
    }
    return /timeout|temporar|try again/i.test(emailError.message);
}
/**
 * Send a password reset email. Does not throw; callers can decide whether to retry
 * or degrade gracefully based on the returned classification.
 */
export async function sendPasswordResetEmail(email, resetLink) {
    const transport = getMailTransport();
    if (!transport) {
        if (IS_DEV) {
            console.info('[email] (dev stub) Password reset link:', resetLink, '->', email);
            return { retryable: false };
        }
        console.warn('[email] No SMTP config; skipping password reset email to', email);
        return { error: new Error('Email not configured'), retryable: false };
    }
    try {
        await transport.sendMail({
            from: MAIL_FROM,
            to: email,
            subject: 'Reset your password',
            text: `Use this link to reset your password: ${resetLink}`,
            html: `<!DOCTYPE html><html><body><p>Use this link to reset your password:</p><p><a href="${resetLink}">${resetLink}</a></p></body></html>`,
        });
        return { retryable: false };
    }
    catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        console.error('[email] Failed to send password reset:', error.message, '->', email);
        return { error, retryable: isRetryableEmailError(error) };
    }
}
