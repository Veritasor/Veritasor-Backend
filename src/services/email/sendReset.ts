import { z } from 'zod';
import { getMailTransport } from './client.js';
import { logger } from '../../utils/logger.js';

const MAIL_FROM = process.env.MAIL_FROM ?? process.env.SMTP_USER ?? 'noreply@veritasor.local';
const IS_DEV = process.env.NODE_ENV !== 'production';

export interface PasswordResetEmailResult {
  error?: Error;
  retryable: boolean;
}

const RETRYABLE_EMAIL_ERROR_CODES = new Set([
  'ECONNECTION',
  'ECONNREFUSED',
  'ECONNRESET',
  'EAI_AGAIN',
  'ESOCKET',
  'ETIMEDOUT',
]);

interface EmailErrorShape extends Error {
  code?: string;
  responseCode?: number;
}

export function isRetryableEmailError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const emailError = error as EmailErrorShape;

  if (typeof emailError.responseCode === 'number') {
    return emailError.responseCode >= 400 && emailError.responseCode < 500;
  }

  if (emailError.code && RETRYABLE_EMAIL_ERROR_CODES.has(emailError.code)) {
    return true;
  }

  return /timeout|temporar|try again/i.test(emailError.message);
}

/**
 * Simple HTML escape function to prevent template injection.
 * Replaces critical characters with their HTML entity equivalents.
 */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const ResetEmailSchema = z.object({
  email: z.string().email(),
  resetLink: z.string().url().refine(
    (url) => url.startsWith('https://') || (IS_DEV && url.startsWith('http://')),
    { message: "Unsafe URL protocol in reset link" }
  ),
});

/**
 * Send a password reset email. Does not throw; callers can decide whether to retry
 * or degrade gracefully based on the returned classification.
 */
export async function sendPasswordResetEmail(
  email: string,
  resetLink: string
): Promise<PasswordResetEmailResult> {
  // Validate inputs to prevent injection and malformed emails
  const validation = ResetEmailSchema.safeParse({ email, resetLink });
  if (!validation.success) {
    logger.warn({ errors: validation.error.format(), email }, 'Invalid password reset input');
    return { error: new Error('Invalid input'), retryable: false };
  }

  const transport = getMailTransport();

  if (!transport) {
    if (IS_DEV) {
      logger.info({ resetLink, email }, '[email] (dev stub) Password reset link sent');
      return { retryable: false };
    }

    logger.warn({ email }, '[email] No SMTP config; skipping password reset email');
    return { error: new Error('Email not configured'), retryable: false };
  }

  const escapedLink = escapeHtml(resetLink);

  try {
    await transport.sendMail({
      from: MAIL_FROM,
      to: email,
      subject: 'Reset your password',
      text: `Use this link to reset your password: ${resetLink}`,
      html: `<!DOCTYPE html><html><body><p>Use this link to reset your password:</p><p><a href="${escapedLink}">${escapedLink}</a></p></body></html>`,
    });

    logger.info({ email }, 'Password reset email sent successfully');
    return { retryable: false };
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    logger.error({ err: error, email }, 'Failed to send password reset email');
    return { error, retryable: isRetryableEmailError(error) };
  }
}
