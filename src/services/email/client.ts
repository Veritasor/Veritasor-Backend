import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

/**
 * Build SMTP transport from env. Use SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS.
 * Optional: MAIL_FROM (defaults to SMTP_USER), SMTP_SECURE ('true' for 465).
 * Returns null when SMTP is not configured. Partial or invalid configuration
 * throws MailTransportConfigError without exposing configuration values.
 */
export class MailTransportConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MailTransportConfigError';
  }
}

export function getMailTransport(): Transporter | null {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  const smtpSettings = [
    host,
    process.env.SMTP_PORT,
    user,
    pass,
    process.env.SMTP_SECURE,
  ];
  if (smtpSettings.every((setting) => setting === undefined || setting === '')) {
    return null;
  }

  if (!host?.trim() || !user?.trim() || !pass?.trim()) {
    throw new MailTransportConfigError(
      'SMTP_HOST, SMTP_USER, and SMTP_PASS must all be configured'
    );
  }

  const portValue = process.env.SMTP_PORT ?? '587';
  if (!/^\d+$/.test(portValue)) {
    throw new MailTransportConfigError(
      'SMTP_PORT must be an integer between 1 and 65535'
    );
  }
  const port = Number(portValue);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new MailTransportConfigError(
      'SMTP_PORT must be an integer between 1 and 65535'
    );
  }

  const secureValue = process.env.SMTP_SECURE;
  if (secureValue !== undefined && secureValue !== '' &&
      secureValue !== 'true' && secureValue !== 'false') {
    throw new MailTransportConfigError(
      "SMTP_SECURE must be either 'true' or 'false'"
    );
  }
  const secure = secureValue === 'true';

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });
}
