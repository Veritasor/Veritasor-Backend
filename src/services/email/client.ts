import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

const DEFAULT_SMTP_PORT = 587;

/**
 * Build SMTP transport from env. Use SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS.
 * Optional: MAIL_FROM (defaults to SMTP_USER), SMTP_SECURE ('true' for 465).
 * Returns null if SMTP is not configured (e.g. dev stub).
 */
export function getMailTransport(): Transporter | null {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) {
    return null;
  }
  const port = parseInt(process.env.SMTP_PORT ?? String(DEFAULT_SMTP_PORT), 10);
  const secure = process.env.SMTP_SECURE === 'true';
  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });
}
