import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getMailTransport, MailTransportConfigError } from './client.js';

const SMTP_ENV_KEYS = [
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_USER',
  'SMTP_PASS',
  'SMTP_SECURE',
] as const;

beforeEach(() => {
  for (const key of SMTP_ENV_KEYS) {
    vi.stubEnv(key, '');
  }
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('getMailTransport', () => {
  it('returns null when SMTP is not configured', () => {
    for (const key of SMTP_ENV_KEYS) {
      vi.stubEnv(key, '');
    }

    expect(getMailTransport()).toBeNull();
  });

  it('creates a transport from a complete SMTP configuration', () => {
    vi.stubEnv('SMTP_HOST', 'smtp.example.com');
    vi.stubEnv('SMTP_PORT', '465');
    vi.stubEnv('SMTP_USER', 'mailer@example.com');
    vi.stubEnv('SMTP_PASS', 'secret');
    vi.stubEnv('SMTP_SECURE', 'true');
    const transporter = {} as Transporter;
    const createTransport = vi
      .spyOn(nodemailer, 'createTransport')
      .mockReturnValue(transporter);

    expect(getMailTransport()).toBe(transporter);
    expect(createTransport).toHaveBeenCalledWith({
      host: 'smtp.example.com',
      port: 465,
      secure: true,
      auth: { user: 'mailer@example.com', pass: 'secret' },
    });
  });

  it('rejects partial configuration with a safe, deterministic error', () => {
    vi.stubEnv('SMTP_HOST', 'smtp.example.com');
    vi.stubEnv('SMTP_USER', 'mailer@example.com');

    expect(() => getMailTransport()).toThrow(MailTransportConfigError);
    expect(() => getMailTransport()).toThrow(
      'SMTP_HOST, SMTP_USER, and SMTP_PASS must all be configured'
    );
  });

  it.each(['587oops', '0', '65536', '1.5'])('rejects invalid SMTP_PORT %s', (port) => {
    vi.stubEnv('SMTP_HOST', 'smtp.example.com');
    vi.stubEnv('SMTP_USER', 'mailer@example.com');
    vi.stubEnv('SMTP_PASS', 'secret');
    vi.stubEnv('SMTP_PORT', port);

    expect(() => getMailTransport()).toThrow(MailTransportConfigError);
    expect(() => getMailTransport()).toThrow(
      'SMTP_PORT must be an integer between 1 and 65535'
    );
  });

  it('rejects an unsupported SMTP_SECURE value', () => {
    vi.stubEnv('SMTP_HOST', 'smtp.example.com');
    vi.stubEnv('SMTP_PORT', '587');
    vi.stubEnv('SMTP_USER', 'mailer@example.com');
    vi.stubEnv('SMTP_PASS', 'secret');
    vi.stubEnv('SMTP_SECURE', 'yes');

    expect(() => getMailTransport()).toThrow(MailTransportConfigError);
    expect(() => getMailTransport()).toThrow(
      "SMTP_SECURE must be either 'true' or 'false'"
    );
  });
});