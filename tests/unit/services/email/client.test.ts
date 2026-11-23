import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('nodemailer', () => {
  return {
    default: {
      createTransport: vi.fn(() => ({ __mockTransport: true })),
    },
  };
});

import nodemailer from 'nodemailer';
import { getMailTransport } from '../../../../src/services/email/client';

const ORIGINAL_ENV = { ...process.env };

const SMTP_KEYS = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_SECURE'] as const;

function setValidEnv(overrides: Partial<Record<(typeof SMTP_KEYS)[number], string | undefined>> = {}) {
  const base: Record<string, string | undefined> = {
    SMTP_HOST: 'smtp.example.test',
    SMTP_USER: 'user@example.test',
    SMTP_PASS: 'secret',
    SMTP_PORT: undefined,
    SMTP_SECURE: undefined,
    ...overrides,
  };
  for (const [key, value] of Object.entries(base)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}

describe('getMailTransport', () => {
  beforeEach(() => {
    vi.mocked(nodemailer.createTransport).mockClear();
    for (const key of SMTP_KEYS) {
      delete process.env[key];
    }
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('returns null when SMTP_HOST is missing', () => {
    setValidEnv({ SMTP_HOST: undefined });
    expect(getMailTransport()).toBeNull();
    expect(nodemailer.createTransport).not.toHaveBeenCalled();
  });

  it('returns null when SMTP_USER is missing', () => {
    setValidEnv({ SMTP_USER: undefined });
    expect(getMailTransport()).toBeNull();
    expect(nodemailer.createTransport).not.toHaveBeenCalled();
  });

  it('returns null when SMTP_PASS is missing', () => {
    setValidEnv({ SMTP_PASS: undefined });
    expect(getMailTransport()).toBeNull();
    expect(nodemailer.createTransport).not.toHaveBeenCalled();
  });

  it('returns null when all SMTP variables are missing', () => {
    expect(getMailTransport()).toBeNull();
    expect(nodemailer.createTransport).not.toHaveBeenCalled();
  });

  it('defaults to port 587 and secure false when optional vars are unset', () => {
    setValidEnv();
    const transport = getMailTransport();
    expect(transport).not.toBeNull();
    expect(nodemailer.createTransport).toHaveBeenCalledTimes(1);
    expect(nodemailer.createTransport).toHaveBeenCalledWith({
      host: 'smtp.example.test',
      port: 587,
      secure: false,
      auth: { user: 'user@example.test', pass: 'secret' },
    });
  });

  it('passes SMTP_PORT=465 and SMTP_SECURE=true through to nodemailer', () => {
    setValidEnv({ SMTP_PORT: '465', SMTP_SECURE: 'true' });
    getMailTransport();
    expect(nodemailer.createTransport).toHaveBeenCalledWith({
      host: 'smtp.example.test',
      port: 465,
      secure: true,
      auth: { user: 'user@example.test', pass: 'secret' },
    });
  });

  it('treats SMTP_SECURE values other than the string "true" as false', () => {
    setValidEnv({ SMTP_SECURE: 'TRUE' });
    getMailTransport();
    expect(nodemailer.createTransport).toHaveBeenCalledWith(
      expect.objectContaining({ secure: false }),
    );
  });
});
