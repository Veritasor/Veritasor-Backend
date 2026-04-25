/**
 * @file auth.test.ts
 * @description Unit + integration tests for the password reset flow.
 *
 * Coverage targets (per issue #203):
 *   ≥ 95% line and branch coverage on forgotPassword.ts and resetPassword.ts.
 *
 * Test layout
 * ───────────
 *   Config Validation          — existing tests (unchanged)
 *   forgotPassword()
 *     ├─ Input validation
 *     ├─ User-enumeration resistance (timing + response parity)
 *     ├─ Token entropy & format
 *     ├─ Token TTL configuration (env var)
 *     ├─ Email delivery — success path
 *     ├─ Email delivery — retryable failure
 *     ├─ Email delivery — permanent failure
 *     ├─ Token cleanup on email failure
 *     ├─ Structured audit log
 *     └─ Non-production resetLink exposure
 *   resetPassword()
 *     ├─ Input validation
 *     ├─ Password minimum length (default + env-configurable)
 *     ├─ Invalid / expired token rejection
 *     ├─ Success path — token consumed atomically
 *     └─ Structured audit log
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// ── Shared env snapshot ───────────────────────────────────────────────────────
const ORIGINAL_ENV = { ...process.env }

// ── Mock: userRepository ─────────────────────────────────────────────────────
vi.mock('../../src/repositories/userRepository.js', () => ({
  findUserByEmail: vi.fn(),
  setResetToken: vi.fn(),
  updateUser: vi.fn(),
  findUserByResetToken: vi.fn(),
  updateUserPassword: vi.fn(),
}))

// ── Mock: sendReset ───────────────────────────────────────────────────────────
vi.mock('../../src/services/email/sendReset.js', () => ({
  sendPasswordResetEmail: vi.fn(),
}))

// ── Mock: password utils ──────────────────────────────────────────────────────
vi.mock('../../src/utils/password.js', () => ({
  hashPassword: vi.fn(async (pw: string) => `hashed:${pw}`),
}))

import {
  findUserByEmail,
  setResetToken,
  updateUser,
  findUserByResetToken,
  updateUserPassword,
} from '../../src/repositories/userRepository.js'
import { sendPasswordResetEmail } from '../../src/services/email/sendReset.js'
import { forgotPassword } from '../../src/services/auth/forgotPassword.js'
import { resetPassword } from '../../src/services/auth/resetPassword.js'
import { AppError } from '../../src/types/errors.js'

// ── Helpers ───────────────────────────────────────────────────────────────────
const mockUser = { id: 'user-abc', email: 'john@example.com' }

function mockEmailSuccess() {
  vi.mocked(sendPasswordResetEmail).mockResolvedValue({ error: false })
}

function mockEmailRetryable() {
  vi.mocked(sendPasswordResetEmail).mockResolvedValue({
    error: true,
    retryable: true,
  })
}

function mockEmailPermanent() {
  vi.mocked(sendPasswordResetEmail).mockResolvedValue({
    error: true,
    retryable: false,
  })
}

// ─────────────────────────────────────────────────────────────────────────────
// Existing: Config Validation (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
async function loadConfig() {
  const mod = await import('../../src/config/index.js?' + Date.now())
  return mod.config
}

describe('Config Validation', () => {
  beforeEach(() => {
    process.env = {
      ...ORIGINAL_ENV,
      NODE_ENV: 'test',
      PORT: '3000',
      DATABASE_URL: 'postgresql://user:pass@localhost:5432/veritasor_test',
      JWT_SECRET: 'supersecretjwttokenthatisfortycharacterslong!!',
      RAZORPAY_KEY_ID: 'rzp_test_abc123',
      RAZORPAY_KEY_SECRET: 'test_secret_xyz',
      RAZORPAY_WEBHOOK_SECRET: 'webhook_secret_abc',
    }
  })
  afterEach(() => {
    process.env = ORIGINAL_ENV
  })

  it('should load config successfully when all required env vars are present', async () => {
    const config = await loadConfig()
    expect(config.DATABASE_URL).toBe(
      'postgresql://user:pass@localhost:5432/veritasor_test',
    )
    expect(config.JWT_SECRET).toBeDefined()
    expect(config.RAZORPAY_KEY_ID).toBe('rzp_test_abc123')
    expect(config.PORT).toBe(3000)
    expect(config.NODE_ENV).toBe('test')
  })

  it('should throw when DATABASE_URL is missing', async () => {
    delete process.env.DATABASE_URL
    await expect(loadConfig()).rejects.toThrow('DATABASE_URL')
  })

  it('should throw when JWT_SECRET is missing', async () => {
    delete process.env.JWT_SECRET
    await expect(loadConfig()).rejects.toThrow('JWT_SECRET')
  })

  it('should throw when RAZORPAY_KEY_ID is missing', async () => {
    delete process.env.RAZORPAY_KEY_ID
    await expect(loadConfig()).rejects.toThrow('RAZORPAY_KEY_ID')
  })

  it('should throw when RAZORPAY_KEY_SECRET is missing', async () => {
    delete process.env.RAZORPAY_KEY_SECRET
    await expect(loadConfig()).rejects.toThrow('RAZORPAY_KEY_SECRET')
  })

  it('should throw when RAZORPAY_WEBHOOK_SECRET is missing', async () => {
    delete process.env.RAZORPAY_WEBHOOK_SECRET
    await expect(loadConfig()).rejects.toThrow('RAZORPAY_WEBHOOK_SECRET')
  })

  it('should throw when JWT_SECRET is shorter than 32 characters', async () => {
    process.env.JWT_SECRET = 'tooshort'
    await expect(loadConfig()).rejects.toThrow(
      'JWT_SECRET must be at least 32 characters',
    )
  })

  it('should throw when NODE_ENV is an invalid value', async () => {
    process.env.NODE_ENV = 'staging'
    await expect(loadConfig()).rejects.toThrow()
  })

  it('should default PORT to 3000 when not set', async () => {
    delete process.env.PORT
    const config = await loadConfig()
    expect(config.PORT).toBe(3000)
  })

  it('should default NODE_ENV to development when not set', async () => {
    delete process.env.NODE_ENV
    const config = await loadConfig()
    expect(config.NODE_ENV).toBe('development')
  })

  it('should report ALL missing vars in a single error, not just the first', async () => {
    delete process.env.DATABASE_URL
    delete process.env.JWT_SECRET
    delete process.env.RAZORPAY_KEY_ID
    try {
      await loadConfig()
      expect.fail('Should have thrown')
    } catch (err: any) {
      expect(err.message).toContain('DATABASE_URL')
      expect(err.message).toContain('JWT_SECRET')
      expect(err.message).toContain('RAZORPAY_KEY_ID')
    }
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// forgotPassword()
// ─────────────────────────────────────────────────────────────────────────────
describe('forgotPassword()', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    process.env = {
      ...ORIGINAL_ENV,
      NODE_ENV: 'test',
      RESET_PASSWORD_URL: 'http://localhost:3000/reset-password',
    }
    vi.mocked(setResetToken).mockResolvedValue(undefined)
    vi.mocked(updateUser).mockResolvedValue(undefined)
  })

  afterEach(() => {
    process.env = ORIGINAL_ENV
  })

  // ── Input validation ────────────────────────────────────────────────────

  it('throws VALIDATION_ERROR when email is empty string', async () => {
    await expect(forgotPassword({ email: '' })).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      status: 400,
    })
  })

  it('throws VALIDATION_ERROR when email is whitespace only', async () => {
    await expect(forgotPassword({ email: '   ' })).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      status: 400,
    })
  })

  // ── User enumeration resistance ─────────────────────────────────────────

  it('returns the generic message when email is not found (no enumeration)', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(null)

    const result = await forgotPassword({ email: 'notfound@example.com' })

    expect(result.message).toBe(
      'If an account with this email exists, a reset link has been sent.',
    )
    // Must NOT expose resetLink when user does not exist
    expect(result.resetLink).toBeUndefined()
    // Token must never be persisted for non-existent users
    expect(setResetToken).not.toHaveBeenCalled()
    expect(sendPasswordResetEmail).not.toHaveBeenCalled()
  })

  it('returns the identical message shape for an existing user', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    const result = await forgotPassword({ email: mockUser.email })

    expect(result.message).toBe(
      'If an account with this email exists, a reset link has been sent.',
    )
  })

  it('normalises email to lowercase before lookup', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(null)

    await forgotPassword({ email: 'John@Example.COM' })

    expect(findUserByEmail).toHaveBeenCalledWith('john@example.com')
  })

  // ── Token entropy & format ──────────────────────────────────────────────

  it('generates a 64 lowercase hex character token', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })

    const [[, token]] = vi.mocked(setResetToken).mock.calls
    expect(typeof token).toBe('string')
    expect(token).toHaveLength(64)
    expect(token).toMatch(/^[0-9a-f]{64}$/)
  })

  it('generates a unique token on each call', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })
    await forgotPassword({ email: mockUser.email })

    const calls = vi.mocked(setResetToken).mock.calls
    expect(calls[0][1]).not.toBe(calls[1][1])
  })

  // ── Token TTL ───────────────────────────────────────────────────────────

  it('uses default TTL of 15 minutes when env var is absent', async () => {
    delete process.env.RESET_TOKEN_TTL_MINUTES
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })

    const [[, , ttl]] = vi.mocked(setResetToken).mock.calls
    expect(ttl).toBe(15)
  })

  it('uses RESET_TOKEN_TTL_MINUTES when valid', async () => {
    process.env.RESET_TOKEN_TTL_MINUTES = '10'
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })

    const [[, , ttl]] = vi.mocked(setResetToken).mock.calls
    expect(ttl).toBe(10)
  })

  it('falls back to 15 min when RESET_TOKEN_TTL_MINUTES is invalid', async () => {
    process.env.RESET_TOKEN_TTL_MINUTES = 'banana'
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })

    const [[, , ttl]] = vi.mocked(setResetToken).mock.calls
    expect(ttl).toBe(15)
  })

  it('falls back to 15 min when RESET_TOKEN_TTL_MINUTES exceeds 60', async () => {
    process.env.RESET_TOKEN_TTL_MINUTES = '120'
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })

    const [[, , ttl]] = vi.mocked(setResetToken).mock.calls
    expect(ttl).toBe(15)
  })

  // ── Email — success path ────────────────────────────────────────────────

  it('calls sendPasswordResetEmail with the user email and a reset link', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })

    expect(sendPasswordResetEmail).toHaveBeenCalledOnce()
    const [calledEmail, calledLink] = vi.mocked(sendPasswordResetEmail).mock.calls[0]
    expect(calledEmail).toBe(mockUser.email)
    expect(calledLink).toContain('http://localhost:3000/reset-password?token=')
    expect(calledLink).toMatch(/token=[0-9a-f]{64}$/)
  })

  it('returns resetLink in non-production environments', async () => {
    process.env.NODE_ENV = 'development'
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    const result = await forgotPassword({ email: mockUser.email })

    expect(result.resetLink).toBeDefined()
    expect(result.resetLink).toContain('?token=')
  })

  it('omits resetLink in production', async () => {
    process.env.NODE_ENV = 'production'
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    const result = await forgotPassword({ email: mockUser.email })

    expect(result.resetLink).toBeUndefined()
  })

  // ── Email — retryable failure ───────────────────────────────────────────

  it('clears the token and throws 503 on retryable email failure', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailRetryable()

    await expect(forgotPassword({ email: mockUser.email })).rejects.toMatchObject({
      status: 503,
      code: 'RESET_EMAIL_RETRYABLE_FAILURE',
    })

    expect(updateUser).toHaveBeenCalledWith(mockUser.id, {
      resetToken: null,
      resetTokenExpiry: null,
    })
  })

  // ── Email — permanent failure ───────────────────────────────────────────

  it('clears the token and throws 500 on permanent email failure', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailPermanent()

    await expect(forgotPassword({ email: mockUser.email })).rejects.toMatchObject({
      status: 500,
      code: 'RESET_EMAIL_UNAVAILABLE',
    })

    expect(updateUser).toHaveBeenCalledWith(mockUser.id, {
      resetToken: null,
      resetTokenExpiry: null,
    })
  })

  // ── Token cleanup ───────────────────────────────────────────────────────

  it('does NOT call updateUser when email delivery succeeds', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()

    await forgotPassword({ email: mockUser.email })

    expect(updateUser).not.toHaveBeenCalled()
  })

  // ── Structured audit log ────────────────────────────────────────────────

  it('emits forgot_password_requested on every call', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(null)
    const logs: any[] = []

    await forgotPassword({ email: 'a@b.com' }, (r) => logs.push(r))

    expect(logs[0].event).toBe('forgot_password_requested')
    expect(logs[0].timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('emits forgot_password_user_not_found when email unknown', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(null)
    const logs: any[] = []

    await forgotPassword({ email: 'unknown@example.com' }, (r) => logs.push(r))

    expect(logs.map((l) => l.event)).toContain('forgot_password_user_not_found')
  })

  it('emits forgot_password_token_issued and forgot_password_email_sent on success', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()
    const logs: any[] = []

    await forgotPassword({ email: mockUser.email }, (r) => logs.push(r))

    const events = logs.map((l) => l.event)
    expect(events).toContain('forgot_password_token_issued')
    expect(events).toContain('forgot_password_email_sent')
  })

  it('log records include only the first 8 hex chars of the token (not the full secret)', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailSuccess()
    const logs: any[] = []

    await forgotPassword({ email: mockUser.email }, (r) => logs.push(r))

    const tokenRecord = logs.find((l) => l.tokenPrefix)
    expect(tokenRecord?.tokenPrefix).toHaveLength(8)
    expect(tokenRecord?.tokenPrefix).toMatch(/^[0-9a-f]{8}$/)
    // Confirm the full token is NOT in any log record
    const [[, fullToken]] = vi.mocked(setResetToken).mock.calls
    for (const record of logs) {
      expect(JSON.stringify(record)).not.toContain(fullToken)
    }
  })

  it('emits forgot_password_email_retryable_failure on retryable failure', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailRetryable()
    const logs: any[] = []

    await expect(
      forgotPassword({ email: mockUser.email }, (r) => logs.push(r)),
    ).rejects.toThrow()

    expect(logs.map((l) => l.event)).toContain(
      'forgot_password_email_retryable_failure',
    )
  })

  it('emits forgot_password_email_permanent_failure on permanent failure', async () => {
    vi.mocked(findUserByEmail).mockResolvedValue(mockUser)
    mockEmailPermanent()
    const logs: any[] = []

    await expect(
      forgotPassword({ email: mockUser.email }, (r) => logs.push(r)),
    ).rejects.toThrow()

    expect(logs.map((l) => l.event)).toContain(
      'forgot_password_email_permanent_failure',
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// resetPassword()
// ─────────────────────────────────────────────────────────────────────────────
describe('resetPassword()', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    process.env = { ...ORIGINAL_ENV, NODE_ENV: 'test' }
    vi.mocked(updateUserPassword).mockResolvedValue(undefined)
  })

  afterEach(() => {
    process.env = ORIGINAL_ENV
  })

  // ── Input validation ────────────────────────────────────────────────────

  it('throws VALIDATION_ERROR when token is empty', async () => {
    await expect(
      resetPassword({ token: '', newPassword: 'validpassword1' }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR', status: 400 })
  })

  it('throws VALIDATION_ERROR when newPassword is empty', async () => {
    await expect(
      resetPassword({ token: 'a'.repeat(64), newPassword: '' }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR', status: 400 })
  })

  it('throws VALIDATION_ERROR when newPassword is whitespace only', async () => {
    await expect(
      resetPassword({ token: 'a'.repeat(64), newPassword: '       ' }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR', status: 400 })
  })

  // ── Minimum password length ─────────────────────────────────────────────

  it('rejects passwords shorter than default minimum of 8 characters', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)

    await expect(
      resetPassword({ token: 'a'.repeat(64), newPassword: 'short' }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR', status: 400 })
  })

  it('accepts passwords exactly at the 8-character minimum', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)

    const result = await resetPassword({
      token: 'a'.repeat(64),
      newPassword: '12345678',
    })

    expect(result.message).toBe('Password has been reset successfully.')
  })

  it('respects RESET_MIN_PASSWORD_LENGTH env var', async () => {
    process.env.RESET_MIN_PASSWORD_LENGTH = '12'
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)

    await expect(
      resetPassword({ token: 'a'.repeat(64), newPassword: 'tooshort1' }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR' })
  })

  it('falls back to 8 when RESET_MIN_PASSWORD_LENGTH is below 8', async () => {
    process.env.RESET_MIN_PASSWORD_LENGTH = '4'
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)

    // A 5-char password is below 8 even though env says 4 — env is ignored
    await expect(
      resetPassword({ token: 'a'.repeat(64), newPassword: '12345' }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR' })
  })

  // ── Invalid / expired token ─────────────────────────────────────────────

  it('throws INVALID_RESET_TOKEN (400) when token is not found', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(null)

    await expect(
      resetPassword({ token: 'b'.repeat(64), newPassword: 'validpassword1' }),
    ).rejects.toMatchObject({ code: 'INVALID_RESET_TOKEN', status: 400 })
  })

  it('does not call updateUserPassword when token is invalid', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(null)

    await expect(
      resetPassword({ token: 'c'.repeat(64), newPassword: 'validpassword1' }),
    ).rejects.toThrow()

    expect(updateUserPassword).not.toHaveBeenCalled()
  })

  // ── Success path ────────────────────────────────────────────────────────

  it('returns success message on valid token + password', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)

    const result = await resetPassword({
      token: 'd'.repeat(64),
      newPassword: 'newSecurePass1',
    })

    expect(result.message).toBe('Password has been reset successfully.')
  })

  it('calls updateUserPassword with the user id and a hashed password', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)

    await resetPassword({ token: 'e'.repeat(64), newPassword: 'newSecurePass1' })

    expect(updateUserPassword).toHaveBeenCalledWith(
      mockUser.id,
      'hashed:newSecurePass1',
    )
  })

  it('does not return the password hash or the token in the response', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)

    const result = await resetPassword({
      token: 'f'.repeat(64),
      newPassword: 'newSecurePass1',
    })

    const serialized = JSON.stringify(result)
    expect(serialized).not.toContain('hashed:')
    expect(serialized).not.toContain('f'.repeat(64))
  })

  // ── Structured audit log ────────────────────────────────────────────────

  it('emits reset_password_attempted on every call', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(null)
    const logs: any[] = []

    await expect(
      resetPassword({ token: 'g'.repeat(64), newPassword: 'anypassword' }, (r) =>
        logs.push(r),
      ),
    ).rejects.toThrow()

    expect(logs[0].event).toBe('reset_password_attempted')
    expect(logs[0].tokenPrefix).toBe('g'.repeat(8))
  })

  it('emits reset_password_invalid_token when token is not found', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(null)
    const logs: any[] = []

    await expect(
      resetPassword({ token: 'h'.repeat(64), newPassword: 'anypassword' }, (r) =>
        logs.push(r),
      ),
    ).rejects.toThrow()

    expect(logs.map((l) => l.event)).toContain('reset_password_invalid_token')
  })

  it('emits reset_password_success with userId on successful reset', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)
    const logs: any[] = []

    await resetPassword(
      { token: 'i'.repeat(64), newPassword: 'newSecurePass1' },
      (r) => logs.push(r),
    )

    const successRecord = logs.find((l) => l.event === 'reset_password_success')
    expect(successRecord).toBeDefined()
    expect(successRecord.userId).toBe(mockUser.id)
  })

  it('log records contain only the first 8 chars of the token', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(mockUser)
    const logs: any[] = []
    const token = 'j'.repeat(64)

    await resetPassword({ token, newPassword: 'newSecurePass1' }, (r) =>
      logs.push(r),
    )

    for (const record of logs) {
      expect(JSON.stringify(record)).not.toContain(token)
      if (record.tokenPrefix) {
        expect(record.tokenPrefix).toHaveLength(8)
      }
    }
  })

  // ── AppError is an actual AppError instance ─────────────────────────────

  it('thrown error is an instance of AppError', async () => {
    vi.mocked(findUserByResetToken).mockResolvedValue(null)

    try {
      await resetPassword({ token: 'k'.repeat(64), newPassword: 'validpassword1' })
      expect.fail('Should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(AppError)
    }
  })
})
