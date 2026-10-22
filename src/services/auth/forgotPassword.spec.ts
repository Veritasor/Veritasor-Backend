import { createHash } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  forgotPassword,
  type ForgotPasswordAuditEvent,
  type ForgotPasswordLogger,
  type ForgotPasswordRequest,
  type ForgotPasswordResponse,
} from './forgotPassword.js'

const mocks = vi.hoisted(() => ({
  findUserByEmail: vi.fn(),
  setResetToken: vi.fn(),
  updateUser: vi.fn(),
  sendPasswordResetEmail: vi.fn(),
}))

vi.mock('../../repositories/userRepository.js', () => ({
  findUserByEmail: mocks.findUserByEmail,
  setResetToken: mocks.setResetToken,
  updateUser: mocks.updateUser,
}))

vi.mock('../email/sendReset.js', () => ({
  sendPasswordResetEmail: mocks.sendPasswordResetEmail,
}))

const user = {
  id: 'user-123',
  email: 'person@example.com',
  passwordHash: 'password-hash',
  createdAt: new Date('2025-01-01T00:00:00.000Z'),
  updatedAt: new Date('2025-01-01T00:00:00.000Z'),
  role: 'user' as const,
}

async function completeRequest(
  request: ForgotPasswordRequest,
  logger?: ForgotPasswordLogger,
): Promise<ForgotPasswordResponse> {
  const result = forgotPassword(request, logger)
  const settled = result.then(
    (response) => ({ response }),
    (error: unknown) => ({ error }),
  )
  await vi.advanceTimersByTimeAsync(200)
  const outcome = await settled
  if ('error' in outcome) throw outcome.error
  return outcome.response
}

describe('forgotPassword', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
    mocks.findUserByEmail.mockResolvedValue(null)
    mocks.setResetToken.mockResolvedValue(undefined)
    mocks.updateUser.mockResolvedValue(user)
    mocks.sendPasswordResetEmail.mockResolvedValue({ retryable: false })
    vi.stubEnv('RESET_TOKEN_TTL_MINUTES', '')
    vi.stubEnv('RESET_PASSWORD_URL', '')
    vi.stubEnv('NODE_ENV', 'test')
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllEnvs()
  })

  it.each([
    ['missing', {}],
    ['empty', { email: '' }],
    ['whitespace-only', { email: '   ' }],
    ['non-string', { email: 42 }],
  ])('rejects a %s email before performing side effects', async (_label, request) => {
    await expect(forgotPassword(request as ForgotPasswordRequest)).rejects.toMatchObject({
      name: 'AppError',
      message: 'Email is required',
      status: 400,
      vrtCode: 'VALIDATION_ERROR',
    })
    expect(mocks.findUserByEmail).not.toHaveBeenCalled()
    expect(mocks.setResetToken).not.toHaveBeenCalled()
    expect(mocks.sendPasswordResetEmail).not.toHaveBeenCalled()
  })

  it('returns the generic response and audits a normalized lookup when no user exists', async () => {
    const logger = vi.fn<ForgotPasswordLogger>()
    const request: ForgotPasswordRequest = { email: '  PERSON@Example.com  ' }
    const response: ForgotPasswordResponse = await completeRequest(request, logger)

    expect(mocks.findUserByEmail).toHaveBeenCalledWith('person@example.com')
    expect(response).toEqual({
      message: 'If an account with this email exists, a reset link has been sent.',
    })
    const events: ForgotPasswordAuditEvent[] = logger.mock.calls.map(([record]) => record.event)
    expect(events).toEqual(['forgot_password_requested', 'forgot_password_user_not_found'])
    expect(logger.mock.calls.every(([record]) => Number.isFinite(Date.parse(record.timestamp)))).toBe(true)
    expect(mocks.setResetToken).not.toHaveBeenCalled()
  })

  it('issues a hashed token, sends the reset link, and returns it outside production', async () => {
    mocks.findUserByEmail.mockResolvedValue(user)
    vi.stubEnv('RESET_TOKEN_TTL_MINUTES', '30')
    vi.stubEnv('RESET_PASSWORD_URL', 'https://app.example.com/reset')
    const logger = vi.fn<ForgotPasswordLogger>()
    const response = await completeRequest({ email: user.email }, logger)

    const [[userId, tokenHash, ttlMinutes]] = mocks.setResetToken.mock.calls
    expect(userId).toBe(user.id)
    expect(ttlMinutes).toBe(30)
    expect(tokenHash).toMatch(/^[a-f0-9]{64}$/)

    const [[sentEmail, resetLink]] = mocks.sendPasswordResetEmail.mock.calls
    const rawToken = new URL(resetLink).searchParams.get('token')
    expect(sentEmail).toBe(user.email)
    expect(rawToken).toMatch(/^[a-f0-9]{64}$/)
    expect(tokenHash).toBe(createHash('sha256').update(rawToken!).digest('hex'))
    expect(tokenHash).not.toBe(rawToken)
    expect(response).toEqual({
      message: 'If an account with this email exists, a reset link has been sent.',
      resetLink,
    })

    const events: ForgotPasswordAuditEvent[] = logger.mock.calls.map(([record]) => record.event)
    expect(events).toEqual([
      'forgot_password_requested',
      'forgot_password_token_issued',
      'forgot_password_email_sent',
    ])
    expect(logger.mock.calls[1][0]).toMatchObject({
      tokenPrefix: rawToken!.slice(0, 8),
      userId: user.id,
    })
    expect(JSON.stringify(logger.mock.calls)).not.toContain(rawToken)
    expect(JSON.stringify(logger.mock.calls)).not.toContain(tokenHash)
  })

  it('omits the reset link from the production response', async () => {
    mocks.findUserByEmail.mockResolvedValue(user)
    vi.stubEnv('NODE_ENV', 'production')

    const response = await completeRequest({ email: user.email })

    expect(response).toEqual({
      message: 'If an account with this email exists, a reset link has been sent.',
    })
    expect(mocks.sendPasswordResetEmail).toHaveBeenCalledOnce()
  })

  it.each([
    ['retryable', true, 503, 'RESET_EMAIL_RETRYABLE_FAILURE', 'forgot_password_email_retryable_failure'],
    ['permanent', false, 500, 'RESET_EMAIL_UNAVAILABLE', 'forgot_password_email_permanent_failure'],
  ] as const)(
    'clears the token and reports a %s email failure',
    async (_kind, retryable, status, vrtCode, failureEvent) => {
      mocks.findUserByEmail.mockResolvedValue(user)
      mocks.sendPasswordResetEmail.mockResolvedValue({ error: new Error('delivery failed'), retryable })
      const logger = vi.fn<ForgotPasswordLogger>()

      await expect(completeRequest({ email: user.email }, logger)).rejects.toMatchObject({
        name: 'AppError',
        status,
        vrtCode,
      })
      expect(mocks.updateUser).toHaveBeenCalledWith(user.id, {
        resetToken: null,
        resetTokenExpiry: null,
      })
      expect(logger.mock.calls.map(([record]) => record.event)).toContain(failureEvent)
    },
  )
})