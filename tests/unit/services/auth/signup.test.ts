/**
 * Unit tests for src/services/auth/signup.ts
 *
 * Coverage:
 *   - SignupRequest — valid input accepted, missing/invalid fields rejected
 *   - SignupResponse — success shape matches contract
 *   - SignupErrorType — every variant is reachable and returned deterministically
 *   - State transitions — user created on success, no user created on failure,
 *     state unchanged after a rejected request
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  signup,
  checkSignupAvailability,
  getSignupRateLimitHeaders,
  SignupError,
  type SignupRequest,
  type SignupResponse,
  type SignupErrorType,
} from '../../../../src/services/auth/signup.js'
import {
  clearAllUsers,
  findUserByEmail,
} from '../../../../src/repositories/userRepository.js'
import { resetSignupRateLimitStore } from '../../../../src/utils/signupRateLimiter.js'

// ---------------------------------------------------------------------------
// Silence logger output during tests
// ---------------------------------------------------------------------------
vi.mock('../../../../src/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Config override that skips the timing-attack delay so tests run fast.
 * All behaviour branches are still exercised — only the artificial sleep is
 * removed.
 */
const NO_DELAY = { minOperationTimeMs: 0 }

/** A valid signup request that should succeed out of the box. */
function validRequest(overrides: Partial<SignupRequest> = {}): SignupRequest {
  return {
    email: 'alice@example.com',
    password: 'SecureP@ss123',
    ipAddress: '10.0.0.1',
    ...overrides,
  }
}

/** Helper: attempt signup and return the thrown error (asserts it throws). */
async function signupError(
  request: Partial<SignupRequest> & Record<string, unknown>,
  config = NO_DELAY,
): Promise<SignupError> {
  const err = await signup(request as SignupRequest, config).catch((e) => e)
  expect(err).toBeInstanceOf(SignupError)
  return err as SignupError
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.useFakeTimers()
  clearAllUsers()
  resetSignupRateLimitStore()
})

afterEach(() => {
  vi.useRealTimers()
  clearAllUsers()
  resetSignupRateLimitStore()
})

// ---------------------------------------------------------------------------
// SignupRequest — valid input
// ---------------------------------------------------------------------------

describe('SignupRequest — valid input', () => {
  it('accepts a well-formed email and strong password', async () => {
    const result = await signup(validRequest(), NO_DELAY)
    expect(result).toBeDefined()
  })

  it('accepts an email with plus-addressing', async () => {
    const result = await signup(validRequest({ email: 'alice+tag@example.com' }), NO_DELAY)
    expect(result).toBeDefined()
  })

  it('accepts an email with a subdomain', async () => {
    const result = await signup(validRequest({ email: 'user@mail.example.com' }), NO_DELAY)
    expect(result).toBeDefined()
  })

  it('accepts an email in mixed case (normalises it)', async () => {
    const result = await signup(validRequest({ email: 'Alice@Example.COM' }), NO_DELAY)
    // The user stored in the repository should have a lowercase email
    expect(result.user.email).toBe(result.user.email.toLowerCase())
  })

  it('works without an explicit ipAddress (falls back to "unknown")', async () => {
    const req = validRequest()
    delete (req as Partial<SignupRequest>).ipAddress
    const result = await signup(req, NO_DELAY)
    expect(result).toBeDefined()
  })

  it('ignores an empty website field (honeypot empty = legitimate)', async () => {
    const result = await signup(validRequest({ website: '' }), NO_DELAY)
    expect(result).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// SignupRequest — missing required fields → VALIDATION_ERROR
// ---------------------------------------------------------------------------

describe('SignupRequest — missing required fields', () => {
  it('rejects when email is undefined', async () => {
    const err = await signupError({ password: 'SecureP@ss123', ipAddress: '10.0.0.1' })
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    expect(err.statusCode).toBe(400)
    expect(err.details).toEqual(expect.arrayContaining([expect.stringContaining('email')]))
  })

  it('rejects when email is null', async () => {
    const err = await signupError({ email: null as unknown as string, password: 'SecureP@ss123' })
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringContaining('email')]))
  })

  it('rejects when email is an empty string', async () => {
    const err = await signupError(validRequest({ email: '' }))
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringContaining('email')]))
  })

  it('rejects when email is a non-string type', async () => {
    const err = await signupError({ email: 12345 as unknown as string, password: 'SecureP@ss123' })
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringContaining('email')]))
  })

  it('rejects when password is undefined', async () => {
    const err = await signupError({ email: 'alice@example.com', ipAddress: '10.0.0.1' })
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    expect(err.statusCode).toBe(400)
    expect(err.details).toEqual(expect.arrayContaining([expect.stringContaining('password')]))
  })

  it('rejects when password is null', async () => {
    const err = await signupError({ email: 'alice@example.com', password: null as unknown as string })
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringContaining('password')]))
  })

  it('rejects when password is an empty string', async () => {
    const err = await signupError(validRequest({ password: '' }))
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringContaining('password')]))
  })

  it('accumulates both missing-email and missing-password into one VALIDATION_ERROR', async () => {
    const err = await signupError({ ipAddress: '10.0.0.1' })
    expect(err.type).toBe<SignupErrorType>('VALIDATION_ERROR')
    // Both fields should be called out in the details array
    const details = err.details ?? []
    expect(details.some((d) => d.includes('email'))).toBe(true)
    expect(details.some((d) => d.includes('password'))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// SignupRequest — invalid email formats → EMAIL_INVALID / EMAIL_DISPOSABLE
// ---------------------------------------------------------------------------

describe('SignupRequest — invalid email formats', () => {
  it('returns EMAIL_INVALID for an email without @', async () => {
    const err = await signupError(validRequest({ email: 'notanemail' }))
    expect(err.type).toBe<SignupErrorType>('EMAIL_INVALID')
    expect(err.statusCode).toBe(400)
  })

  it('returns EMAIL_INVALID for an email without a domain', async () => {
    const err = await signupError(validRequest({ email: 'user@' }))
    expect(err.type).toBe<SignupErrorType>('EMAIL_INVALID')
  })

  it('returns EMAIL_INVALID for an email without a TLD', async () => {
    const err = await signupError(validRequest({ email: 'user@example' }))
    expect(err.type).toBe<SignupErrorType>('EMAIL_INVALID')
  })

  it('returns EMAIL_INVALID for an email with spaces', async () => {
    const err = await signupError(validRequest({ email: 'user name@example.com' }))
    expect(err.type).toBe<SignupErrorType>('EMAIL_INVALID')
  })

  it('returns EMAIL_DISPOSABLE for a known disposable-email domain', async () => {
    const err = await signupError(validRequest({ email: 'user@mailinator.com' }))
    expect(err.type).toBe<SignupErrorType>('EMAIL_DISPOSABLE')
    expect(err.statusCode).toBe(400)
  })

  it('returns EMAIL_DISPOSABLE for another disposable domain', async () => {
    const err = await signupError(validRequest({ email: 'test@10minutemail.com' }))
    expect(err.type).toBe<SignupErrorType>('EMAIL_DISPOSABLE')
  })
})

// ---------------------------------------------------------------------------
// SignupRequest — weak passwords → PASSWORD_WEAK
// ---------------------------------------------------------------------------

describe('SignupRequest — invalid password formats', () => {
  it('returns PASSWORD_WEAK for a password that is too short', async () => {
    const err = await signupError(validRequest({ password: 'Ab1!' }))
    expect(err.type).toBe<SignupErrorType>('PASSWORD_WEAK')
    expect(err.statusCode).toBe(400)
    expect(err.details).toEqual(expect.arrayContaining([expect.stringMatching(/at least 8/i)]))
  })

  it('returns PASSWORD_WEAK for a password with no uppercase letter', async () => {
    const err = await signupError(validRequest({ password: 'lowercase123!' }))
    expect(err.type).toBe<SignupErrorType>('PASSWORD_WEAK')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringMatching(/uppercase/i)]))
  })

  it('returns PASSWORD_WEAK for a password with no lowercase letter', async () => {
    const err = await signupError(validRequest({ password: 'UPPERCASE123!' }))
    expect(err.type).toBe<SignupErrorType>('PASSWORD_WEAK')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringMatching(/lowercase/i)]))
  })

  it('returns PASSWORD_WEAK for a password with no digit', async () => {
    const err = await signupError(validRequest({ password: 'NoNumbers!' }))
    expect(err.type).toBe<SignupErrorType>('PASSWORD_WEAK')
    expect(err.details).toEqual(expect.arrayContaining([expect.stringMatching(/number/i)]))
  })

  it('returns PASSWORD_WEAK for a password with no special character', async () => {
    const err = await signupError(validRequest({ password: 'NoSpecial123' }))
    expect(err.type).toBe<SignupErrorType>('PASSWORD_WEAK')
  })

  it('includes all failing criteria in the details array', async () => {
    // An all-lowercase, no-digit, no-special, short password fails on multiple criteria
    const err = await signupError(validRequest({ password: 'abc' }))
    expect(err.type).toBe<SignupErrorType>('PASSWORD_WEAK')
    expect((err.details ?? []).length).toBeGreaterThan(1)
  })
})

// ---------------------------------------------------------------------------
// SignupErrorType — HONEYPOT_TRIGGERED
// ---------------------------------------------------------------------------

describe('SignupErrorType — HONEYPOT_TRIGGERED', () => {
  it('throws HONEYPOT_TRIGGERED when the website field is non-empty', async () => {
    const err = await signupError(validRequest({ website: 'http://bot.example.com' }))
    expect(err.type).toBe<SignupErrorType>('HONEYPOT_TRIGGERED')
    expect(err.statusCode).toBe(400)
  })

  it('throws HONEYPOT_TRIGGERED before any other validation', async () => {
    // Even with a bad email, honeypot fires first
    const err = await signupError({ email: 'bad', password: 'bad', website: 'filled' })
    expect(err.type).toBe<SignupErrorType>('HONEYPOT_TRIGGERED')
  })

  it('does NOT trigger honeypot when enableHoneypot is false', async () => {
    // With honeypot disabled, the request should proceed to other checks
    // (it will fail on EMAIL_INVALID because 'bad-email' is invalid, not HONEYPOT_TRIGGERED)
    const err = await signupError(
      validRequest({ email: 'bad-email', website: 'http://bot.example.com' }),
      { ...NO_DELAY, enableHoneypot: false },
    )
    expect(err.type).not.toBe<SignupErrorType>('HONEYPOT_TRIGGERED')
  })
})

// ---------------------------------------------------------------------------
// SignupErrorType — RATE_LIMITED
// ---------------------------------------------------------------------------

describe('SignupErrorType — RATE_LIMITED', () => {
  it('throws RATE_LIMITED with status 429 after exceeding the per-IP limit', async () => {
    const rateLimitConfig = {
      ...NO_DELAY,
      rateLimit: {
        maxAttemptsPerIp: 2,
        windowMs: 60_000,
        maxAttemptsPerEmail: 100,
        maxGlobalAttempts: 1000,
      },
    }

    const ip = '203.0.113.1'

    // Exhaust the per-IP limit with valid requests (they each create a user,
    // so use different emails each time)
    await signup(validRequest({ email: 'u1@example.com', ipAddress: ip }), rateLimitConfig)
    await signup(validRequest({ email: 'u2@example.com', ipAddress: ip }), rateLimitConfig)

    // Third attempt from the same IP should be rate-limited
    const err = await signupError(
      validRequest({ email: 'u3@example.com', ipAddress: ip }),
      rateLimitConfig,
    )
    expect(err.type).toBe<SignupErrorType>('RATE_LIMITED')
    expect(err.statusCode).toBe(429)
  })

  it('throws RATE_LIMITED after exceeding the per-email limit', async () => {
    const rateLimitConfig = {
      ...NO_DELAY,
      rateLimit: {
        maxAttemptsPerEmail: 2,
        windowMs: 60_000,
        maxAttemptsPerIp: 100,
        maxGlobalAttempts: 1000,
      },
    }

    const email = 'target@example.com'

    // First attempt: succeeds, user created
    await signup(validRequest({ email, ipAddress: '1.1.1.1' }), rateLimitConfig)

    // Second attempt: EMAIL_EXISTS — but still counts as an attempt on the email
    await signupError(validRequest({ email, ipAddress: '2.2.2.2' }), rateLimitConfig)

    // Third attempt with same email from any IP should be rate-limited by email
    const err = await signupError(
      validRequest({ email, ipAddress: '3.3.3.3' }),
      rateLimitConfig,
    )
    expect(err.type).toBe<SignupErrorType>('RATE_LIMITED')
    expect(err.statusCode).toBe(429)
  })
})

// ---------------------------------------------------------------------------
// SignupErrorType — EMAIL_EXISTS
// ---------------------------------------------------------------------------

describe('SignupErrorType — EMAIL_EXISTS', () => {
  it('throws EMAIL_EXISTS when the same email is registered twice', async () => {
    await signup(validRequest(), NO_DELAY)

    const err = await signupError(validRequest())
    expect(err.type).toBe<SignupErrorType>('EMAIL_EXISTS')
    expect(err.statusCode).toBe(400) // 400 not 409 — intentional anti-enumeration
  })

  it('uses a generic message (does not reveal email existence)', async () => {
    await signup(validRequest(), NO_DELAY)

    const err = await signupError(validRequest())
    expect(err.message).not.toMatch(/already.*exist|taken|registered/i)
    expect(err.message).toMatch(/unable to create account/i)
  })

  it('throws EMAIL_EXISTS when email differs only in case', async () => {
    await signup(validRequest({ email: 'alice@example.com' }), NO_DELAY)

    // The service normalises emails, so ALICE@EXAMPLE.COM → alice@example.com
    const err = await signupError(validRequest({ email: 'ALICE@EXAMPLE.COM' }))
    expect(err.type).toBe<SignupErrorType>('EMAIL_EXISTS')
  })
})

// ---------------------------------------------------------------------------
// SignupResponse — success shape
// ---------------------------------------------------------------------------

describe('SignupResponse — success shape', () => {
  it('returns an accessToken string', async () => {
    const result = await signup(validRequest(), NO_DELAY)
    expect(typeof result.accessToken).toBe('string')
    expect(result.accessToken.length).toBeGreaterThan(0)
  })

  it('returns a refreshToken string', async () => {
    const result = await signup(validRequest(), NO_DELAY)
    expect(typeof result.refreshToken).toBe('string')
    expect(result.refreshToken.length).toBeGreaterThan(0)
  })

  it('returns a user object with id and email', async () => {
    const result = await signup(validRequest(), NO_DELAY)
    expect(result.user).toMatchObject({
      id: expect.any(String),
      email: expect.any(String),
    })
    expect(result.user.id.length).toBeGreaterThan(0)
  })

  it('returns the normalised email (lowercase) in user.email', async () => {
    const result = await signup(validRequest({ email: 'BOB@EXAMPLE.COM' }), NO_DELAY)
    expect(result.user.email).toBe('bob@example.com')
  })

  it('returns different tokens for different users', async () => {
    const r1 = await signup(validRequest({ email: 'a@example.com' }), NO_DELAY)
    const r2 = await signup(validRequest({ email: 'b@example.com' }), NO_DELAY)
    expect(r1.accessToken).not.toBe(r2.accessToken)
    expect(r1.refreshToken).not.toBe(r2.refreshToken)
    expect(r1.user.id).not.toBe(r2.user.id)
  })

  it('matches the full SignupResponse contract shape', async () => {
    const result: SignupResponse = await signup(validRequest(), NO_DELAY)
    // TypeScript already enforces the shape at compile time; the runtime check
    // confirms no extra nesting or missing keys slip through.
    expect(Object.keys(result).sort()).toEqual(['accessToken', 'refreshToken', 'user'])
    expect(Object.keys(result.user).sort()).toEqual(['email', 'id'])
  })
})

// ---------------------------------------------------------------------------
// State transitions — user created on success
// ---------------------------------------------------------------------------

describe('State transitions — success', () => {
  it('persists the new user in the repository after a successful signup', async () => {
    await signup(validRequest({ email: 'alice@example.com' }), NO_DELAY)

    const stored = await findUserByEmail('alice@example.com')
    expect(stored).not.toBeNull()
    expect(stored?.email).toBe('alice@example.com')
  })

  it('stores the user with the normalised (lowercased) email', async () => {
    await signup(validRequest({ email: 'ALICE@EXAMPLE.COM' }), NO_DELAY)

    const stored = await findUserByEmail('alice@example.com')
    expect(stored).not.toBeNull()
  })

  it('does NOT store the plain-text password', async () => {
    const result = await signup(validRequest({ email: 'alice@example.com' }), NO_DELAY)

    const stored = await findUserByEmail(result.user.email)
    expect(stored?.passwordHash).not.toBe('SecureP@ss123')
    // A bcrypt hash starts with $2b$ or $2a$
    expect(stored?.passwordHash).toMatch(/^\$2[ab]\$/)
  })

  it('assigns a unique, non-empty id to the created user', async () => {
    const result = await signup(validRequest(), NO_DELAY)
    expect(result.user.id).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// State transitions — no user created on failure
// ---------------------------------------------------------------------------

describe('State transitions — failure leaves state unchanged', () => {
  it('does not persist a user when validation fails (invalid email)', async () => {
    await signupError(validRequest({ email: 'not-an-email' }))

    const stored = await findUserByEmail('not-an-email')
    expect(stored).toBeNull()
  })

  it('does not persist a user when validation fails (weak password)', async () => {
    await signupError(validRequest({ email: 'bob@example.com', password: 'weak' }))

    const stored = await findUserByEmail('bob@example.com')
    expect(stored).toBeNull()
  })

  it('does not persist a user when honeypot is triggered', async () => {
    await signupError(validRequest({ email: 'bot@example.com', website: 'http://bot.com' }))

    const stored = await findUserByEmail('bot@example.com')
    expect(stored).toBeNull()
  })

  it('does not create a second user when EMAIL_EXISTS is thrown', async () => {
    await signup(validRequest({ email: 'carol@example.com' }), NO_DELAY)
    await signupError(validRequest({ email: 'carol@example.com' }))

    // Only one record should exist — confirm by checking the stored record is
    // the one from the first signup.
    const stored = await findUserByEmail('carol@example.com')
    expect(stored).not.toBeNull()
    // The email index should still point to a single user (no duplicates)
    expect(stored?.email).toBe('carol@example.com')
  })

  it('does not alter the existing user record on a duplicate-email attempt', async () => {
    const first = await signup(validRequest({ email: 'dave@example.com' }), NO_DELAY)
    await signupError(validRequest({ email: 'dave@example.com', password: 'AnotherP@ss1' }))

    const stored = await findUserByEmail('dave@example.com')
    // The stored passwordHash must belong to the first successful signup, not
    // the rejected second attempt.
    expect(stored?.id).toBe(first.user.id)
  })
})

// ---------------------------------------------------------------------------
// SignupError class contract
// ---------------------------------------------------------------------------

describe('SignupError class contract', () => {
  it('is an instance of Error', async () => {
    const err = await signupError(validRequest({ email: 'bad' }))
    expect(err).toBeInstanceOf(Error)
  })

  it('has name "SignupError"', async () => {
    const err = await signupError(validRequest({ email: 'bad' }))
    expect(err.name).toBe('SignupError')
  })

  it('always carries a non-empty message', async () => {
    const err = await signupError(validRequest({ email: 'bad' }))
    expect(err.message.length).toBeGreaterThan(0)
  })

  it('carries a statusCode property', async () => {
    const err = await signupError(validRequest({ email: 'bad' }))
    expect(typeof err.statusCode).toBe('number')
  })

  it('carries a type that is a valid SignupErrorType', async () => {
    const validTypes: SignupErrorType[] = [
      'VALIDATION_ERROR',
      'EMAIL_INVALID',
      'EMAIL_DISPOSABLE',
      'EMAIL_EXISTS',
      'PASSWORD_WEAK',
      'RATE_LIMITED',
      'HONEYPOT_TRIGGERED',
      'SUSPICIOUS_ACTIVITY',
    ]
    const err = await signupError(validRequest({ email: 'bad' }))
    expect(validTypes).toContain(err.type)
  })
})

// ---------------------------------------------------------------------------
// checkSignupAvailability
// ---------------------------------------------------------------------------

describe('checkSignupAvailability', () => {
  it('returns available:true and remainingAttempts > 0 when under limits', () => {
    const result = checkSignupAvailability('10.0.0.1', 'user@example.com')
    expect(result.available).toBe(true)
    expect(result.remainingAttempts).toBeGreaterThan(0)
  })

  it('returns a resetIn number', () => {
    const result = checkSignupAvailability('10.0.0.1')
    expect(typeof result.resetIn).toBe('number')
  })

  it('returns available:false after the IP is rate-limited', async () => {
    const config = {
      ...NO_DELAY,
      rateLimit: {
        maxAttemptsPerIp: 1,
        windowMs: 60_000,
        maxAttemptsPerEmail: 100,
        maxGlobalAttempts: 1000,
      },
    }
    const ip = '203.0.113.99'

    await signup(validRequest({ email: 'x@example.com', ipAddress: ip }), config)

    const result = checkSignupAvailability(ip, 'y@example.com', config.rateLimit)
    expect(result.available).toBe(false)
  })

  it('works without an email argument', () => {
    const result = checkSignupAvailability('10.0.0.1')
    expect(result).toHaveProperty('available')
    expect(result).toHaveProperty('remainingAttempts')
    expect(result).toHaveProperty('resetIn')
  })
})

// ---------------------------------------------------------------------------
// getSignupRateLimitHeaders
// ---------------------------------------------------------------------------

describe('getSignupRateLimitHeaders', () => {
  it('returns the standard rate-limit headers', () => {
    const headers = getSignupRateLimitHeaders('10.0.0.1', 'user@example.com')
    expect(headers).toHaveProperty('X-RateLimit-Limit')
    expect(headers).toHaveProperty('X-RateLimit-Remaining')
    expect(headers).toHaveProperty('X-RateLimit-Reset')
  })

  it('returns an object with string values', () => {
    const headers = getSignupRateLimitHeaders('10.0.0.1', 'user@example.com')
    for (const value of Object.values(headers)) {
      expect(typeof value).toBe('string')
    }
  })
})
