import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Request, Response, NextFunction } from 'express'
import { optionalAuth, AuthEventType } from '../../../src/middleware/optionalAuth.js'
import * as jwt from '../../../src/utils/jwt.js'
import * as userRepository from '../../../src/repositories/userRepository.js'

/**
 * Focused behaviour coverage for `src/middleware/optionalAuth.ts` (issue #914).
 *
 * `optionalAuth` is the middleware that decides, for every public route,
 * whether a request carries an *optional* identity. Its entire public contract
 * is behavioural: never respond with 401, always call `next()` exactly once
 * with no error, and report exactly one structured auth event per request.
 *
 * The existing `optionalAuth.test.ts` cannot exercise that contract: it imports
 * `extractBearerToken`, which this module does not export, so the file fails to
 * load and none of its cases run. Rather than inventing an export just to keep
 * a test alive, this suite drives the middleware through the *real* public
 * surface and asserts the classification it emits. It pins the behaviour that
 * was effectively untested:
 *
 *  * the full malformed-header matrix (empty, prefix-only, wrong scheme, typo,
 *    tab/newline separators) and that a malformed header is never verified;
 *  * stale-identity hygiene — an already-populated `req.user` is cleared on
 *    every non-success path, so a previous middleware cannot leak an identity;
 *  * the `req.user` shape: exactly `id`, `userId`, `email`, and never `role`,
 *    even when the database row carries one;
 *  * log routing — `AUTH_SUCCESS` goes to `console.log` at `info`, every
 *    rejection goes to `console.warn` at `warn`, exactly once, and the
 *    middleware never writes to `console.error` or `res`;
 *  * non-`Error` throws from the JWT and repository layers degrade to
 *    `INVALID_TOKEN` / `DATABASE_ERROR` instead of escaping the middleware;
 *  * request metadata propagation (`x-request-id`, generated id shape, the full
 *    `req.ip` → `connection.remoteAddress` → `socket.remoteAddress` fallback,
 *    `tokenLength`, non-negative `duration`).
 */

type LogEntry = Record<string, unknown>

function parseLog(spy: { mock: { calls: unknown[][] } }): LogEntry {
  const calls = spy.mock.calls
  expect(calls.length).toBeGreaterThan(0)
  return JSON.parse(String(calls[calls.length - 1][0])) as LogEntry
}

const dbUser = (overrides: Partial<{ id: string; email: string | undefined; role: string }> = {}) => ({
  id: 'user-1',
  email: 'user@example.com',
  passwordHash: 'hash',
  role: 'business_admin',
  createdAt: new Date('2026-01-01T00:00:00Z'),
  updatedAt: new Date('2026-01-01T00:00:00Z'),
  ...overrides,
})

describe('optionalAuth — auth event classification', () => {
  let req: Request
  let res: Partial<Response>
  let next: NextFunction
  let warnSpy: ReturnType<typeof vi.spyOn>
  let logSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(dbUser() as never)
    res = { status: vi.fn(), json: vi.fn(), setHeader: vi.fn() }
    next = vi.fn()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  const buildRequest = (headers: Record<string, string> = {}, extra: object = {}): Request =>
    ({ headers, ip: '127.0.0.1', ...extra }) as unknown as Request

  // ── Malformed header matrix ────────────────────────────────────────

  const malformedCases: Array<[string, string, Partial<LogEntry>]> = [
    ['whitespace-only header', '   ', { hasBearerPrefix: false, tokenLength: 0 }],
    ['scheme with no credentials', 'Bearer', { hasBearerPrefix: true, tokenLength: 0 }],
    ['scheme with only spaces', 'Bearer   ', { hasBearerPrefix: true, tokenLength: 0 }],
    ['scheme glued to credentials with a colon', 'Bearer:abc', { hasBearerPrefix: false }],
    ['lower-case scheme typo', 'bearerx abc', { hasBearerPrefix: false }],
    ['wrong scheme', 'Basic dXNlcjpwYXNz', { hasBearerPrefix: false }],
    ['digest scheme', 'Digest username="a"', { hasBearerPrefix: false }],
  ]

  it.each(malformedCases)(
    'classifies a %s as MALFORMED_HEADER and never calls the verifier',
    async (_label, header, expected) => {
      const verifySpy = vi.spyOn(jwt, 'verifyToken')

      await optionalAuth(buildRequest({ authorization: header }), res as Response, next)

      expect(parseLog(warnSpy)).toMatchObject({
        event: AuthEventType.MALFORMED_HEADER,
        level: 'warn',
        service: 'optional-auth',
        headerPresent: true,
        ...expected,
      })
      expect(verifySpy).not.toHaveBeenCalled()
      expect(next).toHaveBeenCalledTimes(1)
      expect(next).toHaveBeenCalledWith()
    }
  )

  it('reports NO_TOKEN with headerPresent=false when the header is absent', async () => {
    await optionalAuth(buildRequest(), res as Response, next)

    expect(parseLog(warnSpy)).toMatchObject({
      event: AuthEventType.NO_TOKEN,
      headerPresent: false,
      hasBearerPrefix: false,
    })
    expect(logSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['tab', 'Bearer\tabc'],
    ['newline', 'Bearer\nabc'],
    ['multiple spaces', 'Bearer    abc'],
  ])('accepts a %s separator and verifies the bare token', async (_label, header) => {
    const verifySpy = vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)

    await optionalAuth(buildRequest({ authorization: header }), res as Response, next)

    expect(verifySpy).toHaveBeenCalledWith('abc')
  })

  it('preserves internal spaces in the credential', async () => {
    const verifySpy = vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)

    await optionalAuth(
      buildRequest({ authorization: 'Bearer a b c' }),
      res as Response,
      next
    )

    expect(verifySpy).toHaveBeenCalledWith('a b c')
  })

  // ── JWT failure classification ─────────────────────────────────────

  it.each([
    ['jwt expired', AuthEventType.EXPIRED_TOKEN],
    ['Token has expired', AuthEventType.EXPIRED_TOKEN],
    ['invalid issuer', AuthEventType.WRONG_ISSUER],
    ['invalid iss claim', AuthEventType.WRONG_ISSUER],
    ['unexpected audience', AuthEventType.WRONG_AUDIENCE],
    ['invalid aud value', AuthEventType.WRONG_AUDIENCE],
    ['invalid signature', AuthEventType.INVALID_TOKEN],
    ['malformed payload', AuthEventType.INVALID_TOKEN],
  ])('maps a "%s" verification error to %s', async (message, event) => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error(message)
    })

    await optionalAuth(buildRequest({ authorization: 'Bearer abc' }), res as Response, next)

    const entry = parseLog(warnSpy)
    expect(entry.event).toBe(event)
    expect(entry.error).toBe(message)
    expect(entry.level).toBe('warn')
    expect(entry.tokenLength).toBe(3)
  })

  it('degrades a non-Error verification throw to INVALID_TOKEN', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      // A thrown string has no `.message`, exercising the else-branch of the
      // classification ladder.
      throw 'boom'
    })

    await optionalAuth(buildRequest({ authorization: 'Bearer abc' }), res as Response, next)

    expect(parseLog(warnSpy)).toMatchObject({
      event: AuthEventType.INVALID_TOKEN,
      error: 'Unknown JWT error',
    })
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('classifies a null verification result as INVALID_TOKEN without an error field', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null as never)
    const findSpy = vi.spyOn(userRepository, 'findUserById')

    await optionalAuth(buildRequest({ authorization: 'Bearer abc' }), res as Response, next)

    const entry = parseLog(warnSpy)
    expect(entry.event).toBe(AuthEventType.INVALID_TOKEN)
    expect(entry.error).toBeUndefined()
    expect(findSpy).not.toHaveBeenCalled()
  })
})

describe('optionalAuth — identity hygiene', () => {
  let res: Partial<Response>
  let next: NextFunction
  let warnSpy: ReturnType<typeof vi.spyOn>
  let logSpy: ReturnType<typeof vi.spyOn>

  /** An identity left behind by an earlier middleware on the same request. */
  const staleUser = {
    id: 'stale-id',
    userId: 'stale-id',
    email: 'stale@example.com',
    role: 'admin' as const,
  }

  const buildRequest = (headers: Record<string, string> = {}, extra: object = {}): Request =>
    ({
      headers,
      ip: '127.0.0.1',
      user: { ...staleUser },
      ...extra,
    }) as unknown as Request

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(dbUser() as never)
    res = { status: vi.fn(), json: vi.fn(), setHeader: vi.fn() }
    next = vi.fn()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('clears an identity left behind by an earlier middleware when no credential is presented', async () => {
    // Silent failure model (docs/specs/optional-auth-middleware/design.md §3 and
    // the threat model): every auth failure -- including "no credential at all" --
    // leaves `req.user` undefined. Without the reset, an unauthenticated request
    // that happened to arrive with a pre-populated `req.user` would be treated as
    // authenticated by downstream handlers.
    const req = buildRequest({})

    await optionalAuth(req, res as Response, next)

    expect(req.user).toBeUndefined()
    expect(parseLog(warnSpy).event).toBe(AuthEventType.NO_TOKEN)
    expect(next).toHaveBeenCalledWith()
  })

  it('clears an identity left behind by an earlier middleware when the header is malformed', async () => {
    const req = buildRequest({ authorization: 'Basic dXNlcjpwYXNz' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toBeUndefined()
    expect(parseLog(warnSpy).event).toBe(AuthEventType.MALFORMED_HEADER)
    expect(next).toHaveBeenCalledWith()
  })

  it('clears a stale identity when the token fails verification', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('jwt expired')
    })
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toBeUndefined()
    expect(parseLog(warnSpy).event).toBe(AuthEventType.EXPIRED_TOKEN)
  })

  it('clears a stale identity when verification yields no payload', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null as never)
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toBeUndefined()
  })

  it('clears a stale identity when the user no longer exists', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'deleted-user' } as never)
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null as never)
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toBeUndefined()
    expect(parseLog(warnSpy)).toMatchObject({
      event: AuthEventType.USER_NOT_FOUND,
      userId: 'deleted-user',
    })
  })

  it('clears a stale identity when the repository throws', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)
    vi.spyOn(userRepository, 'findUserById').mockRejectedValue(new Error('connection refused'))
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toBeUndefined()
    expect(parseLog(warnSpy)).toMatchObject({
      event: AuthEventType.DATABASE_ERROR,
      error: 'connection refused',
      userId: 'user-1',
    })
  })

  it('reports an unknown database failure when the repository throws a non-Error', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)
    vi.spyOn(userRepository, 'findUserById').mockRejectedValue('nope' as never)
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toBeUndefined()
    expect(parseLog(warnSpy)).toMatchObject({
      event: AuthEventType.DATABASE_ERROR,
      error: 'Unknown database error',
    })
  })

  it('replaces a stale identity with the freshly authenticated one', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toEqual({ id: 'user-1', userId: 'user-1', email: 'user@example.com' })
  })

  it('attaches exactly id/userId/email and never a role, even when the row has one', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(Object.keys(req.user as object).sort()).toEqual(['email', 'id', 'userId'])
    expect((req.user as { role?: string }).role).toBeUndefined()
    expect(req.user).not.toHaveProperty('passwordHash')
  })

  it('takes the email from the database row, not from the token payload', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-1',
      email: 'attacker@evil.example',
    } as never)
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toMatchObject({ email: 'user@example.com' })
  })

  it('omits email when the stored user has none', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(
      dbUser({ email: undefined }) as never
    )
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(req.user).toMatchObject({ id: 'user-1', userId: 'user-1' })
    expect(req.user as object).toHaveProperty('email', undefined)
  })

  it('reports USER_NOT_FOUND when the payload carries no userId', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({} as never)
    const findSpy = vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null as never)
    const req = buildRequest({ authorization: 'Bearer abc' })

    await optionalAuth(req, res as Response, next)

    expect(findSpy).toHaveBeenCalledWith(undefined)
    expect(parseLog(warnSpy).event).toBe(AuthEventType.USER_NOT_FOUND)
    expect(req.user).toBeUndefined()
  })

  it('never writes to the response object in any path', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('jwt expired')
    })

    await optionalAuth(buildRequest({ authorization: 'Bearer abc' }), res as Response, next)
    await optionalAuth(buildRequest(), res as Response, next)

    expect(res.status).not.toHaveBeenCalled()
    expect(res.json).not.toHaveBeenCalled()
    expect(res.setHeader).not.toHaveBeenCalled()
  })

  it('logs exactly one event per request, routed by outcome', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)

    await optionalAuth(buildRequest({ authorization: 'Bearer abc' }), res as Response, next)

    expect(logSpy).toHaveBeenCalledTimes(1)
    expect(warnSpy).not.toHaveBeenCalled()
    expect(parseLog(logSpy)).toMatchObject({
      event: AuthEventType.AUTH_SUCCESS,
      level: 'info',
      userId: 'user-1',
      service: 'optional-auth',
    })
  })

  it('does not use the success channel for a rejected request', async () => {
    await optionalAuth(buildRequest(), res as Response, next)

    expect(warnSpy).toHaveBeenCalledTimes(1)
    expect(logSpy).not.toHaveBeenCalled()
  })
})

describe('optionalAuth — request metadata propagation', () => {
  let res: Partial<Response>
  let next: NextFunction
  let warnSpy: ReturnType<typeof vi.spyOn>
  let logSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(dbUser() as never)
    res = {}
    next = vi.fn()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  const buildRequest = (extra: object): Request => ({ headers: {}, ...extra }) as unknown as Request

  it('echoes an inbound x-request-id header', async () => {
    await optionalAuth(
      buildRequest({ headers: { 'x-request-id': 'trace-abc' } }),
      res as Response,
      next
    )

    expect(parseLog(warnSpy).requestId).toBe('trace-abc')
  })

  it('generates a request id when the header is missing', async () => {
    await optionalAuth(buildRequest({}), res as Response, next)

    expect(String(parseLog(warnSpy).requestId)).toMatch(/^req_\d+_[a-z0-9]{9}$/)
  })

  it('prefers req.ip over the socket addresses', async () => {
    await optionalAuth(
      buildRequest({
        ip: '203.0.113.9',
        connection: { remoteAddress: '10.0.0.2' },
        socket: { remoteAddress: '10.0.0.3' },
      }),
      res as Response,
      next
    )

    expect(parseLog(warnSpy).ip).toBe('203.0.113.9')
  })

  it('falls back to connection.remoteAddress when req.ip is absent', async () => {
    await optionalAuth(
      buildRequest({ connection: { remoteAddress: '10.0.0.2' }, socket: { remoteAddress: '10.0.0.3' } }),
      res as Response,
      next
    )

    expect(parseLog(warnSpy).ip).toBe('10.0.0.2')
  })

  it('falls back to socket.remoteAddress when nothing else is present', async () => {
    await optionalAuth(
      buildRequest({ socket: { remoteAddress: '10.0.0.3' } }),
      res as Response,
      next
    )

    expect(parseLog(warnSpy).ip).toBe('10.0.0.3')
  })

  it('reports "unknown" ip and user agent for a bare request', async () => {
    await optionalAuth(buildRequest({}), res as Response, next)

    expect(parseLog(warnSpy)).toMatchObject({ ip: 'unknown', userAgent: 'unknown' })
  })

  it('captures the user agent and a non-negative duration', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1' } as never)

    await optionalAuth(
      buildRequest({ headers: { authorization: 'Bearer abc', 'user-agent': 'vitest/1.0' } }),
      res as Response,
      next
    )

    const entry = parseLog(logSpy)
    expect(entry.userAgent).toBe('vitest/1.0')
    expect(typeof entry.duration).toBe('number')
    expect(entry.duration as number).toBeGreaterThanOrEqual(0)
    expect(entry.tokenLength).toBe(3)
    expect(typeof entry.timestamp).toBe('string')
  })

  it('classifies an unexpected error without escaping the middleware', async () => {
    // `headers` that throw on property access simulate a malformed request
    // object reaching the middleware.
    const hostile = new Proxy(
      {},
      {
        get: () => {
          throw new Error('headers exploded')
        },
      }
    ) as unknown as Request

    await expect(optionalAuth(hostile, res as Response, next)).resolves.toBeUndefined()

    expect(parseLog(warnSpy).event).toBe(AuthEventType.UNEXPECTED_ERROR)
    expect(parseLog(warnSpy).error).toBe('headers exploded')
    expect(next).toHaveBeenCalledTimes(1)
    expect(next).toHaveBeenCalledWith()
  })
})
