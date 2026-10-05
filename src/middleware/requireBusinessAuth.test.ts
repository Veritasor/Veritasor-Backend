import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { NextFunction, Request, Response } from 'express'

vi.mock('../utils/jwt.js', () => ({ verifyToken: vi.fn() }))
vi.mock('../repositories/userRepository.js', () => ({ findUserById: vi.fn() }))
vi.mock('../repositories/business.js', () => ({
  businessRepository: { getById: vi.fn() },
}))
vi.mock('../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}))

import { requireBusinessAuth } from './requireBusinessAuth.js'
import { verifyToken } from '../utils/jwt.js'
import { findUserById } from '../repositories/userRepository.js'
import { businessRepository } from '../repositories/business.js'
import { logger } from '../utils/logger.js'

/**
 * Regression suite for the failure / empty-result paths in requireBusinessAuth.
 *
 * Named evidence from the issue:
 *   - `src/middleware/requireBusinessAuth.ts:39` → `if (!payload) return null;`
 *   - `src/middleware/requireBusinessAuth.ts:42` → `if (!user) return null;`
 *   - `src/middleware/requireBusinessAuth.ts:46` → `return null;`
 *
 * All three `return null` branches collapse into the same `401 INVALID_TOKEN`
 * contract, so they are asserted through `validateUserToken`'s observable
 * outcome (status + code + `next` not being called) rather than by inspecting
 * internals.
 */

type AuthedRequest = Request & { user?: Record<string, unknown>; business?: Record<string, unknown> }

function makeReq(init: { headers?: Record<string, unknown>; body?: unknown } = {}): AuthedRequest {
  return {
    headers: init.headers ?? {},
    body: init.body,
  } as unknown as AuthedRequest
}

function makeRes() {
  const res = {
    statusCode: 0,
    payload: undefined as unknown,
    status(code: number) {
      res.statusCode = code
      return res
    },
    json(payload: unknown) {
      res.payload = payload
      return res
    },
  }
  return res
}

function makeNext() {
  return vi.fn()
}

async function invoke(req: AuthedRequest) {
  const res = makeRes()
  const next = makeNext()
  await requireBusinessAuth(req, res as unknown as Response, next as unknown as NextFunction)
  return { res, next }
}

const ACTIVE_BUSINESS = {
  id: 'b1',
  userId: 'u1',
  name: 'Acme',
  industry: null,
  description: null,
  website: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
  suspended: false,
}

/** Happy-path stubs: valid token, existing user, owned business. */
function stubHappyPath(business: unknown = ACTIVE_BUSINESS) {
  vi.mocked(verifyToken).mockReturnValue({ userId: 'u1', email: 'user@example.com' } as never)
  vi.mocked(findUserById).mockResolvedValue({ id: 'u1' } as never)
  vi.mocked(businessRepository.getById).mockResolvedValue(business as never)
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('requireBusinessAuth - successful authorization', () => {
  it('attaches the user and business then calls next()', async () => {
    stubHappyPath()
    const req = makeReq({
      headers: { authorization: 'Bearer good-token', 'x-business-id': 'b1' },
    })

    const { res, next } = await invoke(req)

    expect(next).toHaveBeenCalledTimes(1)
    expect(res.statusCode).toBe(0)
    expect(req.user).toMatchObject({ id: 'u1', userId: 'u1', email: 'user@example.com' })
    expect(req.business).toMatchObject({ id: 'b1', userId: 'u1' })
    expect(vi.mocked(verifyToken)).toHaveBeenCalledWith('good-token')
    expect(vi.mocked(logger.info)).toHaveBeenCalledWith(expect.stringContaining('business_auth.success'))
  })
})

describe('requireBusinessAuth - validateUserToken null branches', () => {
  it('rejects when verifyToken returns null (line 39)', async () => {
    vi.mocked(verifyToken).mockReturnValue(null as never)

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'INVALID_TOKEN' })
    expect(next).not.toHaveBeenCalled()
    // User lookup never happens without a valid payload.
    expect(vi.mocked(findUserById)).not.toHaveBeenCalled()
  })

  it('rejects when the user no longer exists (line 42)', async () => {
    vi.mocked(verifyToken).mockReturnValue({ userId: 'ghost' } as never)
    vi.mocked(findUserById).mockResolvedValue(null as never)

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'INVALID_TOKEN' })
    expect(next).not.toHaveBeenCalled()
  })

  it('rejects when verifyToken throws (line 46)', async () => {
    vi.mocked(verifyToken).mockImplementation(() => {
      throw new Error('jwt malformed')
    })

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'INVALID_TOKEN' })
    expect(next).not.toHaveBeenCalled()
  })

  it('rejects when the user lookup throws (line 46)', async () => {
    vi.mocked(verifyToken).mockReturnValue({ userId: 'u1' } as never)
    vi.mocked(findUserById).mockRejectedValue(new Error('db down'))

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'INVALID_TOKEN' })
    expect(next).not.toHaveBeenCalled()
  })
})

describe('requireBusinessAuth - authorization header boundary', () => {
  it('rejects a missing authorization header with MISSING_AUTH', async () => {
    const { res, next } = await invoke(makeReq({ headers: { 'x-business-id': 'b1' } }))

    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'MISSING_AUTH' })
    expect(next).not.toHaveBeenCalled()
    expect(vi.mocked(verifyToken)).not.toHaveBeenCalled()
  })

  it('rejects a non-Bearer authorization scheme', async () => {
    const { res } = await invoke(
      makeReq({ headers: { authorization: 'Basic abc', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'MISSING_AUTH' })
  })

  it('does not accept a lowercase bearer prefix', async () => {
    const { res } = await invoke(
      makeReq({ headers: { authorization: 'bearer abc', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'MISSING_AUTH' })
  })

  it('treats an empty bearer token as invalid', async () => {
    vi.mocked(verifyToken).mockReturnValue(null as never)

    const { res } = await invoke(
      makeReq({ headers: { authorization: 'Bearer ', 'x-business-id': 'b1' } }),
    )

    expect(vi.mocked(verifyToken)).toHaveBeenCalledWith('')
    expect(res.statusCode).toBe(401)
    expect(res.payload).toMatchObject({ code: 'INVALID_TOKEN' })
  })
})

describe('requireBusinessAuth - business id extraction', () => {
  it('rejects when no business id is supplied anywhere', async () => {
    stubHappyPath()

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token' }, body: {} }),
    )

    expect(res.statusCode).toBe(400)
    expect(res.payload).toMatchObject({ code: 'MISSING_BUSINESS_ID' })
    expect(next).not.toHaveBeenCalled()
    expect(vi.mocked(businessRepository.getById)).not.toHaveBeenCalled()
  })

  it('prefers the x-business-id header over the body', async () => {
    stubHappyPath()

    await invoke(
      makeReq({
        headers: { authorization: 'Bearer token', 'x-business-id': 'b1' },
        body: { business_id: 'b2' },
      }),
    )

    expect(vi.mocked(businessRepository.getById)).toHaveBeenCalledWith('b1')
  })

  it('falls back to body.business_id when the header is absent', async () => {
    stubHappyPath()

    await invoke(
      makeReq({ headers: { authorization: 'Bearer token' }, body: { business_id: 'b1' } }),
    )

    expect(vi.mocked(businessRepository.getById)).toHaveBeenCalledWith('b1')
  })

  it('falls back to body.businessId as the last option', async () => {
    stubHappyPath()

    await invoke(makeReq({ headers: { authorization: 'Bearer token' }, body: { businessId: 'b1' } }))

    expect(vi.mocked(businessRepository.getById)).toHaveBeenCalledWith('b1')
  })

  it('accepts a repeated header value by taking the first entry', async () => {
    stubHappyPath()

    await invoke(
      makeReq({
        headers: { authorization: 'Bearer token', 'x-business-id': ['b1', 'b2'] },
      }),
    )

    expect(vi.mocked(businessRepository.getById)).toHaveBeenCalledWith('b1')
  })

  it('trims surrounding whitespace from the header value', async () => {
    stubHappyPath()

    await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': '  b1  ' } }),
    )

    expect(vi.mocked(businessRepository.getById)).toHaveBeenCalledWith('b1')
  })

  it.each(['bad id', 'b@d!', 'a'.repeat(51), ''])(
    'rejects the malformed business id %j',
    async (badId) => {
      stubHappyPath()

      const { res } = await invoke(
        makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': badId } }),
      )

      expect(res.statusCode).toBe(400)
      expect(res.payload).toMatchObject({ code: 'MISSING_BUSINESS_ID' })
    },
  )

  it('ignores a malformed header and falls back to a valid body value', async () => {
    stubHappyPath()

    await invoke(
      makeReq({
        headers: { authorization: 'Bearer token', 'x-business-id': 'bad id' },
        body: { business_id: 'b1' },
      }),
    )

    expect(vi.mocked(businessRepository.getById)).toHaveBeenCalledWith('b1')
  })

  it('ignores a non-string body business id', async () => {
    stubHappyPath()

    const { res } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token' }, body: { business_id: 123 } }),
    )

    expect(res.statusCode).toBe(400)
    expect(res.payload).toMatchObject({ code: 'MISSING_BUSINESS_ID' })
  })
})

describe('requireBusinessAuth - business ownership', () => {
  it('rejects when the business does not exist', async () => {
    stubHappyPath(null)

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(403)
    expect(res.payload).toMatchObject({ code: 'BUSINESS_NOT_FOUND' })
    expect(next).not.toHaveBeenCalled()
  })

  it('rejects when the business belongs to another user', async () => {
    stubHappyPath({ ...ACTIVE_BUSINESS, userId: 'someone-else' })

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(403)
    expect(res.payload).toMatchObject({ code: 'BUSINESS_NOT_FOUND' })
    expect(next).not.toHaveBeenCalled()
  })

  it('rejects when the business lookup throws', async () => {
    vi.mocked(verifyToken).mockReturnValue({ userId: 'u1' } as never)
    vi.mocked(findUserById).mockResolvedValue({ id: 'u1' } as never)
    vi.mocked(businessRepository.getById).mockRejectedValue(new Error('db down'))

    const { res, next } = await invoke(
      makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } }),
    )

    expect(res.statusCode).toBe(403)
    expect(res.payload).toMatchObject({ code: 'BUSINESS_NOT_FOUND' })
    expect(next).not.toHaveBeenCalled()
  })
})

describe('requireBusinessAuth - suspended business', () => {
  it('rejects a suspended business with 403 BUSINESS_SUSPENDED and logs it', async () => {
    stubHappyPath({ ...ACTIVE_BUSINESS, suspended: true })
    const req = makeReq({ headers: { authorization: 'Bearer token', 'x-business-id': 'b1' } })

    const { res, next } = await invoke(req)

    expect(res.statusCode).toBe(403)
    expect(res.payload).toMatchObject({ code: 'BUSINESS_SUSPENDED' })
    expect(next).not.toHaveBeenCalled()
    expect(vi.mocked(logger.warn)).toHaveBeenCalledWith(
      expect.stringContaining('business_auth.suspended'),
    )
    // Context is only attached once every check passes.
    expect(req.user).toBeUndefined()
    expect(req.business).toBeUndefined()
  })
})
