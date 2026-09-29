import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Request, Response } from 'express'
import { deleteToken, getToken, saveToken } from './store.js'

const mocks = vi.hoisted(() => ({
  listByBusinessId: vi.fn(),
  deleteById: vi.fn(),
  executeWithRetry: vi.fn(),
  loggerInfo: vi.fn(),
  loggerWarn: vi.fn(),
}))

vi.mock('../../../repositories/integration.js', () => ({
  listByBusinessId: mocks.listByBusinessId,
  deleteById: mocks.deleteById,
}))

vi.mock('../clientWrapper.js', () => ({
  executeWithRetry: mocks.executeWithRetry,
}))

vi.mock('../retryBudget.js', () => ({
  GlobalRetryBudgetExceededError: class GlobalRetryBudgetExceededError extends Error {},
}))

vi.mock('../../../utils/logger.js', () => ({
  logger: {
    info: mocks.loggerInfo,
    warn: mocks.loggerWarn,
  },
}))

import disconnectShopify from './disconnect.js'
import { GlobalRetryBudgetExceededError } from '../retryBudget.js'

const shop = 'sample-shop.myshopify.com'
const businessId = 'business-1'
const userId = 'user-1'

function integration(overrides: Record<string, unknown> = {}) {
  return {
    id: 'integration-1',
    provider: 'shopify',
    externalId: shop,
    token: { accessToken: 'access-token' },
    metadata: {},
    ...overrides,
  }
}

function makeRequest(overrides: Record<string, unknown> = {}): Request {
  return {
    user: { id: userId, userId },
    business: { id: businessId },
    ...overrides,
  } as unknown as Request
}

function makeResponse() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response & {
    status: ReturnType<typeof vi.fn>
    json: ReturnType<typeof vi.fn>
  }
}

function mockFetchResponse(status: number, ok = false) {
  const fetchMock = vi.mocked(fetch)
  fetchMock.mockResolvedValue({ ok, status } as Response)
  return fetchMock
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
  vi.stubGlobal('fetch', vi.fn())
  mocks.listByBusinessId.mockResolvedValue([integration()])
  mocks.deleteById.mockResolvedValue(true)
  mocks.executeWithRetry.mockImplementation((operation: () => Promise<Response>) => operation())
})

describe('disconnectShopify', () => {
  it('rejects missing user or business context before reading integrations', async () => {
    for (const req of [
      makeRequest({ user: undefined }),
      makeRequest({ business: undefined }),
    ]) {
      const res = makeResponse()

      await disconnectShopify(req, res)

      expect(res.status).toHaveBeenCalledWith(401)
      expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized' })
    }

    expect(mocks.listByBusinessId).not.toHaveBeenCalled()
  })

  it('returns not found when the business has no Shopify integration', async () => {
    mocks.listByBusinessId.mockResolvedValue([{ ...integration(), provider: 'stripe' }])
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(mocks.listByBusinessId).toHaveBeenCalledWith(businessId)
    expect(res.status).toHaveBeenCalledWith(404)
    expect(res.json).toHaveBeenCalledWith({ error: 'Shopify integration not found' })
    expect(mocks.executeWithRetry).not.toHaveBeenCalled()
  })

  it.each([
    ['invalid shop host', { externalId: '-invalid' }],
    ['missing access token', { token: {} }],
    ['non-string access token', { token: { accessToken: 42 } }],
  ])('rejects %s without attempting remote or local deletion', async (_case, overrides) => {
    mocks.listByBusinessId.mockResolvedValue([integration(overrides)])
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(res.status).toHaveBeenCalledWith(500)
    expect(res.json).toHaveBeenCalledWith({
      error: 'Shopify integration is missing revocation metadata',
    })
    expect(mocks.executeWithRetry).not.toHaveBeenCalled()
    expect(mocks.deleteById).not.toHaveBeenCalled()
  })

  it('revokes access, removes the local integration and cached token, then reports completion', async () => {
    const fetchMock = mockFetchResponse(200, true)
    saveToken(shop, 'cached-token')
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(fetchMock).toHaveBeenCalledWith(`https://${shop}/admin/api_permissions/current.json`, {
      method: 'DELETE',
      headers: {
        Accept: 'application/json',
        'X-Shopify-Access-Token': 'access-token',
      },
    })
    expect(mocks.executeWithRetry).toHaveBeenCalledWith(expect.any(Function), {
      provider: 'shopify',
      operation: 'revoke_access',
      maxRetries: 2,
    })
    expect(mocks.deleteById).toHaveBeenCalledWith(businessId, 'integration-1')
    expect(getToken(shop)).toBeUndefined()
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith({ message: 'ok', revoked: true, alreadyRevoked: false })
  })

  it.each([401, 403, 404])('treats Shopify status %i as already revoked and completes local cleanup', async (status) => {
    mockFetchResponse(status)
    saveToken(shop, 'cached-token')
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(mocks.deleteById).toHaveBeenCalledWith(businessId, 'integration-1')
    expect(getToken(shop)).toBeUndefined()
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith({ message: 'ok', revoked: true, alreadyRevoked: true })
  })

  it('keeps the local integration and token when Shopify refuses revocation', async () => {
    mockFetchResponse(400)
    saveToken(shop, 'cached-token')
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(res.status).toHaveBeenCalledWith(502)
    expect(res.json).toHaveBeenCalledWith({ error: 'Failed to revoke Shopify access' })
    expect(mocks.deleteById).not.toHaveBeenCalled()
    expect(getToken(shop)).toBe('cached-token')
  })

  it('maps network failures to 502 without deleting local state', async () => {
    mocks.executeWithRetry.mockRejectedValueOnce(new Error('socket closed'))
    saveToken(shop, 'cached-token')
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(res.status).toHaveBeenCalledWith(502)
    expect(res.json).toHaveBeenCalledWith({ error: 'Failed to reach Shopify API' })
    expect(mocks.deleteById).not.toHaveBeenCalled()
    expect(getToken(shop)).toBe('cached-token')
  })

  it('reports retry-budget exhaustion distinctly and preserves local state', async () => {
    mocks.executeWithRetry.mockRejectedValueOnce(new GlobalRetryBudgetExceededError())
    saveToken(shop, 'cached-token')
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(res.status).toHaveBeenCalledWith(502)
    expect(res.json).toHaveBeenCalledWith({ error: 'Global outbound retry budget exhausted' })
    expect(mocks.deleteById).not.toHaveBeenCalled()
    expect(getToken(shop)).toBe('cached-token')
  })

  it('does not clear the cached token when local integration deletion fails', async () => {
    mockFetchResponse(200, true)
    mocks.deleteById.mockResolvedValue(false)
    saveToken(shop, 'cached-token')
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(mocks.deleteById).toHaveBeenCalledWith(businessId, 'integration-1')
    expect(getToken(shop)).toBe('cached-token')
    expect(res.status).toHaveBeenCalledWith(500)
    expect(res.json).toHaveBeenCalledWith({ error: 'Failed to disconnect Shopify integration' })
  })

  it('uses the metadata shop when externalId is not a string and normalizes its host', async () => {
    const fetchMock = mockFetchResponse(200, true)
    mocks.listByBusinessId.mockResolvedValue([
      integration({ externalId: undefined, metadata: { shop: ' SHOP-ALIAS ' } }),
    ])
    const res = makeResponse()

    await disconnectShopify(makeRequest(), res)

    expect(fetchMock).toHaveBeenCalledWith(
      'https://shop-alias.myshopify.com/admin/api_permissions/current.json',
      expect.any(Object),
    )
    expect(res.status).toHaveBeenCalledWith(200)
  })
})