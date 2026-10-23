import express, { type Request } from 'express'
import request from 'supertest'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../utils/jwt.js', () => ({ verifyToken: vi.fn() }))
vi.mock('../../repositories/userRepository.js', () => ({ findUserById: vi.fn() }))
vi.mock('../../repositories/business.js', () => ({
  businessRepository: { getById: vi.fn() },
}))
vi.mock('../../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}))

import { addPermissionContext, requirePermissions } from '../permissions.js'
import { requireBusinessAuth } from '../requireBusinessAuth.js'
import { IntegrationPermission } from '../../types/permissions.js'
import { verifyToken } from '../../utils/jwt.js'
import { findUserById } from '../../repositories/userRepository.js'
import { businessRepository } from '../../repositories/business.js'

const BUSINESS = {
  id: 'business-1', userId: 'user-1', name: 'Acme', industry: null,
  description: null, website: null, createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z', suspended: false,
}

function permissionApp() {
  const app = express()
  app.get('/admin', requireBusinessAuth, requirePermissions(IntegrationPermission.DISCONNECT_ANY), (_req, res) => {
    res.status(204).end()
  })
  return app
}

function contextApp(user: Request['user'], business = BUSINESS) {
  const app = express()
  app.use((req, _res, next) => {
    req.user = user
    req.business = business
    next()
  })
  app.get('/context', addPermissionContext(), (req, res) => res.json(req.permissionContext))
  return app
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(verifyToken).mockReturnValue({ userId: 'user-1', email: 'user@example.com' } as never)
  vi.mocked(businessRepository.getById).mockResolvedValue(BUSINESS as never)
})

describe('permission role trust boundary', () => {
  it('denies a database user attempting to impersonate an admin via x-user-role', async () => {
    vi.mocked(findUserById).mockResolvedValue({ id: 'user-1', role: 'user' } as never)

    const response = await request(permissionApp())
      .get('/admin')
      .set('Authorization', 'Bearer token')
      .set('x-business-id', BUSINESS.id)
      .set('x-user-role', 'admin')

    expect(response.status).toBe(403)
    expect(response.body).toMatchObject({ error: 'Forbidden', message: 'Insufficient permissions' })
  })

  it('grants an actual database admin permission without an x-user-role header', async () => {
    vi.mocked(findUserById).mockResolvedValue({ id: 'user-1', role: 'admin' } as never)

    const response = await request(permissionApp())
      .get('/admin')
      .set('Authorization', 'Bearer token')
      .set('x-business-id', BUSINESS.id)

    expect(response.status).toBe(204)
  })

  it('makes addPermissionContext ignore x-user-role', async () => {
    const response = await request(contextApp({ id: 'user-1', userId: 'user-1', role: 'user' }))
      .get('/context')
      .set('x-user-role', 'admin')

    expect(response.body.role).toBe('user')
    expect(response.body.permissions).not.toContain(IntegrationPermission.DISCONNECT_ANY)
  })

  it('defaults a missing authenticated role to user despite x-user-role', async () => {
    const response = await request(contextApp({ id: 'user-1', userId: 'user-1' }))
      .get('/context')
      .set('x-user-role', 'admin')

    expect(response.body.role).toBe('user')
    expect(response.body.permissions).not.toContain(IntegrationPermission.DISCONNECT_ANY)
  })

  it('uses the authenticated business context instead of x-business-id', async () => {
    const response = await request(contextApp({ id: 'user-1', userId: 'user-1', role: 'user' }))
      .get('/context')
      .set('x-business-id', 'attacker-business')

    expect(response.body.businessId).toBe(BUSINESS.id)
  })
})
