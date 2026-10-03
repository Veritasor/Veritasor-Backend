import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'
import adminRouter from '../../../src/routes/admin.js'
import * as auditLogRepository from '../../../src/repositories/auditLogRepository.js'

// Mock repositories and middleware similar to existing admin tests
vi.mock('../../../src/repositories/auditLogRepository.js')
vi.mock('../../../src/middleware/requireAuth.js', () => ({
  requireAuth: (req: any, res: any, next: any) => {
    const role = (req.headers['x-user-role'] as string) || 'admin'
    req.user = { id: 'admin_123', userId: 'admin_123', email: 'admin@test.com', role }
    next()
  }
}))
vi.mock('../../../src/middleware/permissions.js', () => ({
  requirePermissions: (permissions: any) => (req: any, res: any, next: any) => {
    if (req.user.role === 'admin') return next()
    res.status(403).json({ error: 'Forbidden' })
  }
}))

const app = express()
app.use(express.json())
app.use('/api/v1/admin', adminRouter)

describe('GET /api/v1/admin/audit-logs (cursor pagination)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('valid query with all filters returns filtered and ordered results', async () => {
    vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({
      data: [
        { id: 'b', userId: 'actor1', action: 'UPDATE_USER', resource: 'user', timestamp: new Date('2026-06-01T00:00:00Z'), metadata: {} },
        { id: 'a', userId: 'actor1', action: 'UPDATE_USER', resource: 'user', timestamp: new Date('2026-05-31T23:59:59Z'), metadata: {} },
      ],
      nextCursor: 'cursor123',
      hasMore: true,
    } as any)

    const res = await request(app)
      .get('/api/v1/admin/audit-logs')
      .query({ actorId: 'actor1', action: 'UPDATE_USER', resource: 'user', from: '2026-05-01T00:00:00Z', to: '2026-06-02T00:00:00Z', limit: '2' })

    expect(res.status).toBe(200)
    expect(res.body.data).toHaveLength(2)
    expect(res.body.nextCursor).toBe('cursor123')
  })

  it('invalid date range (from > to) returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/admin/audit-logs')
      .query({ from: '2026-06-02T00:00:00Z', to: '2026-06-01T00:00:00Z' })

    expect(res.status).toBe(400)
  })

  it('limit above 100 returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/admin/audit-logs')
      .query({ limit: '101' })

    expect(res.status).toBe(400)
  })

  it('limit of 0 or negative returns 400', async () => {
    const r1 = await request(app).get('/api/v1/admin/audit-logs').query({ limit: '0' })
    const r2 = await request(app).get('/api/v1/admin/audit-logs').query({ limit: '-5' })
    expect(r1.status).toBe(400)
    expect(r2.status).toBe(400)
  })

  it('empty result set returns 200 with empty data and null nextCursor', async () => {
    vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({ data: [], nextCursor: null, hasMore: false } as any)

    const res = await request(app).get('/api/v1/admin/audit-logs')
    expect(res.status).toBe(200)
    expect(res.body.data).toEqual([])
    expect(res.body.nextCursor).toBeNull()
  })

  it('invalid action returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/admin/audit-logs')
      .query({ action: 'UNKNOWN_ACTION' })

    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Bad Request')
  })

  it('invalid resource returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/admin/audit-logs')
      .query({ resource: 'invalid/resource' })

    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Bad Request')
  })

  it('invalid from date returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/admin/audit-logs')
      .query({ from: 'not-a-date' })

    expect(res.status).toBe(400)
    expect(res.body.error).toBe('Bad Request')
  })

  it('cursor pagination: first page returns nextCursor, second page using that cursor returns next set', async () => {
    vi.mocked(auditLogRepository.queryAuditLogs).mockImplementation(async (q: any) => {
      if (!q.cursor) {
        return { data: [{ id: '2', userId: 'u' }], nextCursor: 'c1', hasMore: true }
      }
      if (q.cursor === 'c1') {
        return { data: [{ id: '1', userId: 'u' }], nextCursor: null, hasMore: false }
      }
      return { data: [], nextCursor: null, hasMore: false }
    })

    const first = await request(app).get('/api/v1/admin/audit-logs').query({ limit: '1' })
    expect(first.status).toBe(200)
    expect(first.body.nextCursor).toBe('c1')

    const second = await request(app).get('/api/v1/admin/audit-logs').query({ cursor: 'c1', limit: '1' })
    expect(second.status).toBe(200)
    expect(second.body.nextCursor).toBeNull()
    expect(second.body.data).toHaveLength(1)
  })

  it('cursor reuse returns same page (idempotent)', async () => {
    const page = { data: [{ id: 'x' }], nextCursor: 'cX', hasMore: true }
    vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue(page as any)

    const a = await request(app).get('/api/v1/admin/audit-logs').query({ limit: '1' })
    const b = await request(app).get('/api/v1/admin/audit-logs').query({ limit: '1' })

    expect(a.status).toBe(200)
    expect(b.status).toBe(200)
    expect(a.body).toEqual(b.body)
  })

  it('request without ADMIN_READ_STATS permission returns 403', async () => {
    const res = await request(app).get('/api/v1/admin/audit-logs').set('x-user-role', 'user')
    expect(res.status).toBe(403)
  })

  it('actorId filter returns only logs from that actor', async () => {
    const repo = await import('../../../src/repositories/auditLogRepository.js')
    vi.mocked(repo.queryAuditLogs).mockResolvedValue({ data: [{ id: 'z', userId: 'actor42', action: 'DELETE_USER', resource: 'user', timestamp: new Date(), metadata: {} }], nextCursor: null, hasMore: false } as any)

    const res = await request(app).get('/api/v1/admin/audit-logs').query({ actorId: 'actor42' })
    expect(res.status).toBe(200)
    expect(res.body.data.every((d: any) => d.userId === 'actor42')).toBe(true)
  })

  it('from/to range filter returns only logs within that window', async () => {
    vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({ data: [{ id: 'r1', timestamp: new Date('2026-06-01T00:00:00Z'), userId: 'u' }], nextCursor: null, hasMore: false } as any)

    const res = await request(app).get('/api/v1/admin/audit-logs').query({ from: '2026-06-01T00:00:00Z', to: '2026-06-02T00:00:00Z' })
    expect(res.status).toBe(200)
    expect(res.body.data).toHaveLength(1)
  })
})
