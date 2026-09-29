import { beforeEach, describe, expect, it, vi } from 'vitest'
import request from 'supertest'
import express from 'express'

const mocks = vi.hoisted(() => ({
  user: { id: 'admin-1', userId: 'admin-1' },
  getAllUsers: vi.fn(),
  updateUser: vi.fn(),
  deleteUser: vi.fn(),
  findUserById: vi.fn(),
  promoteUserToBusinessAdmin: vi.fn(),
  createAuditLog: vi.fn(),
  queryAuditLogs: vi.fn(),
  listAllAttestations: vi.fn(),
  db: {},
  getDeadLetter: vi.fn(),
  deleteDeadLetter: vi.fn(),
  computePayloadHash: vi.fn(),
  isQuarantined: vi.fn(),
  listQuarantinedLetters: vi.fn(),
  releaseQuarantinedLetter: vi.fn(),
  purgeQuarantinedLetter: vi.fn(),
  listDeadLetterShards: vi.fn(),
  handleRazorpayEvent: vi.fn(),
  queryDeliveryReceipts: vi.fn(),
  revokeBatchAttestations: vi.fn(),
  createRolePromotionRequest: vi.fn(),
  findRolePromotionRequestById: vi.fn(),
  updateRolePromotionRequest: vi.fn(),
  findPendingRolePromotionRequestsForTarget: vi.fn(),
  loggerInfo: vi.fn(),
  loggerError: vi.fn(),
}))

vi.mock('../middleware/requireAuth.js', () => ({
  requireAuth: (_req: unknown, _res: unknown, next: (error?: unknown) => void) => next(),
}))

vi.mock('../middleware/permissions.js', () => ({
  requirePermissions: () => (_req: unknown, _res: unknown, next: (error?: unknown) => void) => next(),
  requireBusinessTierRolePromotionPermission: (_req: unknown, _res: unknown, next: (error?: unknown) => void) => next(),
}))

vi.mock('../types/permissions.js', () => ({
  IntegrationPermission: {
    ADMIN_READ_STATS: 'ADMIN_READ_STATS',
    ADMIN_MANAGE_USERS: 'ADMIN_MANAGE_USERS',
  },
}))

vi.mock('../repositories/userRepository.js', () => ({
  getAllUsers: mocks.getAllUsers,
  updateUser: mocks.updateUser,
  deleteUser: mocks.deleteUser,
  findUserById: mocks.findUserById,
  promoteUserToBusinessAdmin: mocks.promoteUserToBusinessAdmin,
}))

vi.mock('../repositories/auditLogRepository.js', () => ({
  createAuditLog: mocks.createAuditLog,
  queryAuditLogs: mocks.queryAuditLogs,
}))

vi.mock('../repositories/attestationRepository.js', () => ({
  listAll: mocks.listAllAttestations,
}))

vi.mock('../db/client.js', () => ({ db: mocks.db }))

vi.mock('../services/webhooks/deadLetterQueue.js', () => ({
  getDeadLetter: mocks.getDeadLetter,
  deleteDeadLetter: mocks.deleteDeadLetter,
  computePayloadHash: mocks.computePayloadHash,
  isQuarantined: mocks.isQuarantined,
  listQuarantinedLetters: mocks.listQuarantinedLetters,
  releaseQuarantinedLetter: mocks.releaseQuarantinedLetter,
  purgeQuarantinedLetter: mocks.purgeQuarantinedLetter,
  listDeadLetterShards: mocks.listDeadLetterShards,
}))

vi.mock('../services/webhooks/razorpayHandler.js', () => ({
  handleRazorpayEvent: mocks.handleRazorpayEvent,
}))

vi.mock('../repositories/deliveryReceiptRepository.js', () => ({
  queryDeliveryReceipts: mocks.queryDeliveryReceipts,
}))

vi.mock('../services/attestation/revokeBatch.js', () => ({
  revokeBatchAttestations: mocks.revokeBatchAttestations,
}))

vi.mock('../repositories/rolePromotionRequestRepository.js', () => ({
  createRolePromotionRequest: mocks.createRolePromotionRequest,
  findRolePromotionRequestById: mocks.findRolePromotionRequestById,
  updateRolePromotionRequest: mocks.updateRolePromotionRequest,
  findPendingRolePromotionRequestsForTarget: mocks.findPendingRolePromotionRequestsForTarget,
}))

vi.mock('../utils/logger.js', () => ({
  logger: { info: mocks.loggerInfo, error: mocks.loggerError },
}))

vi.mock('./admin.graphql.js', () => ({
  default: (_req: unknown, _res: unknown, next: (error?: unknown) => void) => next(),
}))

import adminRouter from './admin.js'

const targetUser = { id: 'user-2', role: 'user', email: 'user@example.com' }

function buildApp() {
  const app = express()
  app.use(express.json())
  app.use((req, _res, next) => {
    ;(req as express.Request & { user?: typeof mocks.user }).user = mocks.user
    next()
  })
  app.use('/api/v1/admin', adminRouter)
  return app
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.user.id = 'admin-1'
  mocks.user.userId = 'admin-1'
  mocks.getAllUsers.mockResolvedValue([])
  mocks.updateUser.mockResolvedValue(null)
  mocks.deleteUser.mockResolvedValue(false)
  mocks.findUserById.mockResolvedValue(null)
  mocks.promoteUserToBusinessAdmin.mockResolvedValue({ outcome: 'not_found', newRole: 'business_admin' })
  mocks.createAuditLog.mockResolvedValue(undefined)
  mocks.queryAuditLogs.mockResolvedValue({ data: [], nextCursor: undefined, hasMore: false })
  mocks.listAllAttestations.mockResolvedValue([])
  mocks.getDeadLetter.mockResolvedValue(null)
  mocks.deleteDeadLetter.mockResolvedValue(undefined)
  mocks.computePayloadHash.mockReturnValue('payload-hash')
  mocks.isQuarantined.mockResolvedValue(false)
  mocks.listQuarantinedLetters.mockResolvedValue([])
  mocks.releaseQuarantinedLetter.mockResolvedValue(false)
  mocks.purgeQuarantinedLetter.mockResolvedValue(false)
  mocks.listDeadLetterShards.mockResolvedValue([])
  mocks.handleRazorpayEvent.mockResolvedValue(undefined)
  mocks.queryDeliveryReceipts.mockResolvedValue({ data: [], nextCursor: undefined })
  mocks.revokeBatchAttestations.mockResolvedValue([])
  mocks.createRolePromotionRequest.mockResolvedValue({ id: 'request-1' })
  mocks.findRolePromotionRequestById.mockResolvedValue(null)
  mocks.updateRolePromotionRequest.mockResolvedValue(null)
  mocks.findPendingRolePromotionRequestsForTarget.mockResolvedValue([])
})

describe('admin router', () => {
  it('returns aggregate statistics and only the five most recent attestations', async () => {
    mocks.getAllUsers.mockResolvedValue([
      { role: 'admin' },
      { role: 'business_admin' },
      { role: 'user' },
      { role: 'user' },
    ])
    const attestations = Array.from({ length: 6 }, (_, index) => ({ id: `attestation-${index + 1}` }))
    mocks.listAllAttestations.mockResolvedValue(attestations)

    const response = await request(buildApp()).get('/api/v1/admin/stats')

    expect(response.status).toBe(200)
    expect(response.body).toEqual({
      totalUsers: 4,
      totalAttestations: 6,
      adminCount: 1,
      businessAdminCount: 1,
      userCount: 2,
      recentAttestations: attestations.slice(-5),
    })
    expect(mocks.listAllAttestations).toHaveBeenCalledWith(mocks.db)
  })

  it('returns a deterministic 500 response when statistics loading fails', async () => {
    mocks.getAllUsers.mockRejectedValue(new Error('user store unavailable'))

    const response = await request(buildApp()).get('/api/v1/admin/stats')

    expect(response.status).toBe(500)
    expect(response.body).toEqual({ error: 'Internal Server Error', message: 'user store unavailable' })
  })

  it('rejects malformed or oversized batch revocation input without invoking the service', async () => {
    const app = buildApp()
    const malformed = await request(app)
      .post('/api/v1/admin/attestations/revoke-batch')
      .send({ attestationIds: ['att-1', 2] })
    const oversized = await request(app)
      .post('/api/v1/admin/attestations/revoke-batch')
      .send({ attestationIds: Array.from({ length: 501 }, (_, index) => `att-${index}`) })

    expect(malformed.status).toBe(400)
    expect(malformed.body.message).toBe('Invalid attestationIds array')
    expect(oversized.status).toBe(400)
    expect(mocks.revokeBatchAttestations).not.toHaveBeenCalled()
  })

  it('revokes a valid batch for the authenticated admin and reports the count', async () => {
    mocks.revokeBatchAttestations.mockResolvedValue(['att-1', 'att-2'])

    const response = await request(buildApp())
      .post('/api/v1/admin/attestations/revoke-batch')
      .send({ attestationIds: ['att-1', 'att-2'] })

    expect(response.status).toBe(200)
    expect(response.body).toEqual({ message: 'Batch revoked successfully', count: 2 })
    expect(mocks.revokeBatchAttestations).toHaveBeenCalledWith(['att-1', 'att-2'], 'admin-1')
  })

  it('updates a user and excludes sensitive fields from the audit metadata', async () => {
    const updatedUser = { ...targetUser, email: 'updated@example.com' }
    mocks.findUserById.mockResolvedValue(targetUser)
    mocks.updateUser.mockResolvedValue(updatedUser)

    const response = await request(buildApp())
      .patch('/api/v1/admin/users/user-2')
      .send({ email: 'updated@example.com', passwordHash: 'secret', resetToken: 'token' })

    expect(response.status).toBe(200)
    expect(response.body).toEqual(updatedUser)
    expect(mocks.updateUser).toHaveBeenCalledWith('user-2', {
      email: 'updated@example.com',
      passwordHash: 'secret',
      resetToken: 'token',
    })
    expect(mocks.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      action: 'UPDATE_USER',
      metadata: { outcome: 'success', updateFields: ['email'] },
    }))
  })

  it('rejects self-promotion and audits the forbidden role transition', async () => {
    const response = await request(buildApp())
      .post('/api/v1/admin/users/admin-1/role')
      .send({ role: 'business_admin' })

    expect(response.status).toBe(403)
    expect(response.body.message).toBe('Self-promotion is not allowed')
    expect(mocks.promoteUserToBusinessAdmin).not.toHaveBeenCalled()
    expect(mocks.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      action: 'PROMOTE_USER_ROLE',
      metadata: expect.objectContaining({ outcome: 'forbidden_self_promotion' }),
    }))
  })

  it('rejects unsupported promotion payloads and records the invalid input', async () => {
    const response = await request(buildApp())
      .post('/api/v1/admin/users/user-2/role')
      .send({ role: 'admin', extra: true })

    expect(response.status).toBe(400)
    expect(response.body.message).toBe('role must be business_admin')
    expect(mocks.promoteUserToBusinessAdmin).not.toHaveBeenCalled()
    expect(mocks.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({ outcome: 'invalid_input' }),
    }))
  })

  it('promotes an eligible user and audits the state transition', async () => {
    const promotedUser = { ...targetUser, role: 'business_admin' }
    mocks.promoteUserToBusinessAdmin.mockResolvedValue({
      outcome: 'promoted',
      user: promotedUser,
      previousRole: 'user',
      newRole: 'business_admin',
    })

    const response = await request(buildApp())
      .post('/api/v1/admin/users/user-2/role')
      .send({ role: 'business_admin' })

    expect(response.status).toBe(200)
    expect(response.body).toEqual(promotedUser)
    expect(mocks.promoteUserToBusinessAdmin).toHaveBeenCalledWith('user-2')
    expect(mocks.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({
        outcome: 'success',
        previousRole: 'user',
        newRole: 'business_admin',
      }),
    }))
  })

  it('returns conflict when a target has an incompatible current role', async () => {
    mocks.promoteUserToBusinessAdmin.mockResolvedValue({
      outcome: 'invalid_current_role',
      previousRole: 'admin',
      newRole: 'business_admin',
    })

    const response = await request(buildApp())
      .post('/api/v1/admin/users/user-2/role')
      .send({ role: 'business_admin' })

    expect(response.status).toBe(409)
    expect(response.body.message).toBe('User cannot be promoted from current role')
    expect(mocks.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({ outcome: 'conflict', previousRole: 'admin' }),
    }))
  })

  it('parses valid audit filters into typed repository arguments', async () => {
    mocks.queryAuditLogs.mockResolvedValue({ data: [{ id: 'log-1' }], nextCursor: 'next', hasMore: true })

    const response = await request(buildApp()).get(
      '/api/v1/admin/audit-logs?action=UPDATE_USER&resource=user&from=2026-01-01&limit=5&cursor=log-0',
    )

    expect(response.status).toBe(200)
    expect(response.body).toEqual({ data: [{ id: 'log-1' }], nextCursor: 'next', hasMore: true })
    expect(mocks.queryAuditLogs).toHaveBeenCalledWith({
      actorId: undefined,
      action: 'UPDATE_USER',
      resource: 'user',
      from: new Date('2026-01-01'),
      to: undefined,
      limit: 5,
      cursor: 'log-0',
    })
  })

  it('rejects invalid audit filters and reversed date ranges before querying', async () => {
    const app = buildApp()
    const badFilter = await request(app).get('/api/v1/admin/audit-logs?action=UNKNOWN')
    const reversedRange = await request(app).get(
      '/api/v1/admin/audit-logs?from=2026-02-01&to=2026-01-01',
    )

    expect(badFilter.status).toBe(400)
    expect(reversedRange.status).toBe(400)
    expect(reversedRange.body.message).toBe('`from` must be <= `to`')
    expect(mocks.queryAuditLogs).not.toHaveBeenCalled()
  })

  it('marks expired role requests as expired and refuses approval', async () => {
    mocks.findRolePromotionRequestById.mockResolvedValue({
      id: 'request-1',
      status: 'pending',
      expiresAt: new Date('2000-01-01T00:00:00.000Z'),
      requestedByAdminId: 'admin-2',
      targetUserId: 'user-2',
      requestedRole: 'business_admin',
    })

    const response = await request(buildApp()).post('/api/v1/admin/role-requests/request-1/approve')

    expect(response.status).toBe(409)
    expect(response.body.message).toBe('Role promotion request has expired')
    expect(mocks.updateRolePromotionRequest).toHaveBeenCalledWith('request-1', { status: 'expired' })
    expect(mocks.updateUser).not.toHaveBeenCalled()
  })

  it('rejects webhook replay when the payload hash does not match', async () => {
    const payload = { id: 'event-1' }
    mocks.getDeadLetter.mockResolvedValue({ payload_hash: 'stored-hash' })
    mocks.computePayloadHash.mockReturnValue('different-hash')

    const response = await request(buildApp())
      .post('/api/v1/admin/webhooks/replay')
      .send({ provider: 'razorpay', eventId: 'event-1', payload })

    expect(response.status).toBe(400)
    expect(response.body.error).toBe('Payload hash mismatch')
    expect(mocks.handleRazorpayEvent).not.toHaveBeenCalled()
    expect(mocks.deleteDeadLetter).not.toHaveBeenCalled()
  })

  it('replays a matching webhook payload and clears its dead-letter entry', async () => {
    const payload = { id: 'event-1' }
    mocks.getDeadLetter.mockResolvedValue({ payload_hash: 'payload-hash' })

    const response = await request(buildApp())
      .post('/api/v1/admin/webhooks/replay')
      .send({ provider: 'razorpay', eventId: 'event-1', payload })

    expect(response.status).toBe(200)
    expect(response.body).toEqual({ status: 'ok', message: 'Replay successful, entry cleared' })
    expect(mocks.handleRazorpayEvent).toHaveBeenCalledWith(payload)
    expect(mocks.deleteDeadLetter).toHaveBeenCalledWith('razorpay', 'event-1')
  })
})