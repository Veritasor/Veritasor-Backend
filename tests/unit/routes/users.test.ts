/**
 * Focused behaviour coverage for `src/routes/users.ts` (`usersRouter`).
 *
 * This suite mounts the *real* router (rather than re-implementing its
 * handlers in the test file) so the assertions bind to the shipped middleware
 * order, status codes and error envelope:
 *
 *   PATCH /api/users/me                                  – profile update
 *   POST  /api/users/me/export                            – initiate GDPR export
 *   GET   /api/users/me/export/:token                      – download export
 *   GET   /api/users/me/export/:exportId/status            – poll export status
 *
 * `requireAuth` is mocked to inject a deterministic `req.user`; every other
 * collaborator is mocked so the tests are hermetic (no DB/Redis/network). The
 * validation schema, `validateBody` middleware and `errorHandler` are the real
 * implementations, so the 400/`VRT-0002` contract is exercised end to end.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import request from 'supertest'
import express from 'express'
import { ProfileUpdateError } from '../../../src/services/user/updateProfile.js'
import usersRouter from '../../../src/routes/users.js'
import { errorHandler } from '../../../src/middleware/errorHandler.js'

const USER_ID = 'user-1'

const mocks = vi.hoisted(() => ({
  updateProfile: vi.fn(),
  initiateDataExport: vi.fn(),
  getExportStatus: vi.fn(),
  getExportArchive: vi.fn(),
  consumeDownloadToken: vi.fn(),
}))

vi.mock('../../../src/middleware/requireAuth.js', () => ({
  requireAuth: (req: any, _res: any, next: any) => {
    req.user = { id: 'user-1', userId: 'user-1', email: 'user@example.com', role: 'user' }
    next()
  },
}))

vi.mock('../../../src/services/user/updateProfile.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/services/user/updateProfile.js')>()
  return {
    ...actual,
    default: mocks.updateProfile,
  }
})

vi.mock('../../../src/services/user/dataExportService.js', () => ({
  initiateDataExport: mocks.initiateDataExport,
  getExportStatus: mocks.getExportStatus,
  getExportArchive: mocks.getExportArchive,
}))

vi.mock('../../../src/repositories/dataExportRepository.js', () => ({
  consumeDownloadToken: mocks.consumeDownloadToken,
}))

vi.mock('../../../src/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}))

function buildApp() {
  const app = express()
  app.use(express.json())
  app.use('/api/users', usersRouter)
  app.use(errorHandler)
  return app
}

let app: ReturnType<typeof buildApp>
const AUTH = 'Bearer fake-token'
const VALID_TOKEN = 'f'.repeat(64)
const VALID_EXPORT_ID = 'e'.repeat(64)

beforeEach(() => {
  vi.clearAllMocks()
  app = buildApp()
})

afterEach(() => {
  vi.restoreAllMocks()
})

// ── PATCH /api/users/me ─────────────────────────────────────────────────────

describe('PATCH /api/users/me', () => {
  it('forwards the authenticated user id and the patch to updateProfile', async () => {
    mocks.updateProfile.mockResolvedValue({ id: USER_ID, name: 'New Name' })

    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ name: 'New Name' })

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ id: USER_ID, name: 'New Name' })
    expect(mocks.updateProfile).toHaveBeenCalledWith(USER_ID, { name: 'New Name' })
  })

  it('accepts a profile object', async () => {
    mocks.updateProfile.mockResolvedValue({ id: USER_ID, profile: { theme: 'dark' } })

    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ profile: { theme: 'dark' } })

    expect(res.status).toBe(200)
    expect(mocks.updateProfile).toHaveBeenCalledWith(USER_ID, { profile: { theme: 'dark' } })
  })

  it('rejects an empty body with 400 and does not call the service', async () => {
    const res = await request(app).patch('/api/users/me').set('Authorization', AUTH).send({})

    expect(res.status).toBe(400)
    expect(res.body.message).toBe('No updatable fields provided')
    expect(mocks.updateProfile).not.toHaveBeenCalled()
  })

  it('rejects unknown fields through the strict schema (VRT-0002)', async () => {
    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ name: 'Alice', unknownField: 'value' })

    expect(res.status).toBe(400)
    expect(res.body.vrtCode).toBe('VRT-0002')
    expect(Array.isArray(res.body.details)).toBe(true)
    expect(mocks.updateProfile).not.toHaveBeenCalled()
  })

  it('rejects a name longer than 100 characters', async () => {
    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ name: 'a'.repeat(101) })

    expect(res.status).toBe(400)
    expect(res.body.vrtCode).toBe('VRT-0002')
    expect(mocks.updateProfile).not.toHaveBeenCalled()
  })

  it.each([
    ['a numeric name', { name: 123 }],
    ['a null name', { name: null }],
    ['a non-object profile', { profile: 'not-an-object' }],
  ])('rejects %s', async (_label, body) => {
    const res = await request(app).patch('/api/users/me').set('Authorization', AUTH).send(body)

    expect(res.status).toBe(400)
    expect(res.body.vrtCode).toBe('VRT-0002')
    expect(mocks.updateProfile).not.toHaveBeenCalled()
  })

  it('rejects an array body (not an object)', async () => {
    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send([{ name: 'Alice' }])

    expect(res.status).toBe(400)
    expect(mocks.updateProfile).not.toHaveBeenCalled()
  })

  it('maps a service rejection to 400 with the service message', async () => {
    mocks.updateProfile.mockRejectedValue(new Error('name must be a string'))

    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ name: 'Alice' })

    expect(res.status).toBe(400)
    expect(res.body.message).toBe('name must be a string')
  })

  it('returns 400 with an error code for a ProfileUpdateError', async () => {
    mocks.updateProfile.mockRejectedValue(
      new ProfileUpdateError('NAME_EMPTY', 'name must not be empty'),
    )

    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ name: 'Alice' })

    expect(res.status).toBe(400)
    expect(res.body).toEqual({ message: 'name must not be empty', code: 'NAME_EMPTY' })
  })

  it('returns 404 with an error code when the user is not found', async () => {
    mocks.updateProfile.mockRejectedValue(
      new ProfileUpdateError('USER_NOT_FOUND', 'user not found'),
    )

    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ name: 'Alice' })

    expect(res.status).toBe(404)
    expect(res.body).toEqual({ message: 'user not found', code: 'USER_NOT_FOUND' })
  })

  it('falls back to a generic message when the service rejects without one', async () => {
    mocks.updateProfile.mockRejectedValue(undefined)

    const res = await request(app)
      .patch('/api/users/me')
      .set('Authorization', AUTH)
      .send({ name: 'Alice' })

    expect(res.status).toBe(400)
    expect(res.body.message).toBe('Invalid input')
  })
})

// ── POST /api/users/me/export ───────────────────────────────────────────────

describe('POST /api/users/me/export', () => {
  it('returns 202 with the export descriptor for the authenticated user', async () => {
    mocks.initiateDataExport.mockResolvedValue({
      exportId: VALID_EXPORT_ID,
      status: 'pending',
      createdAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2026-01-08T00:00:00.000Z',
    })

    const res = await request(app).post('/api/users/me/export').set('Authorization', AUTH)

    expect(res.status).toBe(202)
    expect(res.body.exportId).toBe(VALID_EXPORT_ID)
    expect(res.body.status).toBe('pending')
    expect(res.body.message).toMatch(/Data export initiated/)
    expect(mocks.initiateDataExport).toHaveBeenCalledWith(USER_ID)
  })

  it('returns 500 when the export service throws', async () => {
    mocks.initiateDataExport.mockRejectedValue(new Error('redis down'))

    const res = await request(app).post('/api/users/me/export').set('Authorization', AUTH)

    expect(res.status).toBe(500)
    expect(res.body.message).toBe('Failed to initiate export')
  })
})

// ── GET /api/users/me/export/:token ─────────────────────────────────────────

describe('GET /api/users/me/export/:token', () => {
  it('returns 400 for a token shorter than 32 characters', async () => {
    const res = await request(app).get('/api/users/me/export/short').set('Authorization', AUTH)

    expect(res.status).toBe(400)
    expect(res.body.message).toBe('Invalid export token')
    expect(mocks.consumeDownloadToken).not.toHaveBeenCalled()
  })

  it('returns 410 when the token is unknown, consumed or expired', async () => {
    mocks.consumeDownloadToken.mockResolvedValue(null)

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_TOKEN}`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(410)
    expect(res.body.message).toMatch(/already downloaded, or expired/)
  })

  it('returns 404 when the consumed token resolves to a missing export', async () => {
    mocks.consumeDownloadToken.mockResolvedValue(VALID_EXPORT_ID)
    mocks.getExportStatus.mockResolvedValue(null)

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_TOKEN}`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(404)
    expect(res.body.message).toBe('Export not found')
  })

  it('returns 202 while the export is still processing', async () => {
    mocks.consumeDownloadToken.mockResolvedValue(VALID_EXPORT_ID)
    mocks.getExportStatus.mockResolvedValue({ exportId: VALID_EXPORT_ID, status: 'processing' })

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_TOKEN}`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(202)
    expect(res.body.status).toBe('processing')
    expect(mocks.getExportArchive).not.toHaveBeenCalled()
  })

  it('returns 404 when a completed export has no archive', async () => {
    mocks.consumeDownloadToken.mockResolvedValue(VALID_EXPORT_ID)
    mocks.getExportStatus.mockResolvedValue({ exportId: VALID_EXPORT_ID, status: 'completed' })
    mocks.getExportArchive.mockResolvedValue(null)

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_TOKEN}`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(404)
    expect(res.body.message).toBe('Export archive not found')
  })

  it('streams a completed archive as an attachment', async () => {
    const archive = Buffer.from('encrypted-archive')
    mocks.consumeDownloadToken.mockResolvedValue(VALID_EXPORT_ID)
    mocks.getExportStatus.mockResolvedValue({ exportId: VALID_EXPORT_ID, status: 'completed' })
    mocks.getExportArchive.mockResolvedValue(archive)

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_TOKEN}`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toBe('application/octet-stream')
    expect(res.headers['content-disposition']).toBe(
      `attachment; filename="gdpr-export-${VALID_EXPORT_ID}.enc"`,
    )
    expect(res.headers['content-length']).toBe(String(archive.length))
  })

  it('returns 500 when the download pipeline throws', async () => {
    mocks.consumeDownloadToken.mockRejectedValue(new Error('redis down'))

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_TOKEN}`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(500)
    expect(res.body.message).toBe('Failed to download export')
  })
})

// ── GET /api/users/me/export/:exportId/status ───────────────────────────────

describe('GET /api/users/me/export/:exportId/status', () => {
  it('returns 400 for an export id shorter than 32 characters', async () => {
    const res = await request(app)
      .get('/api/users/me/export/short/status')
      .set('Authorization', AUTH)

    expect(res.status).toBe(400)
    expect(res.body.message).toBe('Invalid export ID')
    expect(mocks.getExportStatus).not.toHaveBeenCalled()
  })

  it('returns the export status without consuming a download token', async () => {
    mocks.getExportStatus.mockResolvedValue({ exportId: VALID_EXPORT_ID, status: 'completed' })

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_EXPORT_ID}/status`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(200)
    expect(res.body.status).toBe('completed')
    expect(mocks.consumeDownloadToken).not.toHaveBeenCalled()
  })

  it('returns 404 for an unknown export id', async () => {
    mocks.getExportStatus.mockResolvedValue(null)

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_EXPORT_ID}/status`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(404)
    expect(res.body.message).toBe('Export not found')
  })

  it('returns 500 when the status lookup throws', async () => {
    mocks.getExportStatus.mockRejectedValue(new Error('redis down'))

    const res = await request(app)
      .get(`/api/users/me/export/${VALID_EXPORT_ID}/status`)
      .set('Authorization', AUTH)

    expect(res.status).toBe(500)
    expect(res.body.message).toBe('Failed to check export status')
  })
})

// ── Router surface ──────────────────────────────────────────────────────────

describe('usersRouter surface', () => {
  it('exposes the four documented routes', () => {
    const routes = (usersRouter as unknown as {
      stack: { route?: { path: string; methods: Record<string, boolean> } }[]
    }).stack
      .filter((layer) => layer.route)
      .map((layer) => ({
        path: layer.route!.path,
        methods: Object.keys(layer.route!.methods).sort(),
      }))

    expect(routes).toEqual(
      expect.arrayContaining([
        { path: '/me', methods: ['patch'] },
        { path: '/me/export', methods: ['post'] },
        { path: '/me/export/:token', methods: ['get'] },
        { path: '/me/export/:exportId/status', methods: ['get'] },
      ]),
    )
  })
})
