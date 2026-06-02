import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { secretLoader } from './secret-loader.js'
import { generateToken, verifyToken, generateRefreshToken, verifyRefreshToken } from './jwt.js'

const ORIGINAL_ENV = { ...process.env }

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) {
      delete process.env[key]
    }
  }

  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    process.env[key] = value
  }
}

describe('JWT secret rotation', () => {
  beforeEach(() => {
    restoreEnv()
    delete process.env.JWT_SECRET
    delete process.env.JWT_REFRESH_SECRET
  })

  afterEach(() => {
    restoreEnv()
  })

  it('uses the updated JWT_SECRET after reload', async () => {
    process.env.JWT_SECRET = 'first-secret'
    await secretLoader.reload()

    const token = generateToken({ userId: 'u1', email: 'user@example.com' })
    expect(verifyToken(token)).not.toBeNull()

    process.env.JWT_SECRET = 'second-secret'
    await secretLoader.reload()

    expect(verifyToken(token)).toBeNull()
    const rotated = generateToken({ userId: 'u1', email: 'user@example.com' })
    expect(verifyToken(rotated)).not.toBeNull()
  })

  it('uses the updated JWT_REFRESH_SECRET after reload', async () => {
    process.env.JWT_SECRET = 'primary-jwt-secret'
    process.env.JWT_REFRESH_SECRET = 'refresh-secret-1'
    await secretLoader.reload()

    const refreshToken = generateRefreshToken({ userId: 'u2', email: 'refresh@example.com' })
    expect(verifyRefreshToken(refreshToken)).not.toBeNull()

    process.env.JWT_REFRESH_SECRET = 'refresh-secret-2'
    await secretLoader.reload()

    expect(verifyRefreshToken(refreshToken)).toBeNull()
    const rotated = generateRefreshToken({ userId: 'u2', email: 'refresh@example.com' })
    expect(verifyRefreshToken(rotated)).not.toBeNull()
  })
})
