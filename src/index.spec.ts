import { afterEach, describe, expect, it, vi } from 'vitest'

describe('SIGHUP handling', () => {
  afterEach(() => {
    process.removeAllListeners('SIGHUP')
    vi.restoreAllMocks()
  })

  it('calls secretLoader.reload exactly once for each SIGHUP signal', async () => {
    const originalNodeEnv = process.env.NODE_ENV
    const originalDatabaseUrl = process.env.DATABASE_URL
    process.env.NODE_ENV = 'test'
    process.env.DATABASE_URL = 'postgresql://localhost:5432/test'
    vi.resetModules()

    const { secretLoader } = await import('./utils/secret-loader.js')
    const reloadSpy = vi.spyOn(secretLoader, 'reload').mockResolvedValue()

    await import('./index.js')

    process.emit('SIGHUP')
    await new Promise((resolve) => setImmediate(resolve))

    expect(reloadSpy).toHaveBeenCalledTimes(1)

    process.emit('SIGHUP')
    await new Promise((resolve) => setImmediate(resolve))

    expect(reloadSpy).toHaveBeenCalledTimes(2)

    process.env.NODE_ENV = originalNodeEnv
    if (originalDatabaseUrl === undefined) {
      delete process.env.DATABASE_URL
    } else {
      process.env.DATABASE_URL = originalDatabaseUrl
    }
  })
})
