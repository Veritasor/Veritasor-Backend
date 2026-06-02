import { afterEach, describe, expect, it, vi } from 'vitest'

describe('SIGHUP handling', () => {
  afterEach(() => {
    process.removeAllListeners('SIGHUP')
    vi.restoreAllMocks()
  })

  it('calls secretLoader.reload exactly once for each SIGHUP signal', async () => {
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
  })
})
