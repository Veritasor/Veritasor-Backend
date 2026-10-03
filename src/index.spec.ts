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

// ---------------------------------------------------------------------------
// Bootstrap / startup path
// ---------------------------------------------------------------------------
//
// `src/index.ts` exports nothing: `bootstrap()` runs as an import side effect
// guarded by `process.env.NODE_ENV !== 'test'`, and the SIGHUP handler is
// registered at module evaluation time. These tests therefore replace every
// collaborator with `vi.doMock` (not hoisted, so the real-module case above is
// unaffected), re-import the entry point with a non-test NODE_ENV, and drive
// the captured SIGHUP handler and shutdown `onCleanup` hook directly.

const MOCKED_MODULES = [
  './app.js',
  './shutdown.js',
  './db/client.js',
  './utils/logger.js',
  './utils/secret-loader.js',
  './utils/jwks.js',
  './services/revenue/kafkaConsumer.js',
  './services/metrics/statsdBootstrap.js',
  './services/pgbouncerScraper.js',
] as const

type Consumer = {
  start: ReturnType<typeof vi.fn>
  stop: ReturnType<typeof vi.fn>
}

function createHarness(consumer: Consumer | null) {
  const server = { close: vi.fn() }
  const register = vi.fn()
  const captured: {
    cleanup?: () => Promise<void>
    pool?: unknown
  } = {}

  const mocks = {
    startServer: vi.fn().mockResolvedValue(server),
    stopIdempotencySweeper: vi.fn().mockResolvedValue(undefined),
    stopSpiffeSvidProviderIfNeeded: vi.fn(),
    stopStatsdDualWriteIfNeeded: vi.fn().mockResolvedValue(undefined),
    stopPgBouncerScraperIfNeeded: vi.fn().mockResolvedValue(undefined),
    secretReload: vi.fn().mockResolvedValue(undefined),
    jwksReload: vi.fn().mockResolvedValue(undefined),
    loggerInfo: vi.fn(),
    loggerError: vi.fn(),
    createRevenueConsumer: vi.fn(() => consumer),
    createShutdownOrchestrator: vi.fn(
      (opts: { pool?: unknown; onCleanup?: () => Promise<void> }) => {
        captured.pool = opts.pool
        captured.cleanup = opts.onCleanup
        return { register }
      },
    ),
    pool: { end: vi.fn() },
  }

  return { server, register, captured, mocks }
}

function installMocks(harness: ReturnType<typeof createHarness>) {
  const { mocks } = harness
  vi.doMock('./app.js', () => ({
    startServer: mocks.startServer,
    stopIdempotencySweeper: mocks.stopIdempotencySweeper,
    stopSpiffeSvidProviderIfNeeded: mocks.stopSpiffeSvidProviderIfNeeded,
  }))
  vi.doMock('./shutdown.js', () => ({
    createShutdownOrchestrator: mocks.createShutdownOrchestrator,
  }))
  vi.doMock('./db/client.js', () => ({ pool: mocks.pool }))
  vi.doMock('./utils/logger.js', () => ({
    logger: { info: mocks.loggerInfo, error: mocks.loggerError, warn: vi.fn() },
  }))
  vi.doMock('./utils/secret-loader.js', () => ({
    secretLoader: { reload: mocks.secretReload },
  }))
  vi.doMock('./utils/jwks.js', () => ({
    jwksManager: { reload: mocks.jwksReload },
  }))
  vi.doMock('./services/revenue/kafkaConsumer.js', () => ({
    createRevenueConsumer: mocks.createRevenueConsumer,
  }))
  vi.doMock('./services/metrics/statsdBootstrap.js', () => ({
    stopStatsdDualWriteIfNeeded: mocks.stopStatsdDualWriteIfNeeded,
  }))
  vi.doMock('./services/pgbouncerScraper.js', () => ({
    stopPgBouncerScraperIfNeeded: mocks.stopPgBouncerScraperIfNeeded,
  }))
}

describe('src/index.ts bootstrap', () => {
  const originalEnv = { ...process.env }
  let capturedSighup: (() => Promise<void>) | undefined
  let consoleError: ReturnType<typeof vi.spyOn>
  let consoleWarn: ReturnType<typeof vi.spyOn>
  let exitSpy: ReturnType<typeof vi.spyOn>

  async function boot(options: {
    consumer?: Consumer | null
    port?: string
  } = {}) {
    vi.resetModules()
    const harness = createHarness(options.consumer ?? null)
    installMocks(harness)
    capturedSighup = undefined
    vi.spyOn(process, 'on').mockImplementation(((
      event: string,
      handler: () => Promise<void>,
    ) => {
      if (event === 'SIGHUP') capturedSighup = handler
      return process
    }) as never)
    process.env.NODE_ENV = 'production'
    if (options.port === undefined) delete process.env.PORT
    else process.env.PORT = options.port
    await import('./index.js')
    return harness
  }

  function flush() {
    return new Promise((resolve) => setImmediate(resolve))
  }

  beforeEach(() => {
    consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never)
  })

  afterEach(() => {
    for (const path of MOCKED_MODULES) vi.doUnmock(path)
    vi.restoreAllMocks()
    vi.resetModules()
    process.env = { ...originalEnv }
  })

  it('does not start the server when NODE_ENV is "test"', async () => {
    vi.resetModules()
    const harness = createHarness(null)
    installMocks(harness)
    process.env.NODE_ENV = 'test'

    await import('./index.js')
    await flush()

    expect(harness.mocks.startServer).not.toHaveBeenCalled()
    expect(harness.mocks.secretReload).not.toHaveBeenCalled()
    expect(harness.mocks.createShutdownOrchestrator).not.toHaveBeenCalled()
  })

  it('reloads secrets and JWKS before starting the server', async () => {
    const harness = await boot()

    await vi.waitFor(() => expect(harness.mocks.startServer).toHaveBeenCalledTimes(1))

    expect(harness.mocks.secretReload).toHaveBeenCalledTimes(1)
    expect(harness.mocks.jwksReload).toHaveBeenCalledTimes(1)
    expect(harness.mocks.secretReload.mock.invocationCallOrder[0]).toBeLessThan(
      harness.mocks.startServer.mock.invocationCallOrder[0],
    )
    expect(harness.mocks.jwksReload.mock.invocationCallOrder[0]).toBeLessThan(
      harness.mocks.startServer.mock.invocationCallOrder[0],
    )
  })

  it('starts the server on PORT and logs a server_ready event', async () => {
    const harness = await boot({ port: '4321' })

    await vi.waitFor(() =>
      expect(harness.mocks.startServer).toHaveBeenCalledWith(4321),
    )
    expect(harness.mocks.loggerInfo).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'server_ready', port: 4321 }),
    )
  })

  it('falls back to port 3000 when PORT is unset or blank', async () => {
    const harness = await boot({ port: '' })

    await vi.waitFor(() =>
      expect(harness.mocks.startServer).toHaveBeenCalledWith(3000),
    )
  })

  it('registers the shutdown orchestrator with the pool and the started server', async () => {
    const harness = await boot()

    await vi.waitFor(() => expect(harness.register).toHaveBeenCalledTimes(1))

    expect(harness.register).toHaveBeenCalledWith(harness.server)
    expect(harness.captured.pool).toBe(harness.mocks.pool)
    expect(harness.mocks.createShutdownOrchestrator).toHaveBeenCalledWith(
      expect.objectContaining({ pool: harness.mocks.pool, onCleanup: expect.any(Function) }),
    )
    expect(typeof harness.captured.cleanup).toBe('function')
  })

  it('starts and later stops the Kafka revenue consumer when one is created', async () => {
    const consumer: Consumer = {
      start: vi.fn().mockResolvedValue(undefined),
      stop: vi.fn().mockResolvedValue(undefined),
    }
    const harness = await boot({ consumer })

    await vi.waitFor(() => expect(consumer.start).toHaveBeenCalledTimes(1))
    expect(harness.mocks.loggerInfo).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'kafka_consumer_started' }),
    )

    await harness.captured.cleanup?.()
    expect(consumer.stop).toHaveBeenCalledTimes(1)
  })

  it('skips the Kafka consumer when createRevenueConsumer returns null', async () => {
    const harness = await boot({ consumer: null })

    await vi.waitFor(() => expect(harness.register).toHaveBeenCalledTimes(1))
    await harness.captured.cleanup?.()

    expect(harness.mocks.loggerInfo).not.toHaveBeenCalledWith(
      expect.objectContaining({ event: 'kafka_consumer_started' }),
    )
    expect(consoleWarn).not.toHaveBeenCalled()
  })

  it('stops every background worker during shutdown cleanup', async () => {
    const harness = await boot()

    await vi.waitFor(() => expect(harness.register).toHaveBeenCalledTimes(1))
    await harness.captured.cleanup?.()

    expect(harness.mocks.stopIdempotencySweeper).toHaveBeenCalledTimes(1)
    expect(harness.mocks.stopPgBouncerScraperIfNeeded).toHaveBeenCalledTimes(1)
    expect(harness.mocks.stopSpiffeSvidProviderIfNeeded).toHaveBeenCalledTimes(1)
    expect(harness.mocks.stopStatsdDualWriteIfNeeded).toHaveBeenCalledTimes(1)
    expect(consoleWarn).not.toHaveBeenCalled()
  })

  it('swallows individual teardown failures so the remaining workers still stop', async () => {
    const harness = await boot()
    harness.mocks.stopIdempotencySweeper.mockRejectedValue(new Error('sweeper down'))
    harness.mocks.stopPgBouncerScraperIfNeeded.mockRejectedValue('scraper down')
    harness.mocks.stopStatsdDualWriteIfNeeded.mockRejectedValue(new Error('statsd down'))

    await vi.waitFor(() => expect(harness.register).toHaveBeenCalledTimes(1))
    await expect(harness.captured.cleanup?.()).resolves.toBeUndefined()

    expect(consoleWarn).toHaveBeenCalledWith(
      expect.stringContaining('[Shutdown] Idempotency sweeper stop error: sweeper down'),
    )
    expect(consoleWarn).toHaveBeenCalledWith(
      expect.stringContaining('[Shutdown] PgBouncer scraper stop error: scraper down'),
    )
    expect(consoleWarn).toHaveBeenCalledWith(
      expect.stringContaining('[Shutdown] StatsD dual-write stop error: statsd down'),
    )
    expect(harness.mocks.stopSpiffeSvidProviderIfNeeded).toHaveBeenCalledTimes(1)
    expect(harness.mocks.stopStatsdDualWriteIfNeeded).toHaveBeenCalledTimes(1)
  })

  it('hot-reloads secrets and JWKS on SIGHUP without restarting the server', async () => {
    const harness = await boot()
    await vi.waitFor(() => expect(harness.mocks.startServer).toHaveBeenCalledTimes(1))

    expect(capturedSighup).toBeTypeOf('function')
    await capturedSighup?.()

    expect(harness.mocks.secretReload).toHaveBeenCalledTimes(2)
    expect(harness.mocks.jwksReload).toHaveBeenCalledTimes(2)
    expect(harness.mocks.loggerInfo).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'secret_reload_requested', key: 'all' }),
    )
    expect(harness.mocks.loggerInfo).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'secret_reload_succeeded', key: 'all' }),
    )
    expect(harness.mocks.startServer).toHaveBeenCalledTimes(1)
  })

  it('logs secret_reload_failed and keeps running when a SIGHUP reload throws', async () => {
    const harness = await boot()
    await vi.waitFor(() => expect(harness.mocks.startServer).toHaveBeenCalledTimes(1))
    harness.mocks.secretReload.mockRejectedValueOnce(new Error('vault sealed'))

    await expect(capturedSighup?.()).resolves.toBeUndefined()

    expect(harness.mocks.loggerError).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'secret_reload_failed',
        key: 'all',
        error: 'vault sealed',
      }),
    )
    expect(harness.mocks.startServer).toHaveBeenCalledTimes(1)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('stringifies non-Error SIGHUP reload failures', async () => {
    const harness = await boot()
    await vi.waitFor(() => expect(harness.mocks.startServer).toHaveBeenCalledTimes(1))
    harness.mocks.secretReload.mockRejectedValueOnce('plain string failure')

    await capturedSighup?.()

    expect(harness.mocks.loggerError).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'secret_reload_failed', error: 'plain string failure' }),
    )
  })

  it('reports a fatal startup error and exits with code 1 when bootstrap fails', async () => {
    vi.resetModules()
    const harness = createHarness(null)
    installMocks(harness)
    harness.mocks.startServer.mockRejectedValueOnce(new Error('port already in use'))
    process.env.NODE_ENV = 'production'

    await import('./index.js')

    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(1))
    expect(consoleError).toHaveBeenCalledWith('[Startup] port already in use')
  })

  it('falls back to a generic message when bootstrap throws a non-Error', async () => {
    vi.resetModules()
    const harness = createHarness(null)
    installMocks(harness)
    harness.mocks.secretReload.mockRejectedValueOnce('boom')
    process.env.NODE_ENV = 'production'

    await import('./index.js')

    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(1))
    expect(consoleError).toHaveBeenCalledWith('[Startup] Unknown startup error')
  })
})
