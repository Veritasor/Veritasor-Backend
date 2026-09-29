/**
 * Focused behaviour coverage for `src/jobs/expiredRolePromotionRequests.ts`.
 *
 * The module's public surface is the stable job-name constant and the job
 * function itself, which is expected to *never throw* — it reports its outcome
 * through `JobOutcome` and leaves error handling to `runInstrumentedJob`.
 *
 * These tests pin down:
 *  - the exported job name (dashboards/alerts key off it),
 *  - the empty sweep, the real pending→expired transition, and the failure
 *    path (all through `JobOutcome`, never a rejection),
 *  - the instrumentation contract with `runInstrumentedJob` (metrics labelled
 *    with the job name and the correct outcome).
 *
 * `src/metrics.js` is mocked with minimal metric stubs, mirroring the existing
 * convention in `tests/unit/services/soroban/batchingQueue.test.ts`, so the
 * suite depends only on the module under test.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => {
  const makeMetric = () => {
    const observe = vi.fn()
    const inc = vi.fn()
    const set = vi.fn()
    const labels = vi.fn(() => ({ observe, inc, set }))
    return { observe, inc, set, labels }
  }
  return {
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    duration: makeMetric(),
    runs: makeMetric(),
    items: makeMetric(),
    lastRun: makeMetric(),
  }
})

vi.mock('../../../src/metrics.js', () => ({
  metricsRegistry: {},
  jobDurationSeconds: { labels: mocks.duration.labels },
  jobRunsTotal: { labels: mocks.runs.labels },
  jobItemsProcessedTotal: { labels: mocks.items.labels },
  jobLastRunTimestamp: { labels: mocks.lastRun.labels },
}))

vi.mock('../../../src/utils/logger.js', () => ({ logger: mocks.logger }))

import {
  EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME,
  expiredRolePromotionRequestsJob,
} from '../../../src/jobs/expiredRolePromotionRequests.js'
import * as repository from '../../../src/repositories/rolePromotionRequestRepository.js'

beforeEach(() => {
  vi.clearAllMocks()
  repository.clearAllRolePromotionRequests()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME', () => {
  it('is the stable, snake_case identifier used by metrics and schedulers', () => {
    expect(EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME).toBe('expired_role_promotion_requests')
  })
})

describe('expiredRolePromotionRequestsJob – empty sweep', () => {
  it('reports success with zero items and logs the no-op message', async () => {
    const outcome = await expiredRolePromotionRequestsJob()

    expect(outcome).toEqual({ itemsProcessed: 0, success: true })
    expect(mocks.logger.info).toHaveBeenCalledWith(
      expect.stringContaining('Running expired role promotion requests sweeper job'),
    )
    expect(mocks.logger.info).toHaveBeenCalledWith(
      expect.stringContaining('No expired role promotion requests to mark'),
    )
  })

  it('does not raise the "marked N" log when nothing expired', async () => {
    await expiredRolePromotionRequestsJob()

    expect(mocks.logger.info).not.toHaveBeenCalledWith(
      expect.stringContaining('Marked '),
    )
  })
})

describe('expiredRolePromotionRequestsJob – pending → expired transition', () => {
  it('sweeps a genuinely expired request, reports it, and mutates its status', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))

    const request = await repository.createRolePromotionRequest('target-1', 'admin', 'admin-1')
    expect(request.status).toBe('pending')

    // Jump a year ahead: comfortably past any configured TTL.
    vi.setSystemTime(new Date('2027-01-01T00:00:00.000Z'))

    const outcome = await expiredRolePromotionRequestsJob()

    expect(outcome).toEqual({ itemsProcessed: 1, success: true })
    expect(mocks.logger.info).toHaveBeenCalledWith(
      expect.stringContaining('Marked 1 expired role promotion requests'),
    )

    const reloaded = await repository.findRolePromotionRequestById(request.id)
    expect(reloaded?.status).toBe('expired')
  })

  it('is idempotent: a second run finds nothing left to expire', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    await repository.createRolePromotionRequest('target-1', 'admin', 'admin-1')
    vi.setSystemTime(new Date('2027-01-01T00:00:00.000Z'))

    const first = await expiredRolePromotionRequestsJob()
    const second = await expiredRolePromotionRequestsJob()

    expect(first.itemsProcessed).toBe(1)
    expect(second).toEqual({ itemsProcessed: 0, success: true })
  })

  it('leaves a not-yet-expired request pending', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    const request = await repository.createRolePromotionRequest('target-1', 'admin', 'admin-1')

    const outcome = await expiredRolePromotionRequestsJob()

    expect(outcome).toEqual({ itemsProcessed: 0, success: true })
    const reloaded = await repository.findRolePromotionRequestById(request.id)
    expect(reloaded?.status).toBe('pending')
  })
})

describe('expiredRolePromotionRequestsJob – failure path', () => {
  it('resolves with success:false (never rejects) when the sweeper throws', async () => {
    const boom = new Error('db unavailable')
    const spy = vi.spyOn(repository, 'sweepExpiredRequests').mockRejectedValueOnce(boom)

    const outcome = await expiredRolePromotionRequestsJob()

    expect(outcome).toEqual({ itemsProcessed: 0, success: false })
    expect(mocks.logger.error).toHaveBeenCalledWith(
      expect.stringContaining('Error running expired role promotion requests job'),
      boom,
    )
    spy.mockRestore()
  })
})

describe('expiredRolePromotionRequestsJob – instrumentation', () => {
  it('records duration, success outcome, item count and last-run under the job name', async () => {
    await expiredRolePromotionRequestsJob()

    expect(mocks.duration.labels).toHaveBeenCalledWith(EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME)
    expect(mocks.duration.observe).toHaveBeenCalledTimes(1)
    expect(mocks.duration.observe.mock.calls[0][0]).toBeGreaterThanOrEqual(0)

    expect(mocks.runs.labels).toHaveBeenCalledWith(
      EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME,
      'success',
    )
    expect(mocks.runs.inc).toHaveBeenCalledTimes(1)

    expect(mocks.items.labels).toHaveBeenCalledWith(EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME)
    expect(mocks.items.inc).toHaveBeenCalledWith(0)

    expect(mocks.lastRun.labels).toHaveBeenCalledWith(EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME)
    expect(mocks.lastRun.set).toHaveBeenCalledTimes(1)
  })

  it('records the failure outcome and zero items when the sweeper throws', async () => {
    const spy = vi
      .spyOn(repository, 'sweepExpiredRequests')
      .mockRejectedValueOnce(new Error('db unavailable'))

    await expiredRolePromotionRequestsJob()

    expect(mocks.runs.labels).toHaveBeenCalledWith(
      EXPIRED_ROLE_PROMOTION_REQUESTS_JOB_NAME,
      'failure',
    )
    expect(mocks.items.inc).toHaveBeenCalledWith(0)
    spy.mockRestore()
  })
})
