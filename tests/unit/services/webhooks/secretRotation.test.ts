import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  setLatestSecretVersion,
  getLatestSecretVersion,
  reportSubscriptionVersion,
  removeSubscription,
  isSubscriptionCurrent,
  getAdoptionSnapshot,
  emitRotationStatus,
  reset,
} from '../../../../src/services/webhooks/secretRotation.js'
import { webhookSecretRotationStatus } from '../../../../src/metrics.js'

describe('secretRotation', () => {
  beforeEach(() => {
    reset()
    vi.restoreAllMocks()
  })

  describe('setLatestSecretVersion / getLatestSecretVersion', () => {
    it('starts at 0 and accepts a monotonically increasing version', () => {
      expect(getLatestSecretVersion()).toBe(0)
      setLatestSecretVersion(3)
      expect(getLatestSecretVersion()).toBe(3)
    })

    it('ignores non-monotonic (lower) version numbers', () => {
      setLatestSecretVersion(5)
      setLatestSecretVersion(3) // lower — should be ignored
      expect(getLatestSecretVersion()).toBe(5)
    })

    it('accepts equal version numbers (no-op)', () => {
      setLatestSecretVersion(4)
      setLatestSecretVersion(4)
      expect(getLatestSecretVersion()).toBe(4)
    })
  })

  describe('reportSubscriptionVersion / isSubscriptionCurrent', () => {
    it('returns undefined for a subscription that has never reported', () => {
      expect(isSubscriptionCurrent('never-reported')).toBeUndefined()
    })

    it('treats a subscription as current when latest version is 0 (none published)', () => {
      reportSubscriptionVersion('sub-1', 'biz-1', 1)
      expect(isSubscriptionCurrent('sub-1')).toBe(true)
    })

    it('reports lagging when subscription version < latest version', () => {
      setLatestSecretVersion(10)
      reportSubscriptionVersion('sub-1', 'biz-1', 5)
      expect(isSubscriptionCurrent('sub-1')).toBe(false)
    })

    it('reports current when subscription version >= latest version', () => {
      setLatestSecretVersion(10)
      reportSubscriptionVersion('sub-1', 'biz-1', 10)
      expect(isSubscriptionCurrent('sub-1')).toBe(true)
    })

    it('reports current when subscription version exceeds latest version (advanced)', () => {
      setLatestSecretVersion(10)
      reportSubscriptionVersion('sub-1', 'biz-1', 12)
      expect(isSubscriptionCurrent('sub-1')).toBe(true)
    })

    it('handles multiple subscriptions independently', () => {
      setLatestSecretVersion(7)
      reportSubscriptionVersion('sub-a', 'biz-1', 7)
      reportSubscriptionVersion('sub-b', 'biz-2', 3)
      reportSubscriptionVersion('sub-c', 'biz-3', 7)

      expect(isSubscriptionCurrent('sub-a')).toBe(true)
      expect(isSubscriptionCurrent('sub-b')).toBe(false)
      expect(isSubscriptionCurrent('sub-c')).toBe(true)
    })
  })

  describe('removeSubscription', () => {
    it('removes a subscription from tracking', () => {
      reportSubscriptionVersion('sub-1', 'biz-1', 5)
      expect(isSubscriptionCurrent('sub-1')).toBe(true)

      removeSubscription('sub-1')
      expect(isSubscriptionCurrent('sub-1')).toBeUndefined()
    })

    it('no-ops when removing a non-existent subscription', () => {
      expect(() => removeSubscription('ghost')).not.toThrow()
    })
  })

  describe('getAdoptionSnapshot', () => {
    it('returns an empty array when no subscriptions are tracked', () => {
      expect(getAdoptionSnapshot()).toEqual([])
    })

    it('returns snapshot with current/lagging status for each subscription', () => {
      setLatestSecretVersion(5)
      reportSubscriptionVersion('sub-1', 'biz-1', 5)
      reportSubscriptionVersion('sub-2', 'biz-2', 2)

      const snapshot = getAdoptionSnapshot()
      expect(snapshot).toHaveLength(2)

      const sub1 = snapshot.find((s) => s.subscriptionId === 'sub-1')
      expect(sub1).toBeDefined()
      expect(sub1!.isCurrent).toBe(true)
      expect(sub1!.currentVersion).toBe(5)

      const sub2 = snapshot.find((s) => s.subscriptionId === 'sub-2')
      expect(sub2).toBeDefined()
      expect(sub2!.isCurrent).toBe(false)
      expect(sub2!.currentVersion).toBe(2)
    })
  })

  describe('emitRotationStatus', () => {
    it('resets and emits the gauge for all tracked subscriptions', () => {
      const setSpy = vi.spyOn(webhookSecretRotationStatus, 'set')
      const resetSpy = vi.spyOn(webhookSecretRotationStatus, 'reset')

      setLatestSecretVersion(3)
      reportSubscriptionVersion('sub-1', 'biz-1', 3)
      reportSubscriptionVersion('sub-2', 'biz-2', 1)

      emitRotationStatus()

      // reset + 2 subscriptions × 2 status labels = 5 calls
      expect(resetSpy).toHaveBeenCalledTimes(1)
      expect(setSpy).toHaveBeenCalledTimes(4)

      // sub-1 should be current
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: 'sub-1', business_id: 'biz-1', status: 'current' },
        1,
      )
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: 'sub-1', business_id: 'biz-1', status: 'lagging' },
        0,
      )

      // sub-2 should be lagging
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: 'sub-2', business_id: 'biz-2', status: 'current' },
        0,
      )
      expect(setSpy).toHaveBeenCalledWith(
        { subscription_id: 'sub-2', business_id: 'biz-2', status: 'lagging' },
        1,
      )
    })

    it('handles empty subscription list without error', () => {
      expect(() => emitRotationStatus()).not.toThrow()
    })
  })

  describe('reset', () => {
    it('clears all state and gauge', () => {
      const resetSpy = vi.spyOn(webhookSecretRotationStatus, 'reset')

      setLatestSecretVersion(10)
      reportSubscriptionVersion('sub-1', 'biz-1', 10)
      expect(getLatestSecretVersion()).toBe(10)
      expect(isSubscriptionCurrent('sub-1')).toBe(true)

      reset()

      expect(getLatestSecretVersion()).toBe(0)
      expect(isSubscriptionCurrent('sub-1')).toBeUndefined()
      expect(resetSpy).toHaveBeenCalledTimes(1)
    })
  })
})
