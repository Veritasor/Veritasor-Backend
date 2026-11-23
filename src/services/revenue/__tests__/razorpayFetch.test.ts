import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  fetchRazorpayRevenue,
  IntegrationNotConnectedError,
  InvalidPaymentAmountError,
  convertMinorToMajor,
  getCurrencyExponent,
} from '../razorpayFetch.js';
import { integrationRepository } from '../../../repositories/integrations.js';

describe('razorpayFetch', () => {
  const originalFetch = global.fetch;
  const originalEnv = process.env;

  beforeEach(() => {
    vi.restoreAllMocks();
    process.env = { ...originalEnv };
    // Clear integration repository store
    const store = (integrationRepository as any).store;
    if (Array.isArray(store)) {
      store.length = 0;
    }
  });

  afterEach(() => {
    global.fetch = originalFetch;
    process.env = originalEnv;
  });

  describe('currency exponent and minor unit conversion', () => {
    it('handles JPY (0 decimals)', () => {
      expect(getCurrencyExponent('JPY')).toBe(0);
      expect(convertMinorToMajor(500, 'JPY')).toBe(500);
    });

    it('handles KWD, BHD, OMR (3 decimals)', () => {
      expect(getCurrencyExponent('KWD')).toBe(3);
      expect(convertMinorToMajor(1234, 'KWD')).toBe(1.234);
      expect(getCurrencyExponent('BHD')).toBe(3);
      expect(convertMinorToMajor(3500, 'BHD')).toBe(3.5);
      expect(getCurrencyExponent('OMR')).toBe(3);
      expect(convertMinorToMajor(5000, 'OMR')).toBe(5);
    });

    it('handles standard 2-decimal currencies like INR and USD', () => {
      expect(getCurrencyExponent('INR')).toBe(2);
      expect(convertMinorToMajor(10050, 'INR')).toBe(100.5);
      expect(getCurrencyExponent('USD')).toBe(2);
      expect(convertMinorToMajor(2500, 'USD')).toBe(25);
    });
  });

  describe('credential isolation & fail-closed tenant scoping', () => {
    it('uses business credentials from repository and never uses platform env keys', async () => {
      process.env.RAZORPAY_KEY_ID = 'PLATFORM_KEY_SHOULD_NEVER_BE_USED';
      process.env.RAZORPAY_KEY_SECRET = 'PLATFORM_SECRET_SHOULD_NEVER_BE_USED';

      integrationRepository.create({
        provider: 'razorpay',
        userId: 'user_biz1',
        businessId: 'biz_1',
        meta: {
          apiKeyId: 'rzp_key_biz_1',
          apiKeySecret: 'rzp_secret_biz_1',
        },
      });

      integrationRepository.create({
        provider: 'razorpay',
        userId: 'user_biz2',
        businessId: 'biz_2',
        meta: {
          apiKeyId: 'rzp_key_biz_2',
          apiKeySecret: 'rzp_secret_biz_2',
        },
      });

      const fetchSpy = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
        return Promise.resolve(
          new Response(JSON.stringify({ items: [] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        );
      });
      global.fetch = fetchSpy;

      await fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z');
      const firstCallAuth = fetchSpy.mock.calls[0][1]?.headers?.Authorization;
      const expectedBiz1Auth = `Basic ${Buffer.from('rzp_key_biz_1:rzp_secret_biz_1').toString('base64')}`;
      expect(firstCallAuth).toBe(expectedBiz1Auth);

      await fetchRazorpayRevenue('biz_2', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z');
      const secondCallAuth = fetchSpy.mock.calls[1][1]?.headers?.Authorization;
      const expectedBiz2Auth = `Basic ${Buffer.from('rzp_key_biz_2:rzp_secret_biz_2').toString('base64')}`;
      expect(secondCallAuth).toBe(expectedBiz2Auth);

      // Verify they are different and neither matches platform env keys
      expect(firstCallAuth).not.toBe(secondCallAuth);
      const platformAuth = `Basic ${Buffer.from('PLATFORM_KEY_SHOULD_NEVER_BE_USED:PLATFORM_SECRET_SHOULD_NEVER_BE_USED').toString('base64')}`;
      expect(firstCallAuth).not.toBe(platformAuth);
      expect(secondCallAuth).not.toBe(platformAuth);
    });

    it('throws IntegrationNotConnectedError when business has no connected credentials', async () => {
      process.env.RAZORPAY_KEY_ID = 'PLATFORM_KEY';
      process.env.RAZORPAY_KEY_SECRET = 'PLATFORM_SECRET';

      await expect(
        fetchRazorpayRevenue('unconnected_biz', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z')
      ).rejects.toThrow(IntegrationNotConnectedError);
    });
  });

  describe('payment calculations and currency handling', () => {
    beforeEach(() => {
      integrationRepository.create({
        provider: 'razorpay',
        userId: 'user_1',
        businessId: 'biz_1',
        meta: {
          apiKeyId: 'key_1',
          apiKeySecret: 'sec_1',
        },
      });
    });

    it('calculates JPY amount: 500 gives 500, KWD amount: 1234 gives 1.234, INR amount: 10050 gives 100.5', async () => {
      const mockItems = [
        {
          id: 'pay_jpy',
          status: 'captured',
          amount: 500,
          currency: 'JPY',
          created_at: 1710000000,
        },
        {
          id: 'pay_kwd',
          status: 'captured',
          amount: 1234,
          currency: 'KWD',
          created_at: 1710000001,
        },
        {
          id: 'pay_inr',
          status: 'captured',
          amount: 10050,
          currency: 'INR',
          created_at: 1710000002,
        },
      ];

      global.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ items: mockItems }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const entries = await fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z');
      expect(entries).toHaveLength(3);
      expect(entries[0].amount).toBe(500);
      expect(entries[0].currency).toBe('JPY');
      expect(entries[1].amount).toBe(1.234);
      expect(entries[1].currency).toBe('KWD');
      expect(entries[2].amount).toBe(100.5);
      expect(entries[2].currency).toBe('INR');
    });

    it('nets out amount_refunded: a captured payment of 10000 with amount_refunded: 2500 (INR) contributes 75.00', async () => {
      const mockItems = [
        {
          id: 'pay_refunded',
          status: 'captured',
          amount: 10000,
          amount_refunded: 2500,
          currency: 'INR',
          created_at: 1710000000,
        },
      ];

      global.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ items: mockItems }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const entries = await fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z');
      expect(entries).toHaveLength(1);
      expect(entries[0].amount).toBe(75.0);
    });

    it('rejects non-numeric amount like "abc" with InvalidPaymentAmountError, never silently 0', async () => {
      const mockItems = [
        {
          id: 'pay_bad',
          status: 'captured',
          amount: 'abc',
          currency: 'INR',
          created_at: 1710000000,
        },
      ];

      global.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ items: mockItems }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      await expect(
        fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z')
      ).rejects.toThrow(InvalidPaymentAmountError);
    });

    it('rejects non-numeric amount_refunded with InvalidPaymentAmountError', async () => {
      const mockItems = [
        {
          id: 'pay_bad_refund',
          status: 'captured',
          amount: 1000,
          amount_refunded: 'invalid',
          currency: 'INR',
          created_at: 1710000000,
        },
      ];

      global.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ items: mockItems }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      await expect(
        fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z')
      ).rejects.toThrow(InvalidPaymentAmountError);
    });

    it('ignores non-captured payments', async () => {
      const mockItems = [
        {
          id: 'pay_failed',
          status: 'failed',
          amount: 5000,
          currency: 'INR',
          created_at: 1710000000,
        },
        {
          id: 'pay_authorized',
          status: 'authorized',
          amount: 5000,
          currency: 'INR',
          created_at: 1710000000,
        },
      ];

      global.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ items: mockItems }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const entries = await fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z');
      expect(entries).toHaveLength(0);
    });
  });

  describe('pagination and timeout controls', () => {
    beforeEach(() => {
      integrationRepository.create({
        provider: 'razorpay',
        userId: 'user_1',
        businessId: 'biz_1',
        meta: {
          apiKeyId: 'key_1',
          apiKeySecret: 'sec_1',
        },
      });
    });

    it('terminates loop when maxPages is reached', async () => {
      // Create a mock that returns a full page (pageSize = 2) infinitely
      let callCount = 0;
      global.fetch = vi.fn().mockImplementation(() => {
        callCount++;
        return Promise.resolve(
          new Response(
            JSON.stringify({
              items: [
                { id: `p_${callCount}_1`, status: 'captured', amount: 100, currency: 'USD', created_at: 1710000000 },
                { id: `p_${callCount}_2`, status: 'captured', amount: 200, currency: 'USD', created_at: 1710000000 },
              ],
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          )
        );
      });

      const entries = await fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z', {
        pageSize: 2,
        maxPages: 3,
      });

      expect(callCount).toBe(3);
      expect(entries).toHaveLength(6);
    });

    it('passes abort signal with per-request timeout', async () => {
      let passedSignal: AbortSignal | undefined;
      global.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
        passedSignal = init?.signal as AbortSignal;
        return Promise.resolve(
          new Response(JSON.stringify({ items: [] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        );
      });

      await fetchRazorpayRevenue('biz_1', '2024-03-01T00:00:00Z', '2024-03-31T23:59:59Z', {
        timeoutMs: 5000,
      });

      expect(passedSignal).toBeDefined();
    });
  });
});
