import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  fetchRazorpayRevenue,
  IntegrationNotConnectedError,
  InvalidPaymentAmountError,
  convertMinorToMajor,
  getCurrencyExponent,
} from '../razorpayFetch.js';
import * as integrationRepository from '../../../repositories/integration.js';

const START_DATE = '2024-03-01T00:00:00Z';
const END_DATE = '2024-03-31T23:59:59Z';

function createRazorpayIntegration(businessId: string, apiKeyId: string, apiKeySecret: string) {
  return integrationRepository.create({
    provider: 'razorpay',
    userId: `user_${businessId}`,
    businessId,
    externalId: apiKeyId,
    token: { apiKeyId, apiKeySecret },
    metadata: {},
  });
}

function jsonResponse(items: unknown[]) {
  return new Response(JSON.stringify({ items }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('razorpayFetch', () => {
  const originalFetch = global.fetch;
  const originalEnv = process.env;

  beforeEach(() => {
    vi.restoreAllMocks();
    process.env = { ...originalEnv };
    delete process.env.RAZORPAY_KEY_ID;
    delete process.env.RAZORPAY_KEY_SECRET;
    integrationRepository.clearAll();
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

      createRazorpayIntegration('biz_1', 'rzp_key_biz_1', 'rzp_secret_biz_1');
      createRazorpayIntegration('biz_2', 'rzp_key_biz_2', 'rzp_secret_biz_2');

      const fetchSpy = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse([])));
      global.fetch = fetchSpy;

      await fetchRazorpayRevenue('biz_1', START_DATE, END_DATE);
      const firstCallAuth = fetchSpy.mock.calls[0][1]?.headers?.Authorization;
      const expectedBiz1Auth = `Basic ${Buffer.from('rzp_key_biz_1:rzp_secret_biz_1').toString('base64')}`;
      expect(firstCallAuth).toBe(expectedBiz1Auth);

      await fetchRazorpayRevenue(START_DATE, END_DATE, 'biz_2');
      const secondCallAuth = fetchSpy.mock.calls[1][1]?.headers?.Authorization;
      const expectedBiz2Auth = `Basic ${Buffer.from('rzp_key_biz_2:rzp_secret_biz_2').toString('base64')}`;
      expect(secondCallAuth).toBe(expectedBiz2Auth);

      expect(firstCallAuth).not.toBe(secondCallAuth);
      const platformAuth = `Basic ${Buffer.from('PLATFORM_KEY_SHOULD_NEVER_BE_USED:PLATFORM_SECRET_SHOULD_NEVER_BE_USED').toString('base64')}`;
      expect(firstCallAuth).not.toBe(platformAuth);
      expect(secondCallAuth).not.toBe(platformAuth);
    });

    it('throws IntegrationNotConnectedError when business has no connected credentials', async () => {
      process.env.RAZORPAY_KEY_ID = 'PLATFORM_KEY';
      process.env.RAZORPAY_KEY_SECRET = 'PLATFORM_SECRET';

      await expect(
        fetchRazorpayRevenue(START_DATE, END_DATE, 'unconnected_biz')
      ).rejects.toThrow(IntegrationNotConnectedError);
      await expect(
        fetchRazorpayRevenue('unconnected_biz', START_DATE, END_DATE)
      ).rejects.toThrow(IntegrationNotConnectedError);
      expect(global.fetch).toBe(originalFetch);
    });

    it('falls back to env credentials for legacy callers with no business ID', async () => {
      process.env.RAZORPAY_KEY_ID = 'legacy_key';
      process.env.RAZORPAY_KEY_SECRET = 'legacy_secret';

      const fetchSpy = vi.fn().mockResolvedValue(
        jsonResponse([
          {
            id: 'pay_legacy',
            status: 'captured',
            amount: 1000,
            currency: 'INR',
            created_at: 1710000000,
          },
        ])
      );
      global.fetch = fetchSpy;

      const entries = await fetchRazorpayRevenue(START_DATE, END_DATE);

      expect(fetchSpy.mock.calls[0][1]?.headers?.Authorization).toBe(
        `Basic ${Buffer.from('legacy_key:legacy_secret').toString('base64')}`
      );
      expect(entries).toHaveLength(1);
      expect(entries[0].amount).toBe(10);
    });

    it('resolves business credentials when options precede the business ID', async () => {
      createRazorpayIntegration('biz_1', 'key_1', 'sec_1');
      const fetchSpy = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse([])));
      global.fetch = fetchSpy;

      await fetchRazorpayRevenue(START_DATE, END_DATE, { pageSize: 7 }, 'biz_1');

      expect(fetchSpy.mock.calls[0][1]?.headers?.Authorization).toBe(
        `Basic ${Buffer.from('key_1:sec_1').toString('base64')}`
      );
      expect(new URL(fetchSpy.mock.calls[0][0] as string).searchParams.get('count')).toBe('7');
    });

    it('throws when no business credentials and no env credentials are available', async () => {
      await expect(fetchRazorpayRevenue(START_DATE, END_DATE)).rejects.toThrow(
        'Missing RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET environment variables'
      );
    });
  });

  describe('payment calculations and currency handling', () => {
    beforeEach(() => {
      createRazorpayIntegration('biz_1', 'key_1', 'sec_1');
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

      global.fetch = vi.fn().mockResolvedValue(jsonResponse(mockItems));

      const entries = await fetchRazorpayRevenue('biz_1', START_DATE, END_DATE);
      expect(entries).toHaveLength(3);
      expect(entries[0].amount).toBe(500);
      expect(entries[0].currency).toBe('JPY');
      expect(entries[0].date).toBe('2024-03-09T16:00:00.000Z');
      expect(entries[1].amount).toBe(1.234);
      expect(entries[1].currency).toBe('KWD');
      expect(entries[2].amount).toBe(100.5);
      expect(entries[2].currency).toBe('INR');
    });

    it('nets out amount_refunded: a captured payment of 10000 with amount_refunded: 2500 (INR) contributes 75.00', async () => {
      global.fetch = vi.fn().mockResolvedValue(
        jsonResponse([
          {
            id: 'pay_refunded',
            status: 'captured',
            amount: 10000,
            amount_refunded: 2500,
            currency: 'INR',
            created_at: 1710000000,
          },
        ])
      );

      const entries = await fetchRazorpayRevenue('biz_1', START_DATE, END_DATE);
      expect(entries).toHaveLength(1);
      expect(entries[0].amount).toBe(75.0);
    });

    it('rejects non-numeric amount like "abc" with InvalidPaymentAmountError, never silently 0', async () => {
      global.fetch = vi.fn().mockResolvedValue(
        jsonResponse([
          {
            id: 'pay_bad',
            status: 'captured',
            amount: 'abc',
            currency: 'INR',
            created_at: 1710000000,
          },
        ])
      );

      await expect(
        fetchRazorpayRevenue('biz_1', START_DATE, END_DATE)
      ).rejects.toThrow(InvalidPaymentAmountError);
    });

    it('rejects non-numeric amount_refunded with InvalidPaymentAmountError', async () => {
      global.fetch = vi.fn().mockResolvedValue(
        jsonResponse([
          {
            id: 'pay_bad_refund',
            status: 'captured',
            amount: 1000,
            amount_refunded: 'invalid',
            currency: 'INR',
            created_at: 1710000000,
          },
        ])
      );

      await expect(
        fetchRazorpayRevenue('biz_1', START_DATE, END_DATE)
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
        {
          id: 'pay_captured',
          status: 'captured',
          amount: 5000,
          currency: 'INR',
          created_at: 1710000000,
        },
      ];

      global.fetch = vi.fn().mockResolvedValue(jsonResponse(mockItems));

      const entries = await fetchRazorpayRevenue('biz_1', START_DATE, END_DATE);
      expect(entries).toHaveLength(1);
      expect(entries[0].id).toBe('pay_captured');
    });
  });

  describe('pagination and timeout controls', () => {
    beforeEach(() => {
      createRazorpayIntegration('biz_1', 'key_1', 'sec_1');
    });

    it('terminates loop when maxPages is reached', async () => {
      let callCount = 0;
      global.fetch = vi.fn().mockImplementation(() => {
        callCount++;
        return Promise.resolve(
          jsonResponse([
            { id: `p_${callCount}_1`, status: 'captured', amount: 100, currency: 'USD', created_at: 1710000000 },
            { id: `p_${callCount}_2`, status: 'captured', amount: 200, currency: 'USD', created_at: 1710000000 },
          ])
        );
      });

      const entries = await fetchRazorpayRevenue('biz_1', START_DATE, END_DATE, {
        pageSize: 2,
        maxPages: 3,
      });

      expect(callCount).toBe(3);
      expect(entries).toHaveLength(6);
    });

    it('uses the canonical date-first signature with business credentials and options', async () => {
      const fetchSpy = vi.fn().mockResolvedValue(jsonResponse([]));
      global.fetch = fetchSpy;

      await fetchRazorpayRevenue(START_DATE, END_DATE, 'biz_1', {
        pageSize: 25,
        maxPages: 2,
      });

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(fetchSpy.mock.calls[0][1]?.headers?.Authorization).toBe(
        `Basic ${Buffer.from('key_1:sec_1').toString('base64')}`
      );
      const url = new URL(fetchSpy.mock.calls[0][0] as string);
      expect(url.searchParams.get('count')).toBe('25');
      expect(url.searchParams.get('skip')).toBe('0');
      expect(url.searchParams.get('from')).toBe(String(Math.floor(Date.parse(START_DATE) / 1000)));
      expect(url.searchParams.get('to')).toBe(String(Math.floor(Date.parse(END_DATE) / 1000)));
    });

    it('advances skip between pages and stops on a short page', async () => {
      const fetchSpy = vi.fn()
        .mockResolvedValueOnce(jsonResponse([{ id: 'p1', status: 'captured', amount: 100, currency: 'USD' }]))
        .mockResolvedValueOnce(jsonResponse([]));
      global.fetch = fetchSpy;

      await fetchRazorpayRevenue('biz_1', START_DATE, END_DATE, { pageSize: 1, maxPages: 5 });

      expect(fetchSpy).toHaveBeenCalledTimes(2);
      expect(new URL(fetchSpy.mock.calls[0][0] as string).searchParams.get('skip')).toBe('0');
      expect(new URL(fetchSpy.mock.calls[1][0] as string).searchParams.get('skip')).toBe('1');
    });

    it('passes abort signal with per-request timeout', async () => {
      let passedSignal: AbortSignal | undefined;
      global.fetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
        passedSignal = init?.signal as AbortSignal;
        return Promise.resolve(jsonResponse([]));
      });

      await fetchRazorpayRevenue('biz_1', START_DATE, END_DATE, {
        timeoutMs: 5000,
      });

      expect(passedSignal).toBeDefined();
      expect(passedSignal).toBeInstanceOf(AbortSignal);
      expect(passedSignal?.aborted).toBe(false);
    });
  });
});
