import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchRazorpayRevenue } from '../../../../src/services/revenue/razorpayFetch.js';

const startDate = '2025-01-01T00:00:00.000Z';
const endDate = '2025-01-02T00:00:00.000Z';

function paymentResponse(items: unknown[], status = 200): Response {
  return new Response(JSON.stringify({ items }), { status });
}

describe('fetchRazorpayRevenue', () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubEnv('RAZORPAY_KEY_ID', 'test-key');
    vi.stubEnv('RAZORPAY_KEY_SECRET', 'test-secret');
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it.each([
    ['RAZORPAY_KEY_ID', undefined],
    ['RAZORPAY_KEY_ID', ''],
    ['RAZORPAY_KEY_SECRET', undefined],
    ['RAZORPAY_KEY_SECRET', ''],
  ] as const)(
    'rejects before making a request when %s is %s',
    async (name, value) => {
      vi.stubEnv(name, value);

      await expect(fetchRazorpayRevenue(startDate, endDate)).rejects.toThrowError(
        new Error('Missing RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET environment variables'),
      );
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it('rejects without a request when both credentials are missing', async () => {
    vi.stubEnv('RAZORPAY_KEY_ID', undefined);
    vi.stubEnv('RAZORPAY_KEY_SECRET', undefined);

    await expect(fetchRazorpayRevenue(startDate, endDate)).rejects.toThrowError(
      new Error('Missing RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET environment variables'),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([401, 429, 500])(
    'rejects with the upstream status and response body for HTTP %s',
    async (status) => {
      fetchMock.mockResolvedValueOnce(new Response('upstream failure', { status }));

      await expect(fetchRazorpayRevenue(startDate, endDate)).rejects.toThrowError(
        new Error(`Razorpay API error: ${status} upstream failure`),
      );
      expect(fetchMock).toHaveBeenCalledTimes(1);
    },
  );

  it('preserves the error contract when the upstream error body is empty', async () => {
    fetchMock.mockResolvedValueOnce(new Response('', { status: 503 }));

    await expect(fetchRazorpayRevenue(startDate, endDate)).rejects.toThrowError(
      new Error('Razorpay API error: 503 '),
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('propagates a network rejection without silently returning empty revenue', async () => {
    const failure = new TypeError('connection unavailable');
    fetchMock.mockRejectedValueOnce(failure);

    await expect(fetchRazorpayRevenue(startDate, endDate)).rejects.toBe(failure);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns captured payments in major units and excludes other statuses', async () => {
    const captured = {
      id: 'pay_1', amount: 12345, currency: 'INR', created_at: 1735689600, status: 'captured',
    };
    fetchMock.mockResolvedValueOnce(paymentResponse([
      captured,
      { id: 'pay_2', amount: 500, currency: 'INR', created_at: 1735689600, status: 'authorized' },
    ]));

    await expect(fetchRazorpayRevenue(startDate, endDate)).resolves.toEqual([{
      id: 'pay_1', amount: 123.45, currency: 'INR', date: startDate,
      source: 'razorpay', raw: captured,
    }]);
    const [requestUrl, options] = fetchMock.mock.calls[0];
    const url = new URL(String(requestUrl));
    expect(url.origin + url.pathname).toBe('https://api.razorpay.com/v1/payments');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      from: '1735689600', to: '1735776000', count: '100', skip: '0',
    });
    expect(options?.headers).toEqual({
      Authorization: `Basic ${Buffer.from('test-key:test-secret').toString('base64')}`,
      Accept: 'application/json',
    });
  });

  it('returns an empty array for an empty page', async () => {
    fetchMock.mockResolvedValueOnce(paymentResponse([]));

    await expect(fetchRazorpayRevenue(startDate, endDate)).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['missing', {}],
    ['null', { items: null }],
    ['object', { items: {} }],
    ['string', { items: 'not an array' }],
  ])('treats %s items as an empty final page', async (_name, body) => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(body), { status: 200 }));

    await expect(fetchRazorpayRevenue(startDate, endDate)).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed JSON instead of disguising it as empty revenue', async () => {
    fetchMock.mockResolvedValueOnce(new Response('{invalid json', { status: 200 }));

    await expect(fetchRazorpayRevenue(startDate, endDate)).rejects.toMatchObject({ name: 'SyntaxError' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('stops at 99 items even when every payment is uncaptured', async () => {
    const items = Array.from({ length: 99 }, (_, index) => ({
      id: `pay_${index}`, created_at: 1735689600, status: 'authorized',
    }));
    fetchMock.mockResolvedValueOnce(paymentResponse(items));

    await expect(fetchRazorpayRevenue(startDate, endDate)).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('requests the next page when the first page has exactly 100 items', async () => {
    const authorized = Array.from({ length: 100 }, (_, index) => ({
      id: `pay_${index}`, created_at: 1735689600, status: 'authorized',
    }));
    const captured = {
      id: 'pay_100', amount: 0, created_at: 1735689600, status: 'captured',
    };
    fetchMock
      .mockResolvedValueOnce(paymentResponse(authorized))
      .mockResolvedValueOnce(paymentResponse([captured]));

    await expect(fetchRazorpayRevenue(startDate, endDate)).resolves.toEqual([{
      id: 'pay_100', amount: 0, currency: 'INR', date: startDate,
      source: 'razorpay', raw: captured,
    }]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(new URL(String(fetchMock.mock.calls[1][0])).searchParams.get('skip')).toBe('100');
  });

  it('continues through full pages and terminates on an empty page', async () => {
    const items = Array.from({ length: 100 }, (_, index) => ({
      id: `pay_${index}`, amount: 100, currency: 'USD',
      created_at: 1735689600, status: 'captured',
    }));
    fetchMock
      .mockResolvedValueOnce(paymentResponse(items))
      .mockResolvedValueOnce(paymentResponse(items.map((item) => ({ ...item, id: `${item.id}_next` }))))
      .mockResolvedValueOnce(paymentResponse([]));

    const entries = await fetchRazorpayRevenue(startDate, endDate);
    expect(entries).toHaveLength(200);
    expect(entries[0]).toEqual({
      id: 'pay_0', amount: 1, currency: 'USD', date: startDate,
      source: 'razorpay', raw: items[0],
    });
    expect(entries[199].id).toBe('pay_99_next');
    expect(fetchMock.mock.calls.map(([url]) => new URL(String(url)).searchParams.get('skip')))
      .toEqual(['0', '100', '200']);
  });

  it('rejects a later-page failure without returning partial revenue, then retries from page zero', async () => {
    const items = Array.from({ length: 100 }, (_, index) => ({
      id: `pay_${index}`, amount: 100, currency: 'INR',
      created_at: 1735689600, status: 'captured',
    }));
    fetchMock
      .mockResolvedValueOnce(paymentResponse(items))
      .mockResolvedValueOnce(new Response('service unavailable', { status: 503 }))
      .mockResolvedValueOnce(paymentResponse([items[0]]));

    await expect(fetchRazorpayRevenue(startDate, endDate)).rejects.toThrowError(
      new Error('Razorpay API error: 503 service unavailable'),
    );
    await expect(fetchRazorpayRevenue(startDate, endDate)).resolves.toEqual([{
      id: 'pay_0', amount: 1, currency: 'INR', date: startDate,
      source: 'razorpay', raw: items[0],
    }]);
    expect(fetchMock.mock.calls.map(([url]) => new URL(String(url)).searchParams.get('skip')))
      .toEqual(['0', '100', '0']);
  });

  it('uses a deterministic clock for a captured payment without a timestamp', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(startDate));
    const captured = { id: 'pay_missing_fields', status: 'captured' };
    fetchMock.mockResolvedValueOnce(paymentResponse([captured]));

    await expect(fetchRazorpayRevenue(startDate, endDate)).resolves.toEqual([{
      id: 'pay_missing_fields', amount: NaN, currency: 'INR', date: startDate,
      source: 'razorpay', raw: captured,
    }]);
  });

  it('floors fractional seconds and keeps equal date bounds equal in the request', async () => {
    fetchMock.mockResolvedValueOnce(paymentResponse([]));
    const date = '2025-01-01T00:00:00.999Z';

    await expect(fetchRazorpayRevenue(date, date)).resolves.toEqual([]);
    const url = new URL(String(fetchMock.mock.calls[0][0]));
    expect(url.searchParams.get('from')).toBe('1735689600');
    expect(url.searchParams.get('to')).toBe('1735689600');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
