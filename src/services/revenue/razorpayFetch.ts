import { getRazorpayCredentials } from '../../repositories/integration.js';

export type RevenueEntry = {
  id: string;
  amount: number; // major units (e.g. INR -> rupees)
  currency: string;
  date: string; // ISO date
  source: 'razorpay';
  raw?: any;
};

export class IntegrationNotConnectedError extends Error {
  public code = 'INTEGRATION_NOT_CONNECTED';
  constructor(message = 'Integration not connected') {
    super(message);
    this.name = 'IntegrationNotConnectedError';
  }
}

export class InvalidPaymentAmountError extends Error {
  public code = 'INVALID_PAYMENT_AMOUNT';
  constructor(message = 'Invalid payment amount') {
    super(message);
    this.name = 'InvalidPaymentAmountError';
  }
}

/**
 * Fetch revenue entries from Razorpay between two ISO dates (inclusive).
 * When a business ID is supplied, credentials are loaded from its connected
 * Razorpay integration. Environment credentials remain available to legacy callers.
 */
export async function fetchRazorpayRevenue(
  businessId: string,
  startDate: string,
  endDate: string,
  businessId?: string,
): Promise<RevenueEntry[]> {
  const businessCredentials = businessId
    ? await getRazorpayCredentials(businessId)
    : null;
  if (businessId && !businessCredentials) {
    throw new Error(`No Razorpay integration credentials found for business ${businessId}`);
  }

  const key = businessCredentials?.apiKeyId ?? process.env.RAZORPAY_KEY_ID;
  const secret = businessCredentials?.apiKeySecret ?? process.env.RAZORPAY_KEY_SECRET;
  if (!key || !secret) {
    throw new Error('Missing RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET environment variables');
  }

  const key = integration.meta.apiKeyId;
  const secret = integration.meta.apiKeySecret;

  const from = Math.floor(new Date(startDate).getTime() / 1000);
  const to = Math.floor(new Date(endDate).getTime() / 1000);

  const auth = Buffer.from(`${key}:${secret}`).toString('base64');
  const results: RevenueEntry[] = [];

  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let skip = 0;
  let pageCount = 0;

  while (pageCount < maxPages) {
    pageCount++;
    const url = new URL('https://api.razorpay.com/v1/payments');
    url.searchParams.set('from', String(from));
    url.searchParams.set('to', String(to));
    url.searchParams.set('count', String(pageSize));
    url.searchParams.set('skip', String(skip));

    const resp = await fetch(url.toString(), {
      headers: {
        Authorization: `Basic ${auth}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Razorpay API error: ${resp.status} ${text}`);
    }

    const body = await resp.json();
    const items = Array.isArray(body.items) ? body.items : [];

    for (const it of items) {
      // Validate payment amount is a numeric value
      if (typeof it.amount !== 'number' || !Number.isFinite(it.amount)) {
        throw new InvalidPaymentAmountError(
          `Invalid or non-numeric payment amount for item ${it.id}: ${JSON.stringify(it.amount)}`
        );
      }

      // Only include captured payments as realized revenue
      if (it.status !== 'captured') continue;

      const currency = (it.currency || 'INR').toUpperCase();

      // Net out amount_refunded if present
      let refundedMinor = 0;
      if (it.amount_refunded !== undefined && it.amount_refunded !== null) {
        if (typeof it.amount_refunded !== 'number' || !Number.isFinite(it.amount_refunded)) {
          throw new InvalidPaymentAmountError(
            `Invalid or non-numeric refund amount for item ${it.id}: ${JSON.stringify(it.amount_refunded)}`
          );
        }
        refundedMinor = it.amount_refunded;
      }

      const netMinor = it.amount - refundedMinor;
      const amount = convertMinorToMajor(netMinor, currency);

      const createdAt = typeof it.created_at === 'number' ? it.created_at : it.created_at;
      const date = createdAt ? new Date(createdAt * 1000).toISOString() : new Date().toISOString();

      results.push({
        id: it.id,
        amount,
        currency,
        date,
        source: 'razorpay',
        raw: it,
      });
    }

    if (items.length < pageSize) break;
    skip += pageSize;
  }

  return results;
}

export default fetchRazorpayRevenue;
