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

const CURRENCY_EXPONENTS: Record<string, number> = {
  JPY: 0,
  KRW: 0,
  VND: 0,
  CLP: 0,
  PYG: 0,
  UGX: 0,
  RWF: 0,
  KWD: 3,
  BHD: 3,
  OMR: 3,
  JOD: 3,
  TND: 3,
  LYD: 3,
  IQD: 3,
};

export function getCurrencyExponent(currency: string): number {
  const upper = currency?.toUpperCase();
  if (upper && Object.prototype.hasOwnProperty.call(CURRENCY_EXPONENTS, upper)) {
    return CURRENCY_EXPONENTS[upper];
  }
  return 2;
}

export function convertMinorToMajor(amountMinor: number, currency: string): number {
  const exponent = getCurrencyExponent(currency);
  const factor = Math.pow(10, exponent);
  return amountMinor / factor;
}

export interface FetchRazorpayRevenueOptions {
  timeoutMs?: number;
  maxPages?: number;
  pageSize?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_PAGES = 50;
const DEFAULT_PAGE_SIZE = 100;

type RazorpayCredentials = { apiKeyId: string; apiKeySecret: string };

function isIsoDate(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}(?:[T\s]|$)/.test(value) && !Number.isNaN(Date.parse(value));
}

function isOptions(value: unknown): value is FetchRazorpayRevenueOptions {
  return typeof value === 'object' && value !== null;
}

async function resolveCredentials(businessId?: string): Promise<RazorpayCredentials> {
  if (businessId) {
    const credentials = await getRazorpayCredentials(businessId);
    if (!credentials) {
      throw new IntegrationNotConnectedError(
        `Razorpay integration not connected for business: ${businessId}`,
      );
    }
    return credentials;
  }

  const apiKeyId = process.env.RAZORPAY_KEY_ID;
  const apiKeySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!apiKeyId || !apiKeySecret) {
    throw new Error('Missing RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET environment variables');
  }
  return { apiKeyId, apiKeySecret };
}

/**
 * Fetch revenue entries from Razorpay between two ISO dates (inclusive).
 */
export async function fetchRazorpayRevenue(
  startDate: string,
  endDate: string,
  businessId?: string,
  options?: FetchRazorpayRevenueOptions,
): Promise<RevenueEntry[]>;
export async function fetchRazorpayRevenue(
  startDate: string,
  endDate: string,
  options?: FetchRazorpayRevenueOptions,
): Promise<RevenueEntry[]>;
export async function fetchRazorpayRevenue(
  startDate: string,
  endDate: string,
  options: FetchRazorpayRevenueOptions,
  businessId?: string,
): Promise<RevenueEntry[]>;
export async function fetchRazorpayRevenue(
  businessId: string,
  startDate: string,
  endDate: string,
  options?: FetchRazorpayRevenueOptions,
): Promise<RevenueEntry[]>;
export async function fetchRazorpayRevenue(
  first: string,
  second: string,
  third?: string | FetchRazorpayRevenueOptions,
  fourth?: string | FetchRazorpayRevenueOptions,
): Promise<RevenueEntry[]> {
  const startsWithBusinessId = typeof third === 'string' && isIsoDate(third);
  const businessId = startsWithBusinessId
    ? first
    : typeof third === 'string'
      ? third
      : typeof fourth === 'string'
        ? fourth
        : undefined;
  const startDate = startsWithBusinessId ? second : first;
  const endDate = startsWithBusinessId ? (third as string) : second;
  const options: FetchRazorpayRevenueOptions = isOptions(third)
    ? third
    : isOptions(fourth)
      ? fourth
      : {};

  const credentials = await resolveCredentials(businessId);
  const key = credentials.apiKeyId;
  const secret = credentials.apiKeySecret;

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
      if (typeof it.amount !== 'number' || !Number.isFinite(it.amount)) {
        throw new InvalidPaymentAmountError(
          `Invalid or non-numeric payment amount for item ${it.id}: ${JSON.stringify(it.amount)}`
        );
      }

      if (it.status !== 'captured') continue;

      const currency = (it.currency || 'INR').toUpperCase();

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

      const createdAt = it.created_at;
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
