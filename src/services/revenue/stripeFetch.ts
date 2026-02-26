import { logger } from '../../utils/logger.js';
import { integrationRepository } from '../../repositories/integration.js';

export type RevenueEntry = {
  id: string;
  amount: number;
  currency: string;
  date: string;
  source: 'stripe';
  raw?: any;
};

const STRIPE_API = 'https://api.stripe.com/v1';
const PAGE_SIZE = 100;
const MAX_RETRIES = 3;
const RATE_LIMIT_DELAY_MS = 2000;

async function stripeRequest(
  path: string,
  params: Record<string, string>,
  apiKey: string,
  attempt = 1,
): Promise<any> {
  const url = new URL(`${STRIPE_API}${path}`);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const resp = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      Accept: 'application/json',
    },
  });

  if (resp.status === 429 && attempt <= MAX_RETRIES) {
    const retryAfter = resp.headers.get('retry-after');
    const delay = retryAfter ? parseInt(retryAfter, 10) * 1000 : RATE_LIMIT_DELAY_MS * attempt;
    logger.warn(`Stripe rate limited, retrying in ${delay}ms (attempt ${attempt}/${MAX_RETRIES})`);
    await new Promise((r) => setTimeout(r, delay));
    return stripeRequest(path, params, apiKey, attempt + 1);
  }

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Stripe API error: ${resp.status} ${text}`);
  }

  return resp.json();
}

function resolveApiKey(integrationId?: string, userId?: string): string {
  if (!integrationId && !userId) {
    throw new Error('Either integrationId or userId is required');
  }

  const envKey = process.env.STRIPE_SECRET_KEY;
  if (envKey) return envKey;

  if (userId) {
    const integration = integrationRepository.findByUserIdAndType(userId, 'stripe');
    if (!integration) {
      throw new Error(`No Stripe integration found for user ${userId}`);
    }
  }

  throw new Error('Missing STRIPE_SECRET_KEY environment variable');
}

export async function fetchRevenueForPeriod(
  integrationId: string,
  startDate: string,
  endDate: string,
): Promise<RevenueEntry[]> {
  const apiKey = resolveApiKey(integrationId);

  const from = Math.floor(new Date(startDate).getTime() / 1000);
  const to = Math.floor(new Date(endDate).getTime() / 1000);

  const results: RevenueEntry[] = [];
  let startingAfter: string | undefined;

  while (true) {
    const params: Record<string, string> = {
      limit: String(PAGE_SIZE),
      'created[gte]': String(from),
      'created[lte]': String(to),
    };

    if (startingAfter) {
      params.starting_after = startingAfter;
    }

    const body = await stripeRequest('/charges', params, apiKey);
    const items: any[] = Array.isArray(body.data) ? body.data : [];

    for (const charge of items) {
      if (charge.status !== 'succeeded') continue;
      if (charge.refunded) continue;

      results.push({
        id: charge.id,
        amount: typeof charge.amount === 'number' ? charge.amount / 100 : NaN,
        currency: (charge.currency || 'usd').toUpperCase(),
        date: new Date((charge.created ?? 0) * 1000).toISOString(),
        source: 'stripe',
        raw: charge,
      });
    }

    if (!body.has_more || items.length === 0) break;
    startingAfter = items[items.length - 1].id;
  }

  logger.info(`Fetched ${results.length} Stripe revenue entries for period ${startDate} – ${endDate}`);
  return results;
}

export async function fetchRevenueByUserId(
  userId: string,
  startDate: string,
  endDate: string,
): Promise<RevenueEntry[]> {
  const integration = integrationRepository.findByUserIdAndType(userId, 'stripe');
  if (!integration) {
    throw new Error(`No Stripe integration found for user ${userId}`);
  }
  return fetchRevenueForPeriod(integration.id, startDate, endDate);
}

export default fetchRevenueForPeriod;
