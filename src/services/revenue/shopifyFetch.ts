import { logger } from "../../utils/logger.js";
import { integrationRepository } from "../../repositories/integration.js";
import { getToken } from "../integrations/shopify/store.js";

export type RevenueEntry = {
  id: string;
  amount: number;
  currency: string;
  date: string;
  source: "shopify";
  raw?: any;
};

const PAGE_SIZE = 250;
const MAX_RETRIES = 3;
const RATE_LIMIT_DELAY_MS = 2000;

function resolveShopAndToken(
  integrationId?: string,
  userId?: string,
): { shop: string; token: string } {
  if (!integrationId && !userId) {
    throw new Error("Either integrationId or userId is required");
  }

  const envShop = process.env.SHOPIFY_SHOP;
  const envToken = process.env.SHOPIFY_ACCESS_TOKEN;
  if (envShop && envToken) {
    const shop = envShop.endsWith(".myshopify.com")
      ? envShop
      : `${envShop}.myshopify.com`;
    return { shop, token: envToken };
  }

  if (userId) {
    const integration = integrationRepository.findByUserIdAndType(
      userId,
      "shopify",
    );
    if (!integration) {
      throw new Error(`No Shopify integration found for user ${userId}`);
    }
  }

  if (envShop) {
    const shop = envShop.endsWith(".myshopify.com")
      ? envShop
      : `${envShop}.myshopify.com`;
    const token = getToken(shop);
    if (token) return { shop, token };
  }

  throw new Error(
    "Missing SHOPIFY_SHOP / SHOPIFY_ACCESS_TOKEN environment variables or stored token",
  );
}

async function shopifyRequest(
  shop: string,
  path: string,
  params: Record<string, string>,
  token: string,
  attempt = 1,
): Promise<any> {
  const url = new URL(`https://${shop}/admin/api/2024-01${path}`);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const resp = await fetch(url.toString(), {
    headers: {
      "X-Shopify-Access-Token": token,
      Accept: "application/json",
    },
  });

  if (resp.status === 429 && attempt <= MAX_RETRIES) {
    const retryAfter = resp.headers.get("retry-after");
    const delay = retryAfter
      ? parseFloat(retryAfter) * 1000
      : RATE_LIMIT_DELAY_MS * attempt;
    logger.warn(
      `Shopify rate limited, retrying in ${delay}ms (attempt ${attempt}/${MAX_RETRIES})`,
    );
    await new Promise((r) => setTimeout(r, delay));
    return shopifyRequest(shop, path, params, token, attempt + 1);
  }

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Shopify API error: ${resp.status} ${text}`);
  }

  return resp.json();
}

function extractNextPageUrl(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  const match = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
  return match ? match[1] : null;
}

export async function fetchShopifyRevenue(
  integrationId: string,
  startDate: string,
  endDate: string,
): Promise<RevenueEntry[]> {
  const { shop, token } = resolveShopAndToken(integrationId);

  const results: RevenueEntry[] = [];
  let sinceId: string | undefined;

  while (true) {
    const params: Record<string, string> = {
      limit: String(PAGE_SIZE),
      status: "any",
      created_at_min: new Date(startDate).toISOString(),
      created_at_max: new Date(endDate).toISOString(),
      financial_status: "paid",
    };

    if (sinceId) {
      params.since_id = sinceId;
    }

    const body = await shopifyRequest(shop, "/orders.json", params, token);
    const orders: any[] = Array.isArray(body.orders) ? body.orders : [];

    for (const order of orders) {
      if (order.cancelled_at) continue;

      const totalPrice = parseFloat(order.total_price);

      results.push({
        id: String(order.id),
        amount: isNaN(totalPrice) ? 0 : totalPrice,
        currency: (order.currency || "USD").toUpperCase(),
        date: order.created_at || new Date().toISOString(),
        source: "shopify",
        raw: order,
      });
    }

    if (orders.length < PAGE_SIZE) break;
    sinceId = String(orders[orders.length - 1].id);
  }

  logger.info(
    `Fetched ${results.length} Shopify revenue entries for period ${startDate} – ${endDate}`,
  );
  return results;
}

export async function fetchRevenueByUserId(
  userId: string,
  startDate: string,
  endDate: string,
): Promise<RevenueEntry[]> {
  const integration = integrationRepository.findByUserIdAndType(
    userId,
    "shopify",
  );
  if (!integration) {
    throw new Error(`No Shopify integration found for user ${userId}`);
  }
  return fetchShopifyRevenue(integration.id, startDate, endDate);
}

export default fetchShopifyRevenue;
