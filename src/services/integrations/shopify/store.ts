/**

 * In-memory store for Shopify OAuth state and tokens.

 * Replace with DB-backed persistence when Shopify integrations move fully out
 * of memory.
 * Tokens are never logged.
 */

export interface ShopifyOAuthState {
  shop: string;
  userId: string;
  businessId: string;
  expiresAt: number;
}

const SHOP_HOST_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com$/;

const stateToShop = new Map<string, ShopifyOAuthState>();
const shopTokens = new Map<string, string>();

export function normalizeShop(shop: string): string {
  const trimmed = shop.trim().toLowerCase();

  if (!trimmed) {
    return "";
  }

  return trimmed.endsWith(".myshopify.com")
    ? trimmed
    : `${trimmed}.myshopify.com`;
}

export function isValidShopHost(shop: string): boolean {
  return SHOP_HOST_REGEX.test(shop);
}

export function setOAuthState(
  state: string,
  shop: string,
  userId: string,
  businessId: string,
  expiresAt: number,
): void {
  const normalizedState = state?.trim() ?? "";
  const normalizedShop = normalizeShop(shop);

  if (!normalizedState || !normalizedShop || !isValidShopHost(normalizedShop)) {
    return;
  }

  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    stateToShop.delete(normalizedState);
    return;
  }

  stateToShop.set(normalizedState, {
    shop: normalizedShop,
    userId,
    businessId,
    expiresAt,
  });
}

export function consumeOAuthState(
  state: string,
): ShopifyOAuthState | undefined {
  const lookupKey = state?.trim() ?? "";
  const record = stateToShop.get(lookupKey);

  if (!record) {
    return undefined;
  }

  // Delete immediately to enforce single-use and prevent replay after expiry.
  stateToShop.delete(lookupKey);

  if (Date.now() > record.expiresAt) {
    return undefined;
  }

  return record;
}

export function saveToken(shop: string, accessToken: string): void {
  shopTokens.set(normalizeShop(shop), accessToken);
}

export function getToken(shop: string): string | undefined {
  return shopTokens.get(normalizeShop(shop));
}

export function deleteToken(shop: string): boolean {
  return shopTokens.delete(normalizeShop(shop));
}

export function clearAll(): void {
  stateToShop.clear();
  shopTokens.clear();
}
