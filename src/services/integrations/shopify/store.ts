/**

 * Store for Shopify OAuth state and tokens.
 * Uses Redis when configured, falls back to in-memory storage.
 * Tokens are never logged.
 */

import { getRedisClient } from '../../../redis.js'

export interface ShopifyOAuthState {
  shop: string;
  userId: string;
  businessId: string;
  expiresAt: number;
}

const SHOP_HOST_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com$/;

const stateToShop = new Map<string, ShopifyOAuthState>();
const shopTokens = new Map<string, string>();

function tokenKey(businessId: string, shop: string): string {
  return JSON.stringify([businessId, normalizeShop(shop)]);
}

/**
 * Check if Redis is configured and available.
 */
function isRedisConfigured(): boolean {
  return !!(process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES || process.env.REDIS_MODE);
}

/**
 * Get the Redis key for Shopify OAuth state storage.
 */
function getShopifyOAuthStateKey(state: string): string {
  return `oauth:shopify:state:${state}`;
}

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

export async function setOAuthState(
  state: string,
  shop: string,
  userId: string,
  businessId: string,
  expiresAt: number,
): Promise<void> {
  const normalizedState = state?.trim() ?? "";
  const normalizedShop = normalizeShop(shop);

  if (!normalizedState || !normalizedShop || !isValidShopHost(normalizedShop)) {
    return;
  }

  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    stateToShop.delete(normalizedState);
    return;
  }

  if (isRedisConfigured()) {
    const client = getRedisClient();
    const key = getShopifyOAuthStateKey(normalizedState);
    const ttlMs = expiresAt - Date.now();

    if (ttlMs <= 0) {
      return;
    }

    await client.set(key, JSON.stringify({
      shop: normalizedShop,
      userId,
      businessId,
      expiresAt,
    }), 'PX', ttlMs);
  } else {
    stateToShop.set(normalizedState, {
      shop: normalizedShop,
      userId,
      businessId,
      expiresAt,
    });
  }
}

export async function consumeOAuthState(
  state: string,
): Promise<ShopifyOAuthState | undefined> {
  const lookupKey = state?.trim() ?? "";

  if (isRedisConfigured()) {
    const client = getRedisClient();
    const key = getShopifyOAuthStateKey(lookupKey);

    // Use GETDEL for atomic get-and-delete (Redis 6.2+)
    try {
      const value = await client.getdel(key);
      if (!value) return undefined;

      const record = JSON.parse(value) as ShopifyOAuthState;
      if (Date.now() > record.expiresAt) return undefined;

      return record;
    } catch (err) {
      // GETDEL might not be available in older Redis versions
      // Fall back to Lua script for atomic GET + DEL
      const script = `
        local value = redis.call('GET', KEYS[1])
        if not value then
          return nil
        end
        redis.call('DEL', KEYS[1])
        return value
      `;
      const value = await client.eval(script, 1, key);
      if (!value) return undefined;

      const record = JSON.parse(value as string) as ShopifyOAuthState;
      if (Date.now() > record.expiresAt) return undefined;

      return record;
    }
  } else {
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
}

export function saveToken(
  businessId: string,
  shop: string,
  accessToken: string,
): void {
  shopTokens.set(tokenKey(businessId, shop), accessToken);
}

export function getToken(businessId: string, shop: string): string | undefined {
  return shopTokens.get(tokenKey(businessId, shop));
}

export function deleteToken(businessId: string, shop: string): boolean {
  return shopTokens.delete(tokenKey(businessId, shop));
}

export function clearAll(): void {
  stateToShop.clear();
  shopTokens.clear();
}
