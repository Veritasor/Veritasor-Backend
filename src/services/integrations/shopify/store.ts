/**
 * In-memory store for Shopify OAuth state and tokens.
 * Replace with DB-backed persistence when Shopify integrations move fully out
 * of memory.
 * Tokens are never logged.
 */

export interface ShopifyOAuthState {
  shop: string
  userId: string
}

const SHOP_HOST_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com$/

const stateToShop = new Map<string, ShopifyOAuthState>()
const shopTokens = new Map<string, string>()

export function normalizeShop(shop: string): string {
  const trimmed = shop.trim().toLowerCase()

  if (!trimmed) {
    return ''
  }

  return trimmed.endsWith('.myshopify.com') ? trimmed : `${trimmed}.myshopify.com`
}

export function isValidShopHost(shop: string): boolean {
  return SHOP_HOST_REGEX.test(shop)
}

export function setOAuthState(state: string, shop: string, userId: string): void {
  stateToShop.set(state, { shop: normalizeShop(shop), userId })
}

export function consumeOAuthState(state: string): ShopifyOAuthState | undefined {
  const shop = stateToShop.get(state)
  stateToShop.delete(state)
  return shop
}

export function saveToken(shop: string, accessToken: string): void {
  shopTokens.set(normalizeShop(shop), accessToken)
}

export function getToken(shop: string): string | undefined {
  return shopTokens.get(normalizeShop(shop))
}

export function deleteToken(shop: string): boolean {
  return shopTokens.delete(normalizeShop(shop))
}

export function clearAll(): void {
  stateToShop.clear()
  shopTokens.clear()
}
