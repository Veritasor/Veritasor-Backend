/**
 * In-memory store for Shopify OAuth state and tokens.
 * Replace with DB-backed persistence when Shopify integrations move fully out
 * of memory.
 * Tokens are never logged.
 */
const SHOP_HOST_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com$/;
const stateToShop = new Map();
const shopTokens = new Map();
export function normalizeShop(shop) {
    const trimmed = shop.trim().toLowerCase();
    if (!trimmed) {
        return '';
    }
    return trimmed.endsWith('.myshopify.com') ? trimmed : `${trimmed}.myshopify.com`;
}
export function isValidShopHost(shop) {
    return SHOP_HOST_REGEX.test(shop);
}
export function setOAuthState(state, shop, userId) {
    stateToShop.set(state, { shop: normalizeShop(shop), userId });
}
export function consumeOAuthState(state) {
    const shop = stateToShop.get(state);
    stateToShop.delete(state);
    return shop;
}
export function saveToken(shop, accessToken) {
    shopTokens.set(normalizeShop(shop), accessToken);
}
export function getToken(shop) {
    return shopTokens.get(normalizeShop(shop));
}
export function deleteToken(shop) {
    return shopTokens.delete(normalizeShop(shop));
}
export function clearAll() {
    stateToShop.clear();
    shopTokens.clear();
}
