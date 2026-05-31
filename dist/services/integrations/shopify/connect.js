/**
 * Shopify OAuth: build redirect URL and register state for callback validation.
 */
import { randomBytes } from 'node:crypto';
import * as store from './store.js';
/**
 * Start Shopify OAuth: generate state, store it, return redirect URL.
 * Caller should redirect the user to redirectUrl.
 */
export function startConnect(shop, userId, businessId) {
    const clientId = process.env.SHOPIFY_CLIENT_ID ?? '';
    const scopes = process.env.SHOPIFY_SCOPES ?? 'read_orders';
    const redirectUri = process.env.SHOPIFY_REDIRECT_URI ?? '';
    const state = randomBytes(16).toString('hex');
    const shopHost = store.normalizeShop(shop);
    if (!clientId || !redirectUri || !store.isValidShopHost(shopHost)) {
        throw new Error('Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop');
    }
    // Read TTL from environment or default to 10 minutes
    const ttlMs = process.env.SHOPIFY_OAUTH_STATE_TTL_MS
        ? Number.parseInt(process.env.SHOPIFY_OAUTH_STATE_TTL_MS, 10)
        : 10 * 60 * 1000;
    const expiresAt = Date.now() + ttlMs;
    store.setOAuthState(state, shopHost, userId, businessId, expiresAt);
    const params = new URLSearchParams({
        client_id: clientId,
        scope: scopes,
        redirect_uri: redirectUri,
        state,
    });
    const redirectUrl = `https://${shopHost}/admin/oauth/authorize?${params.toString()}`;
    return { redirectUrl, state };
}
