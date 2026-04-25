/**
 * Shopify OAuth callback: validate state, exchange code for an access token,
 * and persist the connected installation.
 * Access tokens are never logged or returned.
 */
import * as integrationRepository from '../../../repositories/integration.js';
import * as store from './store.js';
/**
 * Handle OAuth callback: consume state, exchange code for token, persist via integration store.
 */
export async function handleCallback(params) {
    const { code, shop, state } = params;
    const clientId = process.env.SHOPIFY_CLIENT_ID ?? '';
    const clientSecret = process.env.SHOPIFY_CLIENT_SECRET ?? '';
    const { code, shop, state, hmac } = params;
    // Parameter completeness guard — check code, shop, state first
    if (!code || !shop || !state) {
        return { success: false, error: 'Missing required callback parameters' };
    }
    // HMAC presence guard — absent or empty string both count as missing
    if (!hmac) {
        return { success: false, error: 'Missing HMAC signature' };
    }
    // HMAC validation using constant-time comparison
    const computed = computeShopifyHmac(currentClientSecret, params);
    const computedBuf = Buffer.from(computed);
    const providedBuf = Buffer.from(hmac);
    if (computedBuf.length !== providedBuf.length ||
        !timingSafeEqual(computedBuf, providedBuf)) {
        return { success: false, error: 'Invalid HMAC signature' };
    }
    const shopHost = store.normalizeShop(shop);
    if (!store.isValidShopHost(shopHost)) {
        return { success: false, error: 'Invalid shop hostname' };
    }
    const stateRecord = store.consumeOAuthState(state);
    if (!stateRecord || stateRecord.shop !== shopHost) {
        return { success: false, error: 'Invalid or expired state' };
    }
    const tokenUrl = `https://${shopHost}/admin/oauth/access_token`;
    const body = new URLSearchParams({
        client_id: currentClientId,
        client_secret: currentClientSecret,
        code,
    });
    let res;
    try {
        res = await fetch(tokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
            body: body.toString(),
        });
    }
    catch (err) {
        return { success: false, error: 'Token exchange request failed' };
    }
    if (!res.ok) {
        return { success: false, error: 'Token exchange failed' };
    }
    const data = (await res.json());
    const accessToken = data?.access_token;
    if (!accessToken || typeof accessToken !== 'string') {
        return { success: false, error: 'No access token in response' };
    }
    store.saveToken(shopHost, accessToken);
    const existingShopifyIntegration = (await integrationRepository.listByUserId(stateRecord.userId)).find((integration) => integration.provider === 'shopify');
    if (existingShopifyIntegration && existingShopifyIntegration.externalId !== shopHost) {
        await integrationRepository.deleteById(existingShopifyIntegration.id);
        store.deleteToken(existingShopifyIntegration.externalId);
    }
    const reusableIntegration = existingShopifyIntegration && existingShopifyIntegration.externalId === shopHost
        ? existingShopifyIntegration
        : null;
    if (reusableIntegration) {
        const updated = await integrationRepository.update(reusableIntegration.id, {
            token: { accessToken },
            metadata: { shop: shopHost },
        });
        if (!updated) {
            return { success: false, error: 'Failed to persist Shopify integration' };
        }
    }
    else {
        await integrationRepository.create({
            userId: stateRecord.userId,
            provider: 'shopify',
            externalId: shopHost,
            token: { accessToken },
            metadata: { shop: shopHost },
        });
    }
    return { success: true, shop: shopHost };
}
