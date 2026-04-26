/**
 * Shopify OAuth callback: validate state, exchange code for an access token,
 * and persist the connected installation.
 * Access tokens are never logged or returned.
 */


import * as integrationRepository from '../../../repositories/integration.js';
import * as store from './store.js';
import { logger } from '../../../utils/logger.js';

export interface CallbackParams {
  code: string
  shop: string
  state: string
  hmac?: string
  [key: string]: string | undefined
}

export interface CallbackResult {
  success: boolean
  shop?: string
  error?: string
}

/**
 * Compute Shopify HMAC for request verification.
 * Sorts parameters alphabetically and excludes the 'hmac' key.
 */
export function computeShopifyHmac(secret: string, params: Record<string, string | undefined>): string {
  const { hmac: _excluded, ...filtered } = params
  const sorted = Object.keys(filtered).sort()
  const message = sorted.map(key => `${key}=${filtered[key]}`).join('&')
  return createHmac('sha256', secret).update(message).digest('hex')
}

/**
 * Handle OAuth callback: consume state, exchange code for token, persist via integration store.
 */

export async function handleCallback(params: CallbackParams): Promise<CallbackResult> {
  const { code, shop, state, hmac } = params;
  const clientId = process.env.SHOPIFY_CLIENT_ID ?? '';
  const clientSecret = process.env.SHOPIFY_CLIENT_SECRET ?? '';

  // Parameter completeness guard
  if (!code || !shop || !state) {
    logger.warn({ event: 'shopify_callback_param_missing', shop, state, codePresent: !!code }, 'Shopify callback missing required parameters');
    return { success: false, error: 'Missing required callback parameters' };
  }

  // HMAC presence guard
  if (!hmac) {
    logger.warn({ event: 'shopify_callback_hmac_missing', shop, state }, 'Shopify callback missing HMAC');
    return { success: false, error: 'Missing HMAC signature' };
  }

  // HMAC validation
  let computed: string;
  try {
    computed = computeShopifyHmac(clientSecret, params);
  } catch (err) {
    logger.error({ event: 'shopify_callback_hmac_compute_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify HMAC computation failed');
    return { success: false, error: 'HMAC validation error' };
  }
  const computedBuf = Buffer.from(computed);
  const providedBuf = Buffer.from(hmac);
  if (
    computedBuf.length !== providedBuf.length ||
    !timingSafeEqual(computedBuf, providedBuf)
  ) {
    logger.warn({ event: 'shopify_callback_hmac_mismatch', shop, state }, 'Shopify callback HMAC mismatch');
    return { success: false, error: 'Invalid HMAC signature' };
  }

  const shopHost = store.normalizeShop(shop);
  if (!store.isValidShopHost(shopHost)) {
    logger.warn({ event: 'shopify_callback_invalid_shop', shop, shopHost }, 'Shopify callback invalid shop hostname');
    return { success: false, error: 'Invalid shop hostname' };
  }

  const stateRecord = store.consumeOAuthState(state);
  if (!stateRecord || stateRecord.shop !== shopHost) {
    logger.warn({ event: 'shopify_callback_invalid_state', shop, state, shopHost }, 'Shopify callback invalid or expired state');
    return { success: false, error: 'Invalid or expired state' };
  }

  const tokenUrl = `https://${shopHost}/admin/oauth/access_token`;
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: '[REDACTED]', // never log or expose
    code,
  });

  let res: Response;
  try {
    res = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: body.toString().replace(clientSecret, '[REDACTED]'),
    });
  } catch (err) {
    logger.error({ event: 'shopify_callback_token_exchange_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify token exchange request failed');
    return { success: false, error: 'Token exchange request failed' };
  }

  if (!res.ok) {
    logger.warn({ event: 'shopify_callback_token_exchange_failed', shop, state, status: res.status }, 'Shopify token exchange failed');
    return { success: false, error: 'Token exchange failed' };
  }

  let data: any;
  try {
    data = await res.json();
  } catch (err) {
    logger.error({ event: 'shopify_callback_token_response_parse_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify token response parse failed');
    return { success: false, error: 'Token response parse failed' };
  }
  const accessToken = data?.access_token;
  if (!accessToken || typeof accessToken !== 'string') {
    logger.warn({ event: 'shopify_callback_no_access_token', shop, state }, 'Shopify callback: no access token in response');
    return { success: false, error: 'No access token in response' };
  }

  // Never log or return the access token
  try {
    store.saveToken(shopHost, accessToken);
  } catch (err) {
    logger.error({ event: 'shopify_callback_token_save_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify token save failed');
    return { success: false, error: 'Failed to persist Shopify token' };
  }

  let existingShopifyIntegration;
  try {
    existingShopifyIntegration = (await integrationRepository.listByUserId(stateRecord.userId)).find(
      (integration) => integration.provider === 'shopify',
    );
  } catch (err) {
    logger.error({ event: 'shopify_callback_integration_lookup_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify integration lookup failed');
    return { success: false, error: 'Failed to lookup Shopify integration' };
  }

  if (existingShopifyIntegration && existingShopifyIntegration.externalId !== shopHost) {
    try {
      await integrationRepository.deleteById(existingShopifyIntegration.id);
      store.deleteToken(existingShopifyIntegration.externalId);
    } catch (err) {
      logger.error({ event: 'shopify_callback_integration_delete_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify integration delete failed');
      return { success: false, error: 'Failed to update Shopify integration' };
    }
  }

  const reusableIntegration =
    existingShopifyIntegration && existingShopifyIntegration.externalId === shopHost
      ? existingShopifyIntegration
      : null;

  if (reusableIntegration) {
    try {
      const updated = await integrationRepository.update(reusableIntegration.id, {
        token: { accessToken: '[REDACTED]' },
        metadata: { shop: shopHost },
      });
      if (!updated) {
        logger.error({ event: 'shopify_callback_integration_update_error', shop, state }, 'Failed to persist Shopify integration');
        return { success: false, error: 'Failed to persist Shopify integration' };
      }
    } catch (err) {
      logger.error({ event: 'shopify_callback_integration_update_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify integration update failed');
      return { success: false, error: 'Failed to persist Shopify integration' };
    }
  } else {
    try {
      await integrationRepository.create({
        userId: stateRecord.userId,
        provider: 'shopify',
        externalId: shopHost,
        token: { accessToken: '[REDACTED]' },
        metadata: { shop: shopHost },
      });
    } catch (err) {
      logger.error({ event: 'shopify_callback_integration_create_error', shop, state, err: err instanceof Error ? err.message : String(err) }, 'Shopify integration create failed');
      return { success: false, error: 'Failed to persist Shopify integration' };
    }
  }

  return { success: true, shop: shopHost };
}
