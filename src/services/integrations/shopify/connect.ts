/**
 * Shopify OAuth: build redirect URL and register state for callback validation.
 */

import { randomBytes } from "node:crypto";
import * as store from "./store.js";

const DEFAULT_OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

export interface ConnectResult {
  redirectUrl: string;
  state: string;
}

function resolveOAuthStateTtlMs(): number {
  const raw = process.env.SHOPIFY_OAUTH_STATE_TTL_MS;
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_OAUTH_STATE_TTL_MS;
  }

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_OAUTH_STATE_TTL_MS;
  }

  return parsed;
}

/**
 * Start Shopify OAuth: generate state, store it, return redirect URL.
 * Caller should redirect the user to redirectUrl.
 */
export function startConnect(
  shop: string,
  userId: string,
  businessId: string,
): ConnectResult {
  const clientId = process.env.SHOPIFY_CLIENT_ID ?? "";
  const scopes = process.env.SHOPIFY_SCOPES ?? "read_orders";
  const redirectUri = process.env.SHOPIFY_REDIRECT_URI ?? "";
  const state = randomBytes(16).toString("hex");
  const shopHost = store.normalizeShop(shop);

  if (!clientId || !redirectUri || !store.isValidShopHost(shopHost)) {
    throw new Error(
      "Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop",
    );
  }

  const ttlMs = resolveOAuthStateTtlMs();
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
