import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Computes the Shopify HMAC signature for OAuth validation.
 * See: https://shopify.dev/apps/auth/oauth/getting-started#verify-the-installation-request
 */
export function computeShopifyHmac(secret: string, params: Record<string, any>): string {
  const { hmac, ...rest } = params;
  
  // Sort parameters alphabetically by key
  const sortedKeys = Object.keys(rest).sort();
  
  // Create message by joining key=value pairs with '&'
  const message = sortedKeys
    .map(key => {
      const value = rest[key];
      // Values can be arrays if repeated in query string, though unlikely for Shopify OAuth
      const valueStr = Array.isArray(value) ? value.join(',') : String(value);
      return `${key}=${valueStr}`;
    })
    .join('&');
    
  return createHmac('sha256', secret)
    .update(message)
    .digest('hex');
}

export { timingSafeEqual };
