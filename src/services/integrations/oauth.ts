const DEFAULT_OAUTH_CALLBACK_URL = 'http://localhost:3000/integrations/callback';

/**
 * Build the provider authorization URL for the generic integration connect flow.
 *
 * Kept provider-explicit (rather than a lookup table) so the unsupported-provider
 * branch stays a hard error and the URL shapes stay covered by tests.
 */
export function generateAuthUrl(
  provider: string,
  state: string,
  redirectUri?: string,
): string {
  const callbackUrl = redirectUri ?? DEFAULT_OAUTH_CALLBACK_URL;

  switch (provider) {
    case 'stripe': {
      const clientId = process.env.STRIPE_CLIENT_ID ?? 'mock_stripe_client_id';
      return `https://connect.stripe.com/oauth/authorize?client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=read_write`;
    }
    case 'shopify': {
      const clientId = process.env.SHOPIFY_CLIENT_ID ?? 'mock_shopify_client_id';
      const shopDomain = process.env.SHOPIFY_SHOP_DOMAIN ?? 'example';
      return `https://${shopDomain}.myshopify.com/admin/oauth/authorize?client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=read_products,read_orders`;
    }
    case 'razorpay':
      return `${callbackUrl}?provider=razorpay&state=${state}`;
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}
