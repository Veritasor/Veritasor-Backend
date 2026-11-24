import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateAuthUrl } from '../../../../src/services/integrations/oauth.js';

const ORIGINAL_ENV = {
  STRIPE_CLIENT_ID: process.env.STRIPE_CLIENT_ID,
  SHOPIFY_CLIENT_ID: process.env.SHOPIFY_CLIENT_ID,
  SHOPIFY_SHOP_DOMAIN: process.env.SHOPIFY_SHOP_DOMAIN,
};

beforeEach(() => {
  delete process.env.STRIPE_CLIENT_ID;
  delete process.env.SHOPIFY_CLIENT_ID;
  delete process.env.SHOPIFY_SHOP_DOMAIN;
});

afterEach(() => {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

describe('services/integrations/oauth generateAuthUrl', () => {
  it('builds Stripe OAuth URL from STRIPE_CLIENT_ID and encodes redirectUri', () => {
    process.env.STRIPE_CLIENT_ID = 'ca_test_123';
    const url = generateAuthUrl('stripe', 'state_abc', 'https://app.test/cb');

    expect(url).toBe(
      'https://connect.stripe.com/oauth/authorize?client_id=ca_test_123&state=state_abc' +
        `&redirect_uri=${encodeURIComponent('https://app.test/cb')}&scope=read_write`,
    );
  });

  it('builds Shopify OAuth URL from SHOPIFY_CLIENT_ID and SHOPIFY_SHOP_DOMAIN', () => {
    process.env.SHOPIFY_CLIENT_ID = 'sh_client_123';
    process.env.SHOPIFY_SHOP_DOMAIN = 'my-shop';
    const url = generateAuthUrl('shopify', 'state_xyz', 'https://app.test/shopify/cb');

    expect(url).toBe(
      'https://my-shop.myshopify.com/admin/oauth/authorize?client_id=sh_client_123&state=state_xyz' +
        `&redirect_uri=${encodeURIComponent('https://app.test/shopify/cb')}&scope=read_products,read_orders`,
    );
  });

  it('builds Razorpay callback URL with state and default fallback', () => {
    expect(generateAuthUrl('razorpay', 'rp_state')).toBe(
      'http://localhost:3000/integrations/callback?provider=razorpay&state=rp_state',
    );
  });

  it('throws an Error for unsupported providers', () => {
    expect(() => generateAuthUrl('square', 's')).toThrow('Unsupported provider: square');
  });
});
