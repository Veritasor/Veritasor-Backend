import { afterEach, describe, expect, it } from 'vitest';
import { createWebhookSubscriptionSchema } from '../webhookSubscription.js';

describe('webhook subscription URL SSRF validation', () => {
  const original = process.env.NODE_ENV;
  afterEach(() => { process.env.NODE_ENV = original; });

  it('requires HTTPS in production and accepts public HTTPS hosts', () => {
    process.env.NODE_ENV = 'production';
    const base = { secret: 's'.repeat(32) };
    expect(createWebhookSubscriptionSchema.safeParse({ ...base, url: 'http://example.com' }).success).toBe(false);
    expect(createWebhookSubscriptionSchema.safeParse({ ...base, url: 'https://hooks.example.com/x' }).success).toBe(true);
  });

  it.each([
    'https://127.0.0.1/x', 'https://10.0.0.5/', 'https://[::1]/',
    'https://169.254.169.254/', 'https://localhost/',
  ])('rejects restricted endpoint %s', (url) => {
    process.env.NODE_ENV = 'production';
    expect(createWebhookSubscriptionSchema.safeParse({ url, secret: 's'.repeat(32) }).success).toBe(false);
  });
});
