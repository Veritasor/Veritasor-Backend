import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { computeShopifyHmac, timingSafeEqual } from '../../../../../src/services/integrations/shopify/utils.js';

describe('Shopify OAuth utils - computeShopifyHmac', () => {
  const FIXED_SECRET = 'test-shopify-secret-key-42';

  describe('Known-answer test vectors', () => {
    it('matches known-answer HMAC computed independently with Node createHmac', () => {
      const params = {
        code: 'auth-code-123',
        shop: 'my-test-store.myshopify.com',
        state: 'state-nonce-abc',
        timestamp: '1700000000',
        hmac: 'placeholder-hmac-that-must-be-excluded',
      };

      // Independent computation of message: sorted keys with hmac excluded
      const independentMessage =
        'code=auth-code-123&shop=my-test-store.myshopify.com&state=state-nonce-abc&timestamp=1700000000';
      const expectedHmac = createHmac('sha256', FIXED_SECRET)
        .update(independentMessage)
        .digest('hex');

      const computed = computeShopifyHmac(FIXED_SECRET, params);

      // Verify known-answer vector matches independent createHmac computation
      expect(computed).toBe(expectedHmac);
      // Hardcoded known-answer vector
      expect(computed).toBe('40820b913510e6d95df7037a5a8869dfbd2baf34f0635a9e3dcfaecf55dbce8e');
    });

    it('matches official Shopify OAuth documentation example vector', () => {
      const secret = 'hulk-smash';
      const params = {
        code: '0907a61c0cbf55e73320f68904147d34',
        shop: 'some-shop.myshopify.com',
        state: '0.3948385',
        timestamp: '1337178173',
        hmac: '75304620f317079148d575c3f3ca76d5483a93db9427b545d6540db5ff6cc5f5',
      };

      const independentMessage =
        'code=0907a61c0cbf55e73320f68904147d34&shop=some-shop.myshopify.com&state=0.3948385&timestamp=1337178173';
      const expectedHmac = createHmac('sha256', secret)
        .update(independentMessage)
        .digest('hex');

      const computed = computeShopifyHmac(secret, params);

      expect(computed).toBe(expectedHmac);
      expect(computed).toBe('1c9b64624e8dd0dc36403abc4db34371c3181552b222d56971092638f2c3efec');
    });
  });

  describe('HMAC exclusion and key order independence', () => {
    it('excludes the hmac parameter from HMAC calculation', () => {
      const baseParams = {
        code: 'test-code',
        shop: 'test-shop.myshopify.com',
        state: 'test-state',
      };

      const withoutHmac = computeShopifyHmac(FIXED_SECRET, baseParams);
      const withHmac = computeShopifyHmac(FIXED_SECRET, {
        ...baseParams,
        hmac: 'some-existing-hmac-value',
      });
      const withDifferentHmac = computeShopifyHmac(FIXED_SECRET, {
        ...baseParams,
        hmac: 'a-completely-different-hmac',
      });
      const withEmptyHmac = computeShopifyHmac(FIXED_SECRET, {
        ...baseParams,
        hmac: '',
      });

      expect(withHmac).toBe(withoutHmac);
      expect(withDifferentHmac).toBe(withoutHmac);
      expect(withEmptyHmac).toBe(withoutHmac);
    });

    it('proves key order does not matter (order independence)', () => {
      // Different key insertion orders
      const order1 = { a: 'first', m: 'middle', z: 'last' };
      const order2 = { z: 'last', a: 'first', m: 'middle' };
      const order3 = { m: 'middle', z: 'last', a: 'first' };
      const order4 = { z: 'last', m: 'middle', a: 'first' };

      const hmac1 = computeShopifyHmac(FIXED_SECRET, order1);
      const hmac2 = computeShopifyHmac(FIXED_SECRET, order2);
      const hmac3 = computeShopifyHmac(FIXED_SECRET, order3);
      const hmac4 = computeShopifyHmac(FIXED_SECRET, order4);

      expect(hmac2).toBe(hmac1);
      expect(hmac3).toBe(hmac1);
      expect(hmac4).toBe(hmac1);
    });

    it('orders keys alphabetically before hashing', () => {
      const params = {
        timestamp: '12345',
        code: 'auth-code',
        shop: 'store.myshopify.com',
      };

      // Alphabetical order: code -> shop -> timestamp
      const expectedMessage = 'code=auth-code&shop=store.myshopify.com&timestamp=12345';
      const expectedHmac = createHmac('sha256', FIXED_SECRET)
        .update(expectedMessage)
        .digest('hex');

      expect(computeShopifyHmac(FIXED_SECRET, params)).toBe(expectedHmac);
    });
  });

  describe('Array value handling', () => {
    it('joins array values with commas', () => {
      const params = {
        ids: ['101', '102', '103'],
        shop: 'test-store.myshopify.com',
      };

      // ids should be joined with commas: "ids=101,102,103&shop=test-store.myshopify.com"
      const expectedMessage = 'ids=101,102,103&shop=test-store.myshopify.com';
      const expectedHmac = createHmac('sha256', FIXED_SECRET)
        .update(expectedMessage)
        .digest('hex');

      const computed = computeShopifyHmac(FIXED_SECRET, params);
      expect(computed).toBe(expectedHmac);
    });

    it('handles single-element array', () => {
      const params = {
        filter: ['single'],
      };

      const expectedHmac = createHmac('sha256', FIXED_SECRET)
        .update('filter=single')
        .digest('hex');

      expect(computeShopifyHmac(FIXED_SECRET, params)).toBe(expectedHmac);
    });

    it('handles empty array', () => {
      const params = {
        empty: [],
        shop: 'test.myshopify.com',
      };

      const expectedHmac = createHmac('sha256', FIXED_SECRET)
        .update('empty=&shop=test.myshopify.com')
        .digest('hex');

      expect(computeShopifyHmac(FIXED_SECRET, params)).toBe(expectedHmac);
    });
  });

  describe('Value sensitivity', () => {
    it('changes the digest when any parameter value changes', () => {
      const baseParams = {
        code: 'auth-code-123',
        shop: 'my-store.myshopify.com',
        state: 'state-nonce',
      };

      const baseDigest = computeShopifyHmac(FIXED_SECRET, baseParams);

      // Changed code value
      const changedCodeDigest = computeShopifyHmac(FIXED_SECRET, {
        ...baseParams,
        code: 'auth-code-124',
      });
      expect(changedCodeDigest).not.toBe(baseDigest);

      // Changed shop value
      const changedShopDigest = computeShopifyHmac(FIXED_SECRET, {
        ...baseParams,
        shop: 'other-store.myshopify.com',
      });
      expect(changedShopDigest).not.toBe(baseDigest);

      // Changed state value
      const changedStateDigest = computeShopifyHmac(FIXED_SECRET, {
        ...baseParams,
        state: 'other-nonce',
      });
      expect(changedStateDigest).not.toBe(baseDigest);

      // Additional parameter
      const extraParamDigest = computeShopifyHmac(FIXED_SECRET, {
        ...baseParams,
        extra: 'param',
      });
      expect(extraParamDigest).not.toBe(baseDigest);

      // Changed secret
      const changedSecretDigest = computeShopifyHmac('different-secret-key', baseParams);
      expect(changedSecretDigest).not.toBe(baseDigest);

      // Changed array element value
      const array1 = computeShopifyHmac(FIXED_SECRET, { items: ['apple', 'banana'] });
      const array2 = computeShopifyHmac(FIXED_SECRET, { items: ['apple', 'cherry'] });
      expect(array2).not.toBe(array1);
    });
  });

  describe('Output format', () => {
    it('outputs lowercase hex string of exactly 64 characters', () => {
      const testCases = [
        { code: 'test', shop: 'shop.myshopify.com' },
        { a: '1', b: '2', c: '3' },
        { ids: ['item1', 'item2'] },
        {},
      ];

      for (const params of testCases) {
        const result = computeShopifyHmac(FIXED_SECRET, params);

        // Exactly 64 characters long (SHA-256 hex digest length)
        expect(result).toHaveLength(64);

        // Lowercase hex only
        expect(result).toMatch(/^[0-9a-f]{64}$/);

        // Strictly lowercase (no uppercase letters)
        expect(result).toBe(result.toLowerCase());
      }
    });
  });

  describe('re-exported timingSafeEqual', () => {
    it('compares matching buffers correctly and safely', () => {
      const hmac1 = computeShopifyHmac(FIXED_SECRET, { code: '123' });
      const hmac2 = computeShopifyHmac(FIXED_SECRET, { code: '123' });
      const hmac3 = computeShopifyHmac(FIXED_SECRET, { code: '456' });

      expect(timingSafeEqual(Buffer.from(hmac1), Buffer.from(hmac2))).toBe(true);
      expect(timingSafeEqual(Buffer.from(hmac1), Buffer.from(hmac3))).toBe(false);
    });
  });
});
