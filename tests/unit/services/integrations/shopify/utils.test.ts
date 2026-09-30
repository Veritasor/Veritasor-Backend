/**
 * Focused unit tests for Shopify HMAC computation and utilities.
 * 
 * Covers:
 *   - computeShopifyHmac: public contract & output format (64-char lowercase hex)
 *   - computeShopifyHmac: Shopify OAuth spec compliance (stripping 'hmac' param, lexicographical sorting)
 *   - computeShopifyHmac: message construction and known test vectors
 *   - computeShopifyHmac: value formatting transitions (arrays, numbers, booleans, empty strings, null/undefined)
 *   - computeShopifyHmac: boundary conditions (empty params, params with only hmac, empty secret, long secret)
 *   - computeShopifyHmac: invalid inputs and deterministic error behavior
 *   - timingSafeEqual: re-exported utility contract & behavior
 */

import { describe, it, expect } from 'vitest';
import { createHmac } from 'crypto';
import { computeShopifyHmac, timingSafeEqual } from '../../../../../src/services/integrations/shopify/utils.js';

describe('computeShopifyHmac', () => {
  const TEST_SECRET = 'shopify-test-secret-key-12345';

  describe('public contract and output format', () => {
    it('is exported as a function', () => {
      expect(typeof computeShopifyHmac).toBe('function');
    });

    it('returns a 64-character lowercase hex string for valid inputs', () => {
      const result = computeShopifyHmac(TEST_SECRET, {
        shop: 'test-store.myshopify.com',
        code: 'auth-code-123',
      });

      expect(typeof result).toBe('string');
      expect(result).toHaveLength(64);
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    });

    it('produces deterministic output for identical inputs', () => {
      const params = {
        code: 'auth-code-xyz',
        shop: 'examplestore.myshopify.com',
        timestamp: '1600000000',
      };

      const result1 = computeShopifyHmac(TEST_SECRET, params);
      const result2 = computeShopifyHmac(TEST_SECRET, params);

      expect(result1).toBe(result2);
    });

    it('produces different hashes for different secrets', () => {
      const params = { shop: 'store.myshopify.com', code: 'code123' };

      const hashA = computeShopifyHmac('secret-a', params);
      const hashB = computeShopifyHmac('secret-b', params);

      expect(hashA).not.toBe(hashB);
    });
  });

  describe('Shopify OAuth HMAC specification compliance', () => {
    it('excludes the "hmac" parameter from the signature calculation', () => {
      const paramsWithoutHmac = {
        code: 'auth-code-123',
        shop: 'test-store.myshopify.com',
        state: 'nonce-state-abc',
      };

      const paramsWithHmac = {
        ...paramsWithoutHmac,
        hmac: 'existing-or-incoming-hmac-signature-should-be-stripped',
      };

      const hashWithoutHmac = computeShopifyHmac(TEST_SECRET, paramsWithoutHmac);
      const hashWithHmac = computeShopifyHmac(TEST_SECRET, paramsWithHmac);

      expect(hashWithHmac).toBe(hashWithoutHmac);
    });

    it('sorts parameter keys alphabetically before computing hash regardless of object key order', () => {
      const orderA = {
        timestamp: '1609459200',
        shop: 'alpha.myshopify.com',
        code: 'code-1',
        state: 'state-1',
      };

      const orderB = {
        code: 'code-1',
        shop: 'alpha.myshopify.com',
        state: 'state-1',
        timestamp: '1609459200',
      };

      const orderC = {
        state: 'state-1',
        timestamp: '1609459200',
        shop: 'alpha.myshopify.com',
        code: 'code-1',
      };

      const hashA = computeShopifyHmac(TEST_SECRET, orderA);
      const hashB = computeShopifyHmac(TEST_SECRET, orderB);
      const hashC = computeShopifyHmac(TEST_SECRET, orderC);

      expect(hashA).toBe(hashB);
      expect(hashB).toBe(hashC);
    });

    it('joins sorted key=value pairs with "&"', () => {
      const secret = 'hush-secret';
      const params = {
        shop: 'example.myshopify.com',
        code: 'sample-code',
      };

      // Alphabetical order: code=sample-code&shop=example.myshopify.com
      const expectedMessage = 'code=sample-code&shop=example.myshopify.com';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      const actualHash = computeShopifyHmac(secret, params);

      expect(actualHash).toBe(expectedHash);
    });

    it('matches known Shopify OAuth verification vector', () => {
      // Vector using known values
      const secret = 'hush';
      const params = {
        shop: 'some-shop.myshopify.com',
        code: '0907a61c0cbf55e2300acb188a0dec47',
        timestamp: '1337178173',
        hmac: 'placeholder-to-strip',
      };

      // Expected message: code=0907a61c0cbf55e2300acb188a0dec47&shop=some-shop.myshopify.com&timestamp=1337178173
      const expectedMessage = 'code=0907a61c0cbf55e2300acb188a0dec47&shop=some-shop.myshopify.com&timestamp=1337178173';
      const expectedDigest = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      const result = computeShopifyHmac(secret, params);
      expect(result).toBe(expectedDigest);
    });
  });

  describe('parameter value type formatting and transitions', () => {
    it('formats array values as comma-separated strings', () => {
      const secret = 'test-secret';
      const params = {
        ids: ['101', '102', '103'],
        shop: 'array-test.myshopify.com',
      };

      // Expected message: ids=101,102,103&shop=array-test.myshopify.com
      const expectedMessage = 'ids=101,102,103&shop=array-test.myshopify.com';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });

    it('handles empty arrays by producing "key="', () => {
      const secret = 'test-secret';
      const params = {
        items: [],
        shop: 'empty-array.myshopify.com',
      };

      const expectedMessage = 'items=&shop=empty-array.myshopify.com';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });

    it('handles single-item arrays without trailing or leading commas', () => {
      const secret = 'test-secret';
      const params = {
        tag: ['single'],
      };

      const expectedMessage = 'tag=single';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });

    it('formats numeric values with String conversion', () => {
      const secret = 'test-secret';
      const params = {
        timestamp: 1609459200,
        zero: 0,
        negative: -42,
      };

      const expectedMessage = 'negative=-42&timestamp=1609459200&zero=0';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });

    it('formats boolean values with String conversion', () => {
      const secret = 'test-secret';
      const params = {
        isActive: true,
        isArchived: false,
      };

      const expectedMessage = 'isActive=true&isArchived=false';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });

    it('formats empty string values as "key="', () => {
      const secret = 'test-secret';
      const params = {
        emptyVal: '',
        shop: 'store.myshopify.com',
      };

      const expectedMessage = 'emptyVal=&shop=store.myshopify.com';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });

    it('formats null and undefined property values with String conversion', () => {
      const secret = 'test-secret';
      const params = {
        nullKey: null,
        undefKey: undefined,
      };

      const expectedMessage = 'nullKey=null&undefKey=undefined';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });

    it('handles special characters and URI encoded components', () => {
      const secret = 'test-secret';
      const params = {
        query: 'hello world & welcome = 100%',
        special: 'äöü-🚀',
      };

      const expectedMessage = 'query=hello world & welcome = 100%&special=äöü-🚀';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });
  });

  describe('boundary conditions and edge cases', () => {
    it('handles empty params object by computing HMAC of empty message', () => {
      const secret = 'test-secret';
      const expectedHash = createHmac('sha256', secret).update('').digest('hex');

      expect(computeShopifyHmac(secret, {})).toBe(expectedHash);
    });

    it('handles params containing only the hmac key by producing empty message hash', () => {
      const secret = 'test-secret';
      const expectedEmptyHash = createHmac('sha256', secret).update('').digest('hex');

      expect(computeShopifyHmac(secret, { hmac: 'only-hmac-present' })).toBe(expectedEmptyHash);
    });

    it('handles single parameter object', () => {
      const secret = 'test-secret';
      const expectedHash = createHmac('sha256', secret).update('shop=store.myshopify.com').digest('hex');

      expect(computeShopifyHmac(secret, { shop: 'store.myshopify.com' })).toBe(expectedHash);
    });

    it('handles empty string secret', () => {
      const expectedHash = createHmac('sha256', '').update('shop=store.myshopify.com').digest('hex');

      expect(computeShopifyHmac('', { shop: 'store.myshopify.com' })).toBe(expectedHash);
    });

    it('handles long secret keys (> 64 bytes)', () => {
      const longSecret = 'a'.repeat(128);
      const params = { shop: 'store.myshopify.com' };
      const expectedHash = createHmac('sha256', longSecret).update('shop=store.myshopify.com').digest('hex');

      expect(computeShopifyHmac(longSecret, params)).toBe(expectedHash);
    });

    it('handles keys with empty string names', () => {
      const secret = 'test-secret';
      const params = { '': 'val', shop: 'test.myshopify.com' };
      const expectedMessage = '=val&shop=test.myshopify.com';
      const expectedHash = createHmac('sha256', secret).update(expectedMessage).digest('hex');

      expect(computeShopifyHmac(secret, params)).toBe(expectedHash);
    });
  });

  describe('representative invalid inputs and deterministic error behavior', () => {
    it('throws a TypeError when params is null', () => {
      expect(() => {
        computeShopifyHmac(TEST_SECRET, null as any);
      }).toThrow(TypeError);
    });

    it('throws a TypeError when params is undefined', () => {
      expect(() => {
        computeShopifyHmac(TEST_SECRET, undefined as any);
      }).toThrow(TypeError);
    });

    it('throws when secret is null', () => {
      expect(() => {
        computeShopifyHmac(null as any, { shop: 'test.myshopify.com' });
      }).toThrow(/The "key" argument/);
    });

    it('throws when secret is undefined', () => {
      expect(() => {
        computeShopifyHmac(undefined as any, { shop: 'test.myshopify.com' });
      }).toThrow(/The "key" argument/);
    });

    it('throws when secret is a number', () => {
      expect(() => {
        computeShopifyHmac(12345 as any, { shop: 'test.myshopify.com' });
      }).toThrow(/The "key" argument/);
    });

    it('throws when secret is an object', () => {
      expect(() => {
        computeShopifyHmac({} as any, { shop: 'test.myshopify.com' });
      }).toThrow(/The "key" argument/);
    });
  });
});

describe('timingSafeEqual', () => {
  it('is exported as a function', () => {
    expect(typeof timingSafeEqual).toBe('function');
  });

  it('returns true for matching buffers', () => {
    const bufA = Buffer.from('4a5f6e', 'hex');
    const bufB = Buffer.from('4a5f6e', 'hex');

    expect(timingSafeEqual(bufA, bufB)).toBe(true);
  });

  it('returns false for non-matching buffers of equal length', () => {
    const bufA = Buffer.from('4a5f6e', 'hex');
    const bufB = Buffer.from('4a5f6f', 'hex');

    expect(timingSafeEqual(bufA, bufB)).toBe(false);
  });

  it('throws an error for buffers of unequal length', () => {
    const bufA = Buffer.from('4a5f', 'hex');
    const bufB = Buffer.from('4a5f6e', 'hex');

    expect(() => timingSafeEqual(bufA, bufB)).toThrow();
  });
});
