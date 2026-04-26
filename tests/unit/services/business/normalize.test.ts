/**
 * Unit Tests for Business Service Normalization Utilities
 *
 * Tests all normalization and validation functions in the business service.
 * Covers edge cases, security considerations, and normal use cases.
 *
 * Test Coverage:
 * - String normalization (trimming, spaces)
 * - URL normalization and validation
 * - Optional string handling
 * - Industry and description normalization
 * - Validators (business name, URL, etc.)
 * - Sanitization functions
 * - Storage formatting
 *
 * @module tests/unit/services/business/normalize
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  normalizeName,
  normalizeUrl,
  normalizeOptionalString,
  normalizeIndustry,
  normalizeDescription,
  isValidBusinessName,
  isValidUrl,
  sanitizeText,
  isEmpty,
  formatForStorage,
  normalizeCountryCode,
  isValidCountryCode,
} from '../../../../src/services/business/normalize';

describe('Business Normalization Utilities', () => {
  describe('normalizeName', () => {
    it('should trim whitespace from name', () => {
      expect(normalizeName('  abc  ')).toBe('abc');
      expect(normalizeName('\t\nabc\n\t')).toBe('abc');
    });

    it('should collapse multiple internal spaces', () => {
      expect(normalizeName('abc    corp')).toBe('abc corp');
      expect(normalizeName('my   business   name')).toBe('my business name');
    });

    it('should handle mixed whitespace', () => {
      expect(normalizeName('  ABC  \t corp  ')).toBe('ABC corp');
    });

    it('should return empty string for empty input', () => {
      expect(normalizeName('')).toBe('');
      expect(normalizeName('   ')).toBe('');
      expect(normalizeName('\t\n')).toBe('');
    });

    it('should handle non-string input gracefully', () => {
      expect(normalizeName(null as unknown as string)).toBe('');
      expect(normalizeName(undefined as unknown as string)).toBe('');
    });

    it('should preserve valid special characters', () => {
      expect(normalizeName("John's Co.")).toBe("John's Co.");
      expect(normalizeName('Smith & Jones')).toBe('Smith & Jones');
      expect(normalizeName('ABC-123')).toBe('ABC-123');
    });
  });

  describe('normalizeUrl', () => {
    it('should trim whitespace and normalize case', () => {
      expect(normalizeUrl('  HTTPS://EXAMPLE.COM  ')).toBe('https://example.com');
    });

    it('should add https:// if no protocol provided', () => {
      expect(normalizeUrl('example.com')).toBe('https://example.com');
      expect(normalizeUrl('www.example.com')).toBe('https://www.example.com');
    });

    it('should remove trailing slashes', () => {
      expect(normalizeUrl('https://example.com/')).toBe('https://example.com');
      expect(normalizeUrl('https://example.com/path')).toBe('https://example.com/path');
    });

    it('should handle existing http:// protocol', () => {
      expect(normalizeUrl('http://example.com')).toBe('http://example.com');
    });

    it('should return empty string for empty input', () => {
      expect(normalizeUrl('')).toBe('');
      expect(normalizeUrl('   ')).toBe('');
    });

    it('should preserve path and query parameters', () => {
      expect(normalizeUrl('example.com/path?query=1')).toBe('https://example.com/path?query=1');
    });
  });

  describe('normalizeOptionalString', () => {
    it('should trim whitespace and return trimmed value', () => {
      expect(normalizeOptionalString('  hello  ')).toBe('hello');
    });

    it('should return null for empty string', () => {
      expect(normalizeOptionalString('')).toBeNull();
      expect(normalizeOptionalString('   ')).toBeNull();
    });

    it('should return null for non-string input', () => {
      expect(normalizeOptionalString(null)).toBeNull();
      expect(normalizeOptionalString(undefined)).toBeNull();
      expect(normalizeOptionalString(123)).toBeNull();
    });

    it('should preserve whitespace within text', () => {
      expect(normalizeOptionalString('  hello world  ')).toBe('hello world');
    });
  });

  describe('normalizeIndustry', () => {
    it('should trim and normalize spaces', () => {
      expect(normalizeIndustry('  Technology  ')).toBe('Technology');
      expect(normalizeIndustry('Technology    Services')).toBe('Technology Services');
    });

    it('should return null for empty string', () => {
      expect(normalizeIndustry('')).toBeNull();
      expect(normalizeIndustry('   ')).toBeNull();
    });

    it('should return null for non-string input', () => {
      expect(normalizeIndustry(null)).toBeNull();
      expect(normalizeIndustry(undefined)).toBeNull();
    });

    it('should preserve valid characters', () => {
      expect(normalizeIndustry('Technology & Services')).toBe('Technology & Services');
    });
  });

  describe('normalizeDescription', () => {
    it('should trim and normalize spaces on single line', () => {
      expect(normalizeDescription('  Multiple   spaces  ')).toBe('Multiple spaces');
    });

    it('should preserve newlines', () => {
      const input = 'Line 1\nLine 2';
      const result = normalizeDescription(input);
      expect(result).toBe('Line 1\nLine 2');
    });

    it('should normalize spaces within each line', () => {
      const input = '  Start  of  line\n  Another   line  ';
      const expected = 'Start of line\nAnother line';
      expect(normalizeDescription(input)).toBe(expected);
    });

    it('should return null for empty string', () => {
      expect(normalizeDescription('')).toBeNull();
      expect(normalizeDescription('   ')).toBeNull();
      expect(normalizeDescription('\n\n')).toBeNull();
    });

    it('should return null for non-string input', () => {
      expect(normalizeDescription(null)).toBeNull();
      expect(normalizeDescription(undefined)).toBeNull();
    });
  });

  describe('isValidBusinessName', () => {
    it('should accept valid names', () => {
      expect(isValidBusinessName('Acme Corp')).toBe(true);
      expect(isValidBusinessName("John's Bakery")).toBe(true);
      expect(isValidBusinessName('Smith & Associates')).toBe(true);
      expect(isValidBusinessName('ABC-123 Ltd.')).toBe(true);
    });

    it('should reject invalid characters', () => {
      expect(isValidBusinessName('Acme <Corp>')).toBe(false);
      expect(isValidBusinessName('Company@Inc')).toBe(false);
      expect(isValidBusinessName('Business\nName')).toBe(false);
      expect(isValidBusinessName('Acme$Corp')).toBe(false);
    });

    it('should handle empty string', () => {
      expect(isValidBusinessName('')).toBe(false);
    });
  });

  describe('isValidUrl', () => {
    it('should accept valid URLs', () => {
      expect(isValidUrl('https://example.com')).toBe(true);
      expect(isValidUrl('http://www.example.com')).toBe(true);
      expect(isValidUrl('example.com')).toBe(true);
      expect(isValidUrl('www.example.com/path')).toBe(true);
    });

    it('should reject invalid URLs', () => {
      expect(isValidUrl('not a url')).toBe(false);
      expect(isValidUrl('http://')).toBe(false);
    });

    it('should handle localhost and IP addresses', () => {
      expect(isValidUrl('localhost:3000')).toBe(true);
      expect(isValidUrl('127.0.0.1:8080')).toBe(true);
    });

    it('should handle complex URLs', () => {
      expect(isValidUrl('https://example.com/path?query=value')).toBe(true);
      expect(isValidUrl('https://sub.example.co.uk/path')).toBe(true);
    });
  });

  describe('sanitizeText', () => {
    it('should remove HTML tags', () => {
      expect(sanitizeText('<script>alert("xss")</script>')).not.toContain('<');
      expect(sanitizeText('<p>Hello</p> World')).toBe('Hello World');
    });

    it('should handle empty and non-string input', () => {
      expect(sanitizeText('')).toBe('');
      expect(sanitizeText('   ')).toBe('   '); // Doesn't trim, just removes tags
    });

    it('should preserve text without tags', () => {
      const text = 'Clean text without tags';
      expect(sanitizeText(text)).toBe(text);
    });

    it('should handle nested tags', () => {
      expect(sanitizeText('<div><p>Text</p></div>')).toBe('Text');
    });
  });

  describe('isEmpty', () => {
    it('should return true for null and undefined', () => {
      expect(isEmpty(null)).toBe(true);
      expect(isEmpty(undefined)).toBe(true);
    });

    it('should return true for empty strings and whitespace', () => {
      expect(isEmpty('')).toBe(true);
      expect(isEmpty('   ')).toBe(true);
      expect(isEmpty('\t\n')).toBe(true);
    });

    it('should return false for non-empty strings', () => {
      expect(isEmpty('hello')).toBe(false);
      expect(isEmpty('  hello  ')).toBe(false);
    });

    it('should return false for non-string truthy values', () => {
      expect(isEmpty('0')).toBe(false);
      expect(isEmpty('false')).toBe(false); // String 'false' is not empty
    });
  });

  describe('formatForStorage', () => {
    it('should format all fields correctly', () => {
      const input = {
        name: '  My Corp  ',
        industry: '  Technology  ',
        description: '  We make  stuff  ',
        website: '  Example.com  ',
      };

      const result = formatForStorage(input);

      expect(result.name).toBe('My Corp');
      expect(result.industry).toBe('Technology');
      expect(result.description).toBe('We make stuff');
      expect(result.website).toBe('https://example.com');
    });

    it('should handle partial input', () => {
      const input = { name: '  Test  ' };
      const result = formatForStorage(input);

      expect(result.name).toBe('Test');
      expect(result.industry).toBeUndefined();
      expect(result.description).toBeUndefined();
    });

    it('should convert empty strings to null', () => {
      const input = {
        industry: '   ',
        description: '',
      };

      const result = formatForStorage(input);

      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
    });

    it('should preserve null values', () => {
      const input = {
        name: 'Test',
        industry: null,
        description: null,
      };

      const result = formatForStorage(input);

      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
    });

    it('should handle URLs with normalization', () => {
      const input = {
        website: '  HTTPS://EXAMPLE.COM/  ',
      };

      const result = formatForStorage(input);

      expect(result.website).toBe('https://example.com');
    });

    it('should be idempotent for well-formatted input', () => {
      const input = {
        name: 'My Corp',
        industry: 'Technology',
        website: 'https://example.com',
      };

      const result1 = formatForStorage(input);
      const result2 = formatForStorage(result1 as any);

      expect(result1).toEqual(result2);
    });

    it('should normalize countryCode when provided', () => {
      const result = formatForStorage({ name: 'Test', countryCode: 'ng' });
      expect(result.countryCode).toBe('NG');
    });

    it('should pass through null countryCode', () => {
      const result = formatForStorage({ name: 'Test', countryCode: null });
      expect(result.countryCode).toBeNull();
    });

    it('should leave countryCode undefined when not provided', () => {
      const result = formatForStorage({ name: 'Test' });
      expect(result.countryCode).toBeUndefined();
    });
  });

  describe('normalizeCountryCode', () => {
    it('should uppercase a lowercase code', () => {
      expect(normalizeCountryCode('ng')).toBe('NG');
      expect(normalizeCountryCode('us')).toBe('US');
    });

    it('should trim and uppercase', () => {
      expect(normalizeCountryCode('  gb  ')).toBe('GB');
    });

    it('should return null for empty string', () => {
      expect(normalizeCountryCode('')).toBeNull();
      expect(normalizeCountryCode('   ')).toBeNull();
    });

    it('should return null for non-string input', () => {
      expect(normalizeCountryCode(null)).toBeNull();
      expect(normalizeCountryCode(undefined)).toBeNull();
      expect(normalizeCountryCode(42)).toBeNull();
    });

    it('should preserve already-uppercase codes', () => {
      expect(normalizeCountryCode('DE')).toBe('DE');
    });
  });

  describe('isValidCountryCode', () => {
    it('should accept valid two-letter codes', () => {
      expect(isValidCountryCode('US')).toBe(true);
      expect(isValidCountryCode('NG')).toBe(true);
      expect(isValidCountryCode('GB')).toBe(true);
    });

    it('should reject codes with fewer than 2 chars', () => {
      expect(isValidCountryCode('U')).toBe(false);
      expect(isValidCountryCode('')).toBe(false);
    });

    it('should reject codes with more than 2 chars', () => {
      expect(isValidCountryCode('USA')).toBe(false);
    });

    it('should reject numeric codes', () => {
      expect(isValidCountryCode('12')).toBe(false);
    });

    it('should reject lowercase codes (must be pre-uppercased)', () => {
      expect(isValidCountryCode('us')).toBe(false);
    });

    it('should reject alphanumeric codes', () => {
      expect(isValidCountryCode('U1')).toBe(false);
    });
  });
});
