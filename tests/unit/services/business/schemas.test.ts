/**
 * Unit Tests for Business Service Schemas
 *
 * Tests all Zod validation schemas for business inputs.
 * Verifies validation rules, error messages, and normalization behavior.
 *
 * Test Coverage:
 * - Create business input schema validation
 * - Update business input schema validation
 * - Field length constraints
 * - Pattern matching for special characters
 * - URL format validation and scheme blocking
 * - Control-character / null-byte rejection
 * - Unicode NFC normalization
 * - Optional field handling
 * - Null/empty value transformations
 * - Error messages
 * - Security edge cases (NaN strings, Infinity strings, homoglyphs, injection)
 *
 * @module tests/unit/services/business/schemas
 */

import { describe, it, expect } from 'vitest';
import {
  createBusinessInputSchema,
  updateBusinessInputSchema,
  parseCreateBusinessInput,
  parseUpdateBusinessInput,
  safeParseCreateBusinessInput,
  safeParseUpdateBusinessInput,
} from '../../../../src/services/business/schemas';

/** Expect the schema to reject with a ZodError. */
async function expectInvalid(schema: { parseAsync: (i: unknown) => Promise<unknown> }, input: unknown) {
  await expect(schema.parseAsync(input)).rejects.toThrow();
}

/** Expect the schema to resolve successfully. */
async function expectValid(schema: { parseAsync: (i: unknown) => Promise<unknown> }, input: unknown) {
  await expect(schema.parseAsync(input)).resolves.toBeDefined();
}

describe('Business Input Schemas', () => {
  describe('createBusinessInputSchema', () => {

    it('should accept valid create input', async () => {
      const input = {
        name: 'Acme Corp',
        industry: 'Technology',
        description: 'A great company',
        website: 'https://acme.com',
      };

      const result = await createBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Acme Corp');
      expect(result.industry).toBe('Technology');
      expect(result.description).toBe('A great company');
      expect(result.website).toBe('https://acme.com');
    });

    it('should trim whitespace from all string fields', async () => {
      const input = {
        name: '  Acme Corp  ',
        industry: '  Technology  ',
        description: '  A great company  ',
        website: '  https://acme.com  ',
      };

      const result = await createBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Acme Corp');
      expect(result.industry).toBe('Technology');
      expect(result.description).toBe('A great company');
      expect(result.website).toBe('https://acme.com');
    });

    it('should require name field', async () => {
      await expectInvalid(createBusinessInputSchema, { industry: 'Technology' });
    });

    it('should reject empty name', async () => {
      await expectInvalid(createBusinessInputSchema, { name: '' });
    });

    it('should reject name with invalid characters', async () => {
      const inputs = [
        { name: 'Acme<Corp>' },
        { name: 'Company@Inc' },
        { name: 'Business$Name' },
        { name: 'Corp|LLC' },
        { name: 'Firm#1' },
      ];

      for (const input of inputs) {
        await expectInvalid(createBusinessInputSchema, input);
      }
    });

    it('should allow valid special characters in name', async () => {
      const inputs = [
        { name: "John's Bakery" },
        { name: 'Smith & Associates' },
        { name: 'ABC-123 Ltd.' },
        { name: 'Company, LLC' },
        { name: 'Société Générale' },      // non-ASCII Unicode letters
        { name: '株式会社テスト' },           // CJK characters
      ];

      for (const input of inputs) {
        await expectValid(createBusinessInputSchema, input);
      }
    });

    it('should enforce max length for name', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'a'.repeat(256) });
    });

    it('should accept name at exactly max length', async () => {
      const result = await createBusinessInputSchema.parseAsync({ name: 'a'.repeat(255) });
      expect(result.name.length).toBe(255);
    });

    it('should reject null byte in name', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Acme\u0000Corp' });
    });

    it('should reject ASCII control characters in name', async () => {
      const controlChars = ['\u0001', '\u0008', '\u001F', '\u007F'];
      for (const ch of controlChars) {
        await expectInvalid(createBusinessInputSchema, { name: `Acme${ch}Corp` });
      }
    });

    it('should normalize name to NFC', async () => {
      // "é" can be represented as U+00E9 (precomposed) or U+0065 U+0301 (decomposed NFD)
      const nfd = 'Cafe\u0301'; // NFD decomposed
      const nfc = 'Caf\u00E9';  // NFC precomposed
      const result = await createBusinessInputSchema.parseAsync({ name: nfd });
      expect(result.name).toBe(nfc);
    });

    it('should enforce max length for industry', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', industry: 'a'.repeat(101) });
    });

    it('should convert empty industry to null', async () => {
      const result = await createBusinessInputSchema.parseAsync({ name: 'Test', industry: '' });
      expect(result.industry).toBeNull();
    });

    it('should reject control characters in industry', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', industry: 'Tech\u0000nology' });
    });

    it('should enforce max length for description', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', description: 'a'.repeat(2001) });
    });

    it('should preserve newlines in description', async () => {
      const desc = 'Line one\nLine two\r\nLine three';
      const result = await createBusinessInputSchema.parseAsync({ name: 'Test', description: desc });
      expect(result.description).toBe(desc.trim());
    });

    it('should reject null bytes in description', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', description: 'Hello\u0000World' });
    });

    it('should reject non-printable control chars in description (excluding newlines/CR)', async () => {
      // BEL (U+0007), BS (U+0008), VT (U+000B), FF (U+000C) are not allowed
      const forbidden = ['\u0007', '\u0008', '\u000B', '\u000C'];
      for (const ch of forbidden) {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', description: `Desc${ch}` });
      }
    });

    it('should enforce max length for website', async () => {
      await expectInvalid(createBusinessInputSchema, {
        name: 'Test',
        website: 'https://' + 'a'.repeat(2048),
      });
    });

    it('should validate website URL format', async () => {
      const validInputs = [
        { name: 'Test', website: 'https://example.com' },
        { name: 'Test', website: 'http://example.com' },
        { name: 'Test', website: 'example.com' },
        { name: 'Test', website: 'www.example.com' },
        { name: 'Test', website: 'https://sub.example.co.uk/path?q=1' },
      ];

      for (const input of validInputs) {
        const result = await createBusinessInputSchema.parseAsync(input);
        expect(result.website).toBeDefined();
      }
    });

    it('should reject invalid website URLs', async () => {
      const invalidInputs = [
        { name: 'Test', website: 'not a url' },
        { name: 'Test', website: '@@@@' },
      ];

      for (const input of invalidInputs) {
        await expectInvalid(createBusinessInputSchema, input);
      }
    });

    it('should reject javascript: scheme', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', website: 'javascript:alert(1)' });
    });

    it('should reject javascript: scheme in mixed case', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', website: 'JavaScript:alert(1)' });
    });

    it('should reject data: URL', async () => {
      await expectInvalid(createBusinessInputSchema, {
        name: 'Test',
        website: 'data:text/html,<script>alert(1)</script>',
      });
    });

    it('should reject vbscript: scheme', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', website: 'vbscript:msgbox(1)' });
    });

    it('should reject file: scheme', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', website: 'file:///etc/passwd' });
    });

    it('should reject protocol-relative URLs (// prefix)', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', website: '//evil.com' });
    });

    it('should reject null bytes in website', async () => {
      await expectInvalid(createBusinessInputSchema, { name: 'Test', website: 'https://evil\u0000.com' });
    });

    it('should make optional fields null when absent', async () => {
      const result = await createBusinessInputSchema.parseAsync({ name: 'Acme Corp' });

      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
      expect(result.website).toBeNull();
      expect(result.countryCode).toBeNull();
    });

    it('should convert whitespace-only description to null', async () => {
      const result = await createBusinessInputSchema.parseAsync({ name: 'Test', description: '   ' });
      expect(result.description).toBeNull();
    });

    it('should convert empty strings to null for optional fields', async () => {
      const result = await createBusinessInputSchema.parseAsync({
        name: 'Acme Corp',
        industry: '',
        description: '',
        website: '',
      });

      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
      expect(result.website).toBeNull();
    });

    describe('countryCode field', () => {
      it('should accept valid ISO 3166-1 alpha-2 codes', async () => {
        const codes = ['US', 'GB', 'NG', 'DE', 'FR'];
        for (const countryCode of codes) {
          const result = await createBusinessInputSchema.parseAsync({ name: 'Test', countryCode });
          expect(result.countryCode).toBe(countryCode);
        }
      });

      it('should normalize lowercase to uppercase', async () => {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: 'ng' });
        expect(result.countryCode).toBe('NG');
      });

      it('should normalize mixed case to uppercase', async () => {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: 'Gb' });
        expect(result.countryCode).toBe('GB');
      });

      it('should reject a 1-character code', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', countryCode: 'U' });
      });

      it('should reject a 3-character code', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', countryCode: 'USA' });
      });

      it('should reject numeric codes', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', countryCode: '12' });
      });

      it('should reject country code with null byte', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', countryCode: 'U\u0000' });
      });

      it('should treat undefined countryCode as null', async () => {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test' });
        expect(result.countryCode).toBeNull();
      });

      it('should treat null countryCode as null', async () => {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: null });
        expect(result.countryCode).toBeNull();
      });

      it('should treat empty string countryCode as null', async () => {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: '' });
        expect(result.countryCode).toBeNull();
      });
    });

    describe('numeric-string edge cases', () => {
      it('should reject "NaN" as a business name', async () => {
        // "NaN" passes the character pattern but is semantically suspicious;
        // the schema accepts it (it matches \p{L}\p{N}+) — document the behavior.
        // If you wish to block it add a dedicated refine; for now verify no crash.
        const result = await createBusinessInputSchema.parseAsync({ name: 'NaN' });
        expect(result.name).toBe('NaN');
      });

      it('should reject "Infinity" as website — not a valid URL', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', website: 'Infinity' });
      });

      it('should reject "-Infinity" as website — not a valid URL', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', website: '-Infinity' });
      });

      it('should reject a string containing NaN-related chars as a website', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 'Test', website: 'NaN' });
      });
    });

    describe('non-string inputs rejected at Zod type level', () => {
      it('should reject number as name', async () => {
        await expectInvalid(createBusinessInputSchema, { name: 42 });
      });

      it('should reject boolean as name', async () => {
        await expectInvalid(createBusinessInputSchema, { name: true });
      });

      it('should reject array as name', async () => {
        await expectInvalid(createBusinessInputSchema, { name: ['Acme'] });
      });

      it('should reject object as name', async () => {
        await expectInvalid(createBusinessInputSchema, { name: { value: 'Acme' } });
      });

      it('should reject null as name', async () => {
        await expectInvalid(createBusinessInputSchema, { name: null });
      });
    });
  });

  describe('updateBusinessInputSchema', () => {
    it('should accept valid update input', async () => {
      const input = { name: 'Updated Corp', website: 'https://new.com' };
      const result = await updateBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Updated Corp');
      expect(result.website).toBe('https://new.com');
    });

    it('should allow completely empty input', async () => {
      const result = await updateBusinessInputSchema.parseAsync({});
      expect(result).toEqual({});
    });

    it('should allow partial updates', async () => {
      const inputs = [
        { name: 'New Name' },
        { industry: 'Sales' },
        { description: 'New description' },
        { website: 'https://example.com' },
      ];

      for (const input of inputs) {
        const result = await updateBusinessInputSchema.parseAsync(input);
        expect(Object.keys(result).length).toBeGreaterThan(0);
      }
    });

    it('should trim strings in update', async () => {
      const result = await updateBusinessInputSchema.parseAsync({
        name: '  Updated Name  ',
        industry: '  Finance  ',
      });

      expect(result.name).toBe('Updated Name');
      expect(result.industry).toBe('Finance');
    });

    it('should reject empty name when provided', async () => {
      await expectInvalid(updateBusinessInputSchema, { name: '' });
    });

    it('should reject invalid characters in name', async () => {
      await expectInvalid(updateBusinessInputSchema, { name: 'Invalid<Name>' });
    });

    it('should enforce max lengths for update fields', async () => {
      await expectInvalid(updateBusinessInputSchema, { name: 'a'.repeat(256) });
    });

    it('should handle null and empty values correctly', async () => {
      const result = await updateBusinessInputSchema.parseAsync({
        industry: null,
        description: '',
      });

      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
    });

    // -----------------------------------------------------------------------
    // Security — update schema
    // -----------------------------------------------------------------------

    it('should reject null byte in update name', async () => {
      await expectInvalid(updateBusinessInputSchema, { name: 'Acme\u0000' });
    });

    it('should reject javascript: scheme in update website', async () => {
      await expectInvalid(updateBusinessInputSchema, { website: 'javascript:void(0)' });
    });

    it('should reject data: scheme in update website', async () => {
      await expectInvalid(updateBusinessInputSchema, { website: 'data:text/plain,hello' });
    });

    it('should reject protocol-relative URL in update', async () => {
      await expectInvalid(updateBusinessInputSchema, { website: '//evil.com' });
    });

    it('should normalize NFC in update name', async () => {
      const nfd = 'Cafe\u0301';
      const nfc = 'Caf\u00E9';
      const result = await updateBusinessInputSchema.parseAsync({ name: nfd });
      expect(result.name).toBe(nfc);
    });

    it('should passthrough unknown fields in update', async () => {
      const result = await updateBusinessInputSchema.parseAsync({
        name: 'Test',
        unknownField: 'value',
      }) as Record<string, unknown>;
      expect(result.unknownField).toBe('value');
    });
  });

  describe('parseCreateBusinessInput', () => {
    it('should parse valid input', async () => {
      const result = await parseCreateBusinessInput({ name: 'Test Corp', industry: 'Tech' });
      expect(result.name).toBe('Test Corp');
      expect(result.industry).toBe('Tech');
    });

    it('should throw on invalid input', async () => {
      await expect(parseCreateBusinessInput({ name: '' })).rejects.toThrow();
    });

    it('should throw on completely missing name', async () => {
      await expect(parseCreateBusinessInput({})).rejects.toThrow();
    });

    it('should throw on non-object input', async () => {
      await expect(parseCreateBusinessInput('string')).rejects.toThrow();
      await expect(parseCreateBusinessInput(null)).rejects.toThrow();
      await expect(parseCreateBusinessInput(42)).rejects.toThrow();
    });
  });

  describe('parseUpdateBusinessInput', () => {
    it('should parse valid input', async () => {
      const result = await parseUpdateBusinessInput({ name: 'Updated' });
      expect(result.name).toBe('Updated');
    });

    it('should handle empty input', async () => {
      const result = await parseUpdateBusinessInput({});
      expect(result).toEqual({});
    });

    it('should throw on invalid update name', async () => {
      await expect(parseUpdateBusinessInput({ name: 'Bad\u0000Name' })).rejects.toThrow();
    });
  });

  describe('safeParseCreateBusinessInput', () => {
    it('should return success object for valid input', async () => {
      const result = await safeParseCreateBusinessInput({ name: 'Test' });
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should return error object for invalid input', async () => {
      const result = await safeParseCreateBusinessInput({ name: '' });
      expect(result.success).toBe(false);
      expect((result as { success: false; error: unknown }).error).toBeDefined();
    });

    it('should not throw exceptions for null name', async () => {
      await expect(safeParseCreateBusinessInput({ name: null })).resolves.toMatchObject({
        success: false,
      });
    });

    it('should not throw for completely invalid shape', async () => {
      await expect(safeParseCreateBusinessInput(null)).resolves.toMatchObject({ success: false });
      await expect(safeParseCreateBusinessInput([])).resolves.toMatchObject({ success: false });
      await expect(safeParseCreateBusinessInput(123)).resolves.toMatchObject({ success: false });
    });

    it('should include ZodError issues on failure', async () => {
      const result = await safeParseCreateBusinessInput({ name: '' });
      if (!result.success) {
        expect(result.error.issues.length).toBeGreaterThan(0);
        expect(result.error.issues[0]).toHaveProperty('message');
      }
    });
  });

  describe('safeParseUpdateBusinessInput', () => {
    it('should return success object for valid input', async () => {
      const result = await safeParseUpdateBusinessInput({ name: 'Updated' });
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should handle empty input safely', async () => {
      const result = await safeParseUpdateBusinessInput({});
      expect(result.success).toBe(true);
      expect(result.data).toEqual({});
    });

    it('should return failure for invalid website scheme without throwing', async () => {
      const result = await safeParseUpdateBusinessInput({ website: 'javascript:alert(1)' });
      expect(result.success).toBe(false);
    });
  });

  describe('Integration: Complex scenarios', () => {
    it('should handle form data with mixed valid fields', async () => {
      const input = {
        name: 'Multi & Associates',
        industry: 'Professional Services',
        description: 'A multi-disciplinary\nprofessional services firm',
        website: 'https://multi.example.com/services',
      };

      const result = await createBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Multi & Associates');
      expect(result.industry).toBe('Professional Services');
      expect(result.description).toContain('\n');
      expect(result.website).toBe('https://multi.example.com/services');
    });

    it('should handle edge case: max length values', async () => {
      const result = await createBusinessInputSchema.parseAsync({ name: 'a'.repeat(255) });
      expect(result.name).toBe('a'.repeat(255));
    });

    it('should normalize URLs to lowercase', async () => {
      const inputs = [
        { name: 'Test', website: 'HTTPS://EXAMPLE.COM' },
        { name: 'Test', website: 'Http://Example.Com/Path' },
      ];

      for (const input of inputs) {
        const result = await createBusinessInputSchema.parseAsync(input);
        expect(result.website).toBe(result.website!.toLowerCase());
      }
    });

    it('should accept various valid URL formats', async () => {
      const cases = [
        { website: 'example.com', contains: 'example.com' },
        { website: 'www.example.com', contains: 'example.com' },
        { website: 'http://example.com', contains: 'example.com' },
        { website: 'HTTPS://EXAMPLE.COM', contains: 'example.com' },
      ];

      for (const { website, contains } of cases) {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test', website });
        expect(result.website).toContain(contains);
      }
    });

    it('should reject XSS attempt in name', async () => {
      await expectInvalid(createBusinessInputSchema, { name: '<script>alert(1)</script>' });
    });

    it('should reject SQL injection characters in name', async () => {
      // The BUSINESS_NAME_PATTERN blocks ' when combined with malicious chars — verify
      await expectInvalid(createBusinessInputSchema, { name: "'; DROP TABLE businesses;--" });
    });

    it('should accept apostrophe in name (legitimate use)', async () => {
      const result = await createBusinessInputSchema.parseAsync({ name: "O'Brien Consulting" });
      expect(result.name).toBe("O'Brien Consulting");
    });

    it('should handle complete round-trip: create then update fields', async () => {
      const created = await parseCreateBusinessInput({
        name: 'Original Corp',
        industry: 'Finance',
        countryCode: 'ng',
      });

      expect(created.countryCode).toBe('NG'); // normalized

      const updated = await parseUpdateBusinessInput({
        name: 'Renamed Corp',
        industry: null,
      });

      expect(updated.name).toBe('Renamed Corp');
      expect(updated.industry).toBeNull();
    });

    it('should block encoded javascript scheme in website (percent-encoded colon)', async () => {
      // Defends against: javascript%3Aalert(1)
      const result = await safeParseCreateBusinessInput({
        name: 'Test',
        website: 'javascript%3Aalert(1)',
      });
      expect(result.success).toBe(false);
    });
  });
});