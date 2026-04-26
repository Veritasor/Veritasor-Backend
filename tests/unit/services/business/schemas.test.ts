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
 * - URL format validation
 * - Optional field handling
 * - Null/empty value transformations
 * - Error messages
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
      const input = {
        industry: 'Technology',
      };

      await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should reject empty name', async () => {
      const input = {
        name: '',
        industry: 'Technology',
      };

      await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should reject name with invalid characters', async () => {
      const inputs = [
        { name: 'Acme<Corp>' },
        { name: 'Company@Inc' },
        { name: 'Business$Name' },
      ];

      for (const input of inputs) {
        await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
      }
    });

    it('should allow valid special characters in name', async () => {
      const inputs = [
        { name: "John's Bakery" },
        { name: 'Smith & Associates' },
        { name: 'ABC-123 Ltd.' },
        { name: 'Company, LLC' },
      ];

      for (const input of inputs) {
        const result = await createBusinessInputSchema.parseAsync(input);
        expect(result.name).toBeDefined();
      }
    });

    it('should enforce max length for name', async () => {
      const input = {
        name: 'a'.repeat(256), // Exceeds max of 255
      };

      await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should enforce max length for industry', async () => {
      const input = {
        name: 'Test',
        industry: 'a'.repeat(101), // Exceeds max of 100
      };

      await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should enforce max length for description', async () => {
      const input = {
        name: 'Test',
        description: 'a'.repeat(2001), // Exceeds max of 2000
      };

      await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should enforce max length for website', async () => {
      const input = {
        name: 'Test',
        website: 'https://' + 'a'.repeat(2048), // Exceeds max of 2048
      };

      await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should make optional fields optional', async () => {
      const input = {
        name: 'Acme Corp',
      };

      const result = await createBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Acme Corp');
      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
      expect(result.website).toBeNull();
    });

    it('should convert empty strings to null for optional fields', async () => {
      const input = {
        name: 'Acme Corp',
        industry: '',
        description: '   ',
        website: '',
      };

      const result = await createBusinessInputSchema.parseAsync(input);

      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
      expect(result.website).toBeNull();
    });

    it('should validate website URL format', async () => {
      const validInputs = [
        { name: 'Test', website: 'https://example.com' },
        { name: 'Test', website: 'http://example.com' },
        { name: 'Test', website: 'example.com' },
        { name: 'Test', website: 'www.example.com' },
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
        await expect(createBusinessInputSchema.parseAsync(input)).rejects.toThrow();
      }
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
        await expect(
          createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: 'U' }),
        ).rejects.toThrow();
      });

      it('should reject a 3-character code', async () => {
        await expect(
          createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: 'USA' }),
        ).rejects.toThrow();
      });

      it('should reject numeric codes', async () => {
        await expect(
          createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: '12' }),
        ).rejects.toThrow();
      });

      it('should treat undefined countryCode as null (field is optional)', async () => {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test' });
        expect(result.countryCode).toBeNull();
      });

      it('should treat null countryCode as null', async () => {
        const result = await createBusinessInputSchema.parseAsync({ name: 'Test', countryCode: null });
        expect(result.countryCode).toBeNull();
      });
    });
  });

  describe('updateBusinessInputSchema', () => {
    it('should accept valid update input', async () => {
      const input = {
        name: 'Updated Corp',
        website: 'https://new.com',
      };

      const result = await updateBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Updated Corp');
      expect(result.website).toBe('https://new.com');
    });

    it('should allow completely empty input', async () => {
      const input = {};

      const result = await updateBusinessInputSchema.parseAsync(input);

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
      const input = {
        name: '  Updated Name  ',
        industry: '  Finance  ',
      };

      const result = await updateBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Updated Name');
      expect(result.industry).toBe('Finance');
    });

    it('should reject empty name when provided', async () => {
      const input = {
        name: '',
      };

      await expect(updateBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should reject invalid characters in name', async () => {
      const input = {
        name: 'Invalid<Name>',
      };

      await expect(updateBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should enforce max lengths for update fields', async () => {
      const input = {
        name: 'a'.repeat(256),
      };

      await expect(updateBusinessInputSchema.parseAsync(input)).rejects.toThrow();
    });

    it('should handle null and empty values correctly', async () => {
      const input = {
        industry: null,
        description: '',
      };

      const result = await updateBusinessInputSchema.parseAsync(input);

      expect(result.industry).toBeNull();
      expect(result.description).toBeNull();
    });
  });

  describe('parseCreateBusinessInput', () => {
    it('should parse valid input', async () => {
      const input = {
        name: 'Test Corp',
        industry: 'Tech',
      };

      const result = await parseCreateBusinessInput(input);

      expect(result.name).toBe('Test Corp');
      expect(result.industry).toBe('Tech');
    });

    it('should throw on invalid input', async () => {
      const input = {
        name: '', // Invalid - required
      };

      await expect(parseCreateBusinessInput(input)).rejects.toThrow();
    });
  });

  describe('parseUpdateBusinessInput', () => {
    it('should parse valid input', async () => {
      const input = {
        name: 'Updated',
      };

      const result = await parseUpdateBusinessInput(input);

      expect(result.name).toBe('Updated');
    });

    it('should handle empty input', async () => {
      const input = {};

      const result = await parseUpdateBusinessInput(input);

      expect(result).toEqual({});
    });
  });

  describe('safeParseCreateBusinessInput', () => {
    it('should return success object for valid input', async () => {
      const input = {
        name: 'Test',
      };

      const result = await safeParseCreateBusinessInput(input);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should return error object for invalid input', async () => {
      const input = {
        name: '',
      };

      const result = await safeParseCreateBusinessInput(input);

      expect(result.success).toBe(false);
      expect((result as any).error).toBeDefined();
    });

    it('should not throw exceptions', async () => {
      const input = {
        name: null, // Invalid
      };

      await expect(safeParseCreateBusinessInput(input)).resolves.toEqual(
        expect.objectContaining({
          success: false,
        }),
      );
    });
  });

  describe('safeParseUpdateBusinessInput', () => {
    it('should return success object for valid input', async () => {
      const input = {
        name: 'Updated',
      };

      const result = await safeParseUpdateBusinessInput(input);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should handle empty input safely', async () => {
      const input = {};

      const result = await safeParseUpdateBusinessInput(input);

      expect(result.success).toBe(true);
      expect(result.data).toEqual({});
    });
  });

  describe('Integration: Complex scenarios', () => {
    it('should handle form data with mixed valid and invalid fields', async () => {
      const input = {
        name: 'Multi & Associates',
        industry: 'Professional Services',
        description: 'A multi-disciplinary\nprofessional services firm',
        website: 'https://multi.example.com/services',
      };

      const result = await createBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('Multi & Associates');
      expect(result.industry).toBe('Professional Services');
      expect(result.description).toContain('\n'); // Preserves newlines
      expect(result.website).toBe('https://multi.example.com/services');
    });

    it('should handle edge case: max length values', async () => {
      const input = {
        name: 'a'.repeat(255), // Exactly at limit
      };

      const result = await createBusinessInputSchema.parseAsync(input);

      expect(result.name).toBe('a'.repeat(255));
    });

    it('should normalize URLs in various formats', async () => {
      const inputs = [
        { name: 'Test', website: 'example.com' },
        { name: 'Test', website: 'www.example.com' },
        { name: 'Test', website: 'http://example.com' },
        { name: 'Test', website: 'HTTPS://EXAMPLE.COM' },
      ];

      for (const input of inputs) {
        const result = await createBusinessInputSchema.parseAsync(input);
        expect(result.website).toBeDefined();
        expect(result.website!.includes('example.com')).toBe(true);
      }
    });
  });
});
