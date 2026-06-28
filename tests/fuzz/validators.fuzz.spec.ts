import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { loginInputSchema } from '../../src/schemas/auth.js';
import { resetPasswordSchema } from '../../src/schemas/resetPasswordSchema.js';
import { updateUserProfileSchema } from '../../src/routes/users.schema.js';

describe('Zod Schema Fuzzing', () => {
  const schemas = [
    { name: 'loginInputSchema', schema: loginInputSchema },
    { name: 'resetPasswordSchema', schema: resetPasswordSchema },
    { name: 'updateUserProfileSchema', schema: updateUserProfileSchema },
  ];

  schemas.forEach(({ name, schema }) => {
    describe(`${name}`, () => {
      it('should never throw uncaught exceptions for any arbitrary input', () => {
        fc.assert(
          fc.property(fc.anything(), (input) => {
            // Zod's safeParse should not throw; it should return a structured result
            const result = schema.safeParse(input);
            expect(result).toHaveProperty('success');
            if (!result.success) {
              expect(result.error).toBeDefined();
            }
          }),
          { numRuns: 1000 }
        );
      });

      it('should handle exotic strings (surrogate pairs, unicode) without throwing', () => {
        fc.assert(
          fc.property(fc.unicodeString(), fc.fullUnicodeString(), (str1, str2) => {
            const input = {
              email: str1,
              password: str2,
              token: str1,
              newPassword: str2,
              name: str1,
              profile: { key: str2 },
            };
            const result = schema.safeParse(input);
            expect(result).toHaveProperty('success');
          }),
          { numRuns: 1000 }
        );
      });

      it('should handle oversized payloads', () => {
        const largeString = 'A'.repeat(10000);
        const input = {
          email: largeString,
          password: largeString,
          token: largeString,
          newPassword: largeString,
          name: largeString,
          profile: { key: largeString },
        };
        const result = schema.safeParse(input);
        expect(result.success).toBe(false); // Likely fails length constraints, but shouldn't crash
      });

      it('should correctly handle prototype pollution attempts (__proto__)', () => {
        const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}}');
        const result = schema.safeParse(maliciousPayload);
        expect(result).toHaveProperty('success');
      });
    });
  });
});
