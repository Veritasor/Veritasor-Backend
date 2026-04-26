/**
 * Business Service Schemas and Input Normalization
 *
 * This module provides Zod schemas for validating and normalizing business
 * service inputs. It ensures data integrity, security, and consistency across
 * the business domain.
 *
 * Features:
 * - Input validation with comprehensive rules
 * - Automatic string trimming and normalization
 * - URL validation and normalization
 * - Business name and industry validation
 * - Country code validation (ISO 3166-1 alpha-2)
 * - Type-safe parsed inputs
 *
 * @module services/business/schemas
 */

import { z } from 'zod';

/**
 * Maximum length for business name field.
 * Prevents excessively long inputs that could cause display or database issues.
 */
const BUSINESS_NAME_MAX_LENGTH = 255;

/**
 * Maximum length for industry field.
 * Keeps industry classifications manageable.
 */
const INDUSTRY_MAX_LENGTH = 100;

/**
 * Maximum length for description field.
 * Allows reasonable business descriptions without excess.
 */
const DESCRIPTION_MAX_LENGTH = 2000;

/**
 * Maximum length for website URL field.
 * Supports typical domain URLs and paths.
 */
const WEBSITE_MAX_LENGTH = 2048;

/**
 * Regex pattern for validating business names.
 * Unicode-aware: allows letters from any script, numbers, spaces, hyphens,
 * apostrophes, ampersands, periods, and commas.
 * Prevents injection of control characters and HTML-special symbols.
 */
const BUSINESS_NAME_PATTERN = /^[\p{L}\p{N}\s\-'&.,]+$/u;

/**
 * Regex pattern for validating industry values.
 * Allows similar characters to business names for consistency.
 */
const INDUSTRY_PATTERN = /^[\p{L}\p{N}\s\-'&.,]+$/u;

/**
 * Regex pattern for URL validation.
 * Supports http, https, www formats, and basic domain names without protocol.
 * This is permissive to allow various input formats that will be normalized later.
 */
const URL_PATTERN =
  /^(https?:\/\/)?(www\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}|localhost|127\.0\.0\.1)(:[0-9]+)?(\/[^\s]*)?$/;

/**
 * Regex pattern for ISO 3166-1 alpha-2 country codes.
 * Matches exactly two uppercase ASCII letters after normalization.
 */
const COUNTRY_CODE_PATTERN = /^[A-Z]{2}$/;

/**
 * Create Business Input Schema
 *
 * Validates and normalizes input for creating a new business.
 * - Normalizes strings (trim, lowercase for email-like fields)
 * - Validates required fields (name)
 * - Validates optional fields with sensible limits
 * - Provides clear error messages
 *
 * @example
 * ```typescript
 * const input = await createBusinessInputSchema.parseAsync({
 *   name: '  My Business  ',
 *   industry: 'Technology',
 *   description: 'We make cool stuff',
 *   website: 'https://example.com',
 *   countryCode: 'ng',
 * });
 * // Returns: {
 * //   name: 'My Business',
 * //   industry: 'Technology',
 * //   description: 'We make cool stuff',
 * //   website: 'https://example.com',
 * //   countryCode: 'NG',
 * // }
 * ```
 */
export const createBusinessInputSchema = z.object({
  name: z
    .string()
    .min(1, 'Name is required')
    .max(BUSINESS_NAME_MAX_LENGTH, `Name must be at most ${BUSINESS_NAME_MAX_LENGTH} characters`)
    .trim()
    .refine(
      (name) => BUSINESS_NAME_PATTERN.test(name),
      'Name contains invalid characters. Use letters, numbers, spaces, hyphens, apostrophes, and ampersands.',
    ),

  industry: z
    .string()
    .max(INDUSTRY_MAX_LENGTH, `Industry must be at most ${INDUSTRY_MAX_LENGTH} characters`)
    .trim()
    .refine(
      (industry) => industry === '' || INDUSTRY_PATTERN.test(industry),
      'Industry contains invalid characters',
    )
    .optional()
    .nullable()
    .transform((val) => (val === '' || val === undefined) ? null : val),

  description: z
    .string()
    .max(DESCRIPTION_MAX_LENGTH, `Description must be at most ${DESCRIPTION_MAX_LENGTH} characters`)
    .trim()
    .optional()
    .nullable()
    .transform((val) => (val === '' || val === undefined) ? null : val),

  countryCode: z
    .string()
    .length(2, 'Country code must be exactly 2 characters')
    .toUpperCase()
    .refine(
      (code) => COUNTRY_CODE_PATTERN.test(code),
      'Invalid country code format. Must be an ISO 3166-1 alpha-2 code (e.g., US, GB, NG).',
    )
    .optional()
    .nullable()
    .transform((val) => (val === '' || val === undefined) ? null : val),

  website: z
    .string()
    .max(WEBSITE_MAX_LENGTH, `Website URL must be at most ${WEBSITE_MAX_LENGTH} characters`)
    .trim()
    .transform((val) => val.toLowerCase())
    .refine(
      (url) => url === '' || URL_PATTERN.test(url),
      'Website must be a valid URL (e.g., https://example.com or www.example.com)',
    )
    .optional()
    .nullable()
    .transform((val) => (val === '' || val === undefined) ? null : val),
});

/**
 * Parsed Create Business Input Type
 *
 * Represents validated and normalized input for business creation.
 * All strings are trimmed, empty strings converted to null,
 * and patterns validated for security and consistency.
 */
export type CreateBusinessInput = z.infer<typeof createBusinessInputSchema>;

/**
 * Update Business Input Schema
 *
 * Validates and normalizes input for updating an existing business.
 * Similar to create schema but all fields are optional since this is a partial update.
 *
 * @example
 * ```typescript
 * const input = await updateBusinessInputSchema.parseAsync({
 *   name: 'Updated Business Name',
 *   website: 'https://newsite.com',
 *   countryCode: 'GB',
 * });
 * // Returns: { name: 'Updated Business Name', website: 'https://newsite.com', countryCode: 'GB' }
 * ```
 */
export const updateBusinessInputSchema = z.object({
  name: z
    .string()
    .min(1, 'Name cannot be empty')
    .max(BUSINESS_NAME_MAX_LENGTH, `Name must be at most ${BUSINESS_NAME_MAX_LENGTH} characters`)
    .trim()
    .refine(
      (name) => BUSINESS_NAME_PATTERN.test(name),
      'Name contains invalid characters',
    )
    .optional(),

  industry: z
    .string()
    .max(INDUSTRY_MAX_LENGTH, `Industry must be at most ${INDUSTRY_MAX_LENGTH} characters`)
    .trim()
    .refine(
      (industry) => industry === '' || INDUSTRY_PATTERN.test(industry),
      'Industry contains invalid characters',
    )
    .nullable()
    .optional()
    .transform((val) => (val === '' ? null : val)),

  description: z
    .string()
    .max(DESCRIPTION_MAX_LENGTH, `Description must be at most ${DESCRIPTION_MAX_LENGTH} characters`)
    .trim()
    .nullable()
    .optional()
    .transform((val) => (val === '' ? null : val)),

  countryCode: z
    .string()
    .length(2, 'Country code must be exactly 2 characters')
    .toUpperCase()
    .refine(
      (code) => COUNTRY_CODE_PATTERN.test(code),
      'Invalid country code format. Must be an ISO 3166-1 alpha-2 code (e.g., US, GB, NG).',
    )
    .nullable()
    .optional()
    .transform((val) => (val === '' ? null : val)),

  website: z
    .string()
    .max(WEBSITE_MAX_LENGTH, `Website URL must be at most ${WEBSITE_MAX_LENGTH} characters`)
    .trim()
    .transform((val) => val.toLowerCase())
    .refine(
      (url) => url === '' || URL_PATTERN.test(url),
      'Website must be a valid URL',
    )
    .nullable()
    .optional()
    .transform((val) => (val === '' ? null : val)),
}).passthrough();

/**
 * Parsed Update Business Input Type
 *
 * Represents validated and normalized input for business updates.
 * All fields are optional for partial updates.
 */
export type UpdateBusinessInput = z.infer<typeof updateBusinessInputSchema>;

/**
 * Parse and normalize create business input
 *
 * Safely parses and normalizes user-supplied create business input.
 * Throws ZodError on invalid input.
 *
 * @param input - Raw input data from request body
 * @returns Normalized input ready for service layer
 * @throws ZodError if input fails validation
 *
 * @example
 * ```typescript
 * try {
 *   const normalized = await parseCreateBusinessInput(req.body);
 *   const business = await createBusiness(userId, normalized);
 * } catch (error) {
 *   if (error instanceof z.ZodError) {
 *     // Handle validation errors
 *     console.error(error.issues);
 *   }
 * }
 * ```
 */
export async function parseCreateBusinessInput(input: unknown): Promise<CreateBusinessInput> {
  return createBusinessInputSchema.parseAsync(input);
}

/**
 * Parse and normalize update business input
 *
 * Safely parses and normalizes user-supplied update business input.
 * Throws ZodError on invalid input.
 *
 * @param input - Raw input data from request body
 * @returns Normalized input ready for service layer
 * @throws ZodError if input fails validation
 *
 * @example
 * ```typescript
 * try {
 *   const normalized = await parseUpdateBusinessInput(req.body);
 *   const business = await updateBusiness(businessId, normalized);
 * } catch (error) {
 *   if (error instanceof z.ZodError) {
 *     // Handle validation errors
 *   }
 * }
 * ```
 */
export async function parseUpdateBusinessInput(input: unknown): Promise<UpdateBusinessInput> {
  return updateBusinessInputSchema.parseAsync(input);
}

/**
 * Safely parse create input with error handling
 *
 * Returns a result object indicating success or failure.
 * Useful for cases where you want to handle validation errors
 * without exceptions.
 *
 * @param input - Raw input data
 * @returns Object with success status and either data or errors
 *
 * @example
 * ```typescript
 * const result = await safeParseCreateBusinessInput(req.body);
 * if (!result.success) {
 *   return res.status(400).json({ errors: result.error.issues });
 * }
 * const business = await createBusiness(userId, result.data);
 * ```
 */
export async function safeParseCreateBusinessInput(input: unknown) {
  const result = await createBusinessInputSchema.safeParseAsync(input);
  return result;
}

/**
 * Safely parse update input with error handling
 *
 * Returns a result object indicating success or failure.
 *
 * @param input - Raw input data
 * @returns Object with success status and either data or errors
 */
export async function safeParseUpdateBusinessInput(input: unknown) {
  const result = await updateBusinessInputSchema.safeParseAsync(input);
  return result;
}

/**
 * Business List Query Schema
 *
 * Validates pagination and filtering parameters for listing businesses.
 */
export const businessListQuerySchema = z.object({
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(100)
    .default(20),
  cursor: z
    .string()
    .optional(),
  sortBy: z
    .enum(['createdAt', 'name'])
    .default('createdAt'),
  sortOrder: z
    .enum(['asc', 'desc'])
    .default('desc'),
  industry: z
    .string()
    .max(INDUSTRY_MAX_LENGTH)
    .trim()
    .optional()
    .transform((val) => (val === '' ? undefined : val)),
});

export type BusinessListQuery = z.infer<typeof businessListQuerySchema>;
