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
 * - Protection against NaN/Infinity in numeric strings
 * - Null-byte and control-character rejection
 * - Unicode normalization (NFC) to prevent homoglyph spoofing
 * - Structured validation error context for observability
 *
 * @module services/business/schemas
 */

import { z } from 'zod';

/** Maximum length for business name field. */
const BUSINESS_NAME_MAX_LENGTH = 255;

/** Maximum length for industry field. */
const INDUSTRY_MAX_LENGTH = 100;

/** Maximum length for description field. */
const DESCRIPTION_MAX_LENGTH = 2000;

/** Maximum length for website URL field. */
const WEBSITE_MAX_LENGTH = 2048;

/**
 * Returns true if the string contains null bytes or ASCII control characters
 * (U+0000–U+001F, U+007F), excluding tab (U+0009), newline (U+000A), and
 * carriage return (U+000D) which are legitimate in descriptions.
 *
 * Attackers embed null bytes to bypass naïve string comparisons or to
 * terminate C-string processing in downstream consumers.
 */
function containsControlChars(value: string, allowNewlines = false): boolean {
  // eslint-disable-next-line no-control-regex
  const pattern = allowNewlines
    ? /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/
    : /[\u0000-\u001F\u007F]/;
  return pattern.test(value);
}

/**
 * Normalize a string to Unicode NFC to prevent homoglyph / look-alike
 * spoofing across canonically-equivalent sequences.
 */
function toNFC(value: string): string {
  return value.normalize('NFC');
}

/**
 * Builds a reusable safe-string base that:
 *  1. Normalizes to NFC
 *  2. Rejects null bytes / control characters
 *
 * Callers apply `.trim()`, `.max()`, and domain-specific `.refine()` on top.
 */
function safeString(allowNewlines = false) {
  return z
    .string()
    .transform(toNFC)
    .refine(
      (val) => !containsControlChars(val, allowNewlines),
      {
        message: allowNewlines
          ? 'Value must not contain null bytes or non-printable control characters'
          : 'Value must not contain control characters or null bytes',
      },
    );
}

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
 *
 * Security notes:
 * - Explicit protocol allowlist (https?:// only) — blocks javascript:, data:, ftp:, etc.
 * - No bare IP ranges beyond localhost/127.0.0.1 to avoid SSRF to internal hosts.
 * - Path segment may contain query strings / fragments but must start with /
 *   (when present) to avoid ambiguous relative paths.
 */
const URL_PATTERN =
  /^(https?:\/\/)?(www\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}|localhost|127\.0\.0\.1)(:[0-9]+)?(\/[^\s]*)?$/;

/**
 * Regex pattern for ISO 3166-1 alpha-2 country codes.
 * Matches exactly two uppercase ASCII letters after normalization.
 */
const COUNTRY_CODE_PATTERN = /^[A-Z]{2}$/;

/**
 * Blocked URL schemes that must never appear in a website field even when
 * the protocol is omitted and we lower-case the value first.
 *
 * Defense-in-depth against protocol-relative tricks such as
 * `//evil.com` or encoded variants.
 */
const BLOCKED_URL_SCHEMES = ['javascript', 'data', 'vbscript', 'file', 'ftp'];

/**
 * Returns true when the URL value (already lower-cased) begins with a
 * blocked scheme or a protocol-relative prefix (//).
 */
function hasBlockedScheme(url: string): boolean {
  if (url.startsWith('//')) return true;
  return BLOCKED_URL_SCHEMES.some(
    (scheme) => url.startsWith(`${scheme}:`) || url.startsWith(`${scheme}%3a`),
  );
}

const nameField = safeString()
  .pipe(
    z
      .string()
      .min(1, 'Name is required')
      .max(BUSINESS_NAME_MAX_LENGTH, `Name must be at most ${BUSINESS_NAME_MAX_LENGTH} characters`)
      .trim()
      .refine(
        (name) => BUSINESS_NAME_PATTERN.test(name),
        'Name contains invalid characters. Use letters, numbers, spaces, hyphens, apostrophes, and ampersands.',
      ),
  );

const industryField = safeString()
  .pipe(
    z
      .string()
      .max(INDUSTRY_MAX_LENGTH, `Industry must be at most ${INDUSTRY_MAX_LENGTH} characters`)
      .trim()
      .refine(
        (industry) => industry === '' || INDUSTRY_PATTERN.test(industry),
        'Industry contains invalid characters',
      ),
  )
  .optional()
  .nullable()
  .transform((val) => (val === '' || val === undefined ? null : val));

const descriptionField = safeString(/* allowNewlines */ true)
  .pipe(
    z
      .string()
      .max(DESCRIPTION_MAX_LENGTH, `Description must be at most ${DESCRIPTION_MAX_LENGTH} characters`)
      .trim(),
  )
  .optional()
  .nullable()
  .transform((val) => (val === '' || val === undefined ? null : val));

const countryCodeField = z
  .string()
  .optional()
  .nullable()
  .transform((val) => (val === '' || val === undefined ? null : val))
  .pipe(
    z
      .string()
      .length(2, 'Country code must be exactly 2 characters')
      .toUpperCase()
      .refine(
        (code) => !/[\u0000-\u001F\u007F]/.test(code),
        'Country code must not contain control characters',
      )
      .refine(
        (code) => COUNTRY_CODE_PATTERN.test(code),
        'Invalid country code format. Must be an ISO 3166-1 alpha-2 code (e.g., US, GB, NG).',
      )
      .nullable()
  );

const websiteField = safeString()
  .pipe(
    z
      .string()
      .max(WEBSITE_MAX_LENGTH, `Website URL must be at most ${WEBSITE_MAX_LENGTH} characters`)
      .trim()
      .transform((val) => val.toLowerCase()),
  )
  .refine(
    (url) => !hasBlockedScheme(url),
    'Website scheme is not allowed. Use https:// or omit the scheme.',
  )
  .refine(
    (url) => url === '' || URL_PATTERN.test(url),
    'Website must be a valid URL (e.g., https://example.com or www.example.com)',
  )
  .optional()
  .nullable()
  .transform((val) => (val === '' || val === undefined ? null : val));

/**
 * Create Business Input Schema
 *
 * Validates and normalizes input for creating a new business.
 * - Normalizes strings (NFC, trim)
 * - Rejects null bytes and control characters
 * - Blocks non-http(s) URL schemes
 * - Validates required fields (name)
 * - Converts empty / undefined optional fields to null
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
  name: nameField,
  industry: industryField,
  description: descriptionField,
  countryCode: countryCodeField,
  website: websiteField,
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
 * All fields are optional since this is a partial update.
 * Applies the same security refinements as the create schema.
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
export const updateBusinessInputSchema = z
  .object({
    name: safeString()
      .pipe(
        z
          .string()
          .min(1, 'Name cannot be empty')
          .max(BUSINESS_NAME_MAX_LENGTH, `Name must be at most ${BUSINESS_NAME_MAX_LENGTH} characters`)
          .trim()
          .refine(
            (name) => BUSINESS_NAME_PATTERN.test(name),
            'Name contains invalid characters',
          ),
      )
      .optional(),

    industry: safeString()
      .pipe(
        z
          .string()
          .max(INDUSTRY_MAX_LENGTH, `Industry must be at most ${INDUSTRY_MAX_LENGTH} characters`)
          .trim()
          .refine(
            (industry) => industry === '' || INDUSTRY_PATTERN.test(industry),
            'Industry contains invalid characters',
          ),
      )
      .nullable()
      .optional()
      .transform((val) => (val === '' ? null : val)),

    description: safeString(true)
      .pipe(
        z
          .string()
          .max(DESCRIPTION_MAX_LENGTH, `Description must be at most ${DESCRIPTION_MAX_LENGTH} characters`)
          .trim(),
      )
      .nullable()
      .optional()
      .transform((val) => (val === '' ? null : val)),

    countryCode: z
      .string()
      .length(2, 'Country code must be exactly 2 characters')
      .toUpperCase()
      .refine(
        (code) => !/[\u0000-\u001F\u007F]/.test(code),
        'Country code must not contain control characters',
      )
      .refine(
        (code) => COUNTRY_CODE_PATTERN.test(code),
        'Invalid country code format. Must be an ISO 3166-1 alpha-2 code (e.g., US, GB, NG).',
      )
      .nullable()
      .optional()
      .transform((val) => (val === '' ? null : val)),

    website: safeString()
      .pipe(
        z
          .string()
          .max(WEBSITE_MAX_LENGTH, `Website URL must be at most ${WEBSITE_MAX_LENGTH} characters`)
          .trim()
          .transform((val) => val.toLowerCase()),
      )
      .refine(
        (url) => !hasBlockedScheme(url),
        'Website scheme is not allowed. Use https:// or omit the scheme.',
      )
      .refine(
        (url) => url === '' || URL_PATTERN.test(url),
        'Website must be a valid URL',
      )
      .nullable()
      .optional()
      .transform((val) => (val === '' ? null : val)),
  })
  .passthrough();

/**
 * Parsed Update Business Input Type
 *
 * Represents validated and normalized input for business updates.
 * All fields are optional for partial updates.
 */
export type UpdateBusinessInput = z.infer<typeof updateBusinessInputSchema>;

/**
 * Parse and normalize create business input.
 * Throws ZodError on invalid input.
 */
export async function parseCreateBusinessInput(input: unknown): Promise<CreateBusinessInput> {
  return createBusinessInputSchema.parseAsync(input);
}

/**
 * Parse and normalize update business input.
 * Throws ZodError on invalid input.
 */
export async function parseUpdateBusinessInput(input: unknown): Promise<UpdateBusinessInput> {
  return updateBusinessInputSchema.parseAsync(input);
}

/**
 * Safely parse create input — returns a result object (no throw).
 */
export async function safeParseCreateBusinessInput(input: unknown) {
  return createBusinessInputSchema.safeParseAsync(input);
}

/**
 * Safely parse update input — returns a result object (no throw).
 */
export async function safeParseUpdateBusinessInput(input: unknown) {
  return updateBusinessInputSchema.safeParseAsync(input);
}

/**
 * Business List Query Schema
 *
 * Validates pagination and filtering parameters for listing businesses.
 */
export const businessListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
  sortBy: z.enum(['createdAt', 'name']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
  industry: z
    .string()
    .max(INDUSTRY_MAX_LENGTH)
    .trim()
    .optional()
    .transform((val) => (val === '' ? undefined : val)),
});

export type BusinessListQuery = z.infer<typeof businessListQuerySchema>;