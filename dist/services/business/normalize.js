/**
 * Business Service Normalization Utilities
 *
 * This module provides utility functions for normalizing and sanitizing
 * business data. These functions ensure consistent formatting and data
 * quality throughout the business service layer.
 *
 * Normalization includes:
 * - String trimming and case standardization
 * - URL formatting and normalization
 * - Null/empty value handling
 * - Data consistency rules
 *
 * @module services/business/normalize
 */
/**
 * Normalizes a business name string
 *
 * Operations:
 * - Trims whitespace
 * - Removes extra internal spaces
 * - Preserves case as provided by user
 *
 * @param name - The business name to normalize
 * @returns Normalized name, or empty string if input was empty
 *
 * @example
 * ```typescript
 * normalizeName('  ABC  Corp  ') // Returns 'ABC Corp'
 * normalizeName('   ') // Returns ''
 * ```
 */
export function normalizeName(name) {
    if (!name || typeof name !== 'string') {
        return '';
    }
    return name
        .trim()
        .split(/\s+/) // Split on any whitespace
        .filter((part) => part.length > 0)
        .join(' ');
}
/**
 * Normalizes a URL string
 *
 * Operations:
 * - Trims whitespace
 * - Converts to lowercase
 * - Adds https:// if no protocol is provided
 * - Removes trailing slashes
 *
 * @param url - The URL to normalize
 * @returns Normalized URL, or empty string if input was empty
 *
 * @example
 * ```typescript
 * normalizeUrl('  HTTPS://EXAMPLE.COM/  ') // Returns 'https://example.com'
 * normalizeUrl('example.com') // Returns 'https://example.com'
 * normalizeUrl('') // Returns ''
 * ```
 */
export function normalizeUrl(url) {
    if (!url || typeof url !== 'string') {
        return '';
    }
    let normalized = url.trim().toLowerCase();
    // Return empty string for empty/whitespace input
    if (!normalized) {
        return '';
    }
    // Add https:// if no protocol is present
    if (!normalized.match(/^https?:\/\//)) {
        normalized = `https://${normalized}`;
    }
    // Remove trailing slash (unless it's the root path after the domain)
    // Match: anything but ':' or '/' followed by a slash at end, replace with the preceding char
    while (normalized.endsWith('/') && !normalized.endsWith('://')) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
}
/**
 * Normalizes a string field to null or trimmed value
 *
 * Operations:
 * - Trims whitespace
 * - Returns null if result is empty string
 * - Otherwise returns trimmed value
 *
 * @param value - The value to normalize
 * @returns Normalized value (trimmed string or null)
 *
 * @example
 * ```typescript
 * normalizeOptionalString('  hello world  ') // Returns 'hello world'
 * normalizeOptionalString('   ') // Returns null
 * normalizeOptionalString(null) // Returns null
 * ```
 */
export function normalizeOptionalString(value) {
    if (typeof value !== 'string') {
        return null;
    }
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
}
/**
 * Normalizes the industry field
 *
 * Operations:
 * - Trims whitespace
 * - Returns null if empty
 * - Removes extra internal spaces
 * - Optionally lowercase for consistency (optional)
 *
 * @param industry - The industry value to normalize
 * @returns Normalized industry or null
 *
 * @example
 * ```typescript
 * normalizeIndustry('  Technology & Services  ') // Returns 'Technology & Services'
 * normalizeIndustry('') // Returns null
 * ```
 */
export function normalizeIndustry(industry) {
    if (typeof industry !== 'string') {
        return null;
    }
    return industry
        .trim()
        .split(/\s+/)
        .filter((part) => part.length > 0)
        .join(' ') || null;
}
/**
 * Normalizes the description field
 *
 * Operations:
 * - Trims whitespace
 * - Replaces multiple spaces with single space
 * - Preserves newlines (for multiline descriptions)
 * - Returns null if empty
 *
 * @param description - The description to normalize
 * @returns Normalized description or null
 *
 * @example
 * ```typescript
 * normalizeDescription('  Multiple   spaces  ') // Returns 'Multiple spaces'
 * normalizeDescription('Line 1\\nLine 2') // Returns 'Line 1\\nLine 2'
 * ```
 */
export function normalizeDescription(description) {
    if (typeof description !== 'string') {
        return null;
    }
    const trimmed = description.trim();
    if (!trimmed) {
        return null;
    }
    // Replace multiple spaces within lines with single space, but preserve newlines
    return trimmed
        .split('\n')
        .map((line) => line
        .split(/\s+/)
        .filter((part) => part.length > 0)
        .join(' '))
        .join('\n');
}
/**
 * Validator: Check if string contains only valid business name characters
 *
 * Valid characters: alphanumeric, spaces, hyphens, apostrophes, ampersands, periods, commas
 * Rejects: control characters, newlines, special symbols
 *
 * @param name - The name to validate
 * @returns true if valid, false otherwise
 *
 * @example
 * ```typescript
 * isValidBusinessName("John's Co.") // Returns true
 * isValidBusinessName("Company<script>") // Returns false
 * isValidBusinessName("Company\nName") // Returns false (newlines not allowed)
 * ```
 */
export function isValidBusinessName(name) {
    // Check for newlines and other control characters
    if (/[\n\r\t\v\f]/.test(name)) {
        return false;
    }
    const pattern = /^[a-zA-Z0-9\s\-'&.,]+$/;
    return pattern.test(name);
}
/**
 * Validator: Check if string is a valid URL
 *
 * Supports http, https, www formats, and basic domain names.
 *
 * @param url - The URL to validate
 * @returns true if valid, false otherwise
 *
 * @example
 * ```typescript
 * isValidUrl('https://example.com') // Returns true
 * isValidUrl('example.com') // Returns true
 * isValidUrl('www.example.com') // Returns true
 * isValidUrl('not a url') // Returns false
 * ```
 */
export function isValidUrl(url) {
    const pattern = /^(https?:\/\/)?(www\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}|localhost|127\.0\.0\.1)(:[0-9]+)?(\/[^\s]*)?$/;
    return pattern.test(url);
}
/**
 * Sanitizer: Remove or escape HTML/XML characters that could cause issues
 *
 * This is a defensive measure - validation schemas should catch most issues.
 * This function removes potentially dangerous characters.
 *
 * @param text - The text to sanitize
 * @returns Sanitized text
 *
 * @example
 * ```typescript
 * sanitizeText('<script>alert("xss")</script>') // Returns 'scriptalertxssscript'
 * ```
 */
export function sanitizeText(text) {
    if (typeof text !== 'string') {
        return '';
    }
    // Remove HTML/XML tags entirely
    return text.replace(/<[^>]*>/g, '');
}
/**
 * Validator: Check if value represents empty/null
 *
 * @param value - Value to check
 * @returns true if value should be treated as empty/null
 *
 * @example
 * ```typescript
 * isEmpty('   ') // Returns true
 * isEmpty(null) // Returns true
 * isEmpty('hello') // Returns false
 * ```
 */
export function isEmpty(value) {
    if (value === null || value === undefined) {
        return true;
    }
    if (typeof value === 'string') {
        return value.trim().length === 0;
    }
    return false;
}
/**
 * Formatter: Convert business data to consistent format for storage
 *
 * Typical transformations:
 * - Empty strings → null
 * - URLs → normalized format
 * - Names → trimmed, no extra spaces
 *
 * @param data - Raw business data
 * @returns Formatted data ready for database
 *
 * @example
 * ```typescript
 * formatForStorage({
 *   name: '  My Co  ',
 *   website: 'Example.com',
 *   industry: null
 * })
 * // Returns: {
 * //   name: 'My Co',
 * //   website: 'https://example.com',
 * //   industry: null
 * // }
 * ```
 */
export function formatForStorage(data) {
    const result = {};
    if (data.name !== undefined) {
        result.name = normalizeName(data.name);
    }
    if (data.industry !== undefined) {
        result.industry = typeof data.industry === 'string' ? normalizeIndustry(data.industry) : data.industry;
    }
    if (data.description !== undefined) {
        result.description = typeof data.description === 'string' ? normalizeDescription(data.description) : data.description;
    }
    if (data.website !== undefined) {
        result.website = typeof data.website === 'string' ? normalizeUrl(data.website) : data.website;
    }
    return result;
}
