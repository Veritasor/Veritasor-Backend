import { DISPOSABLE_EMAIL_DOMAINS } from "./data/disposableDomains.js";
import { hasRepeatingPattern, looksLikeRandomString } from "./patterns.js";
import {
  type AbusePreventionConfig,
  DEFAULT_ABUSE_PREVENTION_CONFIG,
  type EmailValidationResult,
} from "./types.js";

/**
 * Normalize an email address for persistence and authentication lookups.
 *
 * This is the **stored-form** normalizer shared by signup, login and
 * forgot-password:
 * - Trims whitespace
 * - Converts to lowercase
 * - **Preserves plus tags** (`a+x@b.com` stays `a+x@b.com`)
 *
 * Plus-stripping is intentionally not performed here. The plus-stripped form is
 * the canonical key for rate limiting / abuse detection (see `normalizeEmail`),
 * not the address a user signs in with.
 *
 * @param email - The email address to normalize
 * @returns Trimmed, lowercased email with plus tags preserved
 */
export function normalizeStoredEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Normalize an email address to its canonical abuse-detection form.
 * - Trims whitespace
 * - Converts to lowercase
 * - Removes plus-addressing (e.g., user+tag@gmail.com -> user@gmail.com)
 * - (Optionally) removes dots from Gmail addresses (not enabled by default)
 *
 * Use this only for rate limiting and duplicate-mailbox detection. Persist
 * `normalizeStoredEmail(email)` instead.
 *
 * @param email - The email address to normalize
 * @param options - Optional normalization options
 * @returns Canonical email address
 */
export function normalizeEmail(email: string, options?: { removeGmailDots?: boolean }): string {
  let normalized = email.trim().toLowerCase();
  // Remove plus-addressing (e.g., user+tag@gmail.com → user@gmail.com)
  const atIdx = normalized.indexOf('@');
  if (atIdx !== -1) {
    const local = normalized.slice(0, atIdx).split('+')[0];
    let domain = normalized.slice(atIdx + 1);
    // Optionally remove dots for Gmail addresses
    if (options?.removeGmailDots && (domain === 'gmail.com' || domain === 'googlemail.com')) {
      normalized = local.replace(/\./g, '') + '@' + domain;
    } else {
      normalized = local + '@' + domain;
    }
  }
  return normalized;
}

/**
 * Extract the domain from an email address.
 *
 * @param email - The email address
 * @returns The domain portion of the email
 */
export function extractEmailDomain(email: string): string {
  const normalized = normalizeEmail(email);
  const atIndex = normalized.lastIndexOf("@");
  if (atIndex === -1 || atIndex === normalized.length - 1) {
    return "";
  }
  return normalized.slice(atIndex + 1);
}

/**
 * Check if a domain is a known disposable email provider.
 *
 * @param domain - The domain to check
 * @returns True if the domain is disposable
 */
export function isDisposableDomain(domain: string): boolean {
  return DISPOSABLE_EMAIL_DOMAINS.has(domain.toLowerCase());
}

/**
 * Validate email format according to RFC 5322 (simplified).
 * This is a practical validation that catches most invalid emails
 * while allowing valid edge cases.
 *
 * @param email - The email address to validate
 * @param config - Abuse prevention configuration
 * @returns Email validation result with details
 */
export function validateEmail(
  email: string,
  config: AbusePreventionConfig = DEFAULT_ABUSE_PREVENTION_CONFIG,
): EmailValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  let suspicionScore = 0;

  // Check for empty email
  if (!email || typeof email !== "string") {
    return {
      isValid: false,
      storedEmail: "",
      canonicalEmail: "",
      normalizedEmail: "",
      domain: "",
      errors: ["Email is required"],
      warnings: [],
      isDisposable: false,
      isSuspicious: false,
      suspicionScore: 100,
    };
  }

  // Validate the stored form (plus tags preserved) and derive the canonical
  // abuse-detection form (plus tags stripped) separately.
  const storedEmail = normalizeStoredEmail(email);
  const canonicalEmail = normalizeEmail(email);
  const domain = extractEmailDomain(canonicalEmail);

  // Check email length against the value that will actually be persisted.
  if (storedEmail.length > config.maxEmailLength) {
    errors.push(`Email must not exceed ${config.maxEmailLength} characters`);
  }

  // Basic email format validation
  // This regex is more permissive than strict RFC 5322 but catches most issues
  const emailRegex =
    /^[^\s@"<>()\[\]\\,;:]+@[^\s@"<>()\[\]\\,;:]+\.[^\s@"<>()\[\]\\,;:]+$/;
  if (!emailRegex.test(storedEmail)) {
    errors.push("Invalid email format");
  }

  // Check for common format issues
  if (storedEmail.startsWith("@") || storedEmail.endsWith("@")) {
    errors.push("Email cannot start or end with @");
  }

  if (storedEmail.includes("@@")) {
    errors.push("Email cannot contain consecutive @ symbols");
  }

  // Check domain
  if (!domain) {
    errors.push("Email must have a valid domain");
  } else {
    // Check if domain has a TLD
    if (!domain.includes(".") || domain.split(".").pop()!.length < 2) {
      errors.push("Email domain must have a valid TLD");
    }

    // Check for disposable email
    if (config.blockDisposableEmails && isDisposableDomain(domain)) {
      errors.push("Disposable email addresses are not allowed");
      suspicionScore += 80;
    }
  }

  // Calculate suspicion score based on patterns

  // Use the canonical form for abuse heuristics so a random plus tag cannot
  // hide the underlying mailbox pattern.
  const localPart = canonicalEmail.split("@")[0] || "";
  if (localPart.length > 64) {
    warnings.push("Email local part is unusually long");
    suspicionScore += 20;
  }

  // Check for random-looking patterns
  if (looksLikeRandomString(localPart)) {
    warnings.push("Email local part appears randomly generated");
    suspicionScore += 30;
  }

  // Check for numeric-only local part
  if (/^\d+$/.test(localPart)) {
    warnings.push("Email local part consists only of numbers");
    suspicionScore += 40;
  }

  // Check for repeating patterns
  if (hasRepeatingPattern(localPart)) {
    warnings.push("Email contains repeating patterns");
    suspicionScore += 15;
  }

  const isSuspicious = suspicionScore >= config.suspiciousPatternThreshold;

  return {
    isValid: errors.length === 0,
    storedEmail,
    canonicalEmail,
    // Backward-compatible alias: canonical form, not the persisted address.
    normalizedEmail: canonicalEmail,
    domain,
    errors,
    warnings,
    isDisposable: isDisposableDomain(domain),
    isSuspicious,
    suspicionScore,
  };
}

/**
 * Get statistics about the disposable email domain list.
 * Useful for monitoring and testing.
 *
 * @returns Object with domain count
 */
export function getDisposableEmailStats(): { domainCount: number } {
  return {
    domainCount: DISPOSABLE_EMAIL_DOMAINS.size,
  };
}
