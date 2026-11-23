/**
 * Result of email validation
 */
export interface EmailValidationResult {
  isValid: boolean;
  /**
   * Trimmed + lowercased address exactly as it should be persisted. Plus tags
   * are preserved so users can log in with the address they typed.
   */
  storedEmail: string;
  /**
   * Canonical plus-stripped form used only for rate limiting and duplicate-mailbox
   * abuse detection. Never persist this as the account email.
   */
  canonicalEmail: string;
  /**
   * @deprecated Canonical form retained for backward compatibility. Use
   * `storedEmail` for persistence and `canonicalEmail` for rate limiting.
   */
  normalizedEmail: string;
  domain: string;
  errors: string[];
  warnings: string[];
  isDisposable: boolean;
  isSuspicious: boolean;
  suspicionScore: number; // 0-100, higher = more suspicious
}

/**
 * Result of password validation
 */
export interface PasswordValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  strengthScore: number; // 0-100, higher = stronger
}

/**
 * Configuration for abuse prevention
 */
export interface AbusePreventionConfig {
  minPasswordLength: number;
  maxPasswordLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  blockDisposableEmails: boolean;
  maxEmailLength: number;
  suspiciousPatternThreshold: number;
}

/**
 * Default configuration for abuse prevention
 */
export const DEFAULT_ABUSE_PREVENTION_CONFIG: AbusePreventionConfig = {
  minPasswordLength: 8,
  maxPasswordLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  blockDisposableEmails: true,
  maxEmailLength: 254, // RFC 5321 max length
  suspiciousPatternThreshold: 50,
};
