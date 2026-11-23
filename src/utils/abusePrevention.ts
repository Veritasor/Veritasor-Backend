/**
 * Abuse Prevention Utilities for Signup
 *
 * This module provides heuristics and validation functions to prevent
 * automated abuse of the signup endpoint, including:
 * - Disposable email domain detection
 * - Password strength validation
 * - Email pattern analysis
 * - Suspicious activity scoring
 *
 * @module abusePrevention
 */

export {
  type EmailValidationResult,
  type PasswordValidationResult,
  type AbusePreventionConfig,
  DEFAULT_ABUSE_PREVENTION_CONFIG,
} from "./abuse/types.js";

export {
  normalizeStoredEmail,
  normalizeEmail,
  extractEmailDomain,
  isDisposableDomain,
  validateEmail,
  getDisposableEmailStats,
} from "./abuse/emailValidator.js";

export {
  validatePassword,
  getWeakPasswordStats,
} from "./abuse/passwordValidator.js";

export {
  looksLikeRandomString,
  hasRepeatingPattern,
  hasSequentialChars,
  hasKeyboardPattern,
} from "./abuse/patterns.js";

export {
  calculateBackoffDelay,
  timingSafeEqual,
  addTimingDelay,
} from "./abuse/timing.js";
