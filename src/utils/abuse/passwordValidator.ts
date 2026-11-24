import { COMMON_WEAK_PASSWORDS } from "./data/weakPasswords.js";
import { hasKeyboardPattern, hasSequentialChars } from "./patterns.js";
import {
  type AbusePreventionConfig,
  DEFAULT_ABUSE_PREVENTION_CONFIG,
  type PasswordValidationResult,
} from "./types.js";

/**
 * Validate password strength against security requirements.
 *
 * @param password - The password to validate
 * @param config - Abuse prevention configuration
 * @returns Password validation result with strength score
 */
export function validatePassword(
  password: string,
  config: AbusePreventionConfig = DEFAULT_ABUSE_PREVENTION_CONFIG,
): PasswordValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  let strengthScore = 0;

  // Check for empty password
  if (!password || typeof password !== "string") {
    return {
      isValid: false,
      errors: ["Password is required"],
      warnings: [],
      strengthScore: 0,
    };
  }

  // Check minimum length
  if (password.length < config.minPasswordLength) {
    errors.push(
      `Password must be at least ${config.minPasswordLength} characters`,
    );
  } else {
    strengthScore += 20;
  }

  // Check maximum length (prevent DoS via hashing)
  if (password.length > config.maxPasswordLength) {
    errors.push(
      `Password must not exceed ${config.maxPasswordLength} characters`,
    );
  }

  // Check for uppercase letters
  const hasUppercase = /[A-Z]/.test(password);
  if (config.requireUppercase && !hasUppercase) {
    errors.push("Password must contain at least one uppercase letter");
  } else if (hasUppercase) {
    strengthScore += 15;
  }

  // Check for lowercase letters
  const hasLowercase = /[a-z]/.test(password);
  if (config.requireLowercase && !hasLowercase) {
    errors.push("Password must contain at least one lowercase letter");
  } else if (hasLowercase) {
    strengthScore += 15;
  }

  // Check for numbers
  const hasNumbers = /[0-9]/.test(password);
  if (config.requireNumbers && !hasNumbers) {
    errors.push("Password must contain at least one number");
  } else if (hasNumbers) {
    strengthScore += 15;
  }

  // Check for special characters
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(
    password,
  );
  if (config.requireSpecialChars && !hasSpecialChars) {
    errors.push("Password must contain at least one special character");
  } else if (hasSpecialChars) {
    strengthScore += 15;
  }

  // Check for common weak passwords
  const lowerPassword = password.toLowerCase();
  if (COMMON_WEAK_PASSWORDS.has(lowerPassword)) {
    errors.push("Password is too common. Please choose a more unique password");
    strengthScore = Math.min(strengthScore, 10);
  }

  // Check for sequences
  if (hasSequentialChars(password)) {
    errors.push(
      "Password must not contain sequential characters (e.g., 'abc', '123')",
    );
    strengthScore -= 10;
  }

  // Check for keyboard patterns
  if (hasKeyboardPattern(password)) {
    errors.push("Password must not contain keyboard patterns (e.g., 'qwerty')");
    strengthScore -= 10;
  }

  // Bonus for length beyond minimum
  if (password.length >= 12) {
    strengthScore += 10;
  }
  if (password.length >= 16) {
    strengthScore += 10;
  }

  // Bonus for character variety
  const uniqueChars = new Set(password.toLowerCase()).size;
  if (uniqueChars >= password.length * 0.6) {
    strengthScore += 10;
  }

  // Ensure score is within bounds
  strengthScore = Math.max(0, Math.min(100, strengthScore));

  return {
    isValid: errors.length === 0,
    errors,
    warnings,
    strengthScore,
  };
}

/**
 * Get statistics about the weak password list.
 * Useful for monitoring and testing.
 *
 * @returns Object with password count
 */
export function getWeakPasswordStats(): { passwordCount: number } {
  return {
    passwordCount: COMMON_WEAK_PASSWORDS.size,
  };
}
