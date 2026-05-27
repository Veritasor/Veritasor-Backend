import { z } from "zod";
import {
  validatePassword,
  DEFAULT_ABUSE_PREVENTION_CONFIG,
} from "../utils/abusePrevention.js";

// token validation 

/**
 * Regex for a 64-character lowercase hex string.
 * 32 random bytes → 64 hex chars [0-9a-f].
 */
const TOKEN_HEX_64_REGEX = /^[0-9a-f]{64}$/;

const tokenSchema = z
  .string({
    required_error: "Token is required",
    invalid_type_error: "Token must be a string",
  })
  .min(1, "Token is required")
  .regex(
    TOKEN_HEX_64_REGEX,
    "Token must be a 64-character lowercase hexadecimal string"
  );

//password validation 

/**
 * Custom Zod refinement that reuses the signup password validator.
 * This guarantees identical strength rules across all password flows.
 */
const passwordSchema = z
  .string({
    required_error: "New password is required",
    invalid_type_error: "New password must be a string",
  })
  .min(1, "New password is required")
  .superRefine((password, ctx) => {
    const result = validatePassword(password, DEFAULT_ABUSE_PREVENTION_CONFIG);

    if (!result.isValid) {
      result.errors.forEach((error) => {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: error,
          fatal: true,
        });
      });
    }
  });

//composite schema

/**
 * Reset password request schema.
 *
 * @example Valid payload
 * {
 *   token: "aabbccdd... (64 hex chars)",
 *   newPassword: "SecureP@ss123"
 * }
 */
export const resetPasswordSchema = z.object({
  token: tokenSchema,
  newPassword: passwordSchema,
});

/**
 * Inferred TypeScript type from the schema.
 */
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;