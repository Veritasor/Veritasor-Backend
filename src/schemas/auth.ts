import { z } from "zod";

/**
 * Login input validation schema
 *
 * Enforces:
 * - Email must be a valid email format, normalized to lowercase, trimmed
 * - Password must be a non-empty string with reasonable length limits
 * - Both fields are required
 */
export const loginInputSchema = z.object({
  email: z
    .string({
      required_error: "Email is required",
      invalid_type_error: "Email must be a string",
    })
    .trim()
    .min(1, "Email is required")
    .max(254, "Email must not exceed 254 characters")
    .email("Invalid email format")
    .transform((val) => val.toLowerCase()),

  password: z
    .string({
      required_error: "Password is required",
      invalid_type_error: "Password must be a string",
    })
    .min(1, "Password is required")
    .max(128, "Password must not exceed 128 characters"),
});

export type LoginInput = z.infer<typeof loginInputSchema>;