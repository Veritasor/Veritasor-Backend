import { Request, Response, NextFunction } from "express";
import { ZodSchema, ZodError } from "zod";
import { ValidationError } from "../types/errors.js";

/**
 * Create an Express middleware that validates req.body against a Zod schema.
 *
 * @param schema - Zod schema to validate against
 * @returns Express middleware function
 *
 * @example
 * router.post("/reset-password", validateBody(resetPasswordSchema), handler);
 */
export function validateBody<T>(schema: ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const issues = formatZodIssues(result.error);
      const validationError = new ValidationError(issues);
      res.status(validationError.status).json({
        error: validationError.message,
        details: validationError.details,
      });
      return;
    }

    // Attach validated data to request for downstream use
    (req as Request & { validatedBody: T }).validatedBody = result.data;
    next();
  };
}

/**
 * Flatten ZodError issues into a string array for the ValidationError envelope.
 */
function formatZodIssues(error: ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join(".") : "body";
    return `${path}: ${issue.message}`;
  });
}