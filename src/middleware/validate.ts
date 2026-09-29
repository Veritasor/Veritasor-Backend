import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import { ValidationError } from "../types/errors.js";

export const validateBody = (schema: z.ZodSchema) => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.body = await schema.parseAsync(req.body);
      return next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const validationError = new ValidationError(
          error.issues.map((issue) => ({ path: issue.path, message: issue.message })),
        );
        return next(validationError);
      }
      return next(error);
    }
  };
};

export const validateQuery = (schema: z.ZodSchema) => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.query = (await schema.parseAsync(req.query)) as any;
      return next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const validationError = new ValidationError(
          error.issues.map((issue) => ({ path: issue.path, message: issue.message })),
        );
        return next(validationError);
      }
      return next(error);
    }
  };
};
