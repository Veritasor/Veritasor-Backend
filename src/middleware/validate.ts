import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import { ValidationError } from "../types/errors.js";

export const validateBody = (schema: z.ZodSchema) => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.body = await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return next(new ValidationError(error.issues.map((i) => ({ path: i.path, message: i.message }))));
      }
      next(error);
    }
  };
};

export const validateQuery = (schema: z.ZodSchema) => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.query = (await schema.parseAsync(req.query)) as any;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return next(new ValidationError(error.issues.map((i) => ({ path: i.path, message: i.message }))));
      }
      next(error);
    }
  };
};
