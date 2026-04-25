import { z } from "zod";
import { ValidationError } from "../types/errors.js";
export const validateBody = (schema) => {
    return async (req, _res, next) => {
        try {
            req.body = await schema.parseAsync(req.body);
            next();
        }
        catch (error) {
            if (error instanceof z.ZodError) {
                return next(new ValidationError(error.issues));
            }
            next(error);
        }
    };
};
export const validateQuery = (schema) => {
    return async (req, _res, next) => {
        try {
            req.query = (await schema.parseAsync(req.query));
            next();
        }
        catch (error) {
            if (error instanceof z.ZodError) {
                return next(new ValidationError(error.issues));
            }
            next(error);
        }
    };
};
