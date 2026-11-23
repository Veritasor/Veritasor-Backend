import type { NextFunction, Request, Response } from "express";

const prohibitedKeys = new Set(["__proto__", "constructor", "prototype"]);

function containsProhibitedKey(value: unknown, seen = new WeakSet<object>): boolean {
  if (!value || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);

  for (const key of Object.keys(value)) {
    if (prohibitedKeys.has(key)) return true;
    if (containsProhibitedKey((value as Record<string, unknown>)[key], seen)) {
      return true;
    }
  }

  return false;
}

export const prototypePollutionGuard = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  if (containsProhibitedKey(req.query)) {
    res.status(400).json({
      status: "error",
      code: "VALIDATION_ERROR",
      message: "Invalid query parameters",
    });
    return;
  }

  if (containsProhibitedKey(req.body)) {
    res.status(400).json({
      status: "error",
      code: "VALIDATION_ERROR",
      message: "Invalid body fields",
    });
    return;
  }

  next();
};
