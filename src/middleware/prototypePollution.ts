import type { Request, Response, NextFunction } from "express";

export const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Recursively inspects an object or array for forbidden prototype pollution keys.
 *
 * @param obj - The value to inspect (object, array, primitive).
 * @param maxDepth - Maximum recursion depth bound (default 30).
 * @param maxKeys - Maximum number of inspected keys/items bound (default 2000).
 * @returns True if a forbidden key is found, false otherwise.
 */
export function hasForbiddenKeys(
  obj: unknown,
  maxDepth = 30,
  maxKeys = 2000,
): boolean {
  if (obj === null || typeof obj !== "object") {
    return false;
  }

  let visitedCount = 0;
  const seen = new WeakSet<object>();

  function check(current: unknown, depth: number): boolean {
    if (depth > maxDepth) {
      return false;
    }
    if (current === null || typeof current !== "object") {
      return false;
    }

    if (seen.has(current)) {
      return false;
    }
    seen.add(current);

    if (Array.isArray(current)) {
      for (const item of current) {
        if (++visitedCount > maxKeys) return false;
        if (check(item, depth + 1)) return true;
      }
      return false;
    }

    const keys = Object.getOwnPropertyNames(current);
    for (const key of keys) {
      if (++visitedCount > maxKeys) return false;
      if (FORBIDDEN_KEYS.has(key)) {
        return true;
      }
      try {
        const val = (current as Record<string, unknown>)[key];
        if (check(val, depth + 1)) {
          return true;
        }
      } catch {
        // Skip inaccessible properties
      }
    }

    return false;
  }

  return check(obj, 0);
}

/**
 * Checks if the request query contains forbidden prototype pollution keys,
 * inspecting both parsed req.query objects and raw query parameters (including bracket notation).
 *
 * @param req - Express Request object.
 * @returns True if forbidden keys are present in query, false otherwise.
 */
export function hasForbiddenQuery(req: Request): boolean {
  if (req.query && hasForbiddenKeys(req.query)) {
    return true;
  }

  const url = req.originalUrl || req.url || "";
  const qIndex = url.indexOf("?");
  if (qIndex !== -1) {
    const rawQuery = url.slice(qIndex + 1);
    const params = new URLSearchParams(rawQuery);
    for (const [paramKey] of params.entries()) {
      const segments = paramKey.split(/[\[\]]+/).filter(Boolean);
      for (const segment of segments) {
        if (FORBIDDEN_KEYS.has(segment)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Express middleware that rejects requests containing __proto__, constructor, or prototype
 * keys in query parameters or body payloads.
 */
export const prototypePollutionGuard = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  if (hasForbiddenQuery(req)) {
    res.status(400).json({
      status: "error",
      code: "VALIDATION_ERROR",
      message: "Invalid query parameters",
    });
    return;
  }

  if (req.body && hasForbiddenKeys(req.body)) {
    res.status(400).json({
      status: "error",
      code: "VALIDATION_ERROR",
      message: "Invalid body fields",
    });
    return;
  }

  next();
};
