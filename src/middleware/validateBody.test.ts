import type { NextFunction, Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { validateBody } from "./validateBody.js";

const schema = z.object({
  name: z.string().min(1, "name cannot be empty"),
  profile: z.object({
    age: z.number().int().min(18, "age must be at least 18"),
  }),
});

function invoke(body: unknown) {
  const req = { body } as Request & { validatedBody?: z.infer<typeof schema> };
  const status = vi.fn().mockReturnThis();
  const json = vi.fn();
  const res = { status, json } as unknown as Response;
  const next = vi.fn() as NextFunction;

  validateBody(schema)(req, res, next);

  return { req, status, json, next };
}

describe("validateBody", () => {
  it("passes parsed data to downstream middleware without changing req.body", () => {
    const body = { name: "Ada", profile: { age: 18 }, extra: "discarded" };
    const { req, status, json, next } = invoke(body);

    expect(req.validatedBody).toEqual({ name: "Ada", profile: { age: 18 } });
    expect(req.body).toBe(body);
    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it("returns a 400 envelope with every nested and top-level validation issue", () => {
    const { req, status, json, next } = invoke({ name: "", profile: { age: 17 } });

    expect(status).toHaveBeenCalledExactlyOnceWith(400);
    expect(json).toHaveBeenCalledExactlyOnceWith({
      error: "Validation Error",
      details: [
        "name: name cannot be empty",
        "profile.age: age must be at least 18",
      ],
    });
    expect(req.validatedBody).toBeUndefined();
    expect(next).not.toHaveBeenCalled();
  });

  it("labels root-level failures as body and does not advance", () => {
    const { req, status, json, next } = invoke(null);

    expect(status).toHaveBeenCalledExactlyOnceWith(400);
    expect(json).toHaveBeenCalledExactlyOnceWith({
      error: "Validation Error",
      details: ["body: Expected object, received null"],
    });
    expect(req.validatedBody).toBeUndefined();
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects missing required fields without producing validated data", () => {
    const { req, status, json, next } = invoke({});

    expect(status).toHaveBeenCalledExactlyOnceWith(400);
    expect(json).toHaveBeenCalledExactlyOnceWith({
      error: "Validation Error",
      details: ["name: Required", "profile: Required"],
    });
    expect(req.validatedBody).toBeUndefined();
    expect(next).not.toHaveBeenCalled();
  });
});
