import { describe, it, expect, vi } from "vitest";
import request from "supertest";
import express from "express";
import { z } from "zod";
import { validateBody, validateQuery } from "./validate.js";
import { errorHandler } from "./errorHandler.js";
import { ValidationError } from "../types/errors.js";

describe("Validation Middleware", () => {
  const schema = z.object({
    id: z.string().uuid(),
    count: z.coerce.number().int().positive(),
  });

  describe("validateBody", () => {
    const app = express();
    app.use(express.json());
    app.post("/test", validateBody(schema), (req, res) => {
      res.json({ data: req.body });
    });
    app.use(errorHandler);

    it("passes valid body data and keeps the request state in the success path", async () => {
      const response = await request(app)
        .post("/test")
        .send({ id: "550e8400-e29b-41d4-a716-446655440000", count: 10 });

      expect(response.status).toBe(200);
      expect(response.body.data).toEqual({
        id: "550e8400-e29b-41d4-a716-446655440000",
        count: 10,
      });
    });

    it("forwards a ValidationError with structured details for invalid body input", async () => {
      const req = { body: { id: "not-a-uuid", count: -1 } } as any;
      const next = vi.fn();

      await validateBody(schema)(req, {} as any, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error).toBeInstanceOf(ValidationError);
      expect(error.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ path: ["id"] }),
          expect.objectContaining({ path: ["count"] }),
        ]),
      );
    });

    it("should return 400 for invalid request body", async () => {
      const response = await request(app)
        .post("/test")
        .send({ id: "not-a-uuid", count: -1 });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        status: "error",
        vrtCode: "VRT-0002",
        message: "Validation Error",
      });
      expect(response.body.errors).toHaveLength(2);
      expect(response.body.details).toHaveLength(2);
    });
  });

  describe("validateQuery", () => {
    const app = express();
    app.get("/test", validateQuery(schema), (req, res) => {
      res.json({ query: req.query });
    });
    app.use(errorHandler);

    it("accepts valid query params after coercion and preserves the successful state transition", async () => {
      const response = await request(app)
        .get("/test")
        .query({ id: "550e8400-e29b-41d4-a716-446655440000", count: "42" });

      expect(response.status).toBe(200);
      expect(response.body.query.count).toBe(42);
    });

    it("forwards ValidationError details for malformed query state", async () => {
      const req = { query: { id: "invalid", count: "not-a-number" } } as any;
      const next = vi.fn();

      await validateQuery(schema)(req, {} as any, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error).toBeInstanceOf(ValidationError);
      expect(error.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ path: ["id"] }),
          expect.objectContaining({ path: ["count"] }),
        ]),
      );
    });

    it("should return 400 for invalid query params", async () => {
      const response = await request(app)
        .get("/test")
        .query({ id: "invalid", count: "not-a-number" });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        status: "error",
        vrtCode: "VRT-0002",
        message: "Validation Error",
      });
      expect(response.body.errors).toHaveLength(2);
      expect(response.body.details).toHaveLength(2);
    });
  });
});
