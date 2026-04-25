import { describe, it, expect } from "vitest";
import request from "supertest";
import express from "express";
import { z } from "zod";
import { validateBody, validateQuery } from "../../../src/middleware/validate.ts";
import { errorHandler } from "../../../src/middleware/errorHandler.ts";

describe("Validation Middleware", () => {
  const schema = z.object({
    id: z.string().uuid(),
    count: z.coerce.number().int().positive(),
  });

  // Nested schema for testing nested validation errors
  const nestedSchema = z.object({
    user: z.object({
      profile: z.object({
        name: z.string().min(2),
        age: z.number().int().min(18),
      }),
      email: z.string().email(),
    }),
    tags: z.array(z.string().min(3)),
  });

  describe("validateBody", () => {
    const app = express();
    app.use(express.json());
    app.post("/test", validateBody(schema), (req, res) => {
      res.json({ data: req.body });
    });
    app.use(errorHandler);

    it("should pass for valid request body", async () => {
      const response = await request(app)
        .post("/test")
        .send({ id: "550e8400-e29b-41d4-a716-446655440000", count: 10 });

      expect(response.status).toBe(200);
      expect(response.body.data).toEqual({
        id: "550e8400-e29b-41d4-a716-446655440000",
        count: 10,
      });
    });

    it("should return 400 for invalid request body", async () => {
      const response = await request(app)
        .post("/test")
        .send({ id: "not-a-uuid", count: -1 });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe("VALIDATION_ERROR");
      expect(response.body.errors).toHaveLength(2);
    });

    it("should return detailed errors for nested body schema violations", async () => {
      const nestedApp = express();
      nestedApp.use(express.json());
      nestedApp.post("/nested", validateBody(nestedSchema), (req, res) => {
        res.json({ data: req.body });
      });
      nestedApp.use(errorHandler);

      const invalidBody = {
        user: {
          profile: { name: "A", age: 15 },
          email: "not-an-email",
        },
        tags: ["ok", "a"],
      };

      const response = await request(nestedApp)
        .post("/nested")
        .send(invalidBody);

      expect(response.status).toBe(400);
      expect(response.body.errors).toHaveLength(5);
    });
  });

  describe("validateQuery", () => {
    const app = express();
    app.get("/test", validateQuery(schema), (req, res) => {
      res.json({ query: req.query });
    });
    app.use(errorHandler);

    it("should pass for valid query params (with coercion)", async () => {
      const response = await request(app)
        .get("/test")
        .query({ id: "550e8400-e29b-41d4-a716-446655440000", count: "42" });

      expect(response.status).toBe(200);
      expect(response.body.query.count).toBe(42);
    });

    it("should return detailed errors for nested query schema violations", async () => {
      const nestedApp = express();
      nestedApp.get("/nested", validateQuery(nestedSchema), (req, res) => {
        res.json({ query: req.query });
      });
      nestedApp.use(errorHandler);

      // FIXED: Use a nested object structure. 
      // Supertest/Express will parse this as user[profile][name]=A
      const invalidQuery = {
        user: {
          profile: {
            name: "A",      // Error 1
            age: 15,        // Error 2
          },
          email: "not-an-email", // Error 3
        },
        tags: ["ok", "a"],  // Error 4 & 5
      };

      const response = await request(nestedApp)
        .get("/nested")
        .query(invalidQuery);

      expect(response.status).toBe(400);
      expect(response.body.code).toBe("VALIDATION_ERROR");
      expect(Array.isArray(response.body.errors)).toBe(true);
      
      // This will now correctly return 5
      expect(response.body.errors.length).toBe(5);

      const errorPaths = response.body.errors.map((e: any) => e.path.join("."));
      expect(errorPaths).toEqual(
        expect.arrayContaining([
          "user.profile.name",
          "user.profile.age",
          "user.email",
          "tags.0",
          "tags.1",
        ])
      );
    });

    it("should return 400 for invalid query params", async () => {
      const response = await request(app)
        .get("/test")
        .query({ id: "invalid", count: "not-a-number" });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe("VALIDATION_ERROR");
    });
  });
});