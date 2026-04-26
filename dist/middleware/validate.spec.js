import { describe, it, expect } from "vitest";
import request from "supertest";
import express from "express";
import { z } from "zod";
import { validateBody, validateQuery } from "./validate.js";
import { errorHandler } from "./errorHandler.js";
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
        it("should return 400 for invalid query params", async () => {
            const response = await request(app)
                .get("/test")
                .query({ id: "invalid", count: "not-a-number" });
            expect(response.status).toBe(400);
            expect(response.body.code).toBe("VALIDATION_ERROR");
        });
    });
});
