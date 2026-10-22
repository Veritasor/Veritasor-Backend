import { describe, it, expect } from "vitest";
import request from "supertest";
import { createApp } from "../app.js";
import { hasForbiddenKeys } from "../middleware/prototypePollution.js";
import type { StartupReadinessReport } from "../startup/readiness.js";

const READY_REPORT: StartupReadinessReport = { ready: true, checks: [] };

describe("Prototype Pollution Guard", () => {
  const app = createApp(READY_REPORT);

  describe("JSON body pollution protection", () => {
    it("returns 400 VALIDATION_ERROR for top-level __proto__ in JSON body", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send('{"__proto__":{"isAdmin":true},"email":"a@b.c","password":"x"}');

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid body fields",
      });
    });

    it("returns 400 VALIDATION_ERROR for nested constructor key", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send('{"a":{"b":{"constructor":{}}},"email":"a@b.c","password":"x"}');

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid body fields",
      });
    });

    it("returns 400 VALIDATION_ERROR for nested prototype key", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send('{"a":{"prototype":{"polluted":true}},"email":"a@b.c","password":"x"}');

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid body fields",
      });
    });

    it("returns 400 VALIDATION_ERROR for forbidden key inside array elements", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send('[{"__proto__":{"polluted":true}}]');

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid body fields",
      });
    });

    it("accepts legitimate body containing the string value 'constructor' as a value", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send({
          email: "constructor@example.com",
          password: "my_constructor_pass",
          note: "constructor",
        });

      // Must not be rejected by the prototype pollution guard
      expect(res.body?.message).not.toBe("Invalid body fields");
      expect(res.status).not.toBe(500);
    });

    it("accepts arrays containing forbidden strings as values rather than keys", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send({
          email: "valid@example.com",
          password: "password123",
          tags: ["constructor", "__proto__", "prototype"],
        });

      expect(res.body?.message).not.toBe("Invalid body fields");
      expect(res.status).not.toBe(500);
    });
  });

  describe("Query string pollution protection", () => {
    it("returns 400 VALIDATION_ERROR for nested query ?a[__proto__][x]=1", async () => {
      const res = await request(app).get("/api/health/live?a[__proto__][x]=1");

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid query parameters",
      });
    });

    it("returns 400 VALIDATION_ERROR for top-level query ?prototype=1", async () => {
      const res = await request(app).get("/api/health/live?prototype=1");

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid query parameters",
      });
    });

    it("returns 400 VALIDATION_ERROR for query ?constructor=1", async () => {
      const res = await request(app).get("/api/health/live?constructor=1");

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid query parameters",
      });
    });

    it("accepts query containing forbidden words as values rather than keys", async () => {
      const res = await request(app).get("/api/health/live?search=constructor");

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        status: "ok",
        service: "veritasor-backend",
        timestamp: expect.any(String),
      });
    });
  });

  describe("hasForbiddenKeys unit validation", () => {
    it("detects forbidden keys in arbitrary objects and arrays", () => {
      expect(hasForbiddenKeys({ __proto__: {} })).toBe(true);
      expect(hasForbiddenKeys({ a: { b: { constructor: 1 } } })).toBe(true);
      expect(hasForbiddenKeys({ a: [{ prototype: {} }] })).toBe(true);
      expect(hasForbiddenKeys({ validKey: "constructor" })).toBe(false);
      expect(hasForbiddenKeys(["constructor", "prototype"])).toBe(false);
      expect(hasForbiddenKeys(null)).toBe(false);
      expect(hasForbiddenKeys(undefined)).toBe(false);
      expect(hasForbiddenKeys("string")).toBe(false);
      expect(hasForbiddenKeys(123)).toBe(false);
    });

    it("safely handles circular object references without crashing", () => {
      const circular: Record<string, unknown> = { normal: "data" };
      circular.self = circular;

      expect(hasForbiddenKeys(circular)).toBe(false);

      circular.constructor_prop = { constructor: "bad" };
      expect(hasForbiddenKeys(circular)).toBe(true);
    });
  });
});
