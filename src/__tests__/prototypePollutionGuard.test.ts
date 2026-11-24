import { describe, it, expect, vi } from "vitest";
import request from "supertest";
import { createApp } from "../app.js";
import { hasForbiddenKeys, hasForbiddenQuery } from "../middleware/prototypePollution.js";
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
      const obj1: Record<string, unknown> = {};
      Object.defineProperty(obj1, "__proto__", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys(obj1)).toBe(true);

      const obj2: Record<string, unknown> = { a: { b: {} } };
      Object.defineProperty((obj2.a as Record<string, unknown>).b, "constructor", {
        value: 1,
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys(obj2)).toBe(true);

      const obj3: Record<string, unknown> = { a: [{}] };
      Object.defineProperty((obj3.a as unknown[])[0], "prototype", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys(obj3)).toBe(true);

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

    it("skips throwing getters without crashing", () => {
      const obj: Record<string, unknown> = {
        normalKey: "value",
      };

      Object.defineProperty(obj, "throwingGetter", {
        get() {
          throw new Error("This getter throws");
        },
        enumerable: true,
        configurable: true,
      });

      // Should not throw and should ignore the throwing getter
      expect(hasForbiddenKeys(obj)).toBe(false);

      // If there's a forbidden key elsewhere (as an own property), it should still be detected
      Object.defineProperty(obj, "__proto__", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys(obj)).toBe(true);
    });

    it("returns false when maxDepth is exceeded", () => {
      const nested: Record<string, unknown> = {};
      let current = nested;
      for (let i = 0; i < 35; i++) {
        current.next = {};
        current = current.next as Record<string, unknown>;
      }
      // Place forbidden key beyond default maxDepth (30) as an own property
      Object.defineProperty(current, "__proto__", {
        value: {},
        enumerable: true,
        configurable: true,
      });

      // Default maxDepth=30 should not detect forbidden key at depth 35
      expect(hasForbiddenKeys(nested)).toBe(false);

      // With maxDepth=40, should detect it
      expect(hasForbiddenKeys(nested, 40)).toBe(true);
    });

    it("returns false when maxKeys is exceeded", () => {
      const largeArray: unknown[] = [];
      for (let i = 0; i < 1100; i++) {
        largeArray.push({ key: `value${i}` });
      }
      // Place forbidden key at the end beyond default maxKeys (2000) as an own property
      const lastObj = largeArray[largeArray.length - 1] as Record<string, unknown>;
      Object.defineProperty(lastObj, "__proto__", {
        value: {},
        enumerable: true,
        configurable: true,
      });

      // With 1100 items + 1100 "key" properties = 2200 total keys, which exceeds default maxKeys=2000
      expect(hasForbiddenKeys(largeArray)).toBe(false);

      // With maxKeys=2500, should detect it
      expect(hasForbiddenKeys(largeArray, 30, 2500)).toBe(true);
    });

    it("detects forbidden keys nested in arrays", () => {
      const obj1: Record<string, unknown> = {};
      Object.defineProperty(obj1, "__proto__", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys([obj1])).toBe(true);

      const obj2: Record<string, unknown> = { a: {} };
      Object.defineProperty(obj2.a, "constructor", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys([obj2])).toBe(true);

      const obj3: Record<string, unknown> = {};
      Object.defineProperty(obj3, "prototype", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys([[obj3]])).toBe(true);

      expect(hasForbiddenKeys([["constructor"]])).toBe(false);
    });

    it("detects all three forbidden keys at top level", () => {
      const obj1: Record<string, unknown> = {};
      Object.defineProperty(obj1, "__proto__", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys(obj1)).toBe(true);

      const obj2: Record<string, unknown> = {};
      Object.defineProperty(obj2, "constructor", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys(obj2)).toBe(true);

      const obj3: Record<string, unknown> = {};
      Object.defineProperty(obj3, "prototype", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys(obj3)).toBe(true);
    });

    it("detects all three forbidden keys nested in arrays", () => {
      const obj1: Record<string, unknown> = {};
      Object.defineProperty(obj1, "__proto__", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys([obj1])).toBe(true);

      const obj2: Record<string, unknown> = {};
      Object.defineProperty(obj2, "constructor", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys([obj2])).toBe(true);

      const obj3: Record<string, unknown> = {};
      Object.defineProperty(obj3, "prototype", {
        value: {},
        enumerable: true,
        configurable: true,
      });
      expect(hasForbiddenKeys([obj3])).toBe(true);
    });
  });

  describe("hasForbiddenQuery unit validation", () => {
    it("detects bracketed query keys like a[__proto__][x]=1", () => {
      const mockReq = {
        query: {},
        originalUrl: "/api/health/live?a[__proto__][x]=1",
        url: "/api/health/live?a[__proto__][x]=1",
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(true);
    });

    it("detects bracketed query keys with constructor", () => {
      const mockReq = {
        query: {},
        originalUrl: "/api/health/live?b[constructor][y]=2",
        url: "/api/health/live?b[constructor][y]=2",
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(true);
    });

    it("detects bracketed query keys with prototype", () => {
      const mockReq = {
        query: {},
        originalUrl: "/api/health/live?c[prototype][z]=3",
        url: "/api/health/live?c[prototype][z]=3",
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(true);
    });

    it("detects forbidden keys in parsed req.query", () => {
      const queryObj: Record<string, unknown> = {};
      Object.defineProperty(queryObj, "__proto__", {
        value: { isAdmin: true },
        enumerable: true,
        configurable: true,
      });

      const mockReq = {
        query: queryObj,
        originalUrl: "/api/health/live",
        url: "/api/health/live",
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(true);
    });

    it("accepts query with forbidden words as values", () => {
      const mockReq = {
        query: { search: "constructor" },
        originalUrl: "/api/health/live?search=constructor",
        url: "/api/health/live?search=constructor",
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(false);
    });

    it("accepts query with normal bracketed keys", () => {
      const mockReq = {
        query: {},
        originalUrl: "/api/health/live?a[b][c]=1",
        url: "/api/health/live?a[b][c]=1",
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(false);
    });

    it("handles missing URL gracefully", () => {
      const mockReq = {
        query: {},
        originalUrl: undefined,
        url: undefined,
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(false);
    });

    it("handles URL without query string", () => {
      const mockReq = {
        query: {},
        originalUrl: "/api/health/live",
        url: "/api/health/live",
      } as any;

      expect(hasForbiddenQuery(mockReq)).toBe(false);
    });
  });
});
