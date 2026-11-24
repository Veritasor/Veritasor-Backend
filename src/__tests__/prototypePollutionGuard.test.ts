import { describe, it, expect } from "vitest";
import request from "supertest";
import { createApp } from "../app.js";
import { hasForbiddenKeys, scanForForbiddenKeys } from "../middleware/prototypePollution.js";
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
      expect(hasForbiddenKeys(JSON.parse('{"__proto__":{}}'))).toBe(true);
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

  describe("scanForForbiddenKeys tri-state validation", () => {
    it("reports clean for benign payloads within limits", () => {
      expect(scanForForbiddenKeys({ a: 1, b: [1, 2, 3] })).toBe("clean");
      expect(
        scanForForbiddenKeys({ nested: { deep: { value: "ok" } } }, 5, 20),
      ).toBe("clean");
    });

    it("reports forbidden when a forbidden key is found", () => {
      expect(
        scanForForbiddenKeys(JSON.parse('{"__proto__":{"polluted":true}}')),
      ).toBe("forbidden");
      expect(scanForForbiddenKeys({ a: { b: { constructor: 1 } } })).toBe(
        "forbidden",
      );
    });

    it("reports limit_exceeded when the key budget is exceeded", () => {
      const payload: Record<string, unknown> = {};
      for (let i = 0; i < 2001; i++) {
        payload[`k${i}`] = i;
      }
      Object.defineProperty(payload, "__proto__", {
        value: { polluted: true },
        enumerable: true,
        writable: true,
        configurable: true,
      });
      expect(scanForForbiddenKeys(payload)).toBe("limit_exceeded");
    });

    it("reports limit_exceeded when the depth budget is exceeded", () => {
      const root: Record<string, unknown> = {};
      let current = root;
      for (let i = 0; i < 31; i++) {
        const next: Record<string, unknown> = {};
        Object.defineProperty(current, "a", {
          value: next,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        current = next;
      }
      Object.defineProperty(current, "__proto__", {
        value: { polluted: true },
        enumerable: true,
        writable: true,
        configurable: true,
      });
      expect(scanForForbiddenKeys(root)).toBe("limit_exceeded");
    });

    it("honors configurable depth and key limits", () => {
      expect(scanForForbiddenKeys({ a: { b: 1 } }, 1, 10)).toBe(
        "limit_exceeded",
      );
      expect(scanForForbiddenKeys({ a: { b: 1 } }, 2, 10)).toBe("clean");
      expect(scanForForbiddenKeys({ a: { b: 1, c: 2 } }, 30, 2)).toBe(
        "limit_exceeded",
      );
    });
  });

  describe("Fail-closed budget limits", () => {
    it("rejects with 400 VALIDATION_ERROR when 2001 benign siblings exhaust the key budget before a __proto__ key", async () => {
      const payload: Record<string, unknown> = {};
      for (let i = 0; i < 2001; i++) {
        payload[`k${i}`] = i;
      }
      Object.defineProperty(payload, "__proto__", {
        value: { polluted: true },
        enumerable: true,
        writable: true,
        configurable: true,
      });

      expect(scanForForbiddenKeys(payload)).toBe("limit_exceeded");

      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send(payload);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid body fields",
      });
    });

    it("rejects with 400 VALIDATION_ERROR when nesting reaches depth 31 with the forbidden key beyond the maxDepth budget", async () => {
      const root: Record<string, unknown> = {};
      let current = root;
      for (let i = 0; i < 31; i++) {
        const next: Record<string, unknown> = {};
        Object.defineProperty(current, "a", {
          value: next,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        current = next;
      }
      Object.defineProperty(current, "__proto__", {
        value: { polluted: true },
        enumerable: true,
        writable: true,
        configurable: true,
      });

      expect(scanForForbiddenKeys(root)).toBe("limit_exceeded");

      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send(root);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid body fields",
      });
    });

    it("passes a large benign payload through to the next middleware under the limits", async () => {
      const payload: Record<string, unknown> = {
        email: "benign@example.com",
        password: "benign-password-1234",
      };
      for (let i = 0; i < 1500; i++) {
        payload[`bulk_${i}`] = i;
      }
      payload.nested = { a: { b: { c: { d: "leaf" } } } };

      expect(scanForForbiddenKeys(payload)).toBe("clean");
      expect(hasForbiddenKeys(payload)).toBe(false);

      const res = await request(app)
        .post("/api/auth/login")
        .set("Content-Type", "application/json")
        .send(payload);

      expect(res.body).not.toEqual({
        status: "error",
        code: "VALIDATION_ERROR",
        message: "Invalid body fields",
      });
      expect(res.status).not.toBe(500);
    });
  });
});
