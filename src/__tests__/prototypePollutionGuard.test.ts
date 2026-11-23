import express from "express";
import type { Request, Response } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { prototypePollutionGuard } from "../middleware/prototypePollution.js";

function createResponseMock() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
}

describe("prototypePollutionGuard", () => {
  it("calls next exactly once for a safe request", () => {
    const req = { query: { search: "safe" }, body: { name: "safe" } } as unknown as Request;
    const res = createResponseMock();
    const next = vi.fn();

    prototypePollutionGuard(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  it("rejects prohibited query keys", () => {
    const req = { query: { constructor: "polluted" }, body: undefined } as unknown as Request;
    const res = createResponseMock();
    const next = vi.fn();

    prototypePollutionGuard(req, res as unknown as Response, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: "VALIDATION_ERROR", message: "Invalid query parameters" }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects prohibited nested body keys after JSON parsing", async () => {
    const app = express();
    app.use(express.json());
    app.use(prototypePollutionGuard);
    app.post("/test", (_req, res) => res.sendStatus(204));

    const response = await request(app)
      .post("/test")
      .set("Content-Type", "application/json")
      .send('{"safe":{"prototype":"polluted"}}');

    expect(response.status).toBe(400);
    expect(response.body).toEqual(
      expect.objectContaining({ code: "VALIDATION_ERROR", message: "Invalid body fields" }),
    );
  });

  it("rejects prohibited query keys through the application middleware", async () => {
    const app = express();
    app.use(express.json());
    app.use(prototypePollutionGuard);
    app.get("/test", (_req, res) => res.sendStatus(204));

    const response = await request(app).get("/test?constructor=polluted");

    expect(response.status).toBe(400);
    expect(response.body.code).toBe("VALIDATION_ERROR");
  });
});
