import express, { type NextFunction, type Request, type Response } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { errorHandler } from "../errorHandler.js";

describe("errorHandler body-parser errors", () => {
  function createJsonApp() {
    const app = express();
    app.use(express.json());
    app.post("/", (_req, res) => {
      res.sendStatus(204);
    });
    app.use(errorHandler);
    return app;
  }

  it("returns a safe 400 envelope for malformed JSON", async () => {
    const response = await request(createJsonApp())
      .post("/")
      .set("Content-Type", "application/json")
      .send("{bad");

    expect(response.status).toBe(400);
    expect(response.body.code).toBe("INVALID_JSON");
    expect(response.body.message).toBe("Invalid JSON payload");
    expect(response.text).not.toContain("{bad");
  });

  it("returns a safe 413 envelope for oversized JSON", async () => {
    const secret = "sensitive-body-content";
    const response = await request(createJsonApp())
      .post("/")
      .set("Content-Type", "application/json")
      .send(JSON.stringify({ content: `${secret}${"x".repeat(200_000)}` }));

    expect(response.status).toBe(413);
    expect(response.body.code).toBe("PAYLOAD_TOO_LARGE");
    expect(response.body.message).toBe("Request payload too large");
    expect(response.text).not.toContain(secret);
  });

  it("delegates errors raised after response headers are sent", async () => {
    const app = express();
    let delegatedError: unknown;

    app.get("/", (_req, res, next) => {
      res.write("started");
      next(new Error("stream failed"));
    });
    app.use(errorHandler);
    app.use(
      (
        err: unknown,
        _req: Request,
        res: Response,
        _next: NextFunction
      ) => {
        delegatedError = err;
        res.end();
      }
    );

    const response = await request(app).get("/");

    expect(response.status).toBe(200);
    expect(response.text).toBe("started");
    expect(delegatedError).toBeInstanceOf(Error);
  });

  it("keeps unknown errors generic with a 500 response", async () => {
    const app = express();
    app.get("/", (_req, _res, next) => {
      next(new Error("database password leaked"));
    });
    app.use(errorHandler);

    const response = await request(app).get("/");

    expect(response.status).toBe(500);
    expect(response.body.message).toBe("An unexpected error occurred");
    expect(response.body.message).not.toContain("database password leaked");
  });
});
