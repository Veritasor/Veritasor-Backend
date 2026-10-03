import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import request from "supertest";
import express from "express";
import { authRouter } from "../auth.js";
import { errorHandler } from "../../middleware/errorHandler.js";
import { AppError } from "../../types/errors.js";

vi.mock("../../services/auth/resetPassword.js", () => ({
  resetPassword: vi.fn(),
}));

import { resetPassword } from "../../services/auth/resetPassword.js";

const app = express();
app.use(express.json());
app.use("/api/v1/auth", authRouter);
app.use(errorHandler);

const mockedResetPassword = vi.mocked(resetPassword);

describe("POST /api/v1/auth/reset-password", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 400 for malformed token (too short)", async () => {
    const res = await request(app)
      .post("/api/v1/auth/reset-password")
      .send({
        token: "short",
        newPassword: "SecureP@ss123",
      });

    expect(res.status).toBe(400);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("VALIDATION_ERROR");
    expect(
      res.body.details.some((d: { message: string }) =>
        d.message.includes("64-character"),
      ),
    ).toBe(true);
    expect(mockedResetPassword).not.toHaveBeenCalled();
  });

  it("returns 400 for weak password", async () => {
    const res = await request(app)
      .post("/api/v1/auth/reset-password")
      .send({
        token: "a".repeat(64),
        newPassword: "weak",
      });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe("VALIDATION_ERROR");
    expect(mockedResetPassword).not.toHaveBeenCalled();
  });

  it("passes valid input to the service and returns 200", async () => {
    mockedResetPassword.mockResolvedValue({
      message: "Password has been reset successfully.",
    });

    const res = await request(app)
      .post("/api/v1/auth/reset-password")
      .send({
        token: "a".repeat(64),
        newPassword: "SecureP@ss123",
      });

    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Password has been reset successfully.");
    expect(mockedResetPassword).toHaveBeenCalledWith({
      token: "a".repeat(64),
      newPassword: "SecureP@ss123",
    });
  });

  it("returns error envelope when service throws invalid token", async () => {
    mockedResetPassword.mockRejectedValue(
      new AppError("Invalid or expired reset token", 400, "INVALID_RESET_TOKEN"),
    );

    const res = await request(app)
      .post("/api/v1/auth/reset-password")
      .send({
        token: "a".repeat(64),
        newPassword: "SecureP@ss123",
      });

    expect(res.status).toBe(400);
    expect(res.body.status).toBe("error");
    expect(res.body.code).toBe("INVALID_RESET_TOKEN");
    expect(res.body.message).toMatch(/invalid or expired/i);
  });
});
