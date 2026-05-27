import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import request from "supertest";
import express from "express";
import { authRouter } from "../auth.js";

// Mock the resetPassword service to isolate route behavior
vi.mock("../../services/auth/resetPassword.js", () => ({
  resetPassword: vi.fn(),
}));

import { resetPassword } from "../../services/auth/resetPassword.js";

const app = express();
app.use(express.json());
app.use("/api/v1/auth", authRouter);

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
    expect(res.body.error).toBe("Validation Error");
    expect(res.body.details.some((d: string) => d.includes("64-character"))).toBe(true);
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
    expect(res.body.error).toBe("Validation Error");
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

  it("returns 400 when service throws (e.g., expired token)", async () => {
    mockedResetPassword.mockRejectedValue(new Error("Invalid or expired reset token"));

    const res = await request(app)
      .post("/api/v1/auth/reset-password")
      .send({
        token: "a".repeat(64),
        newPassword: "SecureP@ss123",
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Invalid or expired reset token");
  });
});