import { describe, it, expect, vi, beforeEach } from "vitest";
import { hash, verify, hashPassword } from "../../../src/utils/password.js";
import { resetPassword } from "../../../src/services/auth/resetPassword.js";
import * as userRepository from "../../../src/repositories/userRepository.js";
import * as passwordUtils from "../../../src/utils/password.js";

describe("password utility", () => {
  it("should produce different hashes for the same plain text (salt randomness)", async () => {
    const plain = "my-secret-password";
    const hash1 = await hash(plain);
    const hash2 = await hash(plain);

    expect(hash1).toBeDefined();
    expect(hash2).toBeDefined();
    expect(hash1).not.toBe(hash2);
  });

  it("should verify correctly with the right password", async () => {
    const plain = "correct-password";
    const hashed = await hash(plain);

    const result = await verify(plain, hashed);
    expect(result).toBe(true);
  });

  it("should return false for a wrong password", async () => {
    const plain = "correct-password";
    const hashed = await hash(plain);

    const result = await verify("wrong-password", hashed);
    expect(result).toBe(false);
  });

  it("should return a non-empty string hash", async () => {
    const hashed = await hash("test");
    expect(typeof hashed).toBe("string");
    expect(hashed.length).toBeGreaterThan(0);
  });
});

describe("resetPassword service", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should throw if token or new password is missing", async () => {
    await expect(
      resetPassword({ token: "", newPassword: "newpassword123" })
    ).rejects.toThrow("Token and new password are required");

    await expect(
      resetPassword({ token: "valid-token", newPassword: "" })
    ).rejects.toThrow("Token and new password are required");
  });

  it("should throw if password is shorter than 6 characters", async () => {
    await expect(
      resetPassword({ token: "valid-token", newPassword: "123" })
    ).rejects.toThrow("Password must be at least 6 characters");
  });

  it("should throw if reset token is invalid or expired", async () => {
    vi.spyOn(userRepository, "findUserByResetToken").mockResolvedValue(null);

    await expect(
      resetPassword({ token: "invalid-token", newPassword: "newpassword123" })
    ).rejects.toThrow("Invalid or expired reset token");
  });

  it("should reset password successfully for a valid token", async () => {
    vi.spyOn(userRepository, "findUserByResetToken").mockResolvedValue({
      id: "user-123",
    } as any);

    vi.spyOn(passwordUtils, "hashPassword").mockResolvedValue("hashed-password");
    const updateSpy = vi
      .spyOn(userRepository, "updateUserPassword")
      .mockResolvedValue(undefined);

    const result = await resetPassword({
      token: "valid-token",
      newPassword: "newpassword123",
    });

    expect(passwordUtils.hashPassword).toHaveBeenCalledWith("newpassword123");
    expect(updateSpy).toHaveBeenCalledWith("user-123", "hashed-password");
    expect(result).toEqual({
      message: "Password has been reset successfully",
    });
  });

  it("should allow a reset token to succeed once and fail when reused", async () => {
    vi.spyOn(userRepository, "findUserByResetToken")
      .mockResolvedValueOnce({ id: "user-123" } as any)
      .mockResolvedValueOnce(null);

    vi.spyOn(passwordUtils, "hashPassword").mockResolvedValue("hashed-password");
    vi.spyOn(userRepository, "updateUserPassword").mockResolvedValue(undefined);

    await expect(
      resetPassword({ token: "single-use-token", newPassword: "newpassword123" })
    ).resolves.toEqual({
      message: "Password has been reset successfully",
    });

    await expect(
      resetPassword({ token: "single-use-token", newPassword: "anotherpassword123" })
    ).rejects.toThrow("Invalid or expired reset token");
  });
});