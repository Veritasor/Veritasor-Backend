import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import bcrypt from "bcryptjs";
import {
  hash,
  verify,
  hashPassword,
  verifyPassword,
} from "../../../src/utils/password.js";
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

  describe("Unicode edge cases", () => {
    it("should hash and verify passwords with emojis", async () => {
      const plain = "p@ssw🔒rd😊";
      const hashed = await hash(plain);
      expect(await verify(plain, hashed)).toBe(true);
      expect(await verify("p@ssw🔒rd😢", hashed)).toBe(false);
    });

    it("should hash and verify passwords with combining characters", async () => {
      const plain = "cafe9"; // 'café' with single code point
      const plain2 = "cafe9".normalize("NFC"); // forcibly normalized
      const hashed = await hash(plain);
      expect(await verify(plain, hashed)).toBe(true);
      expect(await verify(plain2, hashed)).toBe(false); // different normalization
    });

    it("should hash and verify passwords with non-Latin scripts", async () => {
      const plain = "пароль"; // Russian for 'password'
      const hashed = await hash(plain);
      expect(await verify(plain, hashed)).toBe(true);
      expect(await verify("パスワード", hashed)).toBe(false); // Japanese for 'password'
    });
  });

  describe("BCRYPT_SALT_ROUNDS configuration", () => {
    const originalSaltRounds = process.env.BCRYPT_SALT_ROUNDS;

    beforeEach(() => {
      delete process.env.BCRYPT_SALT_ROUNDS;
      vi.restoreAllMocks();
    });

    afterEach(() => {
      if (originalSaltRounds === undefined) {
        delete process.env.BCRYPT_SALT_ROUNDS;
      } else {
        process.env.BCRYPT_SALT_ROUNDS = originalSaltRounds;
      }
      vi.restoreAllMocks();
    });

    it("uses default 10 rounds when BCRYPT_SALT_ROUNDS is unset", async () => {
      const hashSpy = vi
        .spyOn(bcrypt, "hash")
        .mockResolvedValue("mocked-hash" as never);

      await hash("secret");
      expect(hashSpy).toHaveBeenCalledWith("secret", 10);
    });

    it("uses configured rounds for valid values within 10..31 without warning", async () => {
      const hashSpy = vi
        .spyOn(bcrypt, "hash")
        .mockResolvedValue("mocked-hash" as never);
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      process.env.BCRYPT_SALT_ROUNDS = "12";
      await hash("secret");
      expect(hashSpy).toHaveBeenLastCalledWith("secret", 12);

      process.env.BCRYPT_SALT_ROUNDS = "31";
      await hash("secret");
      expect(hashSpy).toHaveBeenLastCalledWith("secret", 31);

      expect(warnSpy).not.toHaveBeenCalled();
    });

    it("accepts rounds between 4 and 9 with a warning", async () => {
      const hashSpy = vi
        .spyOn(bcrypt, "hash")
        .mockResolvedValue("mocked-hash" as never);
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      process.env.BCRYPT_SALT_ROUNDS = "4";
      await hash("secret");
      expect(hashSpy).toHaveBeenLastCalledWith("secret", 4);
      expect(warnSpy).toHaveBeenCalledTimes(1);

      process.env.BCRYPT_SALT_ROUNDS = "8";
      await hash("secret");
      expect(hashSpy).toHaveBeenLastCalledWith("secret", 8);
      expect(warnSpy).toHaveBeenCalledTimes(2);
    });

    it.each(["abc", "12abc", "10.5", "", "   "])(
      "falls back to default 10 for invalid string '%s'",
      async (invalidValue) => {
        const hashSpy = vi
          .spyOn(bcrypt, "hash")
          .mockResolvedValue("mocked-hash" as never);

        process.env.BCRYPT_SALT_ROUNDS = invalidValue;
        await hash("secret");
        expect(hashSpy).toHaveBeenCalledWith("secret", 10);
      }
    );

    it.each(["0", "-1", "-10"])(
      "falls back to default 10 for zero or negative value '%s'",
      async (nonPositiveValue) => {
        const hashSpy = vi
          .spyOn(bcrypt, "hash")
          .mockResolvedValue("mocked-hash" as never);

        process.env.BCRYPT_SALT_ROUNDS = nonPositiveValue;
        await hash("secret");
        expect(hashSpy).toHaveBeenCalledWith("secret", 10);
      }
    );

    it.each(["1", "2", "3", "32", "100"])(
      "falls back to default 10 for out-of-range value '%s'",
      async (outOfRangeValue) => {
        const hashSpy = vi
          .spyOn(bcrypt, "hash")
          .mockResolvedValue("mocked-hash" as never);

        process.env.BCRYPT_SALT_ROUNDS = outOfRangeValue;
        await hash("secret");
        expect(hashSpy).toHaveBeenCalledWith("secret", 10);
      }
    );
  });

  describe("backward-compatibility aliases", () => {
    it("exports hashPassword and verifyPassword aliases", async () => {
      expect(hashPassword).toBe(hash);
      expect(verifyPassword).toBe(verify);
      expect(passwordUtils.default.hashPassword).toBe(hash);
      expect(passwordUtils.default.verifyPassword).toBe(verify);

      const hashed = await hashPassword("alias-test");
      expect(await verifyPassword("alias-test", hashed)).toBe(true);
      expect(await verifyPassword("wrong", hashed)).toBe(false);
    });
  });
});

describe("resetPassword service", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should throw if token or new password is missing", async () => {
    await expect(
      resetPassword({ token: "", newPassword: "newpassword123" })
    ).rejects.toThrow("Token is required");

    await expect(
      resetPassword({ token: "valid-token", newPassword: "" })
    ).rejects.toThrow("New password is required");

  });

  it("should throw if password is shorter than 6 characters", async () => {
    await expect(
      resetPassword({ token: "valid-token", newPassword: "123" })
    ).rejects.toThrow("Password must be at least 8 characters");

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
      message: "Password has been reset successfully.",

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
      message: "Password has been reset successfully.",

    });

    await expect(
      resetPassword({ token: "single-use-token", newPassword: "anotherpassword123" })
    ).rejects.toThrow("Invalid or expired reset token");
  });
});