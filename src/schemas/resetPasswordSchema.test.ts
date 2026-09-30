import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  resetPasswordSchema,
  type ResetPasswordInput,
} from "./resetPasswordSchema.js";

const VALID_TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VALID_PASSWORD = "Kx9!mVp#Qs2";

function expectZodError(fn: () => unknown, messageFragment?: string) {
  expect(() => {
    try {
      fn();
    } catch (e) {
      if (e instanceof z.ZodError) {
        if (messageFragment) {
          const joined = e.issues.map((i) => i.message).join(" ");
          expect(joined.toLowerCase()).toContain(
            messageFragment.toLowerCase(),
          );
        }
        throw e;
      }
      throw e;
    }
  }).toThrow(z.ZodError);
}

describe("src/schemas/resetPasswordSchema.ts", () => {
  describe("ResetPasswordInput type inference", () => {
    it("infers a shape of { token: string; newPassword: string }", () => {
      const input: ResetPasswordInput = {
        token: VALID_TOKEN,
        newPassword: VALID_PASSWORD,
      };
      expect(typeof input.token).toBe("string");
      expect(typeof input.newPassword).toBe("string");
      expect(input.token).toHaveLength(64);
    });
  });

  describe("resetPasswordSchema.parse — success path", () => {
    it("returns typed ResetPasswordInput for canonical valid payload", () => {
      const parsed = resetPasswordSchema.parse({
        token: VALID_TOKEN,
        newPassword: VALID_PASSWORD,
      }) satisfies ResetPasswordInput;

      expect(parsed.token).toBe(VALID_TOKEN);
      expect(parsed.newPassword).toBe(VALID_PASSWORD);
    });

    it("accepts a password with all required classes at length 8 (minimum)", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Qa1$Zx8%",
      });
      expect(result.success).toBe(true);
    });

    it("accepts a long but valid password (boundary, 128 chars)", () => {
      const base = "A1b$Q9xZ";
      const longPassword = base.repeat(16);
      expect(longPassword).toHaveLength(128);
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: longPassword,
      });
      expect(result.success).toBe(true);
    });

    it("accepts token made of valid hex digits from entire [0-9a-f] set", () => {
      const token = "fedcba9876543210".repeat(4);
      expect(token).toHaveLength(64);
      const parsed = resetPasswordSchema.parse({
        token,
        newPassword: VALID_PASSWORD,
      });
      expect(parsed.token).toBe(token);
    });

    it("accepts different valid passwords with various special chars", () => {
      const specials = [
        "SecurePass1!",
        "SecurePass1@",
        "SecurePass1#",
        "SecurePass1$",
        "SecurePass1%",
        "SecurePass1^",
        "SecurePass1&",
        "SecurePass1*",
      ];
      for (const pw of specials) {
        const result = resetPasswordSchema.safeParse({
          token: VALID_TOKEN,
          newPassword: pw,
        });
        expect(result.success).toBe(true);
      }
    });
  });

  describe("resetPasswordSchema.parse — failure: empty strings", () => {
    it("throws ZodError for empty token string", () => {
      expectZodError(
        () =>
          resetPasswordSchema.parse({
            token: "",
            newPassword: VALID_PASSWORD,
          }),
        "token is required",
      );
    });

    it("throws ZodError for empty newPassword string", () => {
      expectZodError(
        () =>
          resetPasswordSchema.parse({
            token: VALID_TOKEN,
            newPassword: "",
          }),
        "new password is required",
      );
    });

    it("throws ZodError when both fields are empty strings", () => {
      const result = resetPasswordSchema.safeParse({
        token: "",
        newPassword: "",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const paths = result.error.issues.map((i) => i.path[0]);
        expect(paths).toContain("token");
        expect(paths).toContain("newPassword");
      }
    });
  });

  describe("resetPasswordSchema.parse — failure: missing required fields", () => {
    it("throws ZodError when token field is absent", () => {
      expectZodError(
        () =>
          resetPasswordSchema.parse({
            newPassword: VALID_PASSWORD,
          } as unknown as ResetPasswordInput),
        "token is required",
      );
    });

    it("throws ZodError when newPassword field is absent", () => {
      expectZodError(
        () =>
          resetPasswordSchema.parse({
            token: VALID_TOKEN,
          } as unknown as ResetPasswordInput),
        "new password is required",
      );
    });

    it("throws ZodError when entire payload is empty object", () => {
      const result = resetPasswordSchema.safeParse({});
      expect(result.success).toBe(false);
      if (!result.success) {
        const paths = result.error.issues.map((i) => i.path[0]);
        expect(paths).toContain("token");
        expect(paths).toContain("newPassword");
      }
    });
  });

  describe("resetPasswordSchema.parse — failure: token invalid formats", () => {
    it("rejects token shorter than 64 chars (63 exactly)", () => {
      const result = resetPasswordSchema.safeParse({
        token: "a".repeat(63),
        newPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("64-character");
      }
    });

    it("rejects token longer than 64 chars (65 exactly)", () => {
      const result = resetPasswordSchema.safeParse({
        token: "a".repeat(65),
        newPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(false);
    });

    it("rejects uppercase hex token (A-F instead of a-f)", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN.toUpperCase(),
        newPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("lowercase");
      }
    });

    it("rejects token with non-hex letter g included", () => {
      const token = "g".repeat(64);
      const result = resetPasswordSchema.safeParse({
        token,
        newPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(false);
    });

    it("rejects token with a single invalid character in the middle", () => {
      const bad = VALID_TOKEN.split("");
      bad[32] = "G";
      const result = resetPasswordSchema.safeParse({
        token: bad.join(""),
        newPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(false);
    });

    it("rejects token padded with leading whitespace", () => {
      const result = resetPasswordSchema.safeParse({
        token: " " + VALID_TOKEN,
        newPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(false);
    });

    it("rejects token padded with trailing whitespace", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN + " ",
        newPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("resetPasswordSchema.parse — failure: password too short", () => {
    it("rejects password of length 7 (below 8)", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Ab1!xyz",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("at least 8");
      }
    });

    it("rejects password of length 1 (edge)", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "A",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("resetPasswordSchema.parse — failure: missing required character types", () => {
    it("rejects password without any uppercase letters", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "n0special!chars",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("uppercase");
      }
    });

    it("rejects password without any lowercase letters", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "P@SSW0RD123",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("lowercase");
      }
    });

    it("rejects password without any numbers", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Password!Strong",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("number");
      }
    });

    it("rejects password without any special characters", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Password12345",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("special character");
      }
    });

    it("emits multiple issues when several classes are missing", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "alllowercase",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.length).toBeGreaterThanOrEqual(3);
      }
    });
  });

  describe("resetPasswordSchema.parse — failure: common weak passwords", () => {
    it("rejects literal 'Password123!' (blacklisted)", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Password123!",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("too common");
      }
    });

    it("rejects blacklisted password in different case", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "PASSWORD123!",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("too common");
      }
    });

    it("rejects blacklisted 'qwerty123' (not meeting complexity anyway)", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Qwerty123!",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("resetPasswordSchema.parse — failure: sequential & keyboard patterns", () => {
    it("rejects password with ascending sequential characters", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Abcdefg1!",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("sequential");
      }
    });

    it("rejects password with descending sequential characters", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Zyxwvut1!",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("sequential");
      }
    });

    it("rejects password with numeric ascending sequence", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Pass1234!",
      });
      expect(result.success).toBe(false);
    });

    it("rejects password with qwerty keyboard pattern", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: "Qwerty1!",
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const msgs = result.error.issues.map((i) => i.message).join(" ");
        expect(msgs.toLowerCase()).toContain("keyboard");
      }
    });
  });

  describe("resetPasswordSchema.parse — failure: invalid input types", () => {
    it("rejects token of type number (not string)", () => {
      const result = resetPasswordSchema.safeParse({
        token: 42,
        newPassword: VALID_PASSWORD,
      } as unknown as ResetPasswordInput);
      expect(result.success).toBe(false);
      if (!result.success) {
        const tokenIssue = result.error.issues.find(
          (i) => i.path[0] === "token",
        );
        expect(tokenIssue?.message.toLowerCase()).toContain("string");
      }
    });

    it("rejects token passed as array", () => {
      const result = resetPasswordSchema.safeParse({
        token: [VALID_TOKEN],
        newPassword: VALID_PASSWORD,
      } as unknown as ResetPasswordInput);
      expect(result.success).toBe(false);
    });

    it("rejects newPassword of type number", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: 12345678,
      } as unknown as ResetPasswordInput);
      expect(result.success).toBe(false);
      if (!result.success) {
        const pwIssue = result.error.issues.find(
          (i) => i.path[0] === "newPassword",
        );
        expect(pwIssue?.message.toLowerCase()).toContain("string");
      }
    });

    it("rejects boolean newPassword", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: true,
      } as unknown as ResetPasswordInput);
      expect(result.success).toBe(false);
    });
  });

  describe("resetPasswordSchema.parse — unknown field handling (default strip mode)", () => {
    it("accepts payloads with additional unknown fields (stripped by default)", () => {
      const result = resetPasswordSchema.safeParse({
        token: VALID_TOKEN,
        newPassword: VALID_PASSWORD,
        confirmPassword: VALID_PASSWORD,
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(Object.keys(result.data)).toHaveLength(2);
        expect(Object.keys(result.data)).toEqual(
          expect.arrayContaining(["token", "newPassword"]),
        );
        expect((result.data as any).confirmPassword).toBeUndefined();
      }
    });
  });
});
