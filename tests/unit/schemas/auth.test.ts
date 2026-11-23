import { describe, expect, it } from "vitest";
import { loginInputSchema, type LoginInput } from "../../../src/schemas/auth.js";

// The email boundary: a 242-character local part + "@example.com" (12 chars)
// totals 254 characters, the maximum length accepted by loginInputSchema.
const LONGEST_VALID_EMAIL = `${"a".repeat(242)}@example.com`;
const TOO_LONG_EMAIL = `${"a".repeat(243)}@example.com`;

describe("loginInputSchema", () => {
  describe("valid inputs", () => {
    it("accepts a well-formed email and password", () => {
      const result = loginInputSchema.safeParse({
        email: "user@example.com",
        password: "secret",
      });

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.data).toEqual({ email: "user@example.com", password: "secret" });
    });

    it("trims surrounding whitespace and normalizes the email to lowercase", () => {
      const result = loginInputSchema.safeParse({
        email: "  User.Name@Example.COM  ",
        password: "secret",
      });

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.data.email).toBe("user.name@example.com");
      expect(result.data.password).toBe("secret");
    });

    it("accepts an email at the 254-character boundary", () => {
      const result = loginInputSchema.safeParse({
        email: LONGEST_VALID_EMAIL,
        password: "secret",
      });

      expect(result.success).toBe(true);
    });

    it("accepts a password at the 128-character boundary", () => {
      const result = loginInputSchema.safeParse({
        email: "user@example.com",
        password: "p".repeat(128),
      });

      expect(result.success).toBe(true);
    });

    it("strips unknown keys from the parsed output", () => {
      const result = loginInputSchema.safeParse({
        email: "user@example.com",
        password: "secret",
        rememberMe: true,
      });

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.data).toEqual({ email: "user@example.com", password: "secret" });
    });
  });

  describe("invalid inputs", () => {
    it.each([
      {
        name: "missing email",
        input: { password: "secret" },
        expectedMessage: "Email is required",
      },
      {
        name: "empty email",
        input: { email: "", password: "secret" },
        expectedMessage: "Email is required",
      },
      {
        name: "whitespace-only email",
        input: { email: "   ", password: "secret" },
        expectedMessage: "Email is required",
      },
      {
        name: "non-string email",
        input: { email: 42, password: "secret" },
        expectedMessage: "Email must be a string",
      },
      {
        name: "null email",
        input: { email: null, password: "secret" },
        expectedMessage: "Email must be a string",
      },
      {
        name: "invalid email format",
        input: { email: "not-an-email", password: "secret" },
        expectedMessage: "Invalid email format",
      },
      {
        name: "email without a routable domain",
        input: { email: "user@localhost", password: "secret" },
        expectedMessage: "Invalid email format",
      },
      {
        name: "email over 254 characters",
        input: { email: TOO_LONG_EMAIL, password: "secret" },
        expectedMessage: "Email must not exceed 254 characters",
      },
      {
        name: "missing password",
        input: { email: "user@example.com" },
        expectedMessage: "Password is required",
      },
      {
        name: "empty password",
        input: { email: "user@example.com", password: "" },
        expectedMessage: "Password is required",
      },
      {
        name: "non-string password",
        input: { email: "user@example.com", password: 123456 },
        expectedMessage: "Password must be a string",
      },
      {
        name: "password over 128 characters",
        input: { email: "user@example.com", password: "p".repeat(129) },
        expectedMessage: "Password must not exceed 128 characters",
      },
    ])("rejects $name with a deterministic message", ({ input, expectedMessage }) => {
      const result = loginInputSchema.safeParse(input);

      expect(result.success).toBe(false);
      if (result.success) return;
      const messages = result.error.issues.map((issue) => issue.message);
      expect(messages).toContain(expectedMessage);
    });

    it("reports every failing field in a single parse", () => {
      const result = loginInputSchema.safeParse({
        email: "not-an-email",
        password: "",
      });

      expect(result.success).toBe(false);
      if (result.success) return;
      const messages = result.error.issues.map((issue) => issue.message);
      expect(messages).toContain("Invalid email format");
      expect(messages).toContain("Password is required");
    });
  });

  describe("non-object payloads", () => {
    it.each([
      ["null", null],
      ["a string", "user@example.com"],
      ["a number", 123],
      ["an array", ["user@example.com"]],
      ["a boolean", true],
      ["undefined", undefined],
    ])("rejects %s without throwing", (_label, input) => {
      const result = loginInputSchema.safeParse(input);

      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.issues.length).toBeGreaterThan(0);
    });
  });
});

describe("LoginInput", () => {
  it("exposes the parsed data as a LoginInput", () => {
    const result = loginInputSchema.safeParse({
      email: "user@example.com",
      password: "secret",
    });

    expect(result.success).toBe(true);
    if (!result.success) return;
    const typed: LoginInput = result.data;
    expect(typed).toEqual({ email: "user@example.com", password: "secret" });
  });
});
