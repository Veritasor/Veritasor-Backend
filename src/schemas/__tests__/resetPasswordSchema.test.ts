import { describe, it, expect } from "vitest";
import { resetPasswordSchema } from "../resetPasswordSchema.js";

// helpers 

/** Generate a valid 64-char lowercase hex token. */
function makeValidToken(): string {
  return "a".repeat(64);
}

/** Generate a valid strong password. */
function makeValidPassword(): string {
  return "SecureP@ss123";
}

// happy path 

describe("resetPasswordSchema — valid inputs", () => {
  it("accepts a valid 64-hex token and strong password", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.token).toBe(makeValidToken());
      expect(result.data.newPassword).toBe(makeValidPassword());
    }
  });

  it("accepts a token with mixed hex digits", () => {
    const token = "0123456789abcdef".repeat(4); // 64 chars
    const result = resetPasswordSchema.safeParse({
      token,
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(true);
  });
});

// token validation 

describe("resetPasswordSchema — token format", () => {
  it("rejects a token that is too short (63 chars)", () => {
    const result = resetPasswordSchema.safeParse({
      token: "a".repeat(63),
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("64-character"))).toBe(true);
    }
  });

  it("rejects a token that is too long (65 chars)", () => {
    const result = resetPasswordSchema.safeParse({
      token: "a".repeat(65),
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(false);
  });

  it("rejects uppercase hex characters", () => {
    const result = resetPasswordSchema.safeParse({
      token: "A".repeat(64),
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("lowercase"))).toBe(true);
    }
  });

  it("rejects non-hex characters", () => {
    const result = resetPasswordSchema.safeParse({
      token: "g".repeat(64),
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(false);
  });

  it("rejects an empty token", () => {
    const result = resetPasswordSchema.safeParse({
      token: "",
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(false);
  });

  it("rejects a missing token field", () => {
    const result = resetPasswordSchema.safeParse({
      newPassword: makeValidPassword(),
    } as any);
    expect(result.success).toBe(false);
  });

  it("rejects token with surrounding whitespace", () => {
    const result = resetPasswordSchema.safeParse({
      token: " " + makeValidToken() + " ",
      newPassword: makeValidPassword(),
    });
    expect(result.success).toBe(false);
  });
});

//password strength 

describe("resetPasswordSchema — password strength", () => {
  it("rejects a password shorter than 8 characters", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "Short1!",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("at least 8"))).toBe(true);
    }
  });

  it("rejects password without uppercase", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "securep@ss123",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("uppercase"))).toBe(true);
    }
  });

  it("rejects password without lowercase", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "SECUREP@SS123",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("lowercase"))).toBe(true);
    }
  });

  it("rejects password without numbers", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "SecureP@ssword",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("number"))).toBe(true);
    }
  });

  it("rejects password without special characters", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "SecurePass123",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("special character"))).toBe(true);
    }
  });

  it("rejects a common weak password", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "Password123!",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("too common"))).toBe(true);
    }
  });

  it("rejects password with sequential characters", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "Abcdefg1!",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("sequential"))).toBe(true);
    }
  });

  it("rejects password with keyboard patterns", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "Qwerty1!",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes("keyboard"))).toBe(true);
    }
  });

  it("rejects an empty password", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: "",
    });
    expect(result.success).toBe(false);
  });

  it("rejects a missing newPassword field", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
    } as any);
    expect(result.success).toBe(false);
  });
});

//type safety 

describe("resetPasswordSchema — type coercion rejection", () => {
  it("rejects a numeric token", () => {
    const result = resetPasswordSchema.safeParse({
      token: 1234567890123456789012345678901234567890123456789012345678901234,
      newPassword: makeValidPassword(),
    } as any);
    expect(result.success).toBe(false);
  });

  it("rejects a boolean token", () => {
    const result = resetPasswordSchema.safeParse({
      token: true,
      newPassword: makeValidPassword(),
    } as any);
    expect(result.success).toBe(false);
  });

  it("rejects an array token", () => {
    const result = resetPasswordSchema.safeParse({
      token: ["a".repeat(64)],
      newPassword: makeValidPassword(),
    } as any);
    expect(result.success).toBe(false);
  });

  it("rejects extra fields (strict mode)", () => {
    const result = resetPasswordSchema.safeParse({
      token: makeValidToken(),
      newPassword: makeValidPassword(),
      extraField: "should not be allowed",
    });
    expect(result.success).toBe(false);
  });
});