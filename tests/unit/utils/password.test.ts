import { describe, it, expect } from "vitest";
import { hash, verify } from "../../../src/utils/password.js";

describe("password utility", () => {
  it("should produce different hashes for the same plain text (salt randomness)", async () => {
    const plain = "my-secret-password";
    const hash1 = await hash(plain);
    const hash2 = await hash(plain);

    // Both should be valid bcrypt hashes but different due to random salt
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
