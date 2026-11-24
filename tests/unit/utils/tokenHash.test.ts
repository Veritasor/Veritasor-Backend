import { describe, it, expect } from "vitest";
import {
	hashResetToken,
	tokenLogPrefix,
} from "../../../src/utils/tokenHash.js";

describe("hashResetToken", () => {
	it("matches the known-answer SHA-256 vector for 'abc'", () => {
		expect(hashResetToken("abc")).toBe(
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		);
	});

	it("returns a 64-character lowercase hex digest", () => {
		expect(hashResetToken("token-a")).toMatch(/^[0-9a-f]{64}$/);
	});

	it("is deterministic for the same input", () => {
		const rawToken = "0123456789abcdef";
		expect(hashResetToken(rawToken)).toBe(hashResetToken(rawToken));
	});

	it("produces different digests for distinct inputs", () => {
		expect(hashResetToken("token-a")).not.toBe(hashResetToken("token-b"));
	});

	it("never includes the raw token in the returned digest", () => {
		const rawToken = "super-secret-reset-token";
		const hash = hashResetToken(rawToken);
		expect(hash).not.toContain(rawToken);
	});

	it("does not leak a raw token that happens to look like hex", () => {
		const rawToken = "deadbeefdeadbeef";
		const hash = hashResetToken(rawToken);
		expect(hash).not.toContain(rawToken);
	});
});

describe("tokenLogPrefix", () => {
	const rawToken = "0123456789abcdef";

	it("defaults to an 8-character prefix", () => {
		expect(tokenLogPrefix(rawToken)).toBe("01234567");
		expect(tokenLogPrefix(rawToken)).toHaveLength(8);
	});

	it("honours a custom length of 4", () => {
		expect(tokenLogPrefix(rawToken, 4)).toBe("0123");
	});

	it("honours a custom length of 12", () => {
		expect(tokenLogPrefix(rawToken, 12)).toBe("0123456789ab");
	});

	it("returns short tokens unchanged without throwing", () => {
		expect(() => tokenLogPrefix("ab")).not.toThrow();
		expect(tokenLogPrefix("ab")).toBe("ab");
	});

	it("returns an empty string for an empty token without throwing", () => {
		expect(() => tokenLogPrefix("")).not.toThrow();
		expect(tokenLogPrefix("")).toBe("");
	});

	it("returns the whole token when a custom length exceeds its size", () => {
		expect(() => tokenLogPrefix("ab", 12)).not.toThrow();
		expect(tokenLogPrefix("ab", 12)).toBe("ab");
	});
});
