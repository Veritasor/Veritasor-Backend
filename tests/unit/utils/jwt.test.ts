import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import {
	generateRefreshToken,
	generateToken,
	type TokenPayload,
	verifyRefreshToken,
	verifyToken,
} from "../../../src/utils/jwt";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const payload: TokenPayload = {
	userId: "user-123",
	email: "test@example.com",
};

// Secrets mirror the defaults in src/utils/jwt.ts (env vars not set in tests).
const ACCESS_SECRET = "dev-secret-key";
const REFRESH_SECRET = "dev-refresh-secret-key";

/** Signs a token that is already expired by using a negative expiresIn. */
function makeExpiredToken(secret: string): string {
	return jwt.sign(payload, secret, { expiresIn: -1 });
}

// ---------------------------------------------------------------------------
// generateToken
// ---------------------------------------------------------------------------

describe("generateToken", () => {
	it("returns a non-empty string", () => {
		const token = generateToken(payload);
		expect(typeof token).toBe("string");
		expect(token.length).toBeGreaterThan(0);
	});

	it("returns a valid JWT with three dot-separated segments", () => {
		const token = generateToken(payload);
		expect(token.split(".")).toHaveLength(3);
	});

	it("embeds the correct payload fields", () => {
		const token = generateToken(payload);
		const decoded = jwt.decode(token) as TokenPayload & { exp: number };
		expect(decoded.userId).toBe(payload.userId);
		expect(decoded.email).toBe(payload.email);
	});

	it("sets an expiry roughly 1 hour from now", () => {
		const before = Math.floor(Date.now() / 1000);
		const token = generateToken(payload);
		const { exp } = jwt.decode(token) as { exp: number };
		const after = Math.floor(Date.now() / 1000);
		expect(exp).toBeGreaterThanOrEqual(before + 3600);
		expect(exp).toBeLessThanOrEqual(after + 3600);
	});
});

// ---------------------------------------------------------------------------
// generateRefreshToken
// ---------------------------------------------------------------------------

describe("generateRefreshToken", () => {
	it("returns a non-empty string", () => {
		const token = generateRefreshToken(payload);
		expect(typeof token).toBe("string");
		expect(token.length).toBeGreaterThan(0);
	});

	it("returns a valid JWT with three dot-separated segments", () => {
		const token = generateRefreshToken(payload);
		expect(token.split(".")).toHaveLength(3);
	});

	it("embeds the correct payload fields", () => {
		const token = generateRefreshToken(payload);
		const decoded = jwt.decode(token) as TokenPayload & { exp: number };
		expect(decoded.userId).toBe(payload.userId);
		expect(decoded.email).toBe(payload.email);
	});

	it("sets an expiry roughly 7 days from now", () => {
		const before = Math.floor(Date.now() / 1000);
		const token = generateRefreshToken(payload);
		const { exp } = jwt.decode(token) as { exp: number };
		const after = Math.floor(Date.now() / 1000);
		expect(exp).toBeGreaterThanOrEqual(before + 7 * 24 * 3600);
		expect(exp).toBeLessThanOrEqual(after + 7 * 24 * 3600);
	});
});

// ---------------------------------------------------------------------------
// verifyToken
// ---------------------------------------------------------------------------

describe("verifyToken", () => {
	it("returns the original payload for a valid token", () => {
		const token = generateToken(payload);
		const result = verifyToken(token);
		expect(result).not.toBeNull();
		expect(result!.userId).toBe(payload.userId);
		expect(result!.email).toBe(payload.email);
	});

	it("returns null for a tampered token", () => {
		const token = generateToken(payload);
		const tampered = token.slice(0, -4) + "xxxx";
		expect(verifyToken(tampered)).toBeNull();
	});

	it("returns null for a completely invalid string", () => {
		expect(verifyToken("not.a.token")).toBeNull();
	});

	it("returns null for an empty string", () => {
		expect(verifyToken("")).toBeNull();
	});

	it("returns null for an expired token", () => {
		const expired = makeExpiredToken(ACCESS_SECRET);
		expect(verifyToken(expired)).toBeNull();
	});

	it("returns null when a refresh token is passed to verifyToken", () => {
		// Signed with the wrong secret — must not verify.
		const refreshToken = generateRefreshToken(payload);
		expect(verifyToken(refreshToken)).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// verifyRefreshToken
// ---------------------------------------------------------------------------

describe("verifyRefreshToken", () => {
	it("returns the original payload for a valid refresh token", () => {
		const token = generateRefreshToken(payload);
		const result = verifyRefreshToken(token);
		expect(result).not.toBeNull();
		expect(result!.userId).toBe(payload.userId);
		expect(result!.email).toBe(payload.email);
	});

	it("returns null for a tampered refresh token", () => {
		const token = generateRefreshToken(payload);
		const tampered = token.slice(0, -4) + "xxxx";
		expect(verifyRefreshToken(tampered)).toBeNull();
	});

	it("returns null for a completely invalid string", () => {
		expect(verifyRefreshToken("not.a.token")).toBeNull();
	});

	it("returns null for an empty string", () => {
		expect(verifyRefreshToken("")).toBeNull();
	});

	it("returns null for an expired refresh token", () => {
		const expired = makeExpiredToken(REFRESH_SECRET);
		expect(verifyRefreshToken(expired)).toBeNull();
	});

	it("returns null when an access token is passed to verifyRefreshToken", () => {
		// Signed with the wrong secret — must not verify.
		const accessToken = generateToken(payload);
		expect(verifyRefreshToken(accessToken)).toBeNull();
	});
});
