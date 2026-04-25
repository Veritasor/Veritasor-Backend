import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import {
	generateRefreshToken,
	generateToken,
	type TokenPayload,
	verifyRefreshToken,
	verifyToken,
	generateAccessToken,
	generateRefreshTokenWithFamily,
	generateTokenPair,
	verifyAccessToken,
	verifyRefreshTokenRotationAware,
	refreshTokenPair,
	blacklistToken,
	isTokenBlacklisted,
	getTokenFamily,
	revokeTokenFamily,
	clearExpiredFamilies,
	TokenExpiredError,
	TokenInvalidError,
	TokenReusedError,
	JWTError,
} from "../../../src/utils/jwt";

// ---------------------------------------------------------------------------
// Fixtures & Helpers
// ---------------------------------------------------------------------------

const payload: TokenPayload = {
	userId: "user-123",
	email: "test@example.com",
};

const ACCESS_SECRET = "dev-secret-key";
const REFRESH_SECRET = "dev-refresh-secret-key";

/** Signs a token that is already expired by using a negative expiresIn. */
function makeExpiredToken(secret: string): string {
	return jwt.sign(payload, secret, { expiresIn: -1 });
}

// ---------------------------------------------------------------------------
// LEGACY FUNCTION TESTS (backward compatibility)
// ---------------------------------------------------------------------------

describe("generateToken (legacy)", () => {
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

describe("generateRefreshToken (legacy)", () => {
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

describe("verifyToken (legacy)", () => {
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
		const refreshToken = generateRefreshToken(payload);
		expect(verifyToken(refreshToken)).toBeNull();
	});
});

describe("verifyRefreshToken (legacy)", () => {
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
		const accessToken = generateToken(payload);
		expect(verifyRefreshToken(accessToken)).toBeNull();
	});
});

describe("sign (generic)", () => {
	it("returns a non-empty string for valid payload", async () => {
		const { sign } = await import("../../../src/utils/jwt");
		const token = sign(payload);
		expect(typeof token).toBe("string");
		expect(token.length).toBeGreaterThan(0);
	});

	it("returns a valid JWT with three dot-separated segments", async () => {
		const { sign } = await import("../../../src/utils/jwt");
		const token = sign(payload);
		expect(token.split(".")).toHaveLength(3);
	});

	it("supports expiresIn option", async () => {
		const { sign } = await import("../../../src/utils/jwt");
		const before = Math.floor(Date.now() / 1000);
		const token = sign(payload, { expiresIn: "2h" });
		const { exp } = jwt.decode(token) as { exp: number };
		const after = Math.floor(Date.now() / 1000);
		expect(exp).toBeGreaterThanOrEqual(before + 7200);
		expect(exp).toBeLessThanOrEqual(after + 7200);
	});

	it("supports algorithm option", async () => {
		const { sign } = await import("../../../src/utils/jwt");
		const token = sign(payload, { algorithm: "HS256" });
		const decoded = jwt.decode(token, { complete: true });
		expect(decoded?.header.alg).toBe("HS256");
	});
});

describe("verify (generic)", () => {
	it("returns the decoded payload for a valid token", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload);
		const result = verify(token);
		expect(result).toMatchObject(payload);
	});

	it("throws error for expired token", async () => {
		const { verify } = await import("../../../src/utils/jwt");
		const expired = makeExpiredToken(ACCESS_SECRET);
		expect(() => verify(expired)).toThrow();
	});

	it("throws error for invalid token", async () => {
		const { verify } = await import("../../../src/utils/jwt");
		expect(() => verify("not.a.token")).toThrow();
	});

	it("throws error for tampered token", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload);
		const tampered = token.slice(0, -4) + "xxxx";
		expect(() => verify(tampered)).toThrow();
	});

	it("round-trip: sign then verify returns equivalent payload", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const testPayload = { sub: "user-456", email: "roundtrip@test.com" };
		const token = sign(testPayload);
		const result = verify(token);
		expect(result).toMatchObject(testPayload);
	});
});

// ---------------------------------------------------------------------------
// ENHANCED ROTATION-AWARE FUNCTION TESTS
// ---------------------------------------------------------------------------

describe("generateAccessToken", () => {
	it("generates token with jti and familyId claims", () => {
		const token = generateAccessToken(payload);
		const decoded = jwt.decode(token) as any;
		expect(decoded.jti).toBeDefined();
		expect(decoded.familyId).toBeDefined();
		expect(decoded.type).toBe("access");
	});

	it("uses provided familyId or generates new one", () => {
		const providedFamilyId = "family-123";
		const token = generateAccessToken(payload, providedFamilyId);
		const decoded = jwt.decode(token) as any;
		expect(decoded.familyId).toBe(providedFamilyId);
	});

	it("generates unique jti for each token", () => {
		const token1 = generateAccessToken(payload);
		const token2 = generateAccessToken(payload);
		const decoded1 = jwt.decode(token1) as any;
		const decoded2 = jwt.decode(token2) as any;
		expect(decoded1.jti).not.toBe(decoded2.jti);
	});

	it("has expiry of configured access token TTL", () => {
		const before = Math.floor(Date.now() / 1000);
		const token = generateAccessToken(payload);
		const decoded = jwt.decode(token) as any;
		const after = Math.floor(Date.now() / 1000);
		// Default TTL is 3600 (1 hour)
		expect(decoded.exp).toBeGreaterThanOrEqual(before + 3600 - 1);
		expect(decoded.exp).toBeLessThanOrEqual(after + 3600 + 1);
	});
});

describe("generateRefreshTokenWithFamily", () => {
	it("generates token with jti and familyId claims", () => {
		const token = generateRefreshTokenWithFamily(payload);
		const decoded = jwt.decode(token) as any;
		expect(decoded.jti).toBeDefined();
		expect(decoded.familyId).toBeDefined();
		expect(decoded.type).toBe("refresh");
	});

	it("initializes token family tracking", () => {
		const token = generateRefreshTokenWithFamily(payload);
		const decoded = jwt.decode(token) as any;
		const family = getTokenFamily(decoded.familyId);
		expect(family).toBeDefined();
		expect(family?.userId).toBe(payload.userId);
	});

	it("has expiry of configured refresh token TTL", () => {
		const before = Math.floor(Date.now() / 1000);
		const token = generateRefreshTokenWithFamily(payload);
		const decoded = jwt.decode(token) as any;
		const after = Math.floor(Date.now() / 1000);
		// Default TTL is 604800 (7 days)
		expect(decoded.exp).toBeGreaterThanOrEqual(before + 604800 - 1);
		expect(decoded.exp).toBeLessThanOrEqual(after + 604800 + 1);
	});
});

describe("generateTokenPair", () => {
	it("generates access and refresh tokens with same family", () => {
		const { accessToken, refreshToken, familyId } = generateTokenPair(payload);

		const accessDecoded = jwt.decode(accessToken) as any;
		const refreshDecoded = jwt.decode(refreshToken) as any;

		expect(accessDecoded.familyId).toBe(familyId);
		expect(refreshDecoded.familyId).toBe(familyId);
		expect(accessDecoded.type).toBe("access");
		expect(refreshDecoded.type).toBe("refresh");
	});

	it("preserves provided familyId", () => {
		const providedFamilyId = "family-456";
		const { familyId } = generateTokenPair(payload, providedFamilyId);
		expect(familyId).toBe(providedFamilyId);
	});

	it("initializes family tracking", () => {
		const { familyId } = generateTokenPair(payload);
		const family = getTokenFamily(familyId);
		expect(family).toBeDefined();
		expect(family?.userId).toBe(payload.userId);
	});
});

describe("verifyAccessToken", () => {
	it("verifies valid access token and returns payload", () => {
		const { accessToken } = generateTokenPair(payload);
		const verified = verifyAccessToken(accessToken);
		expect(verified.userId).toBe(payload.userId);
		expect(verified.email).toBe(payload.email);
		expect(verified.jti).toBeDefined();
		expect(verified.familyId).toBeDefined();
	});

	it("throws TokenInvalidError for invalid token", () => {
		expect(() => verifyAccessToken("not.a.token")).toThrow(TokenInvalidError);
	});

	it("throws TokenExpiredError for expired token", () => {
		// Generate a properly typed access token that's expired
		const jti = "test-jti";
		const familyId = "test-family";
		const expiredToken = jwt.sign(
			{
				userId: payload.userId,
				email: payload.email,
				jti,
				familyId,
				type: "access",
			},
			ACCESS_SECRET,
			{ expiresIn: -20 } // Beyond 10s skew tolerance
		);
		expect(() => verifyAccessToken(expiredToken)).toThrow(TokenExpiredError);
	});

	it("throws JWTError for refresh token (type mismatch)", () => {
		const { refreshToken } = generateTokenPair(payload);
		expect(() => verifyAccessToken(refreshToken)).toThrow(JWTError);
	});

	it("throws JWTError if token is blacklisted", () => {
		const { accessToken } = generateTokenPair(payload);
		const decoded = jwt.decode(accessToken) as any;
		blacklistToken(decoded.jti);
		expect(() => verifyAccessToken(accessToken)).toThrow();
	});
});

describe("verifyRefreshTokenRotationAware", () => {
	it("verifies valid refresh token", () => {
		const { refreshToken } = generateTokenPair(payload);
		const verified = verifyRefreshTokenRotationAware(refreshToken);
		expect(verified.userId).toBe(payload.userId);
		expect(verified.email).toBe(payload.email);
		expect(verified.jti).toBeDefined();
		expect(verified.familyId).toBeDefined();
	});

	it("throws TokenInvalidError for invalid token", () => {
		expect(() => verifyRefreshTokenRotationAware("not.a.token")).toThrow(
			TokenInvalidError
		);
	});

	it("throws TokenExpiredError for expired token", () => {
		// Generate a properly typed refresh token that's expired
		const jti = "test-jti";
		const familyId = "test-family";
		const expiredToken = jwt.sign(
			{
				userId: payload.userId,
				email: payload.email,
				jti,
				familyId,
				type: "refresh",
			},
			REFRESH_SECRET,
			{ expiresIn: -20 } // Beyond 10s skew tolerance
		);
		expect(() => verifyRefreshTokenRotationAware(expiredToken)).toThrow(
			TokenExpiredError
		);
	});

	it("throws JWTError for access token (type mismatch)", () => {
		const { accessToken } = generateTokenPair(payload);
		expect(() => verifyRefreshTokenRotationAware(accessToken)).toThrow(JWTError);
	});

	it("throws TokenReusedError when same token used twice", () => {
		const { refreshToken } = generateTokenPair(payload);

		// First use - should succeed
		verifyRefreshTokenRotationAware(refreshToken);

		// Mark it as used (simulating refresh)
		const decoded = jwt.decode(refreshToken) as any;
		const family = getTokenFamily(decoded.familyId)!;
		family.blacklistedJtis.add(decoded.jti);

		// Second use - should fail
		expect(() => verifyRefreshTokenRotationAware(refreshToken)).toThrow(
			TokenReusedError
		);
	});

	it("throws error if family marked as compromised", () => {
		const { refreshToken } = generateTokenPair(payload);
		const decoded = jwt.decode(refreshToken) as any;
		const family = getTokenFamily(decoded.familyId)!;
		family.concurrentRefreshDetected = true;

		expect(() => verifyRefreshTokenRotationAware(refreshToken)).toThrow(JWTError);
	});
});

describe("refreshTokenPair", () => {
	it("returns new access and refresh tokens", () => {
		const { refreshToken } = generateTokenPair(payload);
		const result = refreshTokenPair(refreshToken);

		expect(result.accessToken).toBeDefined();
		expect(result.refreshToken).toBeDefined();
		expect(result.familyId).toBeDefined();
	});

	it("preserves familyId across rotation", () => {
		const { refreshToken, familyId } = generateTokenPair(payload);
		const { familyId: newFamilyId } = refreshTokenPair(refreshToken);
		expect(newFamilyId).toBe(familyId);
	});

	it("invalidates old token after rotation", () => {
		const { refreshToken } = generateTokenPair(payload);
		const decoded = jwt.decode(refreshToken) as any;
		const oldJti = decoded.jti;

		refreshTokenPair(refreshToken);

		// Old token should now be blacklisted
		expect(() => verifyRefreshTokenRotationAware(refreshToken)).toThrow(
			TokenReusedError
		);
	});

	it("creates new jti for each rotated token", () => {
		const { refreshToken: token1 } = generateTokenPair(payload);
		const { refreshToken: token2 } = refreshTokenPair(token1);
		const { refreshToken: token3 } = refreshTokenPair(token2);

		const decoded1 = jwt.decode(token1) as any;
		const decoded2 = jwt.decode(token2) as any;
		const decoded3 = jwt.decode(token3) as any;

		expect(decoded1.jti).not.toBe(decoded2.jti);
		expect(decoded2.jti).not.toBe(decoded3.jti);
	});

	it("throws TokenReusedError on concurrent refresh attempts", () => {
		const { refreshToken } = generateTokenPair(payload);

		// First refresh succeeds
		const { refreshToken: token2 } = refreshTokenPair(refreshToken);

		// Second refresh with original token should fail
		expect(() => refreshTokenPair(refreshToken)).toThrow(TokenReusedError);
	});
});

describe("Token Blacklist Operations", () => {
	it("blacklistToken adds token to blacklist", () => {
		const jti = "test-jti-123";
		blacklistToken(jti);
		expect(isTokenBlacklisted(jti)).toBe(true);
	});

	it("isTokenBlacklisted returns false for non-blacklisted token", () => {
		expect(isTokenBlacklisted("unknown-jti")).toBe(false);
	});

	it("verifyAccessToken throws for blacklisted token", () => {
		const { accessToken } = generateTokenPair(payload);
		const decoded = jwt.decode(accessToken) as any;
		blacklistToken(decoded.jti);
		expect(() => verifyAccessToken(accessToken)).toThrow();
	});
});

describe("Token Family Operations", () => {
	it("revokeTokenFamily marks entire family as compromised", () => {
		const { familyId } = generateTokenPair(payload);
		revokeTokenFamily(familyId);
		expect(getTokenFamily(familyId)).toBeUndefined();
	});

	it("getTokenFamily returns family info", () => {
		const { familyId } = generateTokenPair(payload);
		const family = getTokenFamily(familyId);
		expect(family).toBeDefined();
		expect(family?.userId).toBe(payload.userId);
		expect(family?.familyId).toBe(familyId);
	});
});

describe("clearExpiredFamilies", () => {
	it("removes families older than maxAge", () => {
		const { familyId } = generateTokenPair(payload);
		const family = getTokenFamily(familyId)!;

		// Set createdAt to 40 days ago
		family.createdAt = Date.now() - 40 * 24 * 60 * 60 * 1000;

		const cleared = clearExpiredFamilies(30 * 24 * 60 * 60 * 1000);
		expect(cleared).toBe(1);
		expect(getTokenFamily(familyId)).toBeUndefined();
	});

	it("preserves families within maxAge", () => {
		const { familyId } = generateTokenPair(payload);
		const cleared = clearExpiredFamilies(30 * 24 * 60 * 60 * 1000);
		expect(cleared).toBe(0);
		expect(getTokenFamily(familyId)).toBeDefined();
	});
});

describe("Security edge cases", () => {
	it("prevents reuse of refresh token across multiple refreshes", () => {
		const { refreshToken: token1 } = generateTokenPair(payload);

		// First refresh
		const { refreshToken: token2 } = refreshTokenPair(token1);

		// Attempt to reuse original token2 should fail after consuming it
		const { refreshToken: token3 } = refreshTokenPair(token2);

		// Attempting to use token2 again should fail
		expect(() => refreshTokenPair(token2)).toThrow(TokenReusedError);
	});

	it("maintains separate families for different logins", () => {
		const { familyId: family1 } = generateTokenPair(payload);
		const { familyId: family2 } = generateTokenPair(payload);

		expect(family1).not.toBe(family2);
		expect(getTokenFamily(family1)).toBeDefined();
		expect(getTokenFamily(family2)).toBeDefined();
	});

	it("isolates token families per user login session", () => {
		const payload2 = { userId: "user-999", email: "other@test.com" };

		const { familyId: family1 } = generateTokenPair(payload);
		const { familyId: family2 } = generateTokenPair(payload2);

		const fam1 = getTokenFamily(family1)!;
		const fam2 = getTokenFamily(family2)!;

		expect(fam1.userId).toBe(payload.userId);
		expect(fam2.userId).toBe(payload2.userId);
	});
});
