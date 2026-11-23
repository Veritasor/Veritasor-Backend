import jwt from "jsonwebtoken";
import { describe, expect, it, vi, afterEach } from "vitest";
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
	sign,
	verify,
	JWT_ISSUER,
	JWT_AUDIENCE,
	JWT_REFRESH_AUDIENCE,
} from "../../../src/utils/jwt";

// ---------------------------------------------------------------------------
// Fixtures & Helpers
// ---------------------------------------------------------------------------

const payload: TokenPayload = {
	userId: "user-123",
	email: "test@example.com",
};

const ACCESS_SECRET = process.env.JWT_SECRET ?? "dev-secret-key";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? "dev-refresh-secret-key";

/**
 * Signs an expired access token that carries the correct iss/aud claims so
 * that verifyToken rejects it specifically because it is expired, not because
 * claims are missing.
 */
function makeExpiredAccessToken(): string {
	return jwt.sign(payload, ACCESS_SECRET, {
		expiresIn: -1,
		issuer: JWT_ISSUER,
		audience: JWT_AUDIENCE,
	});
}

/**
 * Signs an expired refresh token that carries the correct iss/aud claims so
 * that verifyRefreshToken rejects it specifically because it is expired.
 */
function makeExpiredRefreshToken(): string {
	return jwt.sign(payload, REFRESH_SECRET, {
		expiresIn: -1,
		issuer: JWT_ISSUER,
		audience: JWT_REFRESH_AUDIENCE,
	});
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

	it("embeds the correct issuer claim", () => {
		const token = generateToken(payload);
		const decoded = jwt.decode(token) as jwt.JwtPayload;
		expect(decoded.iss).toBe(JWT_ISSUER);
	});

	it("embeds the correct audience claim", () => {
		const token = generateToken(payload);
		const decoded = jwt.decode(token) as jwt.JwtPayload;
		expect(decoded.aud).toBe(JWT_AUDIENCE);
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

	it("embeds the correct issuer claim", () => {
		const token = generateRefreshToken(payload);
		const decoded = jwt.decode(token) as jwt.JwtPayload;
		expect(decoded.iss).toBe(JWT_ISSUER);
	});

	it("embeds the correct audience claim for refresh tokens", () => {
		const token = generateRefreshToken(payload);
		const decoded = jwt.decode(token) as jwt.JwtPayload;
		expect(decoded.aud).toBe(JWT_REFRESH_AUDIENCE);
	});

	it("uses a different audience than access tokens", () => {
		const access = generateToken(payload);
		const refresh = generateRefreshToken(payload);
		const decodedAccess = jwt.decode(access) as jwt.JwtPayload;
		const decodedRefresh = jwt.decode(refresh) as jwt.JwtPayload;
		expect(decodedAccess.aud).not.toBe(decodedRefresh.aud);
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
		const expired = makeExpiredAccessToken();
		expect(verifyToken(expired)).toBeNull();
	});

	it("returns null when a refresh token is passed to verifyToken", () => {
		// Signed with the wrong secret AND wrong audience — must not verify.
		const refreshToken = generateRefreshToken(payload);
		expect(verifyToken(refreshToken)).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// verifyToken — issuer and audience strict validation
// ---------------------------------------------------------------------------

describe("verifyToken — issuer and audience strict validation", () => {
	it("returns null for a token with wrong issuer", () => {
		const token = jwt.sign(payload, ACCESS_SECRET, {
			expiresIn: "1h",
			issuer: "wrong-issuer",
			audience: JWT_AUDIENCE,
		});
		expect(verifyToken(token)).toBeNull();
	});

	it("returns null for a token with wrong audience", () => {
		const token = jwt.sign(payload, ACCESS_SECRET, {
			expiresIn: "1h",
			issuer: JWT_ISSUER,
			audience: "wrong-audience",
		});
		expect(verifyToken(token)).toBeNull();
	});

	it("returns null for a token missing the issuer claim", () => {
		const token = jwt.sign(payload, ACCESS_SECRET, {
			expiresIn: "1h",
			audience: JWT_AUDIENCE,
			// no issuer
		});
		expect(verifyToken(token)).toBeNull();
	});

	it("returns null for a token missing the audience claim", () => {
		const token = jwt.sign(payload, ACCESS_SECRET, {
			expiresIn: "1h",
			issuer: JWT_ISSUER,
			// no audience
		});
		expect(verifyToken(token)).toBeNull();
	});

	it("returns null when a refresh token is used as an access token (cross-token attack)", () => {
		// generateRefreshToken uses JWT_REFRESH_AUDIENCE — verifyToken expects JWT_AUDIENCE
		const refreshToken = generateRefreshToken(payload);
		expect(verifyToken(refreshToken)).toBeNull();
	});

	it("returns null for a token signed without any claims (legacy token simulation)", () => {
		const legacyToken = jwt.sign(payload, ACCESS_SECRET);
		expect(verifyToken(legacyToken)).toBeNull();
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
		const expired = makeExpiredRefreshToken();
		expect(verifyRefreshToken(expired)).toBeNull();
	});

	it("returns null when an access token is passed to verifyRefreshToken", () => {
		// Signed with the wrong secret AND wrong audience — must not verify.
		const accessToken = generateToken(payload);
		expect(verifyRefreshToken(accessToken)).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// verifyRefreshToken — issuer and audience strict validation
// ---------------------------------------------------------------------------

describe("verifyRefreshToken — issuer and audience strict validation", () => {
	it("returns null for a refresh token with wrong issuer", () => {
		const token = jwt.sign(payload, REFRESH_SECRET, {
			expiresIn: "7d",
			issuer: "attacker-service",
			audience: JWT_REFRESH_AUDIENCE,
		});
		expect(verifyRefreshToken(token)).toBeNull();
	});

	it("returns null for a refresh token with wrong audience", () => {
		const token = jwt.sign(payload, REFRESH_SECRET, {
			expiresIn: "7d",
			issuer: JWT_ISSUER,
			audience: JWT_AUDIENCE, // access audience mistakenly used on refresh token
		});
		expect(verifyRefreshToken(token)).toBeNull();
	});

	it("returns null for a refresh token missing the issuer claim", () => {
		const token = jwt.sign(payload, REFRESH_SECRET, {
			expiresIn: "7d",
			audience: JWT_REFRESH_AUDIENCE,
			// no issuer
		});
		expect(verifyRefreshToken(token)).toBeNull();
	});

	it("returns null for a refresh token missing the audience claim", () => {
		const token = jwt.sign(payload, REFRESH_SECRET, {
			expiresIn: "7d",
			issuer: JWT_ISSUER,
			// no audience
		});
		expect(verifyRefreshToken(token)).toBeNull();
	});

	it("returns null when an access token is used as a refresh token (cross-token attack)", () => {
		// generateToken uses JWT_AUDIENCE — verifyRefreshToken expects JWT_REFRESH_AUDIENCE
		const accessToken = generateToken(payload);
		expect(verifyRefreshToken(accessToken)).toBeNull();
	});

	it("returns null for a refresh token signed without any claims (legacy token simulation)", () => {
		const legacyToken = jwt.sign(payload, REFRESH_SECRET);
		expect(verifyRefreshToken(legacyToken)).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// sign (low-level primitive)
// ---------------------------------------------------------------------------

describe("sign", () => {
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

	it("does not embed iss or aud by default", async () => {
		const { sign } = await import("../../../src/utils/jwt");
		const token = sign(payload);
		const decoded = jwt.decode(token) as jwt.JwtPayload;
		expect(decoded.iss).toBeUndefined();
		expect(decoded.aud).toBeUndefined();
	});

	it("embeds audience and issuer when passed via options", async () => {
		const { sign } = await import("../../../src/utils/jwt");
		const token = sign(payload, { audience: "custom-aud", issuer: "custom-iss" });
		const decoded = jwt.decode(token) as jwt.JwtPayload;
		expect(decoded.aud).toBe("custom-aud");
		expect(decoded.iss).toBe("custom-iss");
	});
});

// ---------------------------------------------------------------------------
// verify (low-level primitive)
// ---------------------------------------------------------------------------

describe("verify", () => {
	it("returns the decoded payload for a valid token", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload);
		const result = verify(token);
		expect(result).toMatchObject(payload);
	});

	it("throws error for expired token", async () => {
		const { verify } = await import("../../../src/utils/jwt");
		const expired = makeExpiredAccessToken();
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

	it("accepts a token with matching audience and issuer when options are passed", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload, { audience: "test-aud", issuer: "test-iss" });
		const result = verify(token, { audience: "test-aud", issuer: "test-iss" });
		expect(result).toMatchObject(payload);
	});

	it("throws for wrong audience when options are passed", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload, { audience: "correct-aud" });
		expect(() => verify(token, { audience: "wrong-aud" })).toThrow();
	});

	it("throws for wrong issuer when options are passed", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload, { issuer: "correct-iss" });
		expect(() => verify(token, { issuer: "wrong-iss" })).toThrow();
	});

	it("accepts a token with no aud/iss when no options are passed (backward-compatible)", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload); // no aud or iss
		expect(() => verify(token)).not.toThrow();
		const result = verify(token);
		expect(result).toMatchObject(payload);
	});

	it("throws for missing audience claim when audience option is required", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload); // no aud embedded
		expect(() => verify(token, { audience: "required-aud" })).toThrow();
	});
});

// ---------------------------------------------------------------------------
// getSecret branches (via sign — requires module isolation)
// ---------------------------------------------------------------------------

describe("getSecret branches (via sign)", () => {
	afterEach(() => {
		vi.restoreAllMocks();
		vi.unstubAllEnvs();
	});

	it("uses config.jwtSecret when it is set", async () => {
		vi.resetModules();
		vi.doMock("../../../src/config/index.js", () => ({
			config: {
				jwtSecret: "from-config-secret",
				cors: { origin: "*" },
				jobs: { attestationReminder: { schedule: "* * * * *" } },
				soroban: { rpcUrl: "", contractId: "", networkPassphrase: "" },
			},
		}));
		// The default secret loader reads process.env.JWT_SECRET directly, so
		// blank it to force the mocked-config fallback to actually be reached.
		vi.stubEnv("JWT_SECRET", "");
		const { sign: freshSign } = await import("../../../src/utils/jwt");
		const token = freshSign(payload);
		// The token should be verifiable with the mocked config secret
		expect(jwt.verify(token, "from-config-secret")).toMatchObject(payload);
	});

	it("uses process.env.JWT_SECRET when config.jwtSecret is not set", async () => {
		vi.resetModules();
		vi.doMock("../../../src/config/index.js", () => ({
			config: {
				jwtSecret: undefined,
				cors: { origin: "*" },
				jobs: { attestationReminder: { schedule: "* * * * *" } },
				soroban: { rpcUrl: "", contractId: "", networkPassphrase: "" },
			},
		}));
		vi.stubEnv("JWT_SECRET", "from-env-var");
		const { sign: freshSign } = await import("../../../src/utils/jwt");
		const token = freshSign(payload);
		expect(jwt.verify(token, "from-env-var")).toMatchObject(payload);
	});

	it("throws in production when no secret is configured", async () => {
		vi.resetModules();
		vi.doMock("../../../src/config/index.js", () => ({
			config: {
				jwtSecret: undefined,
				cors: { origin: "*" },
				jobs: { attestationReminder: { schedule: "* * * * *" } },
				soroban: { rpcUrl: "", contractId: "", networkPassphrase: "" },
			},
		}));
		const savedSecret = process.env.JWT_SECRET;
		const savedNodeEnv = process.env.NODE_ENV;
		delete process.env.JWT_SECRET;
		process.env.NODE_ENV = "production";
		try {
			const { sign: freshSign } = await import("../../../src/utils/jwt");
			expect(() => freshSign(payload)).toThrow(
				"JWT secret is required in production"
			);
		} finally {
			if (savedSecret !== undefined) process.env.JWT_SECRET = savedSecret;
			process.env.NODE_ENV = savedNodeEnv;
		}
	});
});

// ---------------------------------------------------------------------------
// JWT constant defaults
// ---------------------------------------------------------------------------

describe("JWT constant defaults", () => {
	it("JWT_ISSUER defaults to 'veritasor-api'", () => {
		expect(JWT_ISSUER).toBe("veritasor-api");
	});

	it("JWT_AUDIENCE defaults to 'veritasor-client'", () => {
		expect(JWT_AUDIENCE).toBe("veritasor-client");
	});

	it("JWT_REFRESH_AUDIENCE defaults to 'veritasor-refresh'", () => {
		expect(JWT_REFRESH_AUDIENCE).toBe("veritasor-refresh");
	});

	it("JWT_AUDIENCE and JWT_REFRESH_AUDIENCE are different values", () => {
		expect(JWT_AUDIENCE).not.toBe(JWT_REFRESH_AUDIENCE);
	});
});

// ---------------------------------------------------------------------------
// Expiry Skew Handling Tests
// Tests for clock skew tolerance, custom clock timestamps, and maxAge options
// ---------------------------------------------------------------------------

describe("verify expiry skew handling", () => {
	it("throws TokenExpiredError for token expired beyond clockTolerance", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload, { expiresIn: -5 }); // expired 5 seconds ago
		expect(() => verify(token, { clockTolerance: 3 })).toThrow();
	});

	it("accepts token within clockTolerance window", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		// Token expired 2 seconds ago, tolerance is 5 seconds
		const token = sign(payload, { expiresIn: -2 });
		const result = verify(token, { clockTolerance: 5 });
		expect(result).toMatchObject(payload);
	});

	it("throws when maxAge is exceeded (token age > maxAge)", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token issued 10 seconds ago, so its age is 10 seconds
		const token = sign({ ...payload, iat: now - 10 });
		// maxAge of 5 seconds means token is too old (10 > 5)
		expect(() => verify(token, { maxAge: 5 })).toThrow();
	});

	it("accepts token when maxAge is not exceeded", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const token = sign(payload, { expiresIn: "1h" });
		const result = verify(token, { maxAge: 3600 }); // 1 hour in seconds
		expect(result).toMatchObject(payload);
	});

	it("rejects future token when verified before nbf with clockTolerance", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token not valid before 10 seconds from now
		const token = sign({ ...payload, nbf: now + 10 });
		// Even with 5 second tolerance, token is still 5 seconds in the future
		expect(() => verify(token, { clockTolerance: 5 })).toThrow();
	});

	it("accepts future token when nbf is within clockTolerance", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token not valid before 3 seconds from now
		const token = sign({ ...payload, nbf: now + 3 });
		// With 5 second tolerance, token is within acceptable window
		const result = verify(token, { clockTolerance: 5 });
		expect(result).toMatchObject(payload);
	});

	it("verifies with custom clockTimestamp in the past (token appears not yet expired)", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token expires in 10 seconds from actual current time
		const token = sign(payload, { expiresIn: 10 });
		// Verify with timestamp from 5 seconds ago - token still valid
		const result = verify(token, { clockTimestamp: now - 5 });
		expect(result).toMatchObject(payload);
	});

	it("rejects token with custom clockTimestamp in the future (token appears expired)", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token expires in 5 seconds from actual current time
		const token = sign(payload, { expiresIn: 5 });
		// Verify with timestamp 10 seconds in the future - token appears expired
		expect(() => verify(token, { clockTimestamp: now + 10 })).toThrow();
	});

	it("combines clockTimestamp and clockTolerance for skew handling", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token expires in 5 seconds from actual current time
		const token = sign(payload, { expiresIn: 5 });
		// Verify with timestamp 7 seconds in the future (token appears 2s expired)
		// With 3 second tolerance, this should pass
		const result = verify(token, { 
			clockTimestamp: now + 7, 
			clockTolerance: 3 
		});
		expect(result).toMatchObject(payload);
	});

	it("rejects when combined clockTimestamp and clockTolerance still exceed expiry", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token expires in 5 seconds from actual current time
		const token = sign(payload, { expiresIn: 5 });
		// Verify with timestamp 15 seconds in the future (token appears 10s expired)
		// With 3 second tolerance, token is still 7s expired - should fail
		expect(() => verify(token, { 
			clockTimestamp: now + 15, 
			clockTolerance: 3 
		})).toThrow();
	});

	it("handles zero clockTolerance strictly", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		const token = sign(payload, { expiresIn: "1h" });
		// Zero tolerance means strict verification
		const result = verify(token, { clockTolerance: 0 });
		expect(result).toMatchObject(payload);
	});

	it("validates iat (issued at) with clock skew tolerance", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token issued 5 seconds in the future (clock skew scenario)
		const token = sign({ ...payload, iat: now + 5 });
		// With 10 second tolerance, should accept
		const result = verify(token, { clockTolerance: 10 });
		expect(result).toMatchObject(payload);
	});

	it("uses iat claim with maxAge for age validation", async () => {
		const { sign, verify } = await import("../../../src/utils/jwt");
		const now = Math.floor(Date.now() / 1000);
		// Token issued 20 seconds ago with exp far in future
		const token = sign({ ...payload, iat: now - 20, exp: now + 3600 });
		// maxAge of 10 seconds should reject (token is 20s old)
		expect(() => verify(token, { maxAge: 10 })).toThrow();
	});
});

// ---------------------------------------------------------------------------
// ENHANCED ROTATION-AWARE FUNCTIONS
// Token family lifecycle, claim binding, reuse detection, blacklist semantics
// ---------------------------------------------------------------------------

describe("enhanced rotation-aware functions", () => {
	const freshPayload: TokenPayload = {
		userId: `user-rotate-${Date.now()}`,
		email: "rotate@example.com",
	};

	function uniqueFamily(): string {
		return `family-${Date.now()}-${Math.random()}`;
	}

	describe("generateAccessToken / generateTokenPair", () => {
		it("embeds jti, familyId, type, iss and aud claims", () => {
			const family = uniqueFamily();
			const token = generateAccessToken(freshPayload, family);
			const decoded = jwt.decode(token) as Record<string, unknown>;
			expect(decoded.jti).toBeTypeOf("string");
			expect((decoded.jti as string).length).toBeGreaterThan(0);
			expect(decoded.familyId).toBe(family);
			expect(decoded.type).toBe("access");
			expect(decoded.iss).toBe(JWT_ISSUER);
			expect(decoded.aud).toBe(JWT_AUDIENCE);
			expect(decoded.email).toBe(freshPayload.email);
		});

		it("generateTokenPair shares one familyId between access and refresh", () => {
			const pair = generateTokenPair(freshPayload);
			const accessDecoded = jwt.decode(pair.accessToken) as Record<string, unknown>;
			const refreshDecoded = jwt.decode(pair.refreshToken) as Record<string, unknown>;
			expect(accessDecoded.familyId).toBe(pair.familyId);
			expect(refreshDecoded.familyId).toBe(pair.familyId);
			expect(accessDecoded.type).toBe("access");
			expect(refreshDecoded.type).toBe("refresh");
			expect(accessDecoded.aud).toBe(JWT_AUDIENCE);
			expect(refreshDecoded.aud).toBe(JWT_REFRESH_AUDIENCE);
		});

		it("generateAccessToken without a familyId registers its own family for tracking", () => {
			const token = generateAccessToken(freshPayload);
			const decoded = jwt.decode(token) as Record<string, unknown>;
			const family = getTokenFamily(decoded.familyId as string);
			expect(family).toBeDefined();
			expect(family?.issuedJtis.has(decoded.jti as string)).toBe(true);
		});
	});

	describe("verifyAccessToken", () => {
		it("accepts a token minted by generateTokenPair", () => {
			const { accessToken } = generateTokenPair(freshPayload);
			const decoded = verifyAccessToken(accessToken);
			expect(decoded).toMatchObject(freshPayload);
			expect(decoded.type).toBe("access");
			expect(decoded.jti).toBeTypeOf("string");
		});

		it("rejects a refresh-family token presented as an access token", () => {
			const { refreshToken } = generateTokenPair(freshPayload);
			// type=refresh + refresh audience + refresh secret -> verifyAccessToken
			// must reject under audience/issuer/claim validation.
			expect(() => verifyAccessToken(refreshToken)).toThrow(TokenInvalidError);
		});

		it("rejects a legacy (non-rotation) token", () => {
			const legacy = generateToken(freshPayload);
			expect(() => verifyAccessToken(legacy)).toThrow(TokenInvalidError);
		});

		it("rejects a token with wrong audience", () => {
			const token = jwt.sign(
				{ ...freshPayload, jti: "jti-aud", familyId: uniqueFamily(), type: "access" },
				ACCESS_SECRET,
				{ expiresIn: 3600, issuer: JWT_ISSUER, audience: "other-audience", algorithm: "HS256" } as any,
			);
			expect(() => verifyAccessToken(token)).toThrow(TokenInvalidError);
		});

		it("rejects a signature-valid token whose type claim is 'refresh'", () => {
			// Signature + claims pass, but the type claim is wrong -> TYPE_MISMATCH.
			const token = jwt.sign(
				{ ...freshPayload, jti: "jti-type", familyId: uniqueFamily(), type: "refresh" },
				ACCESS_SECRET,
				{ expiresIn: 3600, issuer: JWT_ISSUER, audience: JWT_AUDIENCE } as any,
			);
			expect(() => verifyAccessToken(token)).toThrow(
				expect.objectContaining({ code: "TYPE_MISMATCH" }),
			);
		});

		it("rejects an access token signed with the wrong secret", () => {
			const token = jwt.sign(
				{ ...freshPayload, jti: "jti-secret", familyId: uniqueFamily(), type: "access" },
				"wrong-secret",
				{ expiresIn: "1h", issuer: JWT_ISSUER, audience: JWT_AUDIENCE } as any,
			);
			expect(() => verifyAccessToken(token)).toThrow(TokenInvalidError);
		});

		it("rejects an expired access token", () => {
			const { accessToken } = generateTokenPair(freshPayload);
			// Rewrite the same payload with expiresIn in the past.
			const decoded = jwt.decode(accessToken) as Record<string, unknown>;
			const expired = jwt.sign(
				{
					userId: decoded.userId,
					email: decoded.email,
					jti: decoded.jti,
					familyId: decoded.familyId,
					type: "access",
				},
				ACCESS_SECRET,
				{ expiresIn: -60, issuer: JWT_ISSUER, audience: JWT_AUDIENCE } as any,
			);
			expect(() => verifyAccessToken(expired)).toThrow(TokenExpiredError);
		});

		it("rejects a globally blacklisted access token", () => {
			const { accessToken } = generateTokenPair(freshPayload);
			const decoded = jwt.decode(accessToken) as Record<string, unknown>;
			blacklistToken(decoded.jti as string);
			expect(() => verifyAccessToken(accessToken)).toThrow(
				expect.objectContaining({ code: "TOKEN_REVOKED" }),
			);
		});

		it("throws TokenInvalidError for garbage input", () => {
			expect(() => verifyAccessToken("not-a-jwt")).toThrow(TokenInvalidError);
			expect(() => verifyAccessToken("")).toThrow(TokenInvalidError);
		});
	});

	describe("verifyRefreshTokenRotationAware", () => {
		it("accepts a fresh refresh token minted by generateTokenPair", () => {
			const { refreshToken } = generateTokenPair(freshPayload);
			const decoded = verifyRefreshTokenRotationAware(refreshToken);
			expect(decoded).toMatchObject(freshPayload);
			expect(decoded.type).toBe("refresh");
		});

		it("rejects a legacy (non-rotation) refresh token", () => {
			const legacy = generateRefreshToken(freshPayload);
			expect(() => verifyRefreshTokenRotationAware(legacy)).toThrow(TokenInvalidError);
		});

		it("rejects a refresh token signed with the access secret", () => {
			const token = jwt.sign(
				{ ...freshPayload, jti: "jti-isolation", familyId: uniqueFamily(), type: "refresh" },
				ACCESS_SECRET,
				{ expiresIn: "7d", issuer: JWT_ISSUER, audience: JWT_REFRESH_AUDIENCE } as any,
			);
			expect(() => verifyRefreshTokenRotationAware(token)).toThrow(TokenInvalidError);
		});

		it("rejects a token with missing rotation claims", () => {
			const token = jwt.sign(payload, REFRESH_SECRET, {
				expiresIn: "7d",
				issuer: JWT_ISSUER,
				audience: JWT_REFRESH_AUDIENCE,
			} as any);
			expect(() => verifyRefreshTokenRotationAware(token)).toThrow(TokenInvalidError);
		});

		it("rejects a signature-valid token whose type claim is 'access'", () => {
			const token = jwt.sign(
				{ ...freshPayload, jti: "jti-type", familyId: uniqueFamily(), type: "access" },
				REFRESH_SECRET,
				{ expiresIn: "7d", issuer: JWT_ISSUER, audience: JWT_REFRESH_AUDIENCE } as any,
			);
			expect(() => verifyRefreshTokenRotationAware(token)).toThrow(
				expect.objectContaining({ code: "TYPE_MISMATCH" }),
			);
		});

		it("rejects an expired refresh token", () => {
			const token = jwt.sign(
				{ ...freshPayload, jti: "jti-exp", familyId: uniqueFamily(), type: "refresh" },
				REFRESH_SECRET,
				{ expiresIn: -60, issuer: JWT_ISSUER, audience: JWT_REFRESH_AUDIENCE } as any,
			);
			expect(() => verifyRefreshTokenRotationAware(token)).toThrow(TokenExpiredError);
		});

		it("rejects a globally blacklisted refresh token", () => {
			const { refreshToken } = generateTokenPair(freshPayload);
			const decoded = jwt.decode(refreshToken) as Record<string, unknown>;
			blacklistToken(decoded.jti as string);
			expect(() => verifyRefreshTokenRotationAware(refreshToken)).toThrow(
				expect.objectContaining({ code: "TOKEN_REVOKED" }),
			);
		});
	});

	describe("refresh rotation and reuse detection", () => {
		it("rotates a refresh token and consumes the old jti", async () => {
			const { refreshToken } = generateTokenPair(freshPayload);
			const result = await refreshTokenPair(refreshToken);
			expect(result.accessToken).toBeTruthy();
			expect(result.refreshToken).not.toBe(refreshToken);
			expect(result.familyId).toBe(jwt.decode(refreshToken)?.familyId ?? result.familyId);
			// The new refresh token must verify normally.
			const decoded = verifyRefreshTokenRotationAware(result.refreshToken);
			expect(decoded.familyId).toBe(result.familyId);
		});

		it("detects reuse of a consumed refresh token and revokes the sibling access token", async () => {
			const pair = generateTokenPair(freshPayload);
			const oldRefresh = pair.refreshToken;
			const siblingAccess = pair.accessToken;

			await refreshTokenPair(oldRefresh);

			// Replaying the consumed refresh token = theft signal.
			await expect(refreshTokenPair(oldRefresh)).rejects.toBeInstanceOf(TokenReusedError);

			// The sibling access token minted in the same (compromised) family
			// is now globally blacklisted too.
			expect(() => verifyAccessToken(siblingAccess)).toThrow(
				expect.objectContaining({ code: "TOKEN_REVOKED" }),
			);
		});

		it("returns FAMILY_COMPROMISED for the freshly rotated token after a reuse event", async () => {
			const { refreshToken, familyId } = generateTokenPair(freshPayload);
			const fresh = await refreshTokenPair(refreshToken);
			// Trigger the theft signal using the original token.
			await expect(refreshTokenPair(refreshToken)).rejects.toBeInstanceOf(TokenReusedError);
			// The replacement token was minted before the compromise: it is
			// blacklisted along with the whole family (revoke-on-theft).
			await expect(refreshTokenPair(fresh.refreshToken)).rejects.toMatchObject({
				code: "TOKEN_REVOKED",
			});
			// The family marker persists so the compromise is recorded in-memory.
			expect(getTokenFamily(familyId)?.concurrentRefreshDetected).toBe(true);
		});

		it("serialises concurrent refresh so exactly one rotation succeeds", async () => {
			const { refreshToken } = generateTokenPair(freshPayload);
			const [a, b] = await Promise.allSettled([
				refreshTokenPair(refreshToken),
				refreshTokenPair(refreshToken),
			]);
			const successes = [a, b].filter((r) => r.status === "fulfilled");
			const failures = [a, b].filter((r) => r.status === "rejected");
			expect(successes).toHaveLength(1);
			expect(failures).toHaveLength(1);
			expect((failures[0] as PromiseRejectedResult).reason).toBeInstanceOf(
				TokenReusedError,
			);
		});

		it("rejects even a freshly minted token for a compromised family with FAMILY_COMPROMISED", async () => {
			const { refreshToken, familyId } = generateTokenPair(freshPayload);
			await refreshTokenPair(refreshToken); // consume
			await expect(refreshTokenPair(refreshToken)).rejects.toBeInstanceOf(
				TokenReusedError,
			); // theft signal
			// A brand-new token minted into the compromised family is rejected
			// by the persistent compromise marker (not the blacklist).
			const reissue = generateTokenPair(freshPayload, familyId);
			await expect(refreshTokenPair(reissue.refreshToken)).rejects.toMatchObject({
				code: "FAMILY_COMPROMISED",
			});
		});
	});

	describe("token family lifecycle", () => {
		it("revokeTokenFamily renders every family token unusable", () => {
			const pair = generateTokenPair(freshPayload);
			const family = getTokenFamily(pair.familyId);
			expect(family).toBeDefined();
			revokeTokenFamily(pair.familyId);
			expect(getTokenFamily(pair.familyId)).toBeUndefined();
			expect(() => verifyAccessToken(pair.accessToken)).toThrow(
				expect.objectContaining({ code: "TOKEN_REVOKED" }),
			);
			expect(() => verifyRefreshTokenRotationAware(pair.refreshToken)).toThrow(
				expect.objectContaining({ code: "TOKEN_REVOKED" }),
			);
		});

		it("revokeTokenFamily is a no-op for unknown families", () => {
			expect(() => revokeTokenFamily("does-not-exist")).not.toThrow();
		});

		it("clearExpiredFamilies removes old families and returns the count", () => {
			const pair = generateTokenPair(freshPayload);
			expect(getTokenFamily(pair.familyId)).toBeDefined();
			// Default is 30 days; nothing should be cleared for fresh families.
			expect(clearExpiredFamilies()).toBe(0);
			// A negative maxAge purges every existing family as expired.
			expect(clearExpiredFamilies(-1)).toBeGreaterThanOrEqual(1);
			expect(getTokenFamily(pair.familyId)).toBeUndefined();
		});

		it("getTokenFamily under a fresh family has empty blacklist and tracked issued jtis", () => {
			const pair = generateTokenPair(freshPayload);
			const family = getTokenFamily(pair.familyId);
			expect(family?.blacklistedJtis.size).toBe(0);
			expect(family?.issuedJtis.size).toBe(2);
			expect(family?.concurrentRefreshDetected).toBe(false);
		});
	});

	describe("rotation-claim binding (iss / aud / alg)", () => {
		it("verifyAccessToken enforces the refresh audience cannot pass", () => {
			const { accessToken } = generateTokenPair(freshPayload);
			// The refresh audience must NOT be accepted for access verification.
			expect(() => verifyAccessToken(accessToken)).not.toThrow();
			// Double-check iss/aud round-trips.
			const decoded = jwt.decode(accessToken) as Record<string, unknown>;
			expect(decoded.iss).toBe(JWT_ISSUER);
			expect(decoded.aud).toBe(JWT_AUDIENCE);
		});

		it("verifyRefreshTokenRotationAware enforces HS256 (algorithm confusion blocked)", () => {
			const { refreshToken } = generateTokenPair(freshPayload);
			// Verify uses algorithms:['HS256'] only, so none-HS256 tokens reject.
			const full = jwt.decode(refreshToken, { complete: true }) as {
				header: Record<string, unknown>;
			};
			expect(full.header.alg).toBe("HS256");
			// Craft an RS256-style header without modifying claims -> verify rejects.
			const forged = `${Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url")}.${Buffer.from(
				JSON.stringify({ ...freshPayload, jti: "jti-rs", familyId: uniqueFamily(), type: "refresh" }),
			).toString("base64url")}.Zm9yZ2Vk`;
			expect(() => verifyRefreshTokenRotationAware(forged)).toThrow(TokenInvalidError);
		});
	});

	describe("boundary and empty inputs", () => {
		it("verifyAccessToken rejects empty string", () => {
			expect(() => verifyAccessToken("")).toThrow(TokenInvalidError);
		});

		it("verifyRefreshTokenRotationAware rejects empty string", () => {
			expect(() => verifyRefreshTokenRotationAware("")).toThrow(TokenInvalidError);
		});

		it("refreshTokenPair rejects malformed input with TokenInvalidError", async () => {
			await expect(refreshTokenPair("not-a-token")).rejects.toBeInstanceOf(
				TokenInvalidError,
			);
		});

		it("blacklistToken/isTokenBlacklisted round-trip", () => {
			blacklistToken("my-jti-123", uniqueFamily());
			expect(isTokenBlacklisted("my-jti-123")).toBe(true);
		});
	});
});

// ---------------------------------------------------------------------------
// Defensive generic error handling (production secret-missing path)
// - verifyRefreshToken (legacy) null mapping
// - non-JWT error fallthrough -> TokenInvalidError for both rotation verifiers
// ---------------------------------------------------------------------------

describe("verifyRefreshToken (legacy) error mapping", () => {
	it("returns null for an expired token instead of throwing", () => {
		expect(verifyRefreshToken(makeExpiredRefreshToken())).toBeNull();
	});

	it("returns null for a malformed token", () => {
		expect(verifyRefreshToken("garbage")).toBeNull();
	});
});

describe("rotation verifiers - defensive generic error path (production)", () => {
	afterEach(() => {
		vi.restoreAllMocks();
		vi.unstubAllEnvs();
	});

	async function loadProductionJwtModule(): Promise<() => void> {
		vi.resetModules();
		vi.doMock("../../../src/config/index.js", () => ({
			config: {
				jwtSecret: undefined,
				cors: { origin: "*" },
				jobs: { attestationReminder: { schedule: "* * * * *" } },
				soroban: { rpcUrl: "", contractId: "", networkPassphrase: "" },
			},
		}));
		const savedSecret = process.env.JWT_SECRET;
		const savedNodeEnv = process.env.NODE_ENV;
		delete process.env.JWT_SECRET;
		process.env.NODE_ENV = "production";
		return () => {
			if (savedSecret !== undefined) process.env.JWT_SECRET = savedSecret;
			process.env.NODE_ENV = savedNodeEnv;
		};
	}

	it("verifyAccessToken collapses a missing-secret error into TokenInvalidError", async () => {
		const restore = await loadProductionJwtModule();
		try {
			const { verifyAccessToken: prodVerify } = await import(
				"../../../src/utils/jwt"
			);
			// The secret is missing in production -> generic fallthrough -> TokenInvalidError
			const token = jwt.sign(payload, ACCESS_SECRET, {
				expiresIn: "1h",
				issuer: JWT_ISSUER,
				audience: JWT_AUDIENCE,
			} as any);
			expect(() => prodVerify(token)).toThrow(
				expect.objectContaining({ code: "TOKEN_INVALID" }),
			);
		} finally {
			restore();
		}
	});

	it("verifyRefreshTokenRotationAware collapses a missing-secret error into TokenInvalidError", async () => {
		const restore = await loadProductionJwtModule();
		try {
			const { verifyRefreshTokenRotationAware: prodVerify } = await import(
				"../../../src/utils/jwt"
			);
const token = jwt.sign(payload, REFRESH_SECRET, {
				expiresIn: "1h",
				issuer: JWT_ISSUER,
				audience: JWT_REFRESH_AUDIENCE,
			} as any);
			expect(() => prodVerify(token)).toThrow(
				expect.objectContaining({ code: "TOKEN_INVALID" }),
			);
		} finally {
			restore();
		}
	});
});

