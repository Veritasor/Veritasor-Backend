import jwt from "jsonwebtoken";
import { describe, expect, it, vi, afterEach } from "vitest";
import {
	generateRefreshToken,
	generateToken,
	type TokenPayload,
	verifyRefreshToken,
	verifyToken,
	sign,
	verify,
	JWT_ISSUER,
	JWT_AUDIENCE,
	JWT_REFRESH_AUDIENCE,
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
