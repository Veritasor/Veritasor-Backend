/**
 * JWT Refresh-Token Reuse Detection — Security Spec
 *
 * Threat model: a stolen refresh token is replayed after a legitimate rotation.
 * `Microsoft 1.0`[TokenRotation] guidance treats any reuse of a consumed refresh
 * token as an active-theft signal. This spec drives the rotation-aware token
 * family API through the full attack lifecycle and asserts the hardened
 * response contract:
 *
 *   1. Refresh tokens are single-use: after one rotation the old jti is
 *      consumed and cannot be used again (TOKEN_REUSED).
 *   2. Reuse revokes the WHOLE family — the sibling access token and the
 *      current refresh token become unusable immediately (TOKEN_REVOKED),
 *      so the attacker loses far more than the victim.
 *   3. The compromise marker persists on the family so even freshly minted
 *      tokens for that family are rejected (FAMILY_COMPROMISED).
 *   4. Concurrent refresh of the same token serialises: exactly one rotation
 *      wins and every peer is rejected as a reuser.
 *   5. Access and refresh tokens are cryptographically bound to distinct
 *      audiences and a `type` claim, so substitution between the two roles is
 *      impossible even under a shared secret.
 *
 * The store is intentionally in-memory (process-local). Multi-instance
 * deployments must use the durable `usedTokenStore` replay detection
 * (`src/services/auth/usedTokenStore.js`) for process-shared coverage.
 *
 * @module tests/security/jwt-reuse-detection
 */

import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import {
  generateTokenPair,
  generateAccessToken,
  verifyAccessToken,
  verifyRefreshTokenRotationAware,
  refreshTokenPair,
  revokeTokenFamily,
  getTokenFamily,
  isTokenBlacklisted,
  TokenReusedError,
  JWT_AUDIENCE,
  JWT_REFRESH_AUDIENCE,
} from '../../src/utils/jwt.js';
import type { TokenPayload } from '../../src/utils/jwt.js';

const victim: TokenPayload = {
  userId: `victim-${Date.now()}`,
  email: 'victim@example.com',
};

describe('JWT refresh-token reuse detection (theft response)', () => {
  it('a replayed consumed refresh token is rejected and the family is revoked wholesale', async () => {
    // 1. Victim logs in → token pair is minted.
    const pair = generateTokenPair(victim);
    const stolenRefresh = pair.refreshToken;
    const stolenAccess = pair.accessToken;

    // 2. Victim legitimately refreshes (e.g. the app calls /refresh).
    const rotated = await refreshTokenPair(stolenRefresh);
    expect(rotated.refreshToken).not.toBe(stolenRefresh);

    // 3. Attacker replays the ORIGINAL refresh token.
    await expect(refreshTokenPair(stolenRefresh)).rejects.toBeInstanceOf(
      TokenReusedError,
    );

    // 4. Theft response: the attacker's stolen access token is revoked too.
    expect(() => verifyAccessToken(stolenAccess)).toThrow(
      expect.objectContaining({ code: 'TOKEN_REVOKED' }),
    );

    // 5. And the replacement token minted for the victim is also dead.
    await expect(refreshTokenPair(rotated.refreshToken)).rejects.toMatchObject({
      code: 'TOKEN_REVOKED',
    });
  });

  it('a compromised family rejects even freshly minted tokens (persistent marker)', async () => {
    const pair = generateTokenPair(victim);
    await refreshTokenPair(pair.refreshToken);
    await expect(refreshTokenPair(pair.refreshToken)).rejects.toBeInstanceOf(
      TokenReusedError,
    );

    // Marker persists in-memory so the compromise is recorded.
    expect(getTokenFamily(pair.familyId)?.concurrentRefreshDetected).toBe(true);

    // A token minted AFTER the compromise event is rejected by the marker.
    const reissue = generateTokenPair(victim, pair.familyId);
    await expect(refreshTokenPair(reissue.refreshToken)).rejects.toMatchObject({
      code: 'FAMILY_COMPROMISED',
    });
  });

  it('concurrent refresh serialises to exactly one winner', async () => {
    const { refreshToken } = generateTokenPair(victim);
    const outcomes = await Promise.allSettled([
      refreshTokenPair(refreshToken),
      refreshTokenPair(refreshToken),
    ]);
    expect(outcomes.filter((o) => o.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter((o) => o.status === 'rejected')).toHaveLength(1);
    const loser = outcomes.find((o) => o.status === 'rejected') as PromiseRejectedResult;
    expect(loser.reason).toBeInstanceOf(TokenReusedError);
  });

  it('access tokens can never be redeemed as refresh tokens (audience + type binding)', async () => {
    const { accessToken } = generateTokenPair(victim);
    const header = jwt.decode(accessToken, { complete: true }) as {
      header: Record<string, unknown>;
      payload: Record<string, unknown>;
    };
    expect(header.header.alg).toBe('HS256');
    expect(header.payload.aud).toBe(JWT_AUDIENCE);
    expect(header.payload.type).toBe('access');

    expect(() => verifyRefreshTokenRotationAware(accessToken)).toThrow(
      expect.objectContaining({ code: 'TOKEN_INVALID' }),
    );
  });

  it('revokeTokenFamily blacklists every token minted in the family', async () => {
    const pair = generateTokenPair(victim);
    // An extra child access token in the same family.
    const childAccess = generateAccessToken(victim, pair.familyId);
    expect(verifyAccessToken(childAccess)).toMatchObject(victim);

    const family = getTokenFamily(pair.familyId);
    expect(family).toBeDefined();

    revokeTokenFamily(pair.familyId);

    // Every jti from the family lands in the global blacklist.
    for (const jti of family?.issuedJtis ?? []) {
      expect(isTokenBlacklisted(jti)).toBe(true);
    }
    expect(getTokenFamily(pair.familyId)).toBeUndefined();
    expect(() => verifyAccessToken(childAccess)).toThrow(
      expect.objectContaining({ code: 'TOKEN_REVOKED' }),
    );
    expect(() => verifyRefreshTokenRotationAware(pair.refreshToken)).toThrow(
      expect.objectContaining({ code: 'TOKEN_REVOKED' }),
    );
  });

  it('rotated refresh tokens keep the replacement fresh for exactly one use', async () => {
    const { refreshToken } = generateTokenPair(victim);
    const first = await refreshTokenPair(refreshToken);
    const second = await refreshTokenPair(first.refreshToken);
    expect(first.refreshToken).not.toBe(refreshToken);
    expect(second.refreshToken).not.toBe(first.refreshToken);
    // The first replacement is now consumed.
    await expect(refreshTokenPair(first.refreshToken)).rejects.toBeInstanceOf(
      TokenReusedError,
    );
  });
});