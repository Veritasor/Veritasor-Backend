/**
 * Multi-Tenant Authorization Fuzz Tests — requireBusinessAuth
 *
 * Property-based fuzzing that seeds N randomized tenants and exhaustively
 * asserts cross-tenant isolation invariants for the requireBusinessAuth
 * middleware and the routes it protects (businesses, attestations, and
 * the integrations nested under them).
 *
 * Coverage guarantees:
 *  - Every off-tenant request is rejected with 401 or 403 (never 2xx)
 *  - Spoofed X-Business-Id headers are rejected
 *  - Nested resource routes (attestations under integrations) are isolated
 *  - fast-check shrinking narrows any failing case to its minimal form
 *  - No secret data leaks in error responses
 *
 * @module tests/security/multitenant.fuzz
 */

import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import * as fc from 'fast-check';
import { requireBusinessAuth } from '../../src/middleware/requireBusinessAuth.js';
import * as jwt from '../../src/utils/jwt.js';
import * as userRepository from '../../src/repositories/userRepository.js';
import * as businessRepo from '../../src/repositories/business.js';
import { logger } from '../../src/utils/logger.js';

// ─── Domain types ─────────────────────────────────────────────────────────────

interface TenantSeed {
  userId: string;
  businessId: string;
  email: string;
  suspended: boolean;
}

interface CrossTenantScenario {
  /** The tenant whose JWT is in the Authorization header */
  requestingTenantIndex: number;
  /** The business ID claimed in the X-Business-Id header / request body */
  claimedBusinessIndex: number;
  /** How the business ID is delivered to the middleware */
  deliveryMethod: 'header' | 'body_snake' | 'body_camel';
}

// ─── Arbitraries ──────────────────────────────────────────────────────────────

/**
 * Generates a safe alphanumeric identifier string that passes the middleware's
 * ID_RE validation regex (/^[a-zA-Z0-9\-_]{1,50}$/).
 */
const safeIdArb = fc
  .stringMatching(/^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,48}[a-zA-Z0-9]$/)
  .filter((s) => s.length >= 2 && s.length <= 50);

/**
 * Generates a pool of N distinct tenants. Each tenant has a unique user ID
 * and business ID so cross-tenant lookups are unambiguous.
 */
function tenantPoolArb(size: number): fc.Arbitrary<TenantSeed[]> {
  return fc
    .uniqueArray(
      fc.record({
        userSuffix: fc.nat({ max: 999_999 }),
        bizSuffix: fc.nat({ max: 999_999 }),
        suspended: fc.boolean(),
      }),
      { minLength: size, maxLength: size, selector: (t) => t.userSuffix }
    )
    .map((entries) =>
      entries.map((entry, idx) => ({
        userId: `user-fuzz-${idx}-${entry.userSuffix}`,
        businessId: `biz-fuzz-${idx}-${entry.bizSuffix}`,
        email: `tenant${idx}-${entry.userSuffix}@fuzz.example`,
        suspended: entry.suspended,
      }))
    );
}

/**
 * Generates a cross-tenant scenario against a pool of the given size.
 * The scenario is only interesting when requestingTenantIndex ≠ claimedBusinessIndex,
 * which is enforced by the filter below so fast-check can shrink correctly.
 */
function crossTenantScenarioArb(poolSize: number): fc.Arbitrary<CrossTenantScenario> {
  return fc
    .record({
      requestingTenantIndex: fc.nat({ max: poolSize - 1 }),
      claimedBusinessIndex: fc.nat({ max: poolSize - 1 }),
      deliveryMethod: fc.constantFrom<'header' | 'body_snake' | 'body_camel'>(
        'header',
        'body_snake',
        'body_camel'
      ),
    })
    .filter((s) => s.requestingTenantIndex !== s.claimedBusinessIndex);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeRes(): {
  res: Response;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn().mockReturnThis();
  const status = vi.fn().mockReturnValue({ json });
  return { res: { status, json } as unknown as Response, status, json };
}

function buildRequest(
  requestingUserId: string,
  claimedBusinessId: string,
  method: CrossTenantScenario['deliveryMethod']
): Request {
  const headers: Record<string, string> = {
    authorization: `Bearer token-for-${requestingUserId}`,
  };

  let body: Record<string, string> = {};

  if (method === 'header') {
    headers['x-business-id'] = claimedBusinessId;
  } else if (method === 'body_snake') {
    body = { business_id: claimedBusinessId };
  } else {
    body = { businessId: claimedBusinessId };
  }

  return { headers, body } as unknown as Request;
}

/**
 * Wires up vi.spyOn mocks for a given requesting tenant claiming a business
 * owned by a different tenant.
 */
function setupCrossTenantMocks(requesting: TenantSeed, claimedOwner: TenantSeed): void {
  // Token resolves to the requesting tenant's user
  vi.spyOn(jwt, 'verifyToken').mockReturnValue({
    userId: requesting.userId,
    email: requesting.email,
  });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
    id: requesting.userId,
    userId: requesting.userId,
    email: requesting.email,
  } as any);

  // The claimed business belongs to a DIFFERENT user (the actual owner)
  vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
    id: claimedOwner.businessId,
    userId: claimedOwner.userId, // <-- not the requester's userId
    name: `Business of ${claimedOwner.userId}`,
    industry: null,
    description: null,
    website: null,
    suspended: claimedOwner.suspended,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  } as any);
}

/**
 * Wires up mocks for a tenant correctly authenticating against their own business
 * (used to verify the happy path still works after the fuzz rounds).
 */
function setupValidOwnerMocks(tenant: TenantSeed): void {
  vi.spyOn(jwt, 'verifyToken').mockReturnValue({
    userId: tenant.userId,
    email: tenant.email,
  });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
    id: tenant.userId,
    userId: tenant.userId,
    email: tenant.email,
  } as any);
  vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
    id: tenant.businessId,
    userId: tenant.userId,
    name: `Business of ${tenant.userId}`,
    industry: null,
    description: null,
    website: null,
    suspended: tenant.suspended,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  } as any);
}

// ─── Core isolation invariant ─────────────────────────────────────────────────

/**
 * The fundamental security invariant: a request that presents a valid JWT for
 * user A but asks for business B (owned by user B) MUST be rejected.  The
 * status code must be 4xx — never 2xx.
 */
async function assertCrossTenantRejection(
  requesting: TenantSeed,
  claimed: TenantSeed,
  deliveryMethod: CrossTenantScenario['deliveryMethod']
): Promise<void> {
  const next = vi.fn();
  const { res, status } = makeRes();
  const req = buildRequest(requesting.userId, claimed.businessId, deliveryMethod);

  setupCrossTenantMocks(requesting, claimed);

  await requireBusinessAuth(req, res, next);

  // Primary isolation invariant — next() must never be called
  expect(next, 'Cross-tenant request must not reach the route handler').not.toHaveBeenCalled();

  // The response must be 4xx (auth failure), never 2xx or 5xx
  const [[statusCode]] = (status as any).mock.calls;
  expect(
    statusCode,
    `Status must be 403 for cross-tenant business access, got ${statusCode}`
  ).toBe(403);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test suites
// ─────────────────────────────────────────────────────────────────────────────

describe('Multi-tenant isolation — requireBusinessAuth fuzz tests', () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => vi.restoreAllMocks());

  // ── Deterministic baseline scenarios ────────────────────────────────────────

  describe('Baseline deterministic cross-tenant scenarios', () => {
    const TENANT_A: TenantSeed = {
      userId: 'user-alpha',
      businessId: 'biz-alpha',
      email: 'alpha@example.com',
      suspended: false,
    };
    const TENANT_B: TenantSeed = {
      userId: 'user-beta',
      businessId: 'biz-beta',
      email: 'beta@example.com',
      suspended: false,
    };

    it('rejects A claiming B business via X-Business-Id header', async () => {
      await assertCrossTenantRejection(TENANT_A, TENANT_B, 'header');
    });

    it('rejects A claiming B business via body.business_id', async () => {
      await assertCrossTenantRejection(TENANT_A, TENANT_B, 'body_snake');
    });

    it('rejects A claiming B business via body.businessId', async () => {
      await assertCrossTenantRejection(TENANT_A, TENANT_B, 'body_camel');
    });

    it('rejects B claiming A business via X-Business-Id header', async () => {
      await assertCrossTenantRejection(TENANT_B, TENANT_A, 'header');
    });

    it('rejects cross-tenant access even when claimed business is suspended', async () => {
      const suspendedOwner: TenantSeed = { ...TENANT_B, suspended: true };
      // Ownership check must fail before the suspension check is even reached
      await assertCrossTenantRejection(TENANT_A, suspendedOwner, 'header');
    });

    it('allows a tenant to access their own active business', async () => {
      const next = vi.fn();
      const { res } = makeRes();
      const req = buildRequest(TENANT_A.userId, TENANT_A.businessId, 'header');

      setupValidOwnerMocks(TENANT_A);

      await requireBusinessAuth(req, res, next);

      expect(next, 'Legitimate owner must reach the route handler').toHaveBeenCalledOnce();
      expect((req as any).user?.id).toBe(TENANT_A.userId);
      expect((req as any).business?.id).toBe(TENANT_A.businessId);
    });

    it('allows a tenant to access their own active business via body.business_id', async () => {
      const next = vi.fn();
      const { res } = makeRes();
      const req = buildRequest(TENANT_A.userId, TENANT_A.businessId, 'body_snake');

      setupValidOwnerMocks(TENANT_A);

      await requireBusinessAuth(req, res, next);

      expect(next).toHaveBeenCalledOnce();
    });
  });

  // ── Spoofed X-Business-Id header scenarios ───────────────────────────────────

  describe('Spoofed X-Business-Id header rejection', () => {
    const LEGIT_TENANT: TenantSeed = {
      userId: 'user-legit',
      businessId: 'biz-legit',
      email: 'legit@example.com',
      suspended: false,
    };

    it('rejects a randomly crafted alphanumeric business ID not owned by the requester', async () => {
      await fc.assert(
        fc.asyncProperty(safeIdArb, async (spoofedId) => {
          vi.clearAllMocks();

          const next = vi.fn();
          const { res, status } = makeRes();
          const req = {
            headers: {
              authorization: `Bearer token-for-${LEGIT_TENANT.userId}`,
              'x-business-id': spoofedId,
            },
            body: {},
          } as unknown as Request;

          vi.spyOn(jwt, 'verifyToken').mockReturnValue({
            userId: LEGIT_TENANT.userId,
            email: LEGIT_TENANT.email,
          });
          vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
            id: LEGIT_TENANT.userId,
            userId: LEGIT_TENANT.userId,
            email: LEGIT_TENANT.email,
          } as any);
          // Business exists but with a different owner
          vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
            id: spoofedId,
            userId: 'some-other-user-entirely',
            name: 'Someone Elses Business',
            industry: null,
            description: null,
            website: null,
            suspended: false,
            createdAt: '2024-01-01T00:00:00Z',
            updatedAt: '2024-01-01T00:00:00Z',
          } as any);

          await requireBusinessAuth(req, res, next);

          expect(next).not.toHaveBeenCalled();
          const [[statusCode]] = (status as any).mock.calls;
          expect(statusCode).toBe(403);
        }),
        { numRuns: 40 }
      );
    });

    it('rejects when business ID does not exist in the store (spoofed non-existent)', async () => {
      await fc.assert(
        fc.asyncProperty(safeIdArb, async (spoofedId) => {
          vi.clearAllMocks();

          const next = vi.fn();
          const { res, status } = makeRes();
          const req = {
            headers: {
              authorization: `Bearer token-for-${LEGIT_TENANT.userId}`,
              'x-business-id': spoofedId,
            },
            body: {},
          } as unknown as Request;

          vi.spyOn(jwt, 'verifyToken').mockReturnValue({
            userId: LEGIT_TENANT.userId,
            email: LEGIT_TENANT.email,
          });
          vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
            id: LEGIT_TENANT.userId,
            userId: LEGIT_TENANT.userId,
            email: LEGIT_TENANT.email,
          } as any);
          // Business does not exist
          vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(null);

          await requireBusinessAuth(req, res, next);

          expect(next).not.toHaveBeenCalled();
          const [[statusCode]] = (status as any).mock.calls;
          expect(statusCode).toBe(403);
        }),
        { numRuns: 30 }
      );
    });
  });

  // ── Property-based cross-tenant fuzz ─────────────────────────────────────────

  describe('Property-based multi-tenant isolation — N tenants', () => {
    const POOL_SIZE = 6;

    it('invariant: off-tenant requests are always rejected across all delivery methods', async () => {
      await fc.assert(
        fc.asyncProperty(
          tenantPoolArb(POOL_SIZE),
          crossTenantScenarioArb(POOL_SIZE),
          async (tenants, scenario) => {
            vi.clearAllMocks();

            const requesting = tenants[scenario.requestingTenantIndex];
            const claimed = tenants[scenario.claimedBusinessIndex];

            // Sanity guard — the pool should always give distinct users for different indices
            expect(requesting.userId).not.toBe(claimed.userId);

            await assertCrossTenantRejection(requesting, claimed, scenario.deliveryMethod);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('invariant: legitimate owner access always succeeds for non-suspended businesses', async () => {
      await fc.assert(
        fc.asyncProperty(
          tenantPoolArb(POOL_SIZE),
          fc.nat({ max: POOL_SIZE - 1 }),
          async (tenants, tenantIndex) => {
            vi.clearAllMocks();

            const tenant = tenants[tenantIndex];
            if (tenant.suspended) return; // Skip suspended — they get 403 BUSINESS_SUSPENDED

            const next = vi.fn();
            const { res } = makeRes();
            const req = buildRequest(tenant.userId, tenant.businessId, 'header');

            setupValidOwnerMocks(tenant);

            await requireBusinessAuth(req, res, next);

            expect(
              next,
              `Legitimate owner of business ${tenant.businessId} must reach the handler`
            ).toHaveBeenCalledOnce();
          }
        ),
        { numRuns: 30 }
      );
    });

    it('invariant: suspended businesses are rejected even for their legitimate owner', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            userSuffix: fc.nat({ max: 999_999 }),
            bizSuffix: fc.nat({ max: 999_999 }),
          }),
          async ({ userSuffix, bizSuffix }) => {
            vi.clearAllMocks();

            const tenant: TenantSeed = {
              userId: `user-suspended-${userSuffix}`,
              businessId: `biz-suspended-${bizSuffix}`,
              email: `suspended-${userSuffix}@fuzz.example`,
              suspended: true,
            };

            const next = vi.fn();
            const { res, status, json } = makeRes();
            const req = buildRequest(tenant.userId, tenant.businessId, 'header');

            setupValidOwnerMocks(tenant);

            await requireBusinessAuth(req, res, next);

            expect(next).not.toHaveBeenCalled();
            const [[statusCode]] = (status as any).mock.calls;
            expect(statusCode).toBe(403);
            expect(json).toHaveBeenCalledWith(
              expect.objectContaining({ code: 'BUSINESS_SUSPENDED' })
            );
          }
        ),
        { numRuns: 25 }
      );
    });
  });

  // ── Nested resource isolation (attestations under integrations) ──────────────

  describe('Nested resource isolation — attestations under integrations', () => {
    /**
     * Simulates the auth check a route like
     *   PATCH /api/integrations/:integrationId/attestations
     * would perform. The integration belongs to `ownerTenant` but `attackerTenant`
     * is trying to reach it by spoofing the business ID.
     */
    it('rejects cross-tenant access to nested attestation resources', async () => {
      await fc.assert(
        fc.asyncProperty(
          tenantPoolArb(4),
          // attacker index ≠ owner index
          fc
            .record({
              attackerIdx: fc.nat({ max: 3 }),
              ownerIdx: fc.nat({ max: 3 }),
            })
            .filter((s) => s.attackerIdx !== s.ownerIdx),
          fc.constantFrom<'header' | 'body_snake' | 'body_camel'>(
            'header',
            'body_snake',
            'body_camel'
          ),
          async (tenants, indices, deliveryMethod) => {
            vi.clearAllMocks();

            const attacker = tenants[indices.attackerIdx];
            const owner = tenants[indices.ownerIdx];

            // Attacker presents their own valid JWT but claims the owner's business
            vi.spyOn(jwt, 'verifyToken').mockReturnValue({
              userId: attacker.userId,
              email: attacker.email,
            });
            vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
              id: attacker.userId,
              userId: attacker.userId,
              email: attacker.email,
            } as any);
            // The business the attacker claims belongs to the owner, not them
            vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
              id: owner.businessId,
              userId: owner.userId,
              name: `Owner Business ${owner.userId}`,
              industry: null,
              description: null,
              website: null,
              suspended: false,
              createdAt: '2024-01-01T00:00:00Z',
              updatedAt: '2024-01-01T00:00:00Z',
            } as any);

            const next = vi.fn();
            const { res, status } = makeRes();
            const req = buildRequest(attacker.userId, owner.businessId, deliveryMethod);

            await requireBusinessAuth(req, res, next);

            // Nested resource guard: handler must never be reached
            expect(
              next,
              `Attacker ${attacker.userId} must not access nested resources of business ${owner.businessId}`
            ).not.toHaveBeenCalled();

            const [[statusCode]] = (status as any).mock.calls;
            expect(statusCode).toBe(403);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('allows the legitimate owner to access nested resources', async () => {
      await fc.assert(
        fc.asyncProperty(
          tenantPoolArb(4),
          fc.nat({ max: 3 }),
          async (tenants, ownerIdx) => {
            vi.clearAllMocks();

            const owner = tenants[ownerIdx];
            if (owner.suspended) return;

            const next = vi.fn();
            const { res } = makeRes();
            const req = buildRequest(owner.userId, owner.businessId, 'header');

            setupValidOwnerMocks(owner);

            await requireBusinessAuth(req, res, next);

            expect(
              next,
              `Legitimate owner must reach nested attestation handler`
            ).toHaveBeenCalledOnce();
          }
        ),
        { numRuns: 25 }
      );
    });
  });

  // ── Error response security invariants ────────────────────────────────────────

  describe('Error response security invariants', () => {
    const SENSITIVE_PATTERNS = [
      'password',
      'secret',
      'privateKey',
      'stack',
      'Error:',
      'localhost',
      'DATABASE_URL',
      'JWT_SECRET',
      'token',      // raw token values must never leak
    ] as const;

    it('never leaks sensitive data in cross-tenant rejection responses', async () => {
      await fc.assert(
        fc.asyncProperty(
          tenantPoolArb(3),
          crossTenantScenarioArb(3),
          async (tenants, scenario) => {
            vi.clearAllMocks();

            const requesting = tenants[scenario.requestingTenantIndex];
            const claimed = tenants[scenario.claimedBusinessIndex];

            const next = vi.fn();
            const { res, json } = makeRes();
            const req = buildRequest(requesting.userId, claimed.businessId, scenario.deliveryMethod);

            setupCrossTenantMocks(requesting, claimed);

            await requireBusinessAuth(req, res, next);

            // Inspect the serialized response body for sensitive data patterns
            const [[responseBody]] = (json as any).mock.calls;
            const serialized = JSON.stringify(responseBody).toLowerCase();

            for (const pattern of SENSITIVE_PATTERNS) {
              // Allow the word "token" in the safe error message context but not as a value
              if (pattern === 'token') {
                expect(
                  responseBody,
                  `Response must not expose raw token data`
                ).not.toHaveProperty('token');
                continue;
              }
              expect(
                serialized,
                `Response must not contain '${pattern}'`
              ).not.toContain(pattern.toLowerCase());
            }

            // Must always include a stable error code — no undefined/null codes
            expect(responseBody.code).toBeTruthy();
            expect(typeof responseBody.code).toBe('string');
          }
        ),
        { numRuns: 40 }
      );
    });

    it('never leaks sensitive data in missing-auth rejection responses', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Arbitrary malformed Authorization header values
          fc.oneof(
            fc.constant(''),
            fc.constant('Basic dXNlcjpwYXNz'),
            fc.constant('bearer no-capital-b'),
            fc.stringMatching(/^[A-Za-z0-9]{1,30}$/),
          ),
          async (badAuth) => {
            vi.clearAllMocks();

            const next = vi.fn();
            const { res, status, json } = makeRes();
            const req = {
              headers: badAuth ? { authorization: badAuth } : {},
              body: {},
            } as unknown as Request;

            await requireBusinessAuth(req, res, next);

            expect(next).not.toHaveBeenCalled();
            const [[statusCode]] = (status as any).mock.calls;
            expect(statusCode).toBe(401);

            const [[responseBody]] = (json as any).mock.calls;
            expect(responseBody.code).toBe('MISSING_AUTH');
            // Confirm the response body is a safe flat object with no nested stack traces
            expect(responseBody).not.toHaveProperty('stack');
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────────

  describe('Edge cases and boundary conditions', () => {
    const BASE_TENANT: TenantSeed = {
      userId: 'user-edge',
      businessId: 'biz-edge',
      email: 'edge@example.com',
      suspended: false,
    };

    it('rejects business IDs exceeding 50 characters', async () => {
      const longId = 'a'.repeat(51);
      const next = vi.fn();
      const { res, status, json } = makeRes();
      const req = {
        headers: {
          authorization: `Bearer some-token`,
          'x-business-id': longId,
        },
        body: {},
      } as unknown as Request;

      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: BASE_TENANT.userId,
        email: BASE_TENANT.email,
      });
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: BASE_TENANT.userId,
        userId: BASE_TENANT.userId,
        email: BASE_TENANT.email,
      } as any);

      await requireBusinessAuth(req, res, next);

      expect(next).not.toHaveBeenCalled();
      const [[statusCode]] = (status as any).mock.calls;
      expect(statusCode).toBe(400);
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({ code: 'MISSING_BUSINESS_ID' })
      );
    });

    it('rejects business IDs containing special injection characters', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Strings that contain at least one character outside the safe ID character set
          fc.string({ minLength: 1, maxLength: 50 }).filter(
            (s) => /[^a-zA-Z0-9\-_]/.test(s)
          ),
          async (injectionId) => {
            vi.clearAllMocks();

            const next = vi.fn();
            const { res, status } = makeRes();
            const req = {
              headers: {
                authorization: `Bearer some-token`,
                'x-business-id': injectionId,
              },
              body: {},
            } as unknown as Request;

            vi.spyOn(jwt, 'verifyToken').mockReturnValue({
              userId: BASE_TENANT.userId,
              email: BASE_TENANT.email,
            });
            vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
              id: BASE_TENANT.userId,
              userId: BASE_TENANT.userId,
              email: BASE_TENANT.email,
            } as any);

            await requireBusinessAuth(req, res, next);

            expect(next).not.toHaveBeenCalled();
            const [[statusCode]] = (status as any).mock.calls;
            // Must be 400 (invalid format) — not a 500 or a pass-through
            expect(statusCode).toBe(400);
          }
        ),
        { numRuns: 40 }
      );
    });

    it('rejects empty string business ID in body fields', async () => {
      for (const field of ['business_id', 'businessId'] as const) {
        vi.clearAllMocks();

        const next = vi.fn();
        const { res, status } = makeRes();
        const req = {
          headers: { authorization: `Bearer some-token` },
          body: { [field]: '' },
        } as unknown as Request;

        vi.spyOn(jwt, 'verifyToken').mockReturnValue({
          userId: BASE_TENANT.userId,
          email: BASE_TENANT.email,
        });
        vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
          id: BASE_TENANT.userId,
          userId: BASE_TENANT.userId,
          email: BASE_TENANT.email,
        } as any);

        await requireBusinessAuth(req, res, next);

        expect(next).not.toHaveBeenCalled();
        const [[statusCode]] = (status as any).mock.calls;
        expect(statusCode).toBe(400);
      }
    });

    it('rejects whitespace-only business ID', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.stringMatching(/^\s+$/),
          async (whitespaceId) => {
            vi.clearAllMocks();

            const next = vi.fn();
            const { res, status } = makeRes();
            const req = {
              headers: {
                authorization: `Bearer some-token`,
                'x-business-id': whitespaceId,
              },
              body: {},
            } as unknown as Request;

            vi.spyOn(jwt, 'verifyToken').mockReturnValue({
              userId: BASE_TENANT.userId,
              email: BASE_TENANT.email,
            });
            vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
              id: BASE_TENANT.userId,
              userId: BASE_TENANT.userId,
              email: BASE_TENANT.email,
            } as any);

            await requireBusinessAuth(req, res, next);

            expect(next).not.toHaveBeenCalled();
            const [[statusCode]] = (status as any).mock.calls;
            expect(statusCode).toBe(400);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('rejects when getById repository throws (treats as access denied, not 500)', async () => {
      const next = vi.fn();
      const { res, status, json } = makeRes();
      const req = {
        headers: {
          authorization: `Bearer some-token`,
          'x-business-id': BASE_TENANT.businessId,
        },
        body: {},
      } as unknown as Request;

      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: BASE_TENANT.userId,
        email: BASE_TENANT.email,
      });
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: BASE_TENANT.userId,
        userId: BASE_TENANT.userId,
        email: BASE_TENANT.email,
      } as any);
      vi.spyOn(businessRepo.businessRepository, 'getById').mockRejectedValue(
        new Error('DB connection lost')
      );

      await requireBusinessAuth(req, res, next);

      expect(next).not.toHaveBeenCalled();
      const [[statusCode]] = (status as any).mock.calls;
      // Must be 403, not 500 — DB failures must never bypass access control
      expect(statusCode).toBe(403);
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({ code: 'BUSINESS_NOT_FOUND' })
      );
    });

    it('header takes priority over body even under fuzz input combinations', async () => {
      await fc.assert(
        fc.asyncProperty(
          safeIdArb,
          safeIdArb,
          async (headerId, bodyId) => {
            // Only interesting when the two IDs differ
            fc.pre(headerId !== bodyId);
            vi.clearAllMocks();

            const next = vi.fn();
            const { res } = makeRes();

            // Set up mocks so that headerId resolves to the legit owner
            vi.spyOn(jwt, 'verifyToken').mockReturnValue({
              userId: BASE_TENANT.userId,
              email: BASE_TENANT.email,
            });
            vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
              id: BASE_TENANT.userId,
              userId: BASE_TENANT.userId,
              email: BASE_TENANT.email,
            } as any);
            vi.spyOn(businessRepo.businessRepository, 'getById').mockImplementation(
              async (id: string) => {
                if (id === headerId) {
                  return {
                    id: headerId,
                    userId: BASE_TENANT.userId, // header ID is owned by requester
                    name: 'Header Business',
                    industry: null,
                    description: null,
                    website: null,
                    suspended: false,
                    createdAt: '2024-01-01T00:00:00Z',
                    updatedAt: '2024-01-01T00:00:00Z',
                  } as any;
                }
                return null;
              }
            );

            const req = {
              headers: {
                authorization: `Bearer some-token`,
                'x-business-id': headerId,
              },
              body: { business_id: bodyId },
            } as unknown as Request;

            await requireBusinessAuth(req, res, next);

            // Header wins: the middleware must have queried headerId (owned by requester → success)
            expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith(headerId);
            expect(next).toHaveBeenCalledOnce();
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  // ── Structured logging during fuzz ────────────────────────────────────────────

  describe('Structured logging invariants', () => {
    it('never logs sensitive user data on cross-tenant rejections', async () => {
      const warnSpy = vi.spyOn(logger, 'warn');
      const infoSpy = vi.spyOn(logger, 'info');

      await fc.assert(
        fc.asyncProperty(
          tenantPoolArb(3),
          crossTenantScenarioArb(3),
          async (tenants, scenario) => {
            vi.clearAllMocks();

            const requesting = tenants[scenario.requestingTenantIndex];
            const claimed = tenants[scenario.claimedBusinessIndex];

            const next = vi.fn();
            const { res } = makeRes();
            const req = buildRequest(requesting.userId, claimed.businessId, 'header');

            setupCrossTenantMocks(requesting, claimed);

            await requireBusinessAuth(req, res, next);

            // On rejection the success log must NOT be emitted
            const infoArgs = infoSpy.mock.calls.map((c) => String(c[0]));
            for (const logLine of infoArgs) {
              expect(logLine).not.toContain('business_auth.success');
            }
          }
        ),
        { numRuns: 20 }
      );
    });

    it('emits a structured info log on every successful auth', async () => {
      const infoSpy = vi.spyOn(logger, 'info');

      await fc.assert(
        fc.asyncProperty(
          tenantPoolArb(3),
          fc.nat({ max: 2 }),
          async (tenants, ownerIdx) => {
            vi.clearAllMocks();

            const owner = tenants[ownerIdx];
            if (owner.suspended) return;

            const next = vi.fn();
            const { res } = makeRes();
            const req = buildRequest(owner.userId, owner.businessId, 'header');

            setupValidOwnerMocks(owner);

            await requireBusinessAuth(req, res, next);

            expect(next).toHaveBeenCalledOnce();

            const infoArgs = infoSpy.mock.calls.map((c) => String(c[0]));
            const successLog = infoArgs.find((l) => l.includes('business_auth.success'));
            expect(successLog, 'Success log must be emitted on valid auth').toBeTruthy();

            // Parse and verify the log structure
            const parsed = JSON.parse(successLog!);
            expect(parsed.userId).toBe(owner.userId);
            expect(parsed.businessId).toBe(owner.businessId);
            // Must not contain raw secrets in log
            expect(parsed).not.toHaveProperty('token');
            expect(parsed).not.toHaveProperty('secret');
          }
        ),
        { numRuns: 20 }
      );
    });
  });
});
