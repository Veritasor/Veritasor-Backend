import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import {
  evaluatePolicy,
  requirePermissions,
  requirePolicy,
  requireRoutePermissions,
  DEFAULT_POLICY,
  type PolicyRequest,
  type PolicyRule,
} from '../../src/middleware/permissions.js';
import { IntegrationPermission } from '../../src/types/permissions.js';
import '../../src/middleware/requireBusinessAuth.js';

const AUTHENTICATED_USER = { id: 'user_123', userId: 'user_123', email: 'test@example.com' };

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    user: AUTHENTICATED_USER,
    headers: {},
    params: {},
    ...overrides,
  } as unknown as Request;
}

function makeRes(): {
  res: Response;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn().mockReturnThis();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json } as unknown as Response;
  return { res, status, json };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('evaluatePolicy — PolicyRule failure and empty-result paths', () => {
  it('allows a request that matches an allow rule', () => {
    const request: PolicyRequest = {
      action: 'read',
      resource: 'integration',
      role: 'user',
      actorTenantId: 'tenant-1',
      resourceTenantId: 'tenant-1',
    };

    const decision = evaluatePolicy(request);

    expect(decision).toEqual({
      allowed: true,
      ruleId: 'integration-user-own',
      reason: 'Allowed by policy rule: integration-user-own',
    });
  });

  it('denies with an empty-result reason when no rule matches', () => {
    const request: PolicyRequest = {
      action: 'read',
      resource: 'unregistered-resource',
      role: 'user',
      actorTenantId: 'tenant-1',
      resourceTenantId: 'tenant-1',
    };

    const decision = evaluatePolicy(request);

    expect(decision.allowed).toBe(false);
    expect(decision.ruleId).toBeUndefined();
    expect(decision.reason).toBe('Denied: no matching policy rule');
  });

  it('denies with an empty policy list (default-deny path)', () => {
    const decision = evaluatePolicy(
      { action: 'read', resource: 'integration', role: 'user' },
      [],
    );

    expect(decision).toEqual({
      allowed: false,
      reason: 'Denied: no matching policy rule',
    });
  });

  it('lets an applicable deny override an applicable allow', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-all', effect: 'allow', actions: ['*'], resources: ['*'] },
      { id: 'deny-delete', effect: 'deny', actions: ['delete'], resources: ['integration'] },
    ];

    const decision = evaluatePolicy(
      { action: 'delete', resource: 'integration', role: 'admin' },
      rules,
    );

    expect(decision.allowed).toBe(false);
    expect(decision.ruleId).toBe('deny-delete');
    expect(decision.reason).toBe('Denied by policy rule: deny-delete');
  });

  it('reports a cross-tenant mismatch distinctly from "no rule"', () => {
    const decision = evaluatePolicy({
      action: 'read',
      resource: 'integration',
      role: 'user',
      actorTenantId: 'tenant-1',
      resourceTenantId: 'tenant-2',
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('Denied: resource belongs to a different tenant');
  });

  it('treats a missing tenant scope as a match for any tenant', () => {
    const rules: PolicyRule[] = [
      { id: 'tenant-agnostic', effect: 'allow', actions: ['read'], resources: ['integration'] },
    ];

    const decision = evaluatePolicy(
      { action: 'read', resource: 'integration', role: 'user' },
      rules,
    );

    expect(decision.allowed).toBe(true);
    expect(decision.ruleId).toBe('tenant-agnostic');
  });

  it('does not match a same-tenant rule when the actor tenant is absent', () => {
    const decision = evaluatePolicy({
      action: 'read',
      resource: 'integration',
      role: 'user',
      resourceTenantId: 'tenant-1',
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('Denied: resource belongs to a different tenant');
  });

  it('ships a least-privilege default policy', () => {
    expect(DEFAULT_POLICY.map((rule) => rule.id)).toEqual([
      'integration-user-own',
      'integration-business-admin',
      'platform-admin',
    ]);
  });
});

describe('requireRoutePermissions — unknown-route failure contract', () => {
  it('throws a deterministic error for an unknown route pattern', () => {
    expect(() => requireRoutePermissions('GET:/does-not-exist')).toThrow(
      'No permissions defined for route pattern: GET:/does-not-exist',
    );
  });

  it('throws for an empty route pattern', () => {
    expect(() => requireRoutePermissions('')).toThrow(
      'No permissions defined for route pattern: ',
    );
  });

  it('returns a middleware for a known route pattern and proceeds when the role has the permission', async () => {
    const middleware = requireRoutePermissions('GET:/:id');
    expect(typeof middleware).toBe('function');

    const req = makeReq({ params: { id: 'business_1_integration' } as any });
    const { res, status } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
    expect(req.permissionContext?.permissions).toContain(IntegrationPermission.READ_OWN);
  });

  it('denies 403 when the caller role carries none of the route permissions', async () => {
    const middleware = requireRoutePermissions('GET:/:id');

    const req = makeReq({
      params: { id: 'business_1_integration' } as any,
      user: { ...AUTHENTICATED_USER, role: 'nobody' as any },
    });
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith({
      error: 'Forbidden',
      message: 'Insufficient permissions',
      details: expect.stringContaining('Missing required permissions'),
    });
    expect(next).not.toHaveBeenCalled();
  });
});

describe('requirePermissions — ownership-check failure path', () => {
  it('allows when the integration id is scoped to the caller business', async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
    });

    const req = makeReq({
      params: { id: 'biz_123_integration_456' } as any,
      headers: { 'x-business-id': 'biz_123' },
    });
    const { res } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('returns 403 when the integration id is not scoped to the caller business', async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
    });

    const req = makeReq({
      params: { id: 'biz_999_integration_456' } as any,
      headers: { 'x-business-id': 'biz_123' },
    });
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith({
      error: 'Forbidden',
      message: 'You do not have permission to access this integration',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('falls back to params.provider when params.id is absent', async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
    });

    const req = makeReq({
      params: { provider: 'biz_123_stripe' } as any,
      headers: { 'x-business-id': 'biz_123' },
    });
    const { res, status } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('skips the ownership check when no integration identifier is present', async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
    });

    const req = makeReq({ headers: { 'x-business-id': 'biz_123' } });
    const { res, status } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('allows the placeholder ownership check when no business context is supplied', async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
    });

    const req = makeReq({ params: { id: 'anything' } as any });
    const { res, status } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });
});

describe('requirePolicy — PolicyRule decision middleware', () => {
  it('returns 401 before evaluating any rule when the caller is unauthenticated', async () => {
    const middleware = requirePolicy('read', 'integration');

    const req = makeReq();
    delete (req as any).user;
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 403 with the policy reason when no rule allows the request', async () => {
    const middleware = requirePolicy('read', 'unregistered-resource');

    const req = makeReq();
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith({
      error: 'Forbidden',
      message: 'Policy denied',
      details: 'Denied: no matching policy rule',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('proceeds when a tenant-scoped rule allows the request', async () => {
    const middleware = requirePolicy('read', 'integration', {
      resourceTenantId: () => 'tenant-1',
    });

    const req = makeReq({
      business: { id: 'tenant-1' } as any,
    });
    const { res, status } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
  });

  it('uses caller-supplied rules when provided', async () => {
    const rules: PolicyRule[] = [
      { id: 'allow-read', effect: 'allow', actions: ['read'], resources: ['integration'] },
    ];
    const middleware = requirePolicy('read', 'integration', { rules });

    const req = makeReq({ business: { id: 'tenant-1' } as any });
    const { res } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });
});
