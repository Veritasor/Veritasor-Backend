import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { NextFunction, Request, Response } from 'express';
import { clearAllAuditLogs, getAllAuditLogs } from '../../src/repositories/auditLogRepository.js';
import { evaluatePolicy, requirePolicy, type PolicyRule } from '../../src/middleware/permissions.js';

describe('policy engine', () => {
  beforeEach(() => clearAllAuditLogs());

  it('allows a user action on a resource in the same tenant', () => {
    expect(evaluatePolicy({ action: 'read', resource: 'integration', role: 'user', actorTenantId: 'tenant-a', resourceTenantId: 'tenant-a' }).allowed).toBe(true);
  });

  it('denies cross-tenant access by default', () => {
    const decision = evaluatePolicy({ action: 'read', resource: 'integration', role: 'user', actorTenantId: 'tenant-a', resourceTenantId: 'tenant-b' });
    expect(decision).toMatchObject({ allowed: false, reason: 'Denied: resource belongs to a different tenant' });
  });

  it('gives an overlapping explicit deny priority over an allow', () => {
    const rules: PolicyRule[] = [
      { id: 'allow-read', effect: 'allow', actions: ['read'], resources: ['report'], tenantScope: 'any' },
      { id: 'deny-read', effect: 'deny', actions: ['read'], resources: ['report'], tenantScope: 'any' },
    ];
    expect(evaluatePolicy({ action: 'read', resource: 'report', role: 'admin' }, rules)).toMatchObject({ allowed: false, ruleId: 'deny-read' });
  });

  it('logs the denied middleware decision with its reason', async () => {
    const req = { user: { id: 'u1', userId: 'u1', role: 'user' }, business: { id: 'tenant-a' } } as Request;
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() } as unknown as Response;
    const next = vi.fn() as unknown as NextFunction;
    await requirePolicy('delete', 'integration', { resourceId: () => 'i1', resourceTenantId: () => 'tenant-b' })(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    expect(await getAllAuditLogs()).toEqual([expect.objectContaining({ userId: 'u1', action: 'POLICY_DECISION', resourceId: 'i1', metadata: expect.objectContaining({ allowed: false, reason: 'Denied: resource belongs to a different tenant' }) })]);
  });
});
