import { describe, it, expect, beforeEach, vi, expectTypeOf, afterEach } from 'vitest';
import {
  createRolePromotionRequest,
  findRolePromotionRequestById,
  updateRolePromotionRequest,
  findPendingRolePromotionRequestsForTarget,
  sweepExpiredRequests,
  clearAllRolePromotionRequests,
  type Role,
  type RolePromotionRequestStatus,
  type RolePromotionRequest
} from '../../../src/repositories/rolePromotionRequestRepository';

describe('Role Promotion Request Repository', () => {
  beforeEach(() => {
    clearAllRolePromotionRequests();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Types', () => {
    it('should correctly define Role type', () => {
      type ExpectedRole = 'user' | 'admin' | 'business_admin';
      expectTypeOf<Role>().toEqualTypeOf<ExpectedRole>();
    });

    it('should correctly define RolePromotionRequestStatus type', () => {
      type ExpectedStatus = 'pending' | 'approved' | 'expired' | 'rejected';
      expectTypeOf<RolePromotionRequestStatus>().toEqualTypeOf<ExpectedStatus>();
    });

    it('should correctly shape RolePromotionRequest', () => {
      expectTypeOf<RolePromotionRequest>().toHaveProperty('id').toEqualTypeOf<string>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('targetUserId').toEqualTypeOf<string>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('requestedRole').toEqualTypeOf<Role>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('requestedByAdminId').toEqualTypeOf<string>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('status').toEqualTypeOf<RolePromotionRequestStatus>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('createdAt').toEqualTypeOf<Date>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('expiresAt').toEqualTypeOf<Date>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('approvedByAdminId').toEqualTypeOf<string | undefined>();
      expectTypeOf<RolePromotionRequest>().toHaveProperty('approvedAt').toEqualTypeOf<Date | undefined>();
    });
  });

  describe('createRolePromotionRequest', () => {
    it('should create a new promotion request with pending status', async () => {
      const now = new Date('2024-01-01T12:00:00Z');
      vi.setSystemTime(now);

      const request = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      
      expect(request.id).toBeDefined();
      expect(typeof request.id).toBe('string');
      expect(request.id.length).toBeGreaterThan(0);
      expect(request.targetUserId).toBe('target-123');
      expect(request.requestedRole).toBe('admin');
      expect(request.requestedByAdminId).toBe('admin-456');
      expect(request.status).toBe('pending');
      expect(request.createdAt).toEqual(now);
      expect(request.expiresAt).toBeInstanceOf(Date);
      expect(request.expiresAt.getTime()).toBeGreaterThan(now.getTime());
    });

    it('should handle edge cases for targetUserId and requestedByAdminId (empty strings)', async () => {
      // Testing representative invalid inputs at runtime since TS types are wiped
      const request = await createRolePromotionRequest('', 'user' as Role, '');
      expect(request.id).toBeDefined();
      expect(request.targetUserId).toBe('');
      expect(request.requestedByAdminId).toBe('');
    });
  });

  describe('findRolePromotionRequestById', () => {
    it('should retrieve an existing request by ID', async () => {
      const created = await createRolePromotionRequest('target-123', 'business_admin', 'admin-456');
      const retrieved = await findRolePromotionRequestById(created.id);
      
      expect(retrieved).not.toBeNull();
      expect(retrieved!.id).toBe(created.id);
      expect(retrieved!.targetUserId).toBe('target-123');
    });

    it('should return null for non-existent ID', async () => {
      const retrieved = await findRolePromotionRequestById('non-existent-id');
      expect(retrieved).toBeNull();
    });

    it('should return null for empty ID', async () => {
      const retrieved = await findRolePromotionRequestById('');
      expect(retrieved).toBeNull();
    });
  });

  describe('updateRolePromotionRequest', () => {
    it('should update request status to approved', async () => {
      const created = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      const approvedAt = new Date();
      
      const updated = await updateRolePromotionRequest(created.id, {
        status: 'approved',
        approvedByAdminId: 'admin-789',
        approvedAt,
      });

      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('approved');
      expect(updated!.approvedByAdminId).toBe('admin-789');
      expect(updated!.approvedAt).toEqual(approvedAt);
    });

    it('should return null when updating non-existent request', async () => {
      const updated = await updateRolePromotionRequest('non-existent-id', { status: 'approved' });
      expect(updated).toBeNull();
    });

    it('should not update unprovided fields', async () => {
      const created = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      const updated = await updateRolePromotionRequest(created.id, {
        status: 'rejected'
      });

      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('rejected');
      expect(updated!.approvedByAdminId).toBeUndefined();
      expect(updated!.approvedAt).toBeUndefined();
    });
  });

  describe('findPendingRolePromotionRequestsForTarget', () => {
    it('should return pending requests for a target user', async () => {
      await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      await createRolePromotionRequest('target-123', 'business_admin', 'admin-789');
      
      // Approved requests should not be returned
      const toApprove = await createRolePromotionRequest('target-123', 'admin', 'admin-999');
      await updateRolePromotionRequest(toApprove.id, { status: 'approved' });

      // Other targets should not be returned
      await createRolePromotionRequest('other-target', 'admin', 'admin-012');

      const pending = await findPendingRolePromotionRequestsForTarget('target-123');
      expect(pending.length).toBe(2);
      expect(pending.every(r => r.targetUserId === 'target-123')).toBe(true);
      expect(pending.every(r => r.status === 'pending')).toBe(true);
    });

    it('should return empty array for target with no pending requests', async () => {
      const pending = await findPendingRolePromotionRequestsForTarget('no-requests');
      expect(pending.length).toBe(0);
    });

    it('should return empty array for target with empty string', async () => {
      const pending = await findPendingRolePromotionRequestsForTarget('');
      expect(pending.length).toBe(0);
    });
  });

  describe('sweepExpiredRequests', () => {
    it('should mark expired requests as expired', async () => {
      // Create request at T0
      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
      const request = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      
      // Fast-forward past TTL (24h)
      vi.advanceTimersByTime(25 * 60 * 60 * 1000);

      const count = await sweepExpiredRequests();
      expect(count).toBe(1);
      
      const updated = await findRolePromotionRequestById(request.id);
      expect(updated!.status).toBe('expired');
    });

    it('should not modify non-expired requests', async () => {
      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
      const request = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      
      // Fast-forward partially (not past TTL)
      vi.advanceTimersByTime(12 * 60 * 60 * 1000);

      const count = await sweepExpiredRequests();
      expect(count).toBe(0);
      
      const updated = await findRolePromotionRequestById(request.id);
      expect(updated!.status).toBe('pending');
    });

    it('should not modify already approved requests even if they are past their original TTL', async () => {
      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
      const request = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      
      // Approve it
      await updateRolePromotionRequest(request.id, { status: 'approved' });

      // Fast-forward past TTL (24h)
      vi.advanceTimersByTime(25 * 60 * 60 * 1000);

      const count = await sweepExpiredRequests();
      expect(count).toBe(0);
      
      const updated = await findRolePromotionRequestById(request.id);
      expect(updated!.status).toBe('approved');
    });
  });
});
