import { describe, it, expect, beforeEach } from 'vitest';
import {
  createRolePromotionRequest,
  findRolePromotionRequestById,
  updateRolePromotionRequest,
  findPendingRolePromotionRequestsForTarget,
  sweepExpiredRequests,
  clearAllRolePromotionRequests,
} from '../../../src/repositories/rolePromotionRequestRepository';

describe('Role Promotion Request Repository', () => {
  beforeEach(() => {
    clearAllRolePromotionRequests();
  });

  describe('createRolePromotionRequest', () => {
    it('should create a new promotion request with pending status', async () => {
      const request = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      
      expect(request.id).toBeDefined();
      expect(request.targetUserId).toBe('target-123');
      expect(request.requestedRole).toBe('admin');
      expect(request.requestedByAdminId).toBe('admin-456');
      expect(request.status).toBe('pending');
      expect(request.createdAt).toBeInstanceOf(Date);
      expect(request.expiresAt).toBeInstanceOf(Date);
      expect(request.expiresAt.getTime()).toBeGreaterThan(request.createdAt.getTime());
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
  });

  describe('updateRolePromotionRequest', () => {
    it('should update request status to approved', async () => {
      const created = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      const updated = await updateRolePromotionRequest(created.id, {
        status: 'approved',
        approvedByAdminId: 'admin-789',
        approvedAt: new Date(),
      });

      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('approved');
      expect(updated!.approvedByAdminId).toBe('admin-789');
      expect(updated!.approvedAt).toBeInstanceOf(Date);
    });

    it('should return null when updating non-existent request', async () => {
      const updated = await updateRolePromotionRequest('non-existent-id', { status: 'approved' });
      expect(updated).toBeNull();
    });
  });

  describe('findPendingRolePromotionRequestsForTarget', () => {
    it('should return pending requests for a target user', async () => {
      await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      await createRolePromotionRequest('target-123', 'business_admin', 'admin-789');
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
  });

  describe('sweepExpiredRequests', () => {
    it('should mark expired requests as expired', async () => {
      // Create a request that's already expired by manipulating time
      const request = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      // Manually set expiresAt to past
      (request as any).expiresAt = new Date(Date.now() - 1000);
      // Save it back
      await updateRolePromotionRequest(request.id, {});

      const count = await sweepExpiredRequests();
      expect(count).toBe(1);
      
      const updated = await findRolePromotionRequestById(request.id);
      expect(updated!.status).toBe('expired');
    });

    it('should not modify non-expired requests', async () => {
      const request = await createRolePromotionRequest('target-123', 'admin', 'admin-456');
      
      const count = await sweepExpiredRequests();
      expect(count).toBe(0);
      
      const updated = await findRolePromotionRequestById(request.id);
      expect(updated!.status).toBe('pending');
    });
  });
});
