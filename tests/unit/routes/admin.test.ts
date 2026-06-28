import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import adminRouter from '../../../src/routes/admin.js';
import * as userRepository from '../../../src/repositories/userRepository.js';
import * as auditLogRepository from '../../../src/repositories/auditLogRepository.js';
import * as attestationRepository from '../../../src/repositories/attestationRepository.js';
import * as rolePromotionRepository from '../../../src/repositories/rolePromotionRequestRepository.js';
import { IntegrationPermission } from '../../../src/types/permissions.js';

// Mock repositories
vi.mock('../../../src/repositories/userRepository.js');
vi.mock('../../../src/repositories/auditLogRepository.js');
vi.mock('../../../src/repositories/attestationRepository.js');
vi.mock('../../../src/repositories/rolePromotionRequestRepository.js');
vi.mock('../../../src/db/client.js', () => ({
  db: { query: vi.fn() }
}));

// Mock auth and permission middleware
vi.mock('../../../src/middleware/requireAuth.js', () => ({
  requireAuth: (req: any, res: any, next: any) => {
    const role = (req.headers['x-user-role'] as string) || 'admin';
    req.user = { id: 'admin_123', userId: 'admin_123', email: 'admin@test.com', role };
    next();
  }
}));

vi.mock('../../../src/middleware/permissions.js', () => ({
  requirePermissions: (permissions: any) => (req: any, res: any, next: any) => {
    // If user is admin, allow everything for these tests
    if (req.user.role === 'admin') {
      return next();
    }
    res.status(403).json({ error: 'Forbidden' });
  }
}));

const app = express();
app.use(express.json());
app.use('/api/v1/admin', adminRouter);

describe('Admin Routes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('GET /stats', () => {
    it('should return platform statistics', async () => {
      const mockUsers = [
        { id: '1', role: 'admin' },
        { id: '2', role: 'user' },
        { id: '3', role: 'user' },
      ];
      const mockAttestations = [
        { id: 'a1', status: 'confirmed' },
        { id: 'a2', status: 'pending' },
      ];

      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers as any);
      vi.mocked(attestationRepository.listAll).mockResolvedValue(mockAttestations as any);

      const response = await request(app).get('/api/v1/admin/stats');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        totalUsers: 3,
        totalAttestations: 2,
        adminCount: 1,
        businessAdminCount: 0,
        userCount: 2,
        recentAttestations: expect.any(Array),
      });
    });
  });

  describe('GET /users', () => {
    it('should return all users', async () => {
      const mockUsers = [
        { id: '1', email: 'user1@test.com' },
        { id: '2', email: 'user2@test.com' },
      ];
      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers as any);

      const response = await request(app).get('/api/v1/admin/users');

      expect(response.status).toBe(200);
      expect(response.body).toHaveLength(2);
      expect(response.body[0].email).toBe('user1@test.com');
    });
  });

  describe('PATCH /users/:id', () => {
    it('should update user and create audit log', async () => {
      const mockUser = { id: 'user_1', email: 'user1@test.com', role: 'user' };
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUser as any);
      vi.mocked(userRepository.updateUser).mockResolvedValue({ ...mockUser, role: 'admin' } as any);

      const response = await request(app)
        .patch('/api/v1/admin/users/user_1')
        .send({ role: 'admin', passwordHash: 'secret' });

      expect(response.status).toBe(200);
      expect(response.body.role).toBe('admin');
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
        action: 'UPDATE_USER',
        resourceId: 'user_1',
        metadata: expect.objectContaining({
          outcome: 'success',
          updateFields: ['role'],
        }),
      }));
    });

    it('should allow admin to update self and create audit log', async () => {
      const mockUser = { id: 'admin_123', email: 'admin@test.com', role: 'admin' };
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUser as any);
      vi.mocked(userRepository.updateUser).mockResolvedValue({ ...mockUser, role: 'admin' } as any);

      const response = await request(app)
        .patch('/api/v1/admin/users/admin_123')
        .send({ role: 'admin' });

      expect(response.status).toBe(200);
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
        action: 'UPDATE_USER',
        resourceId: 'admin_123',
        metadata: expect.objectContaining({
          outcome: 'success',
        }),
      }));
    });

    it('should return 404 if user not found', async () => {
      vi.mocked(userRepository.findUserById).mockResolvedValue(null);

      const response = await request(app)
        .patch('/api/v1/admin/users/invalid')
        .send({ role: 'admin' });

      expect(response.status).toBe(404);
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
        action: 'UPDATE_USER',
        resourceId: 'invalid',
        metadata: expect.objectContaining({
          outcome: 'not_found',
        }),
      }));
    });

    it('should return 403 when permissions are denied', async () => {
      const response = await request(app)
        .patch('/api/v1/admin/users/user_1')
        .set('x-user-role', 'user')
        .send({ role: 'admin' });

      expect(response.status).toBe(403);
      expect(auditLogRepository.createAuditLog).not.toHaveBeenCalled();
    });
  });

  describe('DELETE /users/:id', () => {
    it('should delete user and create audit log', async () => {
      const mockUser = { id: 'user_1', email: 'user1@test.com' };
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUser as any);
      vi.mocked(userRepository.deleteUser).mockResolvedValue(true);

      const response = await request(app).delete('/api/v1/admin/users/user_1');

      expect(response.status).toBe(204);
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
        action: 'DELETE_USER',
        resourceId: 'user_1',
        metadata: expect.objectContaining({
          outcome: 'success',
        }),
      }));
    });

    it('should return 404 if user not found', async () => {
      vi.mocked(userRepository.findUserById).mockResolvedValue(null);

      const response = await request(app).delete('/api/v1/admin/users/missing');

      expect(response.status).toBe(404);
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
        action: 'DELETE_USER',
        resourceId: 'missing',
        metadata: expect.objectContaining({
          outcome: 'not_found',
        }),
      }));
    });
  });

  describe('GET /audit-logs', () => {
    it('should return paginated audit logs', async () => {
      const mockLogs = [
        { id: 'log1', action: 'UPDATE_USER' },
        { id: 'log2', action: 'DELETE_USER' },
      ];
      vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({ data: mockLogs, nextCursor: null, hasMore: false } as any);

      const response = await request(app).get('/api/v1/admin/audit-logs');

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveLength(2);
      expect(response.body.nextCursor).toBeNull();
      expect(response.body.hasMore).toBe(false);
    });
  });

  describe('POST /role-requests', () => {
    it('should create a new role promotion request', async () => {
      const mockTargetUser = { id: 'target-123', email: 'target@test.com' };
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockTargetUser as any);
      vi.mocked(rolePromotionRepository.findPendingRolePromotionRequestsForTarget).mockResolvedValue([]);
      const mockRequest = {
        id: 'req-123',
        targetUserId: 'target-123',
        requestedRole: 'admin',
        requestedByAdminId: 'admin-123',
        status: 'pending',
        createdAt: new Date(),
        expiresAt: new Date(),
      };
      vi.mocked(rolePromotionRepository.createRolePromotionRequest).mockResolvedValue(mockRequest as any);

      const response = await request(app)
        .post('/api/v1/admin/role-requests')
        .send({ targetUserId: 'target-123', role: 'admin' });

      expect(response.status).toBe(201);
      expect(response.body.id).toBe('req-123');
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'CREATE_ROLE_PROMOTION_REQUEST' }),
        expect.anything()
      );
    });

    it('should return 404 if target user not found', async () => {
      vi.mocked(userRepository.findUserById).mockResolvedValue(null);

      const response = await request(app)
        .post('/api/v1/admin/role-requests')
        .send({ targetUserId: 'non-existent', role: 'admin' });

      expect(response.status).toBe(404);
    });

    it('should return 409 if pending request for role already exists', async () => {
      const mockTargetUser = { id: 'target-123', email: 'target@test.com' };
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockTargetUser as any);
      vi.mocked(rolePromotionRepository.findPendingRolePromotionRequestsForTarget).mockResolvedValue([
        { requestedRole: 'admin' } as any,
      ]);

      const response = await request(app)
        .post('/api/v1/admin/role-requests')
        .send({ targetUserId: 'target-123', role: 'admin' });

      expect(response.status).toBe(409);
    });

    it('should return 403 for non-admin', async () => {
      const response = await request(app)
        .post('/api/v1/admin/role-requests')
        .set('x-user-role', 'user')
        .send({ targetUserId: 'target-123', role: 'admin' });

      expect(response.status).toBe(403);
    });
  });

  describe('POST /role-requests/:id/approve', () => {
    it('should approve a pending request and update user role', async () => {
      const mockRequest = {
        id: 'req-123',
        targetUserId: 'target-123',
        requestedRole: 'admin',
        requestedByAdminId: 'admin-456', // Different from requester
        status: 'pending',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
      };
      vi.mocked(rolePromotionRepository.findRolePromotionRequestById).mockResolvedValue(mockRequest as any);
      vi.mocked(userRepository.findUserById).mockResolvedValue({ id: 'target-123' } as any);
      vi.mocked(rolePromotionRepository.updateRolePromotionRequest).mockResolvedValue({
        ...mockRequest,
        status: 'approved',
        approvedByAdminId: 'admin-123',
        approvedAt: new Date(),
      } as any);

      const response = await request(app).post('/api/v1/admin/role-requests/req-123/approve');

      expect(response.status).toBe(200);
      expect(userRepository.updateUser).toHaveBeenCalledWith('target-123', { role: 'admin' });
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'APPROVE_ROLE_PROMOTION_REQUEST' }),
        expect.anything()
      );
    });

    it('should return 403 for self-approval', async () => {
      const mockRequest = {
        id: 'req-123',
        targetUserId: 'target-123',
        requestedRole: 'admin',
        requestedByAdminId: 'admin-123', // Same as requester
        status: 'pending',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
      };
      vi.mocked(rolePromotionRepository.findRolePromotionRequestById).mockResolvedValue(mockRequest as any);

      const response = await request(app).post('/api/v1/admin/role-requests/req-123/approve');

      expect(response.status).toBe(403);
      expect(auditLogRepository.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({ 
          action: 'APPROVE_ROLE_PROMOTION_REQUEST',
          metadata: expect.objectContaining({ outcome: 'forbidden_self_approval' })
        })
      );
    });

    it('should return 409 if request is already approved', async () => {
      const mockRequest = {
        id: 'req-123',
        targetUserId: 'target-123',
        requestedRole: 'admin',
        requestedByAdminId: 'admin-456',
        status: 'approved',
        createdAt: new Date(),
        expiresAt: new Date(),
      };
      vi.mocked(rolePromotionRepository.findRolePromotionRequestById).mockResolvedValue(mockRequest as any);

      const response = await request(app).post('/api/v1/admin/role-requests/req-123/approve');

      expect(response.status).toBe(409);
    });

    it('should return 409 if request is expired', async () => {
      const mockRequest = {
        id: 'req-123',
        targetUserId: 'target-123',
        requestedRole: 'admin',
        requestedByAdminId: 'admin-456',
        status: 'pending',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() - 3600000), // Expired
      };
      vi.mocked(rolePromotionRepository.findRolePromotionRequestById).mockResolvedValue(mockRequest as any);

      const response = await request(app).post('/api/v1/admin/role-requests/req-123/approve');

      expect(response.status).toBe(409);
    });

    it('should return 404 if request not found', async () => {
      vi.mocked(rolePromotionRepository.findRolePromotionRequestById).mockResolvedValue(null);

      const response = await request(app).post('/api/v1/admin/role-requests/non-existent/approve');

      expect(response.status).toBe(404);
    });
  });
});
