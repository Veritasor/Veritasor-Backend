import { describe, it, expect, vi, beforeEach } from 'vitest';
import { execute, parse } from 'graphql';
import { userSchema } from '../../../../src/graphql/subgraphs/user.js';
import * as userRepository from '../../../../src/repositories/userRepository.js';
import * as auditLogRepository from '../../../../src/repositories/auditLogRepository.js';

vi.mock('../../../../src/repositories/userRepository.js');
vi.mock('../../../../src/repositories/auditLogRepository.js');

describe('User Subgraph Schema', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Query: users', () => {
    it('returns a list of users', async () => {
      const mockUsers = [
        { id: 'u1', email: 'user1@example.com', role: 'user', createdAt: '2023-01-01T00:00:00Z', updatedAt: '2023-01-01T00:00:00Z' },
        { id: 'u2', email: 'user2@example.com', role: 'admin', createdAt: '2023-01-02T00:00:00Z', updatedAt: '2023-01-02T00:00:00Z' }
      ];
      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers);

      const result = await execute({
        schema: userSchema,
        document: parse('{ users { id email role createdAt updatedAt } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.users).toEqual(mockUsers);
      expect(userRepository.getAllUsers).toHaveBeenCalledTimes(1);
    });

    it('returns empty array when no users', async () => {
      vi.mocked(userRepository.getAllUsers).mockResolvedValue([]);

      const result = await execute({
        schema: userSchema,
        document: parse('{ users { id email } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.users).toEqual([]);
    });
  });

  describe('Query: user(id)', () => {
    it('returns a specific user by id', async () => {
      const mockUser = { id: 'u1', email: 'user1@example.com', role: 'user', createdAt: '2023-01-01T00:00:00Z', updatedAt: '2023-01-01T00:00:00Z' };
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUser);

      const result = await execute({
        schema: userSchema,
        document: parse('{ user(id: "u1") { id email } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.user).toEqual({ id: 'u1', email: 'user1@example.com' });
      expect(userRepository.findUserById).toHaveBeenCalledWith('u1');
    });

    it('returns null when user not found', async () => {
      vi.mocked(userRepository.findUserById).mockResolvedValue(null);

      const result = await execute({
        schema: userSchema,
        document: parse('{ user(id: "nonexistent") { id email } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.user).toBeNull();
    });
  });

  describe('Query: auditLogs', () => {
    it('returns a list of audit logs', async () => {
      const mockLogs = [
        { id: 'al1', userId: 'u1', action: 'login', resource: 'auth', timestamp: '2023-01-01T00:00:00Z' }
      ];
      vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({ data: mockLogs, nextCursor: null });

      const result = await execute({
        schema: userSchema,
        document: parse('{ auditLogs { id userId action resource timestamp } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.auditLogs).toEqual(mockLogs);
      expect(auditLogRepository.queryAuditLogs).toHaveBeenCalledWith({ limit: 100 });
    });
  });

  describe('Query: auditLog(id)', () => {
    it('returns a specific audit log by id', async () => {
      const mockLogs = [
        { id: 'al1', userId: 'u1', action: 'login', resource: 'auth', timestamp: '2023-01-01T00:00:00Z' },
        { id: 'al2', userId: 'u2', action: 'update', resource: 'profile', timestamp: '2023-01-02T00:00:00Z' }
      ];
      vi.mocked(auditLogRepository.getAllAuditLogs).mockResolvedValue(mockLogs);

      const result = await execute({
        schema: userSchema,
        document: parse('{ auditLog(id: "al2") { id action resource } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.auditLog).toEqual({ id: 'al2', action: 'update', resource: 'profile' });
      expect(auditLogRepository.getAllAuditLogs).toHaveBeenCalledTimes(1);
    });

    it('returns null if audit log not found', async () => {
      vi.mocked(auditLogRepository.getAllAuditLogs).mockResolvedValue([]);

      const result = await execute({
        schema: userSchema,
        document: parse('{ auditLog(id: "al3") { id action } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.auditLog).toBeNull();
    });
  });

  describe('Type: User', () => {
    it('resolves auditLogs for a user', async () => {
      const mockUser = { id: 'u1', email: 'user1@example.com', role: 'user', createdAt: '2023-01-01T00:00:00Z', updatedAt: '2023-01-01T00:00:00Z' };
      const mockLogs = [
        { id: 'al1', userId: 'u1', action: 'login', resource: 'auth', timestamp: '2023-01-01T00:00:00Z' }
      ];
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUser);
      vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({ data: mockLogs, nextCursor: null });

      const result = await execute({
        schema: userSchema,
        document: parse('{ user(id: "u1") { id auditLogs { id action } } }'),
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.user?.auditLogs).toEqual([{ id: 'al1', action: 'login' }]);
      expect(auditLogRepository.queryAuditLogs).toHaveBeenCalledWith({ actorId: 'u1', limit: 50 });
    });
  });

  describe('Type: AuditLog', () => {
    it('resolves actor via context loaders', async () => {
      const mockLogs = [
        { id: 'al1', userId: 'u1', action: 'login', resource: 'auth', timestamp: '2023-01-01T00:00:00Z' }
      ];
      vi.mocked(auditLogRepository.getAllAuditLogs).mockResolvedValue(mockLogs);
      
      const mockUser = { id: 'u1', email: 'user1@example.com', role: 'user', createdAt: '2023-01-01T00:00:00Z', updatedAt: '2023-01-01T00:00:00Z' };
      const userLoaderMock = {
        load: vi.fn().mockResolvedValue(mockUser)
      };

      const result = await execute({
        schema: userSchema,
        document: parse('{ auditLog(id: "al1") { id actor { id email } } }'),
        contextValue: {
          loaders: {
            userLoader: userLoaderMock
          }
        }
      });

      expect(result.errors).toBeUndefined();
      expect(result.data?.auditLog?.actor).toEqual({ id: 'u1', email: 'user1@example.com' });
      expect(userLoaderMock.load).toHaveBeenCalledWith('u1');
    });
    
    it('handles context failure gracefully', async () => {
      const mockLogs = [
        { id: 'al1', userId: 'u1', action: 'login', resource: 'auth', timestamp: '2023-01-01T00:00:00Z' }
      ];
      vi.mocked(auditLogRepository.getAllAuditLogs).mockResolvedValue(mockLogs);
      
      const userLoaderMock = {
        load: vi.fn().mockRejectedValue(new Error('Loader failed'))
      };

      const result = await execute({
        schema: userSchema,
        document: parse('{ auditLog(id: "al1") { id actor { id } } }'),
        contextValue: {
          loaders: {
            userLoader: userLoaderMock
          }
        }
      });

      expect(result.errors).toBeDefined();
      expect(result.errors![0].message).toContain('Loader failed');
    });
  });
});
