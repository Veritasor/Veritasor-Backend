import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import * as userRepository from '../../../src/repositories/userRepository.js';
import * as auditLogRepository from '../../../src/repositories/auditLogRepository.js';
import * as businessRepository from '../../../src/repositories/business.js';

vi.mock('../../../src/repositories/userRepository.js');
vi.mock('../../../src/repositories/auditLogRepository.js');
vi.mock('../../../src/repositories/business.js');
vi.mock('../../../src/db/client.js', () => ({
  db: { query: vi.fn() },
}));

vi.mock('../../../src/middleware/requireAuth.js', () => ({
  requireAuth: (req: any, _res: any, next: any) => {
    const role = (req.headers['x-user-role'] as string) || 'admin';
    req.user = {
      id: 'admin_123',
      userId: 'admin_123',
      email: 'admin@test.com',
      role,
    };
    next();
  },
}));

vi.mock('../../../src/middleware/permissions.js', () => ({
  requirePermissions: (_permissions: any) => (req: any, res: any, next: any) => {
    if (req.user.role === 'admin') {
      return next();
    }
    res.status(403).json({ error: 'Forbidden', message: 'Insufficient permissions' });
  },
}));

const mockGraphqlConfig = { enableIntrospection: true };

vi.mock('../../../src/config/index.js', () => ({
  config: {
    get graphql() {
      return mockGraphqlConfig;
    },
  },
}));

const { default: adminGraphqlRouter } = await import('../../../src/routes/admin.graphql.js');

const app = express();
app.use(express.json());
app.use('/api/v1/admin', adminGraphqlRouter);

const mockUsers = [
  {
    id: 'user-1',
    email: 'alice@test.com',
    role: 'admin' as const,
    createdAt: new Date('2025-01-01'),
    updatedAt: new Date('2025-01-02'),
    passwordHash: 'hashed',
  },
  {
    id: 'user-2',
    email: 'bob@test.com',
    role: 'user' as const,
    createdAt: new Date('2025-01-03'),
    updatedAt: new Date('2025-01-04'),
    passwordHash: 'hashed',
  },
];

const mockAuditLogs = [
  {
    id: 'log-1',
    userId: 'user-1',
    action: 'UPDATE_USER',
    resource: 'user',
    resourceId: 'user-1',
    metadata: { outcome: 'success' },
    timestamp: new Date('2025-01-05'),
  },
  {
    id: 'log-2',
    userId: 'user-1',
    action: 'DELETE_USER',
    resource: 'user',
    resourceId: 'user-2',
    metadata: { outcome: 'success' },
    timestamp: new Date('2025-01-06'),
  },
];

const mockBusinesses = [
  {
    id: 'biz-1',
    userId: 'user-1',
    name: 'Acme Inc',
    email: 'acme@test.com',
    industry: 'Tech',
    description: null,
    website: null,
    reportingPeriod: 'monthly',
    reportingTimezone: 'UTC',
    lastReminderSentAt: null,
    createdAt: '2025-01-01T00:00:00.000Z',
    updatedAt: '2025-01-02T00:00:00.000Z',
  },
];

beforeEach(() => {
  vi.clearAllMocks();
});

function gql(query: string) {
  return request(app)
    .post('/api/v1/admin/graphql')
    .set('Content-Type', 'application/json')
    .send({ query });
}

function extractMetricValue(metricsText: string, metricName: string): number {
  for (const line of metricsText.split('\n')) {
    if (line.startsWith(metricName) && !line.startsWith('#')) {
      return Number(line.split(/\s+/).pop() || '0');
    }
  }
  return 0;
}

async function getMetricValue(name: string): Promise<number> {
  const { metricsRegistry } = await import('../../../src/metrics.js');
  const text = await metricsRegistry.metrics();
  return extractMetricValue(text, name);
}

describe('Admin GraphQL endpoint', () => {
  describe('users query', () => {
    it('returns all users', async () => {
      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers as any);

      const res = await gql('{ users { id email role } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.users).toHaveLength(2);
      expect(res.body.data.users[0]).toEqual({
        id: 'user-1',
        email: 'alice@test.com',
        role: 'admin',
      });
      expect(res.body.data.users[1]).toEqual({
        id: 'user-2',
        email: 'bob@test.com',
        role: 'user',
      });
    });

    it('returns a single user by id', async () => {
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUsers[0] as any); vi.mocked(userRepository.findUsersByIds).mockResolvedValue([mockUsers[0]] as any);

      const res = await gql('{ user(id: "user-1") { id email role } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.user).toEqual({
        id: 'user-1',
        email: 'alice@test.com',
        role: 'admin',
      });
    });

    it('returns null for non-existent user', async () => {
      vi.mocked(userRepository.findUserById).mockResolvedValue(null);

      const res = await gql('{ user(id: "nonexistent") { id } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.user).toBeNull();
    });

    it('resolves nested auditLogs on User', async () => {
      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers as any);
      vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({
        data: mockAuditLogs as any,
        nextCursor: null,
        hasMore: false,
      });

      const res = await gql('{ users { id auditLogs { id action } } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.users[0].auditLogs).toHaveLength(2);
      expect(auditLogRepository.queryAuditLogs).toHaveBeenCalledWith(
        expect.objectContaining({ actorId: 'user-1' }),
      );
    });
  });

  describe('auditLogs query', () => {
    it('returns all audit logs', async () => {
      vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({
        data: mockAuditLogs as any,
        nextCursor: null,
        hasMore: false,
      });

      const res = await gql('{ auditLogs { id action resource } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.auditLogs).toHaveLength(2);
      expect(res.body.data.auditLogs[0]).toEqual({
        id: 'log-1',
        action: 'UPDATE_USER',
        resource: 'user',
      });
    });

    it('returns a single audit log by id', async () => {
      vi.mocked(auditLogRepository.getAllAuditLogs).mockResolvedValue(
        mockAuditLogs as any,
      );

      const res = await gql('{ auditLog(id: "log-1") { id action resource } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.auditLog).toEqual({
        id: 'log-1',
        action: 'UPDATE_USER',
        resource: 'user',
      });
    });

    it('returns null for non-existent audit log', async () => {
      vi.mocked(auditLogRepository.getAllAuditLogs).mockResolvedValue(
        mockAuditLogs as any,
      );

      const res = await gql('{ auditLog(id: "nonexistent") { id } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.auditLog).toBeNull();
    });

    it('resolves nested actor on AuditLog', async () => {
      vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({
        data: mockAuditLogs as any,
        nextCursor: null,
        hasMore: false,
      });
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUsers[0] as any); vi.mocked(userRepository.findUsersByIds).mockResolvedValue([mockUsers[0]] as any);

      const res = await gql('{ auditLogs { id actor { id email } } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.auditLogs[0].actor).toEqual({
        id: 'user-1',
        email: 'alice@test.com',
      });
      expect(userRepository.findUserById).toHaveBeenCalledWith('user-1');
    });
  });

  describe('businesses query', () => {
    it('returns all businesses', async () => {
      vi.mocked(businessRepository.getAll).mockResolvedValue(
        mockBusinesses as any,
      );

      const res = await gql('{ businesses { id name email } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.businesses).toHaveLength(1);
      expect(res.body.data.businesses[0]).toEqual({
        id: 'biz-1',
        name: 'Acme Inc',
        email: 'acme@test.com',
      });
    });

    it('returns a single business by id', async () => {
      vi.mocked(businessRepository.getById).mockResolvedValue(
        mockBusinesses[0] as any,
      );

      const res = await gql('{ business(id: "biz-1") { id name } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.business).toEqual({
        id: 'biz-1',
        name: 'Acme Inc',
      });
    });

    it('returns null for non-existent business', async () => {
      vi.mocked(businessRepository.getById).mockResolvedValue(null);

      const res = await gql('{ business(id: "nonexistent") { id } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.data.business).toBeNull();
    });
  });

  describe('security and validation', () => {
    it('rejects mutations with HTTP 400 and increments metric', async () => {
      const res = await gql('mutation { __typename }');

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
      expect(res.body.errors[0].message).toBe(
        'Mutations are not allowed on this endpoint',
      );

      const val = await getMetricValue('graphql_admin_mutation_rejections_total');
      expect(val).toBe(1);
    });

    it('rejects deep nested query with HTTP 400 and increments metric', async () => {
      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers as any);
      vi.mocked(auditLogRepository.queryAuditLogs).mockResolvedValue({
        data: mockAuditLogs as any,
        nextCursor: null,
        hasMore: false,
      });
      vi.mocked(userRepository.findUserById).mockResolvedValue(mockUsers[0] as any); vi.mocked(userRepository.findUsersByIds).mockResolvedValue([mockUsers[0]] as any);

      const deepQuery = `
        {
          users {
            auditLogs {
              actor {
                auditLogs {
                  actor { id }
                }
              }
            }
          }
        }
      `;

      const res = await gql(deepQuery);

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
      expect(res.body.errors[0].message).toContain('depth');

      const val = await getMetricValue(
        'graphql_admin_depth_limit_rejections_total',
      );
      expect(val).toBe(1);
    });

    it('rejects introspection __schema query (deep nested) with graphql error', async () => {
      const res = await gql(
        '{ __schema { types { fields { type { fields { type { name } } } } } } }',
      );

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
    });

    it('rejects requests from non-admin users with 403', async () => {
      const res = await request(app)
        .post('/api/v1/admin/graphql')
        .set('Content-Type', 'application/json')
        .set('x-user-role', 'user')
        .send({ query: '{ users { id } }' });

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Forbidden');
    });

    it('masks internal resolver errors', async () => {
      vi.mocked(userRepository.getAllUsers).mockRejectedValue(
        new Error('internal secret'),
      );

      const res = await gql('{ users { id } }');

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.errors).toBeDefined();
      expect(res.body.errors[0].message).toBe('Unexpected error.');
      expect(res.body.errors[0].message).not.toContain('secret');
    });

    it('rejects empty query string with GraphQL error', async () => {
      const res = await request(app)
        .post('/api/v1/admin/graphql')
        .set('Content-Type', 'application/json')
        .send({ query: '' });

      if (res.status !== 200) console.log(res.status, res.text); expect(res.status).toBe(200);
      expect(res.body.errors).toBeDefined();
      expect(res.body.errors[0].message).toContain('Syntax Error');
    });
  });

  describe('introspection gating', () => {
    it('allows __schema query when introspection is enabled', async () => {
      mockGraphqlConfig.enableIntrospection = true;

      const res = await gql('{ __schema { queryType { name } } }');

      expect(res.status).toBe(200);
      expect(res.body.data.__schema).toBeDefined();
      expect(res.body.data.__schema.queryType.name).toBe('Query');
    });

    it('allows __type query when introspection is enabled', async () => {
      mockGraphqlConfig.enableIntrospection = true;

      const res = await gql('{ __type(name: "User") { name fields { name } } }');

      expect(res.status).toBe(200);
      expect(res.body.data.__type).toBeDefined();
      expect(res.body.data.__type.name).toBe('User');
    });

    it('rejects __schema query when introspection is disabled', async () => {
      mockGraphqlConfig.enableIntrospection = false;

      const res = await gql('{ __schema { queryType { name } } }');

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
      expect(res.body.errors[0].message).toBe(
        'Introspection is not allowed on this endpoint',
      );

      const val = await getMetricValue(
        'graphql_admin_introspection_rejections_total',
      );
      expect(val).toBeGreaterThanOrEqual(1);
    });

    it('rejects __type query when introspection is disabled', async () => {
      mockGraphqlConfig.enableIntrospection = false;

      const res = await gql('{ __type(name: "User") { name } }');

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
      expect(res.body.errors[0].message).toBe(
        'Introspection is not allowed on this endpoint',
      );
    });

    it('rejects introspection query masked as inline fragment', async () => {
      mockGraphqlConfig.enableIntrospection = false;

      const res = await gql(`
        {
          ... on Query {
            __schema {
              types {
                name
              }
            }
          }
        }
      `);

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
      expect(res.body.errors[0].message).toBe(
        'Introspection is not allowed on this endpoint',
      );
    });

    it('rejects __schema inside fragment spread when introspection is disabled', async () => {
      mockGraphqlConfig.enableIntrospection = false;

      const res = await gql(`
        query IntrospectionQuery {
          ...FullIntrospection
        }
        fragment FullIntrospection on Query {
          __schema {
            types {
              name
            }
          }
        }
      `);

      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
    });

    it('allows normal queries when introspection is disabled', async () => {
      mockGraphqlConfig.enableIntrospection = false;
      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers as any);

      const res = await gql('{ users { id email role } }');

      expect(res.status).toBe(200);
      expect(res.body.data.users).toHaveLength(2);
    });

    it('does not increment introspection metric for non-introspection queries', async () => {
      mockGraphqlConfig.enableIntrospection = false;
      vi.mocked(userRepository.getAllUsers).mockResolvedValue(mockUsers as any);

      const before = await getMetricValue(
        'graphql_admin_introspection_rejections_total',
      );
      await gql('{ users { id } }');
      const after = await getMetricValue(
        'graphql_admin_introspection_rejections_total',
      );
      expect(after).toBe(before);
    });
  });
});
