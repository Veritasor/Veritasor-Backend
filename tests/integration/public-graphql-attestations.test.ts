import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app.js';
import { db } from '../../src/db/client.js';
import * as jwt from '../../src/utils/jwt.js';

describe('Public GraphQL Attestations', () => {
  const testHash = 'test-hash-123';
  const testBusinessId = 'test-business-id';
  const testUser = {
    userId: testBusinessId,
    email: 'test@example.com',
    role: 'user',
  };

  const validToken = 'valid-token';
  const unauthorizedToken = 'unauth-token';

  beforeAll(async () => {
    // Setup mocks
    vi.mock('../../src/repositories/attestationRepository.js', () => ({
      getById: vi.fn(async (_db, hash) => {
        if (hash === 'test-hash-123') {
          return {
            id: 'test-id',
            businessId: 'test-business-id',
            period: '2023-Q1',
            merkleRoot: 'test-root',
            txHash: 'test-tx',
            status: 'attested',
            createdAt: new Date('2023-01-01T00:00:00Z'),
          };
        }
        return null;
      }),
    }));

    vi.mock('../../src/repositories/userRepository.js', () => ({
      findUserById: vi.fn(async (id) => {
        if (id === 'test-business-id') return { id, role: 'user', email: 'a@a.com' };
        if (id === 'other-id') return { id, role: 'user', email: 'b@b.com' };
        return null;
      }),
    }));

    vi.spyOn(jwt, 'verifyToken').mockImplementation((token) => {
      if (token === validToken) return { userId: testBusinessId, email: 'a@a.com' };
      if (token === unauthorizedToken) return { userId: 'other-id', email: 'b@b.com' };
      return null;
    });
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('allows anonymous access to public fields', async () => {
    const response = await request(app)
      .post('/api/v1/public/attestations/graphql')
      .send({
        query: `
          query {
            attestationByHash(hash: "${testHash}") {
              id
              period
              status
            }
          }
        `,
      });

    expect(response.status).toBe(200);
    expect(response.body.data.attestationByHash).toEqual({
      id: 'test-id',
      period: '2023-Q1',
      status: 'attested',
    });
  });

  it('returns null for sensitive fields without auth (tenancy required)', async () => {
    const response = await request(app)
      .post('/api/v1/public/attestations/graphql')
      .send({
        query: `
          query {
            attestationByHash(hash: "${testHash}") {
              id
              businessId
            }
          }
        `,
      });

    expect(response.status).toBe(200);
    expect(response.body.data.attestationByHash).toEqual({
      id: 'test-id',
      businessId: null,
    });
  });

  it('returns null for sensitive fields with wrong tenant auth', async () => {
    const response = await request(app)
      .post('/api/v1/public/attestations/graphql')
      .set('Authorization', `Bearer ${unauthorizedToken}`)
      .send({
        query: `
          query {
            attestationByHash(hash: "${testHash}") {
              id
              businessId
            }
          }
        `,
      });

    expect(response.status).toBe(200);
    expect(response.body.data.attestationByHash).toEqual({
      id: 'test-id',
      businessId: null,
    });
  });

  it('allows access to sensitive fields with correct tenant auth', async () => {
    const response = await request(app)
      .post('/api/v1/public/attestations/graphql')
      .set('Authorization', `Bearer ${validToken}`)
      .send({
        query: `
          query {
            attestationByHash(hash: "${testHash}") {
              id
              businessId
            }
          }
        `,
      });

    expect(response.status).toBe(200);
    expect(response.body.data.attestationByHash).toEqual({
      id: 'test-id',
      businessId: testBusinessId,
    });
  });
});
