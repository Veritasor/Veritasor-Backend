import express from 'express';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import businessesRouter from '../../src/routes/businesses.js';
import { businessRepository, clearAll as clearBusinesses } from '../../src/repositories/business.js';
import { clearAllUsers, createUser } from '../../src/repositories/userRepository.js';
import * as webhookSubscriptionRepo from '../../src/repositories/webhookSubscriptionRepository.js';
import { generateToken, JWT_AUDIENCE, JWT_ISSUER, sign } from '../../src/utils/jwt.js';

const app = express();
app.use(express.json());
app.use('/api/businesses', businessesRouter);

describe('businesses JWT authentication', () => {
  beforeEach(() => {
    clearBusinesses();
    clearAllUsers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function createAuthenticatedUser(email: string) {
    const user = await createUser(email, 'not-used-by-this-test');
    return { user, token: generateToken({ userId: user.id, email: user.email }) };
  }

  it('rejects x-user-id without a Bearer token for protected business routes', async () => {
    await request(app)
      .post('/api/businesses')
      .set('x-user-id', 'attacker')
      .send({ name: 'Impostor Co' })
      .expect(401);

    await request(app)
      .get('/api/businesses/me')
      .set('x-user-id', 'attacker')
      .expect(401);
  });

  it('uses the verified JWT identity and ignores x-user-id', async () => {
    const authenticated = await createAuthenticatedUser('authenticated@example.test');
    const otherUser = await createAuthenticatedUser('other@example.test');

    const createResponse = await request(app)
      .post('/api/businesses')
      .set('Authorization', `Bearer ${authenticated.token}`)
      .set('x-user-id', otherUser.user.id)
      .send({ name: 'Verified Identity Co' })
      .expect(201);

    expect(createResponse.body.userId).toBe(authenticated.user.id);

    const getResponse = await request(app)
      .get('/api/businesses/me')
      .set('Authorization', `Bearer ${authenticated.token}`)
      .set('x-user-id', otherUser.user.id)
      .expect(200);

    expect(getResponse.body.id).toBe(createResponse.body.id);
    expect(getResponse.body.userId).toBe(authenticated.user.id);
  });

  it('rejects malformed and expired JWTs', async () => {
    const user = await createUser('expired@example.test', 'not-used-by-this-test');
    const expiredToken = sign(
      { userId: user.id, email: user.email },
      { algorithm: 'HS256', audience: JWT_AUDIENCE, expiresIn: -1, issuer: JWT_ISSUER },
    );

    await request(app)
      .get('/api/businesses/me')
      .set('Authorization', 'Bearer malformed.token.value')
      .expect(401);

    await request(app)
      .get('/api/businesses/me')
      .set('Authorization', `Bearer ${expiredToken}`)
      .expect(401);
  });

  it('rejects registering a webhook for another business with 403', async () => {
    const owner = await createAuthenticatedUser('owner@example.test');
    const attacker = await createAuthenticatedUser('attacker@example.test');
    const ownerBiz = await businessRepository.create({
      userId: owner.user.id,
      name: 'Owner Biz',
    });
    const attackerBiz = await businessRepository.create({
      userId: attacker.user.id,
      name: 'Attacker Biz',
    });

    // Attacker targets owner's business ID directly
    await request(app)
      .post(`/api/businesses/${ownerBiz.id}/webhooks`)
      .set('Authorization', `Bearer ${attacker.token}`)
      .send({ url: 'https://example.com/webhook', secret: 'a'.repeat(32) })
      .expect(403);

    // Attacker passes their own x-business-id header while targeting owner's :id param
    await request(app)
      .post(`/api/businesses/${ownerBiz.id}/webhooks`)
      .set('Authorization', `Bearer ${attacker.token}`)
      .set('x-business-id', attackerBiz.id)
      .send({ url: 'https://example.com/webhook', secret: 'a'.repeat(32) })
      .expect(403);
  });

  it('forwards owned business webhook registration to persistent repository without echoing secret', async () => {
    const owner = await createAuthenticatedUser('webhook-owner@example.test');
    const ownerBiz = await businessRepository.create({
      userId: owner.user.id,
      name: 'Webhook Owner Biz',
    });

    const countSpy = vi.spyOn(webhookSubscriptionRepo, 'countByBusiness').mockResolvedValue(0);
    const createSpy = vi.spyOn(webhookSubscriptionRepo, 'create').mockResolvedValue({
      id: 'sub-123',
      businessId: ownerBiz.id,
      url: 'https://example.com/webhook',
      secret: 'a'.repeat(32),
      eventFilters: {},
      enabled: true,
      maxPayloadSize: null,
      secretVersion: 1,
      mtlsConfig: null,
      createdAt: new Date('2026-01-01T00:00:00Z'),
      updatedAt: new Date('2026-01-01T00:00:00Z'),
    });

    const res = await request(app)
      .post(`/api/businesses/${ownerBiz.id}/webhooks`)
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ url: 'https://example.com/webhook', secret: 'a'.repeat(32) })
      .expect(201);

    expect(res.headers.deprecation).toBe('true');
    expect(countSpy).toHaveBeenCalledWith(ownerBiz.id);
    expect(createSpy).toHaveBeenCalledWith(ownerBiz.id, {
      url: 'https://example.com/webhook',
      secret: 'a'.repeat(32),
      eventFilters: {},
      enabled: true,
    });
    expect(res.body.id).toBe('sub-123');
    expect(res.body.businessId).toBe(ownerBiz.id);
    expect(res.body.secret).toBeUndefined();
    expect(res.body.secretLast4).toBe('aaaa');
  });
});
