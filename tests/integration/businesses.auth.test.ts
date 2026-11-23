import express from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import businessesRouter from '../../src/routes/businesses.js';
import { clearAll as clearBusinesses } from '../../src/repositories/business.js';
import { clearAllUsers, createUser } from '../../src/repositories/userRepository.js';
import { generateToken, JWT_AUDIENCE, JWT_ISSUER, sign } from '../../src/utils/jwt.js';

const app = express();
app.use(express.json());
app.use('/api/businesses', businessesRouter);

describe('businesses JWT authentication', () => {
  beforeEach(() => {
    clearBusinesses();
    clearAllUsers();
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
});
