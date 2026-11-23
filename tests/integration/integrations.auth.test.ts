import express from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import integrationsRouter from '../../src/routes/integrations.js';
import { businessRepository, clearAll as clearBusinesses } from '../../src/repositories/business.js';
import { clearAllUsers, createUser } from '../../src/repositories/userRepository.js';
import { generateToken } from '../../src/utils/jwt.js';

const app = express();
app.use(express.json());
app.use('/api/integrations', integrationsRouter);

describe('integrations JWT authentication', () => {
  beforeEach(() => {
    clearBusinesses();
    clearAllUsers();
  });

  it('requires a verified Bearer token and ignores x-user-id', async () => {
    const authenticatedUser = await createUser('integration-user@example.test', 'not-used-by-this-test');
    const otherUser = await createUser('integration-other@example.test', 'not-used-by-this-test');
    const business = await businessRepository.create({
      userId: authenticatedUser.id,
      email: authenticatedUser.email,
      name: 'Integration Test Business',
      industry: null,
      description: null,
      website: null,
    });
    const token = generateToken({ userId: authenticatedUser.id, email: authenticatedUser.email });

    await request(app)
      .get('/api/integrations/connected')
      .set('x-user-id', authenticatedUser.id)
      .set('x-business-id', business.id)
      .expect(401);

    const response = await request(app)
      .get('/api/integrations/connected')
      .set('Authorization', `Bearer ${token}`)
      .set('x-user-id', otherUser.id)
      .set('x-business-id', business.id)
      .expect(200);

    expect(response.body).toMatchObject({ integrations: [], count: 0 });
  });
});
