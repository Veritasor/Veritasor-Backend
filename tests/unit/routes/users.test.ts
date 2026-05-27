import { describe, it, expect } from 'vitest';
import request from 'supertest';
import express from 'express';
import usersRouter from '../../../src/routes/users.js';
import { errorHandler } from '../../../src/middleware/errorHandler.js';

const app = express();
app.use(express.json());
app.use('/api/users', usersRouter);
app.use(errorHandler);

const authHeader = 'Bearer fake-token';

describe('PATCH /api/users/me', () => {
  it('should update name successfully', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ name: 'New Name' });

    expect(response.status).toBe(200);
    expect(response.body.name).toBe('New Name');
  });

  it('should update profile successfully', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ profile: { bio: 'Hello' } });

    expect(response.status).toBe(200);
    expect(response.body.profile).toEqual({ bio: 'Hello' });
  });

  it('should update both name and profile', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ name: 'Alice', profile: { theme: 'dark' } });

    expect(response.status).toBe(200);
    expect(response.body.name).toBe('Alice');
    expect(response.body.profile).toEqual({ theme: 'dark' });
  });

  it('should return 400 for empty body', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({});

    expect(response.status).toBe(400);
    expect(response.body.message).toBe('No updatable fields provided');
  });

  it('should reject unknown fields', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ name: 'Alice', unknownField: 'value' });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('VALIDATION_ERROR');
  });

  it('should reject oversized name', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ name: 'a'.repeat(101) });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('VALIDATION_ERROR');
  });

  it('should reject non-string name', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ name: 123 });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('VALIDATION_ERROR');
  });

  it('should reject non-object profile', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ profile: 'not-an-object' });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('VALIDATION_ERROR');
  });

  it('should reject null name', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .set('Authorization', authHeader)
      .send({ name: null });

    expect(response.status).toBe(400);
    expect(response.body.code).toBe('VALIDATION_ERROR');
  });

  it('should return 401 without auth header', async () => {
    const response = await request(app)
      .patch('/api/users/me')
      .send({ name: 'Alice' });

    expect(response.status).toBe(401);
  });
});
