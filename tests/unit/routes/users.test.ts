import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import usersRouter from '../../../src/routes/users.js';
import * as userRepository from '../../../src/repositories/userRepository.js';
import updateProfile from '../../../src/services/user/updateProfile.js';
import { generateToken } from '../../../src/utils/jwt.js';

// Mock userRepository and updateProfile service
vi.mock('../../../src/repositories/userRepository.js', () => ({
  findUserById: vi.fn(),
}));

vi.mock('../../../src/services/user/updateProfile.js', () => ({
  default: vi.fn(),
}));

vi.mock('../../../src/db/client.js', () => ({
  db: { query: vi.fn() }
}));

const app = express();
app.use(express.json());
app.use('/api/users', usersRouter);

describe('Users Routes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('PATCH /api/users/me', () => {
    it('should return 401 when Authorization header is missing', async () => {
      const response = await request(app)
        .patch('/api/users/me')
        .send({ name: 'Alice' });

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Missing or invalid authorization header' });
    });

    it('should return 401 when Authorization header is malformed', async () => {
      const response = await request(app)
        .patch('/api/users/me')
        .set('Authorization', 'Basic userpass')
        .send({ name: 'Alice' });

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Missing or invalid authorization header' });
    });

    it('should return 401 when Token is invalid or expired', async () => {
      const response = await request(app)
        .patch('/api/users/me')
        .set('Authorization', 'Bearer invalid-token-string')
        .send({ name: 'Alice' });

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Invalid or expired token' });
    });

    it('should return 401 when user is not found in database', async () => {
      const token = generateToken({ userId: 'user_not_found', email: 'missing@example.com' });
      vi.mocked(userRepository.findUserById).mockResolvedValue(null);

      const response = await request(app)
        .patch('/api/users/me')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Alice' });

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'User not found' });
      expect(userRepository.findUserById).toHaveBeenCalledWith('user_not_found');
    });

    it('should update profile successfully when valid token is provided', async () => {
      const token = generateToken({ userId: 'user_123', email: 'alice@example.com' });
      const mockDbUser = { id: 'user_123', role: 'user' };
      const updatedUser = { id: 'user_123', name: 'Alice Updated' };

      vi.mocked(userRepository.findUserById).mockResolvedValue(mockDbUser as any);
      vi.mocked(updateProfile).mockResolvedValue(updatedUser as any);

      const response = await request(app)
        .patch('/api/users/me')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Alice Updated', profile: { bio: 'hello' } });

      expect(response.status).toBe(200);
      expect(response.body).toEqual(updatedUser);
      expect(updateProfile).toHaveBeenCalledWith('user_123', {
        name: 'Alice Updated',
        profile: { bio: 'hello' },
      });
    });

    it('should return 400 when no updatable fields are provided', async () => {
      const token = generateToken({ userId: 'user_123', email: 'alice@example.com' });
      const mockDbUser = { id: 'user_123', role: 'user' };

      vi.mocked(userRepository.findUserById).mockResolvedValue(mockDbUser as any);

      const response = await request(app)
        .patch('/api/users/me')
        .set('Authorization', `Bearer ${token}`)
        .send({ email: 'new@example.com' }); // not in allowed fields ('name', 'profile')

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ message: 'No updatable fields provided' });
    });

    it('should return 400 when updateProfile service throws an error', async () => {
      const token = generateToken({ userId: 'user_123', email: 'alice@example.com' });
      const mockDbUser = { id: 'user_123', role: 'user' };

      vi.mocked(userRepository.findUserById).mockResolvedValue(mockDbUser as any);
      vi.mocked(updateProfile).mockRejectedValue(new Error('Update failed due to database constraint'));

      const response = await request(app)
        .patch('/api/users/me')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Alice' });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ message: 'Update failed due to database constraint' });
    });
  });
});
