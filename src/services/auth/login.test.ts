import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../repositories/userRepository.js', () => ({
  findUserByEmail: vi.fn(),
}));
vi.mock('../../utils/password.js', () => ({
  verifyPassword: vi.fn(),
}));
vi.mock('../../utils/jwt.js', () => ({
  generateToken: vi.fn(),
  generateRefreshToken: vi.fn(),
}));

import { findUserByEmail } from '../../repositories/userRepository.js';
import { verifyPassword } from '../../utils/password.js';
import { generateToken, generateRefreshToken } from '../../utils/jwt.js';
import { login } from './login.js';
import { AuthenticationError } from '../../types/errors.js';

/**
 * Focused behaviour coverage for `src/services/auth/login.ts` (issue #966):
 * `LoginRequest` / `LoginResponse`, the success contract and the rejected-input
 * branches, without touching a database or the JWT implementation.
 */
const mockFindUserByEmail = vi.mocked(findUserByEmail);
const mockVerifyPassword = vi.mocked(verifyPassword);
const mockGenerateToken = vi.mocked(generateToken);
const mockGenerateRefreshToken = vi.mocked(generateRefreshToken);

const storedUser = {
  id: 'user-1',
  email: 'ada@example.com',
  passwordHash: 'stored-hash',
  createdAt: new Date('2026-01-01T00:00:00.000Z'),
  updatedAt: new Date('2026-01-01T00:00:00.000Z'),
  role: 'user' as const,
};

describe('login service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGenerateToken.mockReturnValue('access-token');
    mockGenerateRefreshToken.mockReturnValue('refresh-token');
  });

  it('returns the token pair and the minimal user for valid credentials', async () => {
    mockFindUserByEmail.mockResolvedValue(storedUser);
    mockVerifyPassword.mockResolvedValue(true);

    const result = await login({ email: storedUser.email, password: 'correct-horse' });

    expect(result).toEqual({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      user: { id: storedUser.id, email: storedUser.email },
    });
  });

  it('looks the user up by email and verifies the submitted password against the stored hash', async () => {
    mockFindUserByEmail.mockResolvedValue(storedUser);
    mockVerifyPassword.mockResolvedValue(true);

    await login({ email: storedUser.email, password: 'correct-horse' });

    expect(mockFindUserByEmail).toHaveBeenCalledWith(storedUser.email);
    expect(mockVerifyPassword).toHaveBeenCalledWith('correct-horse', storedUser.passwordHash);
    expect(mockGenerateToken).toHaveBeenCalledWith({
      userId: storedUser.id,
      email: storedUser.email,
    });
    expect(mockGenerateRefreshToken).toHaveBeenCalledWith({
      userId: storedUser.id,
      email: storedUser.email,
    });
  });

  it('never leaks the password hash in the response payload', async () => {
    mockFindUserByEmail.mockResolvedValue(storedUser);
    mockVerifyPassword.mockResolvedValue(true);

    const result = await login({ email: storedUser.email, password: 'correct-horse' });

    expect(result.user).not.toHaveProperty('passwordHash');
    expect(JSON.stringify(result)).not.toContain('stored-hash');
  });

  it('rejects an unknown email without running the password or token steps', async () => {
    mockFindUserByEmail.mockResolvedValue(null);

    await expect(login({ email: 'missing@example.com', password: 'whatever' })).rejects.toThrow(
      'Invalid email or password',
    );
    expect(mockVerifyPassword).not.toHaveBeenCalled();
    expect(mockGenerateToken).not.toHaveBeenCalled();
    expect(mockGenerateRefreshToken).not.toHaveBeenCalled();
  });

  it('rejects a wrong password without issuing any token', async () => {
    mockFindUserByEmail.mockResolvedValue(storedUser);
    mockVerifyPassword.mockResolvedValue(false);

    await expect(login({ email: storedUser.email, password: 'wrong' })).rejects.toThrow(
      'Invalid email or password',
    );
    expect(mockGenerateToken).not.toHaveBeenCalled();
    expect(mockGenerateRefreshToken).not.toHaveBeenCalled();
  });

  it('surfaces failures as AuthenticationError with the 401 taxonomy contract', async () => {
    mockFindUserByEmail.mockResolvedValue(null);

    const failure = await login({ email: 'nobody@example.com', password: 'x' }).catch((e) => e);

    expect(failure).toBeInstanceOf(AuthenticationError);
    expect(failure.name).toBe('AuthenticationError');
    expect(failure.message).toBe('Invalid email or password');
    expect(failure.status).toBe(401);
  });

  it('treats an empty password as a failed verification rather than a success', async () => {
    mockFindUserByEmail.mockResolvedValue(storedUser);
    mockVerifyPassword.mockResolvedValue(false);

    await expect(login({ email: storedUser.email, password: '' })).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    // The service still delegates the empty secret to the verifier.
    expect(mockVerifyPassword).toHaveBeenCalledWith('', storedUser.passwordHash);
  });

  it('propagates repository failures instead of masking them as auth errors', async () => {
    const dbError = new Error('connection terminated');
    mockFindUserByEmail.mockRejectedValue(dbError);

    await expect(login({ email: storedUser.email, password: 'x' })).rejects.toBe(dbError);
  });
});
