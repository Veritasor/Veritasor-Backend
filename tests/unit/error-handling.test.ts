import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  AppError,
  UnauthorizedError,
  AuthenticationError,
  ValidationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  VRTErrorCodes,
  isAppError,
  isValidationError,
} from '../../src/types/errors.js';

describe('Error Classes', () => {
  describe('AppError', () => {
    it('should create an error with default values', () => {
      const error = new AppError('Test error');
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Test error');
      expect(error.status).toBe(500);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_9999);
    });

    it('should create an error with custom values', () => {
      const context = { userId: '123' };
      const error = new AppError('Custom error', 400, VRTErrorCodes.VRT_0002, context);
      expect(error.message).toBe('Custom error');
      expect(error.status).toBe(400);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0002);
      expect(error.context).toEqual(context);
    });
  });

  describe('UnauthorizedError', () => {
    it('should create an error with correct VRT code', () => {
      const error = new UnauthorizedError();
      expect(error).toBeInstanceOf(AppError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0001);
      expect(error.status).toBe(401);
    });
  });

  describe('AuthenticationError (backward compatibility)', () => {
    it('should create an error with correct VRT code', () => {
      const error = new AuthenticationError();
      expect(error).toBeInstanceOf(AppError);
      expect(error).toBeInstanceOf(UnauthorizedError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0001);
      expect(error.status).toBe(401);
    });
  });

  describe('ValidationError', () => {
    it('should create a validation error with details', () => {
      const details = [{ field: 'email', message: 'Invalid email' }];
      const error = new ValidationError(details);
      expect(error).toBeInstanceOf(Error);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0002);
      expect(error.status).toBe(400);
      expect(error.details).toEqual(details);
    });
  });

  describe('AuthorizationError', () => {
    it('should create an authorization error with correct VRT code', () => {
      const error = new AuthorizationError();
      expect(error).toBeInstanceOf(AppError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0003);
      expect(error.status).toBe(403);
    });
  });

  describe('NotFoundError', () => {
    it('should create a not found error with correct VRT code', () => {
      const error = new NotFoundError();
      expect(error).toBeInstanceOf(AppError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0004);
      expect(error.status).toBe(404);
    });
  });

  describe('ConflictError', () => {
    it('should create a conflict error with correct VRT code', () => {
      const error = new ConflictError();
      expect(error).toBeInstanceOf(AppError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0005);
      expect(error.status).toBe(409);
    });
  });

  describe('RateLimitError', () => {
    it('should create a rate limit error with correct VRT code', () => {
      const error = new RateLimitError();
      expect(error).toBeInstanceOf(AppError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0006);
      expect(error.status).toBe(429);
    });
  });

  describe('DatabaseError', () => {
    it('should create a database error with correct VRT code', () => {
      const error = new DatabaseError();
      expect(error).toBeInstanceOf(AppError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0007);
      expect(error.status).toBe(500);
    });
  });

  describe('ExternalServiceError', () => {
    it('should create an external service error with correct VRT code', () => {
      const error = new ExternalServiceError();
      expect(error).toBeInstanceOf(AppError);
      expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0008);
      expect(error.status).toBe(503);
    });
  });

  describe('Type Guards', () => {
    it('should identify AppError instances', () => {
      expect(isAppError(new AppError('test'))).toBe(true);
      expect(isAppError(new UnauthorizedError())).toBe(true);
      expect(isAppError(new Error())).toBe(false);
    });

    it('should identify ValidationError instances', () => {
      expect(isValidationError(new ValidationError([]))).toBe(true);
      expect(isValidationError(new AppError('test'))).toBe(false);
    });
  });
});
