/**
 * Unit tests for requireBusinessAuth middleware
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Request, Response, NextFunction } from 'express'
import { requireBusinessAuth } from '../../../src/middleware/requireBusinessAuth.js'
import * as jwt from '../../../src/utils/jwt.js'
import * as userRepository from '../../../src/repositories/userRepository.js'
import * as businessRepository from '../../../src/repositories/business.js'

describe('requireBusinessAuth middleware', () => {
  let mockRequest: Partial<Request> & { 
    user?: { id: string; userId: string; email?: string };
    business?: any;
  }
  let mockResponse: Partial<Response>
  let mockNext: NextFunction

  beforeEach(() => {
    mockRequest = {
      headers: {},
      body: {},
    }
    mockResponse = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    }
    mockNext = vi.fn()
    vi.clearAllMocks()
  })

  describe('Authentication Validation', () => {
    it('should reject requests without Authorization header', async () => {
      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(401)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Business authentication required",
        message: "Missing or invalid authorization header. Format: 'Bearer <token>'",
        code: "MISSING_AUTH"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should reject requests with invalid Authorization format', async () => {
      mockRequest.headers = {
        authorization: 'InvalidFormat token',
        'x-business-id': 'business-123'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(401)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Business authentication required",
        message: "Missing or invalid authorization header. Format: 'Bearer <token>'",
        code: "MISSING_AUTH"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should reject requests with invalid JWT token', async () => {
      const verifySpy = vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)
      
      mockRequest.headers = {
        authorization: 'Bearer invalid-token',
        'x-business-id': 'business-123'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(verifySpy).toHaveBeenCalledWith('invalid-token')
      expect(mockResponse.status).toHaveBeenCalledWith(401)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Invalid authentication",
        message: "Token is invalid, expired, or user not found",
        code: "INVALID_TOKEN"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should reject requests when user not found in database', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      
      const findUserSpy = vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'x-business-id': 'business-123'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(findUserSpy).toHaveBeenCalledWith('user-123')
      expect(mockResponse.status).toHaveBeenCalledWith(401)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Invalid authentication",
        message: "Token is invalid, expired, or user not found",
        code: "INVALID_TOKEN"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })
  })

  describe('Business ID Validation', () => {
    it('should reject requests without business ID', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(400)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Business context required",
        message: "Business ID is required. Provide via 'x-business-id' header or 'business_id'/'businessId' in request body",
        code: "MISSING_BUSINESS_ID"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should reject requests with invalid business ID format in header', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'x-business-id': 'invalid@business#id'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(400)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Business context required",
        message: "Business ID is required. Provide via 'x-business-id' header or 'business_id'/'businessId' in request body",
        code: "MISSING_BUSINESS_ID"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should accept business ID from request body (businessId field)', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      vi.spyOn(businessRepository, 'getById').mockResolvedValue({
        id: 'business-123',
        userId: 'user-123',
        name: 'Test Business'
      } as any)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      }
      mockRequest.body = {
        businessId: 'business-123',
        period: '2024-01'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockNext).toHaveBeenCalled()
      expect(mockRequest.user).toEqual({
        id: 'user-123',
        userId: 'user-123',
        email: 'test@example.com'
      })
      expect(mockRequest.business).toEqual({
        id: 'business-123',
        userId: 'user-123',
        name: 'Test Business'
      })
    })

    it('should accept business ID from request body (business_id field)', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      vi.spyOn(businessRepository, 'getById').mockResolvedValue({
        id: 'business-123',
        userId: 'user-123',
        name: 'Test Business'
      } as any)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      }
      mockRequest.body = {
        business_id: 'business-123',
        period: '2024-01'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockNext).toHaveBeenCalled()
      expect(mockRequest.user).toEqual({
        id: 'user-123',
        userId: 'user-123',
        email: 'test@example.com'
      })
      expect(mockRequest.business).toEqual({
        id: 'business-123',
        userId: 'user-123',
        name: 'Test Business'
      })
    })

    it('should prioritize header over body business ID', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      vi.spyOn(businessRepository, 'getById').mockResolvedValue({
        id: 'business-123',
        userId: 'user-123',
        name: 'Test Business'
      } as any)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'x-business-id': 'business-123' // Header takes priority
      }
      mockRequest.body = {
        business_id: 'business-456', // This should be ignored
        period: '2024-01'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(businessRepository.getById).toHaveBeenCalledWith('business-123') // Header ID used
      expect(mockNext).toHaveBeenCalled()
    })
  })

  describe('Business Authorization', () => {
    it('should reject requests for non-existent business', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      vi.spyOn(businessRepository, 'getById').mockResolvedValue(null)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'x-business-id': 'non-existent-business'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(403)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Business access denied",
        message: "Business not found or access denied. User must own the business.",
        code: "BUSINESS_NOT_FOUND"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should reject requests for business owned by different user', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      vi.spyOn(businessRepository, 'getById').mockResolvedValue({
        id: 'business-456',
        userId: 'user-456', // Different user owns this business
        name: 'Other Business'
      } as any)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'x-business-id': 'business-456'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(403)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Business access denied",
        message: "Business not found or access denied. User must own the business.",
        code: "BUSINESS_NOT_FOUND"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should allow requests for business owned by authenticated user', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com'
      } as any)
      vi.spyOn(businessRepository, 'getById').mockResolvedValue({
        id: 'business-123',
        userId: 'user-123', // Same user owns this business
        name: 'Test Business',
        industry: 'Technology',
        description: 'A test business',
        website: 'https://test.com',
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z'
      } as any)
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'x-business-id': 'business-123'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockNext).toHaveBeenCalled()
      expect(mockRequest.user).toEqual({
        id: 'user-123',
        userId: 'user-123',
        email: 'test@example.com'
      })
      expect(mockRequest.business).toEqual({
        id: 'business-123',
        userId: 'user-123',
        name: 'Test Business',
        industry: 'Technology',
        description: 'A test business',
        website: 'https://test.com',
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z'
      })
    })
  })

  describe('Error Handling', () => {
    it('should handle JWT verification errors gracefully', async () => {
      vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
        throw new Error('JWT verification failed')
      })
      
      mockRequest.headers = {
        authorization: 'Bearer malformed-token',
        'x-business-id': 'business-123'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(401)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Invalid authentication",
        message: "Token is invalid, expired, or user not found",
        code: "INVALID_TOKEN"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should handle database errors gracefully', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com'
      })
      vi.spyOn(userRepository, 'findUserById').mockImplementation(() => {
        throw new Error('Database connection failed')
      })
      
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'x-business-id': 'business-123'
      }

      await requireBusinessAuth(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      )

      expect(mockResponse.status).toHaveBeenCalledWith(401)
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: "Invalid authentication",
        message: "Token is invalid, expired, or user not found",
        code: "INVALID_TOKEN"
      })
      expect(mockNext).not.toHaveBeenCalled()
    })
  })
})
