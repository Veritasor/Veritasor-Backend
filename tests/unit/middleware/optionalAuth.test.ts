import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Request, Response, NextFunction } from 'express'
import { optionalAuth, extractBearerToken, AuthEventType } from '../../../src/middleware/optionalAuth.js'
import * as jwt from '../../../src/utils/jwt.js'
import * as userRepository from '../../../src/repositories/userRepository.js'

describe('extractBearerToken - Helper Function', () => {
  describe('Valid Bearer tokens', () => {
    it('should extract Bearer token with single space', () => {
      const result = extractBearerToken('Bearer valid-token-123')
      expect(result).toBe('valid-token-123')
    })

    it('should extract Bearer token with JWT-like format', () => {
      const result = extractBearerToken('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ')
      expect(result).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ')
    })

    it('should handle case-insensitive Bearer prefix (lowercase)', () => {
      const result = extractBearerToken('bearer token-here')
      expect(result).toBe('token-here')
    })

    it('should handle case-insensitive Bearer prefix (uppercase)', () => {
      const result = extractBearerToken('BEARER token-here')
      expect(result).toBe('token-here')
    })

    it('should handle case-insensitive Bearer prefix (mixed case)', () => {
      const result = extractBearerToken('BeArEr token-here')
      expect(result).toBe('token-here')
    })

    it('should handle multiple spaces and trim correctly', () => {
      const result = extractBearerToken('Bearer   multiple-spaces-token')
      expect(result).toBe('multiple-spaces-token')
    })

    it('should handle token with internal spaces preserved', () => {
      const result = extractBearerToken('Bearer token with spaces inside')
      expect(result).toBe('token with spaces inside')
    })

    it('should handle token with trailing whitespace trimmed', () => {
      const result = extractBearerToken('Bearer valid-token   ')
      expect(result).toBe('valid-token')
    })
  })

  describe('Malformed Bearer prefixes - Typos', () => {
    it('should return null for "Bearr" typo', () => {
      const result = extractBearerToken('Bearr token')
      expect(result).toBeNull()
    })

    it('should return null for "Barer" typo', () => {
      const result = extractBearerToken('Barer token')
      expect(result).toBeNull()
    })

    it('should return null for "Beear" typo', () => {
      const result = extractBearerToken('Beear token')
      expect(result).toBeNull()
    })

    it('should return null for "Baer" typo', () => {
      const result = extractBearerToken('Baer token')
      expect(result).toBeNull()
    })
  })

  describe('Malformed Bearer prefixes - Special characters', () => {
    it('should return null for "Bearer:" (colon instead of space)', () => {
      const result = extractBearerToken('Bearer:token')
      expect(result).toBeNull()
    })

    it('should return null for "Bearer;" (semicolon instead of space)', () => {
      const result = extractBearerToken('Bearer;token')
      expect(result).toBeNull()
    })

    it('should return null for "Bearer," (comma instead of space)', () => {
      const result = extractBearerToken('Bearer,token')
      expect(result).toBeNull()
    })

    it('should return null for "Bearer-" (hyphen instead of space)', () => {
      const result = extractBearerToken('Bearer-token')
      expect(result).toBeNull()
    })
  })

  describe('Wrong authentication schemes', () => {
    it('should return null for "Basic" scheme', () => {
      const result = extractBearerToken('Basic dXNlcjpwYXNz')
      expect(result).toBeNull()
    })

    it('should return null for "Token" scheme', () => {
      const result = extractBearerToken('Token token-value')
      expect(result).toBeNull()
    })

    it('should return null for "Bearer-Token" scheme', () => {
      const result = extractBearerToken('Bearer-Token token-value')
      expect(result).toBeNull()
    })

    it('should return null for "OAuth" scheme', () => {
      const result = extractBearerToken('OAuth oauth-token')
      expect(result).toBeNull()
    })

    it('should return null for "Digest" scheme', () => {
      const result = extractBearerToken('Digest username=user')
      expect(result).toBeNull()
    })
  })

  describe('Missing or empty tokens', () => {
    it('should return null for "Bearer" with no token', () => {
      const result = extractBearerToken('Bearer')
      expect(result).toBeNull()
    })

    it('should return null for "Bearer " with only spaces', () => {
      const result = extractBearerToken('Bearer   ')
      expect(result).toBeNull()
    })

    it('should return null for empty string', () => {
      const result = extractBearerToken('')
      expect(result).toBeNull()
    })

    it('should return null for undefined', () => {
      const result = extractBearerToken(undefined)
      expect(result).toBeNull()
    })

    it('should return null for null (cast to undefined)', () => {
      const result = extractBearerToken(null as any)
      expect(result).toBeNull()
    })
  })

  describe('Edge cases', () => {
    it('should handle token with numbers and special url-safe characters', () => {
      const result = extractBearerToken('Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyMyJ9.8zCr5_6ZzVu-kJsEu5zdGPM-QMxQGqhV6H6Ft')
      expect(result).toBe('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyMyJ9.8zCr5_6ZzVu-kJsEu5zdGPM-QMxQGqhV6H6Ft')
    })

    it('should return null for only prefix and tab character', () => {
      const result = extractBearerToken('Bearer\t')
      expect(result).toBeNull()
    })

    it('should handle Bearer prefix with tab separator', () => {
      const result = extractBearerToken('Bearer\ttoken-value')
      expect(result).toBe('token-value')
    })

    it('should handle Bearer prefix with newline (treated as whitespace)', () => {
      const result = extractBearerToken('Bearer\ntoken-value')
      expect(result).toBe('token-value')
    })

    it('should handle very long token', () => {
      const longToken = 'a'.repeat(1000)
      const result = extractBearerToken(`Bearer ${longToken}`)
      expect(result).toBe(longToken)
    })
  })
})

// Mock console methods to capture structured logs
const mockConsoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
const mockConsoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});

describe('Enhanced optionalAuth middleware - Auth Event Classification', () => {
  let mockRequest: Partial<Request>
  let mockResponse: Partial<Response>
  let mockNext: NextFunction

  beforeEach(() => {
    mockRequest = {
      headers: {},
      ip: '127.0.0.1'
    }
    mockResponse = {}
    mockNext = vi.fn()
    vi.clearAllMocks()
    mockConsoleLog.mockClear()
    mockConsoleWarn.mockClear()
    
    // Default mock for findUserById to return a user with required role
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
      id: '123',
      email: 'test@example.com',
      passwordHash: 'hash',
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    })
  })

  it('should log NO_TOKEN event when Authorization header is missing', async () => {
    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    // Verify structured log was created
    expect(mockConsoleWarn).toHaveBeenCalledWith(
      expect.stringMatching(/\{"event":"NO_TOKEN"/)
    )
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'NO_TOKEN',
      service: 'optional-auth',
      level: 'warn',
      headerPresent: false,
      hasBearerPrefix: false
    })
  })

  it('should log MALFORMED_HEADER event when Authorization header is empty', async () => {
    mockRequest.headers = { authorization: '' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'MALFORMED_HEADER',
      headerPresent: true,
      hasBearerPrefix: false,
      tokenLength: 0
    })
  })

  it('should log MALFORMED_HEADER event when Authorization header has wrong scheme', async () => {
    mockRequest.headers = { authorization: 'Basic dXNlcjpwYXNz' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'MALFORMED_HEADER',
      headerPresent: true,
      hasBearerPrefix: false
    })
  })

  it('should log EXPIRED_TOKEN event when JWT is expired', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      const error = new Error('Token expired')
      error.message = 'jwt expired'
      throw error
    })

    mockRequest.headers = { authorization: 'Bearer expired-token' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'EXPIRED_TOKEN',
      error: 'jwt expired',
      tokenLength: 13
    })
  })

  it('should log WRONG_ISSUER event when JWT has wrong issuer', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      const error = new Error('Invalid issuer')
      error.message = 'jwt issuer invalid'
      throw error
    })

    mockRequest.headers = { authorization: 'Bearer wrong-issuer-token' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'WRONG_ISSUER',
      error: 'jwt issuer invalid'
    })
  })

  it('should log WRONG_AUDIENCE event when JWT has wrong audience', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      const error = new Error('Invalid audience')
      error.message = 'jwt audience invalid'
      throw error
    })

    mockRequest.headers = { authorization: 'Bearer wrong-audience-token' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'WRONG_AUDIENCE',
      error: 'jwt audience invalid'
    })
  })

  it('should log INVALID_TOKEN event when JWT is cryptographically invalid', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Invalid signature')
    })

    mockRequest.headers = { authorization: 'Bearer invalid-token' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'INVALID_TOKEN',
      error: 'Invalid signature'
    })
  })

  it('should log USER_NOT_FOUND event when token is valid but user not found', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'non-existent-user',
      email: 'none@test.com'
    })
    
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null)

    mockRequest.headers = { authorization: 'Bearer valid-token-but-no-user' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'USER_NOT_FOUND',
      userId: 'non-existent-user'
    })
  })

  it('should log DATABASE_ERROR event when database lookup fails', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com'
    })
    
    vi.spyOn(userRepository, 'findUserById').mockRejectedValue(new Error('Database connection failed'))

    mockRequest.headers = { authorization: 'Bearer valid-token' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'DATABASE_ERROR',
      error: 'Database connection failed',
      userId: 'user-123'
    })
  })

  it('should log AUTH_SUCCESS event when token is valid and user found', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-456',
      email: 'user@test.com'
    })
    
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
      id: 'user-456',
      email: 'user@test.com',
      passwordHash: 'hash',
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    })

    mockRequest.headers = { authorization: 'Bearer valid-token' }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toEqual({
      id: 'user-456',
      userId: 'user-456',
      email: 'user@test.com'
    })
    
    // Verify success log was created with info level
    expect(mockConsoleLog).toHaveBeenCalledWith(
      expect.stringMatching(/\{"event":"AUTH_SUCCESS"/)
    )
    
    const logEntry = JSON.parse(mockConsoleLog.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'AUTH_SUCCESS',
      service: 'optional-auth',
      level: 'info',
      userId: 'user-456'
    })
  })

  it('should include request metadata in all log entries', async () => {
    const testRequest = {
      headers: { 
        authorization: 'Bearer test-token',
        'user-agent': 'TestAgent/1.0',
        'x-request-id': 'req-123'
      },
      ip: '192.168.1.100'
    } as unknown as Request

    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)

    await optionalAuth(testRequest, mockResponse as Response, mockNext)

    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      userAgent: 'TestAgent/1.0',
      ip: '192.168.1.100',
      requestId: 'req-123',
      duration: expect.any(Number)
    })
  })

  it('should generate requestId when not provided in headers', async () => {
    mockRequest.headers = { authorization: 'Bearer test-token' }

    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry.requestId).toMatch(/^req_\d+_[a-z0-9]+$/)
  })

  it('should handle UNEXPECTED_ERROR when header access throws', async () => {
    // Simulate an unexpected error by making headers.authorization throw
    Object.defineProperty(mockRequest, 'headers', {
      get: () => {
        throw new Error('Unexpected error accessing headers')
      },
    })

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockRequest.user).toBeUndefined()
    
    const logEntry = JSON.parse(mockConsoleWarn.mock.calls[0][0])
    expect(logEntry).toMatchObject({
      event: 'UNEXPECTED_ERROR',
      error: 'Unexpected error accessing headers'
    })
  })
})

describe('optionalAuth middleware - Token Verification & Consistency', () => {
  let mockRequest: Partial<Request>
  let mockResponse: Partial<Response>
  let mockNext: NextFunction

  beforeEach(() => {
    mockRequest = {
      headers: {},
    }
    mockResponse = {}
    mockNext = vi.fn()
    vi.clearAllMocks()
    
    // Default mock for findUserById to return a user
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
      id: '123',
      email: 'test@example.com',
      passwordHash: 'hash',
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    })
  })

  it('should call verifyToken with extracted token', async () => {
    const verifySpy = vi.spyOn(jwt, 'verifyToken')
    verifySpy.mockReturnValue({ userId: '123', email: 'test@example.com' })

    mockRequest.headers = {
      authorization: 'Bearer valid-token-123',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(verifySpy).toHaveBeenCalledWith('valid-token-123')
  })

  it('should set req.user with id, userId and email on successful verification', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-456',
      email: 'user@test.com',
    })
    
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
      id: 'user-456',
      email: 'user@test.com',
      passwordHash: 'hash',
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    })

    mockRequest.headers = {
      authorization: 'Bearer valid-token',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toEqual({
      id: 'user-456',
      userId: 'user-456',
      email: 'user@test.com',
    })
    expect(mockNext).toHaveBeenCalledOnce()
  })

  it('should leave req.user undefined when verifyToken returns null', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)

    mockRequest.headers = {
      authorization: 'Bearer invalid-token',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
  })

  it('should leave req.user undefined when no Authorization header', async () => {
    mockRequest.headers = {}

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
  })

  it('should leave req.user undefined when user is not found in database', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'non-existent',
      email: 'none@test.com',
    })
    
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null)

    mockRequest.headers = {
      authorization: 'Bearer valid-token',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
  })
})

describe('optionalAuth middleware - Task 2.2: Error Handling', () => {
  let mockRequest: Partial<Request>
  let mockResponse: Partial<Response>
  let mockNext: NextFunction

  beforeEach(() => {
    mockRequest = {
      headers: {},
    }
    mockResponse = {}
    mockNext = vi.fn()
    vi.clearAllMocks()
  })

  it('should handle verifyToken throwing an exception by calling next() without error', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('JWT verification failed')
    })

    mockRequest.headers = {
      authorization: 'Bearer malformed-token',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // Called without error parameter
  })

  it('should handle findUserById throwing an exception by calling next() without error', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
    })
    
    vi.spyOn(userRepository, 'findUserById').mockRejectedValue(new Error('DB Error'))

    mockRequest.headers = {
      authorization: 'Bearer valid-token',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith()
  })

  it('should handle unexpected errors during processing', async () => {
    // Simulate an unexpected error by making headers.authorization throw
    Object.defineProperty(mockRequest, 'headers', {
      get: () => {
        throw new Error('Unexpected error accessing headers')
      },
    })

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // Called without error parameter
  })
})

describe('optionalAuth middleware - Task 2.3: Ensure next() is always called', () => {
  let mockRequest: Partial<Request>
  let mockResponse: Partial<Response>
  let mockNext: NextFunction

  beforeEach(() => {
    mockRequest = {
      headers: {},
    }
    mockResponse = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
    }
    mockNext = vi.fn()
    vi.clearAllMocks()
    
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
      id: 'user-789',
      email: 'success@example.com',
      passwordHash: 'hash',
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    })
  })

  it('should call next() in success path after setting req.user', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-789',
      email: 'success@example.com',
    })

    mockRequest.headers = {
      authorization: 'Bearer valid-token',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toEqual({
      id: 'user-789',
      userId: 'user-789',
      email: 'success@example.com',
    })
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // No error parameter
  })

  it('should call next() when no token is present', async () => {
    mockRequest.headers = {}

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // No error parameter
  })

  it('should call next() when Authorization header does not start with Bearer', async () => {
    mockRequest.headers = {
      authorization: 'Basic dXNlcjpwYXNz',
    }

    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // No error parameter
  })

  it('should call next() exactly once regardless of authentication status', async () => {
    // Valid token scenario
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
    })
    mockRequest.headers = { authorization: 'Bearer valid-token' }
    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)

    // Invalid token scenario
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)
    mockRequest.headers = { authorization: 'Bearer invalid-token' }
    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)

    // No token scenario
    vi.clearAllMocks()
    mockRequest.headers = {}
    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)

    // Error scenario
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Error')
    })
    mockRequest.headers = { authorization: 'Bearer error-token' }
    await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)
  })
})

describe('optionalAuth middleware - Malformed Bearer Prefix Handling', () => {
  let mockRequest: Partial<Request>
  let mockResponse: Partial<Response>
  let mockNext: NextFunction

  beforeEach(() => {
    mockRequest = {
      headers: {},
    }
    mockResponse = {}
    mockNext = vi.fn()
    vi.clearAllMocks()
    
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue({
      id: '123',
      email: 'test@example.com',
      passwordHash: 'hash',
      createdAt: new Date(),
      updatedAt: new Date()
    })
  })

  describe('Common typos in "Bearer" prefix', () => {
    it('should not authenticate when Authorization header is "Bearr token"', async () => {
      mockRequest.headers = {
        authorization: 'Bearr token-value',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should not authenticate when Authorization header is "Barer token"', async () => {
      mockRequest.headers = {
        authorization: 'Barer token-value',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should not throw 500 error for typo "Bearr token"', async () => {
      mockRequest.headers = {
        authorization: 'Bearr token-value',
      }

      const error = await new Promise<Error | null>((resolve) => {
        optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
          .catch((e) => resolve(e))
          .then(() => resolve(null))
      })

      expect(error).toBeNull()
      expect(mockNext).toHaveBeenCalledWith()
    })
  })

  describe('Bearer prefix with wrong separator', () => {
    it('should not authenticate for "Bearer:[token]" (colon instead of space)', async () => {
      mockRequest.headers = {
        authorization: 'Bearer:token-value',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should not authenticate for "Bearer;token" (semicolon instead of space)', async () => {
      mockRequest.headers = {
        authorization: 'Bearer;token-value',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should not authenticate for "Bearer,token" (comma instead of space)', async () => {
      mockRequest.headers = {
        authorization: 'Bearer,token-value',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })
  })

  describe('Bearer prefix without token', () => {
    it('should not authenticate when Authorization header is "Bearer" only', async () => {
      mockRequest.headers = {
        authorization: 'Bearer',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should not authenticate when Authorization header is "Bearer  " (only spaces after prefix)', async () => {
      mockRequest.headers = {
        authorization: 'Bearer   ',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should not throw 500 error for empty token', async () => {
      mockRequest.headers = {
        authorization: 'Bearer',
      }

      const error = await new Promise<Error | null>((resolve) => {
        optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
          .catch((e) => resolve(e))
          .then(() => resolve(null))
      })

      expect(error).toBeNull()
      expect(mockNext).toHaveBeenCalledWith()
    })
  })

  describe('Bearer prefix with multiple spaces', () => {
    it('should authenticate correctly when Authorization header is "Bearer  token" (extra spaces)', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com',
      })

      mockRequest.headers = {
        authorization: 'Bearer   valid-token-value',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toEqual({
        id: '123',
        userId: '123',
        email: 'test@example.com',
      })
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should extract token correctly when multiple spaces are present', async () => {
      const verifySpy = vi.spyOn(jwt, 'verifyToken')
      verifySpy.mockReturnValue({ userId: '123', email: 'test@example.com' })

      mockRequest.headers = {
        authorization: 'Bearer   token-with-multiple-spaces-before',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(verifySpy).toHaveBeenCalledWith('token-with-multiple-spaces-before')
    })
  })

  describe('Wrong authentication schemes', () => {
    it('should not authenticate when scheme is "Token" instead of "Bearer"', async () => {
      mockRequest.headers = {
        authorization: 'Token token-value',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })

    it('should not authenticate when scheme is "Basic" instead of "Bearer"', async () => {
      mockRequest.headers = {
        authorization: 'Basic dXNlcjpwYXNz',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toBeUndefined()
      expect(mockNext).toHaveBeenCalledOnce()
    })
  })

  describe('Case sensitivity - Bearer prefix', () => {
    it('should authenticate correctly when prefix is lowercase "bearer"', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com',
      })

      mockRequest.headers = {
        authorization: 'bearer valid-token',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toEqual({
        id: '123',
        userId: '123',
        email: 'test@example.com',
      })
    })

    it('should authenticate correctly when prefix is uppercase "BEARER"', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com',
      })

      mockRequest.headers = {
        authorization: 'BEARER valid-token',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toEqual({
        id: '123',
        userId: '123',
        email: 'test@example.com',
      })
    })

    it('should authenticate correctly when prefix is mixed case "BeArEr"', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'user-123',
        email: 'test@example.com',
      })

      mockRequest.headers = {
        authorization: 'BeArEr valid-token',
      }

      await optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

      expect(mockRequest.user).toEqual({
        id: '123',
        userId: '123',
        email: 'test@example.com',
      })
    })
  })
})
