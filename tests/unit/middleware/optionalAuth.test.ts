import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Request, Response, NextFunction } from 'express'
import { optionalAuth } from '../../../src/middleware/optionalAuth.js'
import * as jwt from '../../../src/utils/jwt.js'
import * as userRepository from '../../../src/repositories/userRepository.js'

describe('optionalAuth middleware - Task 2.1: Token Verification & Consistency', () => {
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
