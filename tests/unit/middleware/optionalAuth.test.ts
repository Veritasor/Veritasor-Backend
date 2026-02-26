import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Request, Response, NextFunction } from 'express'
import { optionalAuth } from '../../../src/middleware/optionalAuth.js'
import * as jwt from '../../../src/utils/jwt.js'

describe('optionalAuth middleware - Task 2.1: Token Verification', () => {
  let mockRequest: Partial<Request> & { user?: { userId: string; email: string } }
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

  it('should call verifyToken with extracted token', () => {
    const verifySpy = vi.spyOn(jwt, 'verifyToken')
    verifySpy.mockReturnValue({ userId: '123', email: 'test@example.com' })

    mockRequest.headers = {
      authorization: 'Bearer valid-token-123',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(verifySpy).toHaveBeenCalledWith('valid-token-123')
  })

  it('should set req.user with userId and email on successful verification', () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-456',
      email: 'user@test.com',
    })

    mockRequest.headers = {
      authorization: 'Bearer valid-token',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toEqual({
      userId: 'user-456',
      email: 'user@test.com',
    })
    expect(mockNext).toHaveBeenCalledOnce()
  })

  it('should leave req.user undefined when verifyToken returns null', () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)

    mockRequest.headers = {
      authorization: 'Bearer invalid-token',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
  })

  it('should leave req.user undefined when no Authorization header', () => {
    mockRequest.headers = {}

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
  })
})

describe('optionalAuth middleware - Task 2.2: Error Handling', () => {
  let mockRequest: Partial<Request> & { user?: { userId: string; email: string } }
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

  it('should handle verifyToken throwing an exception by calling next() without error', () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('JWT verification failed')
    })

    mockRequest.headers = {
      authorization: 'Bearer malformed-token',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // Called without error parameter
  })

  it('should handle unexpected errors during processing', () => {
    // Simulate an unexpected error by making headers.authorization throw
    Object.defineProperty(mockRequest, 'headers', {
      get: () => {
        throw new Error('Unexpected error accessing headers')
      },
    })

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // Called without error parameter
  })

  it('should not propagate authentication errors to next handler', () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Token expired')
    })

    mockRequest.headers = {
      authorization: 'Bearer expired-token',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    // Verify next() was called without any arguments (no error propagation)
    expect(mockNext).toHaveBeenCalledOnce()
    const callArgs = (mockNext as any).mock.calls[0]
    expect(callArgs.length).toBe(0)
  })
})

describe('optionalAuth middleware - Task 2.3: Ensure next() is always called', () => {
  let mockRequest: Partial<Request> & { user?: { userId: string; email: string } }
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
  })

  it('should call next() in success path after setting req.user', () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-789',
      email: 'success@example.com',
    })

    mockRequest.headers = {
      authorization: 'Bearer valid-token',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toEqual({
      userId: 'user-789',
      email: 'success@example.com',
    })
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // No error parameter
  })

  it('should call next() when no token is present', () => {
    mockRequest.headers = {}

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // No error parameter
  })

  it('should call next() when Authorization header does not start with Bearer', () => {
    mockRequest.headers = {
      authorization: 'Basic dXNlcjpwYXNz',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // No error parameter
  })

  it('should call next() in catch block when error occurs', () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Verification error')
    })

    mockRequest.headers = {
      authorization: 'Bearer error-token',
    }

    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)

    expect(mockRequest.user).toBeUndefined()
    expect(mockNext).toHaveBeenCalledOnce()
    expect(mockNext).toHaveBeenCalledWith() // No error parameter
  })

  it('should never send HTTP responses - no res.status calls', () => {
    const statusSpy = mockResponse.status as any

    // Test with no token
    mockRequest.headers = {}
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(statusSpy).not.toHaveBeenCalled()

    // Test with valid token
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
    })
    mockRequest.headers = { authorization: 'Bearer valid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(statusSpy).not.toHaveBeenCalled()

    // Test with invalid token
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)
    mockRequest.headers = { authorization: 'Bearer invalid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(statusSpy).not.toHaveBeenCalled()

    // Test with error
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Error')
    })
    mockRequest.headers = { authorization: 'Bearer error-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(statusSpy).not.toHaveBeenCalled()
  })

  it('should never send HTTP responses - no res.json calls', () => {
    const jsonSpy = mockResponse.json as any

    // Test with no token
    mockRequest.headers = {}
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(jsonSpy).not.toHaveBeenCalled()

    // Test with valid token
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
    })
    mockRequest.headers = { authorization: 'Bearer valid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(jsonSpy).not.toHaveBeenCalled()

    // Test with invalid token
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)
    mockRequest.headers = { authorization: 'Bearer invalid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(jsonSpy).not.toHaveBeenCalled()

    // Test with error
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Error')
    })
    mockRequest.headers = { authorization: 'Bearer error-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(jsonSpy).not.toHaveBeenCalled()
  })

  it('should never send HTTP responses - no res.send calls', () => {
    const sendSpy = mockResponse.send as any

    // Test with no token
    mockRequest.headers = {}
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(sendSpy).not.toHaveBeenCalled()

    // Test with valid token
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
    })
    mockRequest.headers = { authorization: 'Bearer valid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(sendSpy).not.toHaveBeenCalled()

    // Test with invalid token
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)
    mockRequest.headers = { authorization: 'Bearer invalid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(sendSpy).not.toHaveBeenCalled()

    // Test with error
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Error')
    })
    mockRequest.headers = { authorization: 'Bearer error-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(sendSpy).not.toHaveBeenCalled()
  })

  it('should call next() exactly once regardless of authentication status', () => {
    // Valid token scenario
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({
      userId: 'user-123',
      email: 'test@example.com',
    })
    mockRequest.headers = { authorization: 'Bearer valid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)

    // Invalid token scenario
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null)
    mockRequest.headers = { authorization: 'Bearer invalid-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)

    // No token scenario
    vi.clearAllMocks()
    mockRequest.headers = {}
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)

    // Error scenario
    vi.clearAllMocks()
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
      throw new Error('Error')
    })
    mockRequest.headers = { authorization: 'Bearer error-token' }
    optionalAuth(mockRequest as Request, mockResponse as Response, mockNext)
    expect(mockNext).toHaveBeenCalledTimes(1)
  })
})
