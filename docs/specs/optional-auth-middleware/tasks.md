# Implementation Plan: Optional Authentication Middleware

## Overview

This implementation plan breaks down the optional authentication middleware into discrete coding tasks. The middleware will extract and verify JWT tokens from requests, attach user information when valid, but always allow requests to proceed regardless of authentication status. The implementation reuses existing JWT verification infrastructure and includes comprehensive testing with both unit tests and property-based tests using fast-check.

## Tasks

- [x] 1. Create middleware file and implement core token extraction logic
  - Create `src/middleware/optionalAuth.ts` file
  - Import required dependencies (Express types, verifyToken from jwt utils)
  - Implement the `optionalAuth` function signature with Request, Response, NextFunction parameters
  - Implement Authorization header extraction logic
  - Implement Bearer token parsing (check for "Bearer " prefix and extract token)
  - Handle missing or malformed Authorization headers by calling next() immediately
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 2. Implement JWT verification and user attachment
  - [x] 2.1 Add token verification using verifyToken
    - Call verifyToken with extracted token
    - Handle successful verification by setting req.user with userId and email
    - Handle verification failure by leaving req.user undefined
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.2_
  
  - [x] 2.2 Implement error handling with try-catch
    - Wrap all logic in try-catch block
    - Catch any exceptions and call next() without error parameter
    - Ensure req.user remains undefined on any error
    - _Requirements: 5.1, 5.2, 5.3_
  
  - [x] 2.3 Ensure next() is always called
    - Verify next() is called in success path after setting req.user
    - Verify next() is called when no token present
    - Verify next() is called in catch block
    - Ensure no HTTP responses are sent (no res.status or res.json calls)
    - _Requirements: 3.3, 4.1, 4.2, 4.3_

- [ ]* 3. Write unit tests for optionalAuth middleware
  - Create `tests/unit/middleware/optionalAuth.spec.ts`
  - Test request with no Authorization header (req.user should be undefined)
  - Test request with non-Bearer authentication scheme (req.user should be undefined)
  - Test request with empty Bearer token (req.user should be undefined)
  - Test request with valid token (req.user should be set with correct userId and email)
  - Test request with expired token (req.user should be undefined)
  - Test request with invalid signature (req.user should be undefined)
  - Test request with malformed JWT structure (req.user should be undefined)
  - Verify next() is called exactly once in all scenarios
  - Verify no HTTP responses are sent in any scenario
  - Mock verifyToken to control test outcomes
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 5.1, 5.2, 5.3_

- [ ]* 4. Write property-based tests for correctness properties
  - [ ]* 4.1 Property test for valid token authentication
    - **Property 1: Valid Token Authentication**
    - **Validates: Requirements 1.1, 2.2, 3.1**
    - Create `tests/integration/middleware/optionalAuth.property.spec.ts`
    - Use fast-check to generate random valid token payloads (userId, email)
    - Generate valid JWT tokens for each payload
    - Verify req.user is set correctly for all valid tokens
    - Run minimum 100 iterations
  
  - [ ]* 4.2 Property test for invalid token non-blocking
    - **Property 2: Invalid Token Non-Blocking**
    - **Validates: Requirements 2.3, 3.2**
    - Use fast-check to generate invalid/malformed tokens
    - Verify req.user remains undefined for all invalid tokens
    - Verify next() is called without error parameter
    - Run minimum 100 iterations
  
  - [ ]* 4.3 Property test for always proceeds to next handler
    - **Property 3: Always Proceeds to Next Handler**
    - **Validates: Requirements 3.3, 4.3, 5.3**
    - Use fast-check to generate various request scenarios (valid, invalid, missing tokens)
    - Verify next() is called exactly once for all scenarios
    - Verify next() is never called with error parameter
    - Run minimum 100 iterations
  
  - [ ]* 4.4 Property test for no 401 responses
    - **Property 4: No 401 Responses**
    - **Validates: Requirements 4.1, 4.2**
    - Use fast-check to generate requests with missing or invalid credentials
    - Verify res.status is never called
    - Verify res.json is never called
    - Verify no HTTP response is sent
    - Run minimum 100 iterations
  
  - [ ]* 4.5 Property test for error resilience
    - **Property 5: Error Resilience**
    - **Validates: Requirements 5.1, 5.2**
    - Use fast-check to generate scenarios that cause verifyToken to throw exceptions
    - Verify req.user remains undefined when errors occur
    - Verify next() is called without error parameter
    - Run minimum 100 iterations

- [x] 5. Checkpoint - Ensure all tests pass
  - Run all unit tests and property-based tests
  - Verify 100% code coverage for the middleware function
  - Ensure all tests pass, ask the user if questions arise

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The middleware reuses `verifyToken` from `src/utils/jwt.ts` for consistency
- All authentication failures result in the same behavior: req.user undefined, next() called
- Property-based tests use fast-check with minimum 100 iterations per property
- Unit tests and property tests are complementary: unit tests verify specific examples, property tests verify universal correctness
