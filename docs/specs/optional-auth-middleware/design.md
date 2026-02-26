# Design Document: Optional Authentication Middleware

## Overview

The Optional Authentication Middleware provides a non-blocking authentication layer for Express.js routes that need to differentiate between authenticated and anonymous users without rejecting unauthenticated requests. This middleware attempts to extract and verify JWT tokens from incoming requests, attaching user information when valid credentials are present, but always allowing the request to proceed to the next handler regardless of authentication status.

The middleware reuses the existing JWT verification infrastructure (`verifyToken` from `src/utils/jwt.ts`) to maintain consistency with the strict `requireAuth` middleware, but differs fundamentally in its error handling philosophy: where `requireAuth` returns 401 responses for authentication failures, `optionalAuth` silently continues processing.

This design enables use cases such as:
- Public content endpoints that show additional information to authenticated users
- Rate limiting that applies different thresholds based on authentication status
- Analytics that track both authenticated and anonymous user behavior
- Feature flags that enable premium features for authenticated users

## Architecture

### Component Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Express Request Pipeline                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              optionalAuth Middleware                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 1. Extract Authorization header                       │  │
│  │ 2. Parse Bearer token (if present)                    │  │
│  │ 3. Verify token using verifyToken()                   │  │
│  │ 4. Attach user to req.user (if valid)                 │  │
│  │ 5. Call next() regardless of outcome                  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Route Handler (downstream)                      │
│  - Checks req.user to determine authentication status       │
│  - Provides appropriate response based on user presence     │
└─────────────────────────────────────────────────────────────┘
```

### Design Decisions

1. **Reuse JWT Verification Logic**: The middleware uses `verifyToken` from `src/utils/jwt.ts` rather than implementing custom verification. This ensures consistency with `requireAuth` and centralizes JWT configuration (secret, algorithm, expiration).

2. **No User Repository Lookup**: Unlike `requireAuth`, this middleware does NOT verify that the user still exists in the database. This trade-off prioritizes performance for optional authentication scenarios where the downstream handler can perform additional validation if needed.

3. **Silent Failure Model**: All authentication failures (missing token, invalid token, expired token, malformed header) result in the same behavior: `req.user` remains undefined and processing continues. This prevents information leakage about why authentication failed.

4. **Type Safety**: The middleware leverages the existing Express Request type extension that adds the optional `user` property, maintaining type consistency across the application.

## Components and Interfaces

### Middleware Function Signature

```typescript
export function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void
```

**Parameters:**
- `req`: Express Request object, potentially containing Authorization header
- `res`: Express Response object (not used for sending responses)
- `next`: Callback to invoke the next middleware in the chain

**Side Effects:**
- May set `req.user` to `{ userId: string, email: string }` if authentication succeeds
- Always invokes `next()` without error parameter

### Dependencies

**External Dependencies:**
- `express`: Provides Request, Response, NextFunction types
- `src/utils/jwt.ts`: Provides `verifyToken` function and `TokenPayload` interface

**Type Extensions:**
The middleware relies on the existing global Express namespace extension:

```typescript
declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string
        email: string
      }
    }
  }
}
```

This type extension is already defined in `src/middleware/requireAuth.ts` and will be available globally.

### Token Extraction Logic

The middleware extracts tokens using the following algorithm:

1. Read `req.headers.authorization`
2. Check if header exists and starts with `"Bearer "`
3. If yes, extract token by removing the `"Bearer "` prefix (7 characters)
4. If no, proceed to next handler with `req.user` undefined

### Verification Flow

```
┌─────────────────────────┐
│ Authorization header?   │
└───────┬─────────────────┘
        │
    ┌───▼───┐
    │ Yes   │ No ──────────────┐
    └───┬───┘                  │
        │                      │
┌───────▼──────────────────┐   │
│ Starts with "Bearer "?   │   │
└───────┬──────────────────┘   │
        │                      │
    ┌───▼───┐                  │
    │ Yes   │ No ──────────────┤
    └───┬───┘                  │
        │                      │
┌───────▼──────────────────┐   │
│ Extract token            │   │
└───────┬──────────────────┘   │
        │                      │
┌───────▼──────────────────┐   │
│ verifyToken(token)       │   │
└───────┬──────────────────┘   │
        │                      │
    ┌───▼───┐                  │
    │ Valid │ Invalid ─────────┤
    └───┬───┘                  │
        │                      │
┌───────▼──────────────────┐   │
│ Set req.user = payload   │   │
└───────┬──────────────────┘   │
        │                      │
        └──────────┬───────────┘
                   │
            ┌──────▼──────┐
            │  next()     │
            └─────────────┘
```

## Data Models

### TokenPayload Interface

The middleware uses the existing `TokenPayload` interface from `src/utils/jwt.ts`:

```typescript
interface TokenPayload {
  userId: string
  email: string
}
```

This payload is decoded from valid JWTs and attached to `req.user`.

### Request User Property

When authentication succeeds, the middleware sets:

```typescript
req.user = {
  userId: string,  // Unique identifier for the authenticated user
  email: string    // Email address from the JWT payload
}
```

When authentication fails or is not attempted, `req.user` remains `undefined`.


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Valid Token Authentication

*For any* request with a valid Authorization header containing a Bearer token that can be successfully verified, the middleware SHALL set `req.user` to an object containing `userId` and `email` properties matching the token payload.

**Validates: Requirements 1.1, 2.2, 3.1**

### Property 2: Invalid Token Non-Blocking

*For any* request with an invalid, expired, or malformed JWT token, the middleware SHALL leave `req.user` as undefined and invoke `next()` without error.

**Validates: Requirements 2.3, 3.2**

### Property 3: Always Proceeds to Next Handler

*For any* request regardless of authentication status (valid token, invalid token, missing token, or error condition), the middleware SHALL invoke `next()` exactly once without an error parameter.

**Validates: Requirements 3.3, 4.3, 5.3**

### Property 4: No 401 Responses

*For any* request with missing or invalid authentication credentials, the middleware SHALL NOT send an HTTP 401 response or any other HTTP response.

**Validates: Requirements 4.1, 4.2**

### Property 5: Error Resilience

*For any* error that occurs during token extraction, verification, or processing (including exceptions thrown by `verifyToken`), the middleware SHALL handle the error gracefully by leaving `req.user` undefined and invoking `next()` without error.

**Validates: Requirements 5.1, 5.2**

## Error Handling

The middleware implements a "fail open" error handling strategy where all errors result in the same behavior as missing authentication: the request proceeds with `req.user` undefined.

### Error Categories

1. **Missing Authorization Header**
   - Behavior: Immediately call `next()` with `req.user` undefined
   - No error logging required (this is expected behavior)

2. **Malformed Authorization Header**
   - Examples: Missing "Bearer " prefix, empty token, wrong scheme
   - Behavior: Call `next()` with `req.user` undefined
   - No error logging required (this is expected behavior)

3. **Invalid JWT Token**
   - Examples: Expired token, wrong signature, malformed JWT structure
   - Behavior: `verifyToken` returns `null`, middleware calls `next()` with `req.user` undefined
   - No error logging required (this is expected behavior)

4. **Unexpected Exceptions**
   - Examples: Null pointer errors, type errors, unexpected runtime exceptions
   - Behavior: Catch all exceptions, call `next()` with `req.user` undefined
   - Should log error for debugging purposes but not expose to client

### Error Handling Implementation

```typescript
try {
  // Token extraction and verification logic
  const authHeader = req.headers.authorization
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    next()
    return
  }
  
  const token = authHeader.slice(7)
  const payload = verifyToken(token)
  
  if (payload) {
    req.user = {
      userId: payload.userId,
      email: payload.email,
    }
  }
  
  next()
} catch (error) {
  // Log unexpected errors for debugging
  // but don't expose to client or block request
  next()
}
```

### Comparison with requireAuth

| Aspect | requireAuth | optionalAuth |
|--------|-------------|--------------|
| Missing token | Returns 401 | Calls next() |
| Invalid token | Returns 401 | Calls next() |
| Valid token | Sets req.user, calls next() | Sets req.user, calls next() |
| User DB lookup | Yes | No |
| Error handling | Returns 401 | Calls next() |

## Testing Strategy

### Dual Testing Approach

The middleware will be validated using both unit tests and property-based tests to ensure comprehensive coverage:

- **Unit tests**: Verify specific examples, edge cases, and error conditions
- **Property tests**: Verify universal properties across all inputs

Together, these approaches provide comprehensive coverage where unit tests catch concrete bugs and property tests verify general correctness.

### Property-Based Testing

We will use **fast-check** (a property-based testing library for TypeScript/JavaScript) to implement the correctness properties defined above. Each property test will:

- Run a minimum of 100 iterations with randomly generated inputs
- Reference the corresponding design document property in a comment tag
- Use the format: `// Feature: optional-auth-middleware, Property {number}: {property_text}`

**Example Property Test Structure:**

```typescript
import fc from 'fast-check'
import { describe, it, expect } from 'vitest'

describe('optionalAuth Property Tests', () => {
  it('Property 1: Valid Token Authentication', () => {
    // Feature: optional-auth-middleware, Property 1: Valid token authentication
    fc.assert(
      fc.property(
        fc.record({
          userId: fc.uuid(),
          email: fc.emailAddress(),
        }),
        (payload) => {
          // Generate valid token, create mock request, invoke middleware
          // Assert req.user matches payload
        }
      ),
      { numRuns: 100 }
    )
  })
})
```

### Unit Testing

Unit tests will focus on:

1. **Specific Examples**
   - Request with no Authorization header
   - Request with "Basic" authentication scheme (not Bearer)
   - Request with empty Bearer token
   - Request with valid token containing specific user data

2. **Edge Cases**
   - Authorization header with extra whitespace
   - Case sensitivity of "Bearer" prefix
   - Token with special characters
   - Very long tokens

3. **Error Conditions**
   - Expired tokens
   - Tokens with invalid signatures
   - Malformed JWT structure
   - Null or undefined headers

4. **Integration Points**
   - Verify `verifyToken` is called with correct arguments
   - Verify `next()` is called in all scenarios
   - Verify response methods (status, json) are never called

### Test File Organization

```
tests/
├── unit/
│   └── middleware/
│       └── optionalAuth.spec.ts          # Unit tests
└── integration/
    └── middleware/
        └── optionalAuth.property.spec.ts  # Property-based tests
```

### Coverage Goals

- 100% line coverage for the middleware function
- All 5 correctness properties implemented as property tests
- Minimum 10 unit tests covering examples and edge cases
- All error paths explicitly tested

