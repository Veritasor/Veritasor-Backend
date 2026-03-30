# Global Error Envelope Standardization

## Overview
This document describes the global error envelope standardization implemented in the Veritasor-Backend to ensure consistent error responses across API, services, and middleware.

## Error Envelope Format

All error responses follow a standardized JSON envelope format:

```json
{
  "status": "error",
  "code": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": {}, // Optional: additional error details (e.g., validation errors)
  "timestamp": "2026-03-24T00:00:00.000Z",
  "requestId": "req_123456789_abc" // Optional: request ID for tracing
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string | Yes | Always "error" for error responses |
| `code` | string | Yes | Machine-readable error code (e.g., VALIDATION_ERROR) |
| `message` | string | Yes | Human-readable error message |
| `details` | any | No | Additional error details (validation errors, etc.) |
| `timestamp` | string | Yes | ISO 8601 timestamp of the error |
| `requestId` | string | No | Request ID for tracing (if available) |

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `AUTHENTICATION_ERROR` | 401 | Authentication required or failed |
| `AUTHORIZATION_ERROR` | 403 | User lacks permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource conflict (e.g., duplicate email) |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded |
| `INTERNAL_SERVER_ERROR` | 500 | Unexpected server error |
| `DATABASE_ERROR` | 500 | Database operation failed |
| `EXTERNAL_SERVICE_ERROR` | 502/503 | External service unavailable |

## Error Classes

The following error classes are available in [`src/types/errors.ts`](src/types/errors.ts):

- `ValidationError` - For request validation failures
- `AppError` - Base application error class
- `AuthenticationError` - For auth-related errors (401)
- `AuthorizationError` - For permission errors (403)
- `NotFoundError` - For missing resources (404)
- `ConflictError` - For resource conflicts (409)
- `RateLimitError` - For rate limit exceeded (429)
- `DatabaseError` - For database errors (500)
- `ExternalServiceError` - For external service failures (502/503)

## Middleware

### errorHandler

The error handler middleware is defined in [`src/middleware/errorHandler.ts`](src/middleware/errorHandler.ts).

#### Features:
- Handles all Express errors
- Converts errors to standardized envelope format
- Logs errors for debugging
- Sanitizes 5xx error messages to prevent info leakage
- Includes request ID when available

#### Usage:
```typescript
import { errorHandler, notFoundHandler } from './middleware/errorHandler';

app.use(notFoundHandler);
app.use(errorHandler);
```

### asyncErrorHandler

Utility wrapper for async route handlers that automatically catches and forwards errors:

```typescript
import { asyncErrorHandler } from './middleware/errorHandler';

router.get('/users', asyncErrorHandler(async (req, res) => {
  const users = await getUsers();
  res.json(users);
}));
```

### notFoundHandler

Handler for unmatched routes that returns a 404 error envelope.

## Security Considerations

1. **Info Leakage Prevention**: Internal error messages (5xx errors) are sanitized to return a generic message "An unexpected error occurred" to prevent exposing internal details.

2. **Request ID Tracking**: Each error response can include a request ID for tracing, which helps with debugging without exposing internal system details to clients.

3. **Timestamp**: All error responses include a timestamp for audit purposes.

## Behavior Changes

### Before
Error responses were inconsistent, with some endpoints returning `{ error: "message" }` and others returning different formats.

### After
All error responses follow the standardized envelope format, ensuring:
- Consistent API interface for clients
- Easier error handling in frontend applications
- Better logging and monitoring capabilities
- Improved security through message sanitization

## Testing

Integration tests are available in [`tests/integration/auth.test.ts`](tests/integration/auth.test.ts) covering:
- Validation errors (400)
- Authentication errors (401)
- Not found errors (404)
- Conflict errors (409)
- Internal server errors (500)
- Error envelope format validation
- Security considerations

## Migration Guide

To update existing code to use the new error handling:

1. Import the appropriate error class:
```typescript
import { ValidationError, NotFoundError, AuthenticationError } from './types/errors';
```

2. Throw errors in your route handlers:
```typescript
// Before
if (!user) {
  return res.status(404).json({ error: 'User not found' });
}

// After
if (!user) {
  throw new NotFoundError('User not found');
}
```

3. Ensure error handler middleware is mounted:
```typescript
app.use(errorHandler);
```
