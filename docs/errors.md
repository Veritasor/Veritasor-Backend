# Veritasor Error Taxonomy System (VRT-XXXX)

## Overview

This document describes the standardized error taxonomy system used by the Veritasor backend. All API errors return a machine-readable `vrtCode` in the format `VRT-XXXX`, allowing clients to programmatically handle errors without relying on string matching.

## Error Response Format

All error responses follow this envelope format:

```json
{
  "status": "error",
  "vrtCode": "VRT-XXXX",
  "message": "Human-readable error message",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "requestId": "abc123",
  "details": [
    {
      "path": ["fieldName"],
      "message": "Validation error message",
      "code": "invalid_type"
    }
  ]
}
```

## Error Taxonomy Codes

| Code       | HTTP Status | Description                          |
|------------|-------------|--------------------------------------|
| VRT-0001   | 401         | Unauthorized / Authentication Error  |
| VRT-0002   | 400         | Validation Error                     |
| VRT-0003   | 403         | Authorization Error (Access Denied)  |
| VRT-0004   | 404         | Not Found                            |
| VRT-0005   | 409         | Conflict (Resource already exists)   |
| VRT-0006   | 429         | Rate Limit Exceeded                  |
| VRT-0007   | 500         | Database Error                       |
| VRT-0008   | 502/503     | External Service Error               |
| VRT-9999   | 500         | Internal Server Error (Fallback)     |

### VRT-0001: Unauthorized
Authentication is required or the provided credentials are invalid. This includes invalid JWT tokens, expired tokens, and missing authentication.

### VRT-0002: Validation Error
The request contains invalid parameters or data. The `details` field will include specific validation issues.

### VRT-0003: Authorization Error
The user is authenticated but does not have permission to access the requested resource.

### VRT-0004: Not Found
The requested resource does not exist.

### VRT-0005: Conflict
The request could not be completed due to a conflict with the current state of the resource (e.g., duplicate email).

### VRT-0006: Rate Limit Exceeded
Too many requests have been made in a short period.

### VRT-0007: Database Error
An error occurred while interacting with the database.

### VRT-0008: External Service Error
An error occurred while calling an external service (Stripe, Shopify, Razorpay, etc.).

### VRT-9999: Internal Server Error (Fallback)
Any unmapped, unhandled, or generic error. Always returns a generic message to avoid exposing internal details.

## OpenAPI Specification

Here's how to define the error responses in your OpenAPI spec:

```yaml
components:
  schemas:
    ErrorResponse:
      type: object
      required:
        - status
        - vrtCode
        - message
        - timestamp
      properties:
        status:
          type: string
          enum:
            - error
        vrtCode:
          type: string
          description: Machine-readable VRT-XXXX taxonomy code
          enum:
            - VRT-0001
            - VRT-0002
            - VRT-0003
            - VRT-0004
            - VRT-0005
            - VRT-0006
            - VRT-0007
            - VRT-0008
            - VRT-9999
        message:
          type: string
          description: Human-readable error message
        timestamp:
          type: string
          format: date-time
          description: ISO 8601 timestamp
        requestId:
          type: string
          description: Unique request identifier for tracing
        details:
          type: array
          items:
            type: object
            properties:
              path:
                type: array
                items:
                  type: string
              message:
                type: string
              code:
                type: string
```

## Usage Examples

### Throwing a Custom Error

```typescript
import { UnauthorizedError, NotFoundError } from '../types/errors.js';

// Throwing an unauthorized error
throw new UnauthorizedError('Invalid credentials');

// Throwing a not found error with context
throw new NotFoundError('User not found', { userId: '123' });
```

### Handling Errors in Clients

```javascript
// Example client-side error handling
async function fetchData() {
  try {
    const response = await fetch('/api/resource');
    if (!response.ok) {
      const error = await response.json();
      switch (error.vrtCode) {
        case 'VRT-0001':
          handleLoginRedirect();
          break;
        case 'VRT-0002':
          handleValidationErrors(error.details);
          break;
        case 'VRT-0004':
          handleResourceNotFound();
          break;
        case 'VRT-9999':
        default:
          handleGenericError();
      }
      return;
    }
    // Process successful response
  } catch (error) {
    // Handle network errors
  }
}
```

## Security Considerations

1. **Never expose stack traces** in production responses
2. **Use generic messages** for 5xx errors to avoid leaking internal implementation details
3. **Log all errors server-side** with full context for debugging
4. **Sanitize error codes** to prevent injection attacks

## Extending the Taxonomy

When adding new error codes:

1. Add the code to `src/types/errors.ts`
2. Create a corresponding error class extending `AppError`
3. Update this document with the new code and description
4. Ensure tests cover the new error type
