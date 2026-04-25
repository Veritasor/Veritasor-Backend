# Business Authorization Boundary Checks

## Overview

This document describes the implementation of Business Authorization Boundary Checks in the Veritasor-Backend. This security feature ensures that users can only access and operate on businesses they own, providing a robust authorization boundary that prevents cross-business data access.

## Architecture

### Core Components

1. **`requireBusinessAuth` Middleware** (`src/middleware/requireBusinessAuth.ts`)
   - Primary authorization middleware for business-scoped operations
   - Validates JWT tokens and business ownership
   - Enforces strict authorization boundaries

2. **Enhanced Test Suite** (`tests/integration/attestations.test.ts`)
   - Comprehensive test coverage for all authorization scenarios
   - Security edge case testing
   - Performance and load testing

## Security Features

### Authentication Validation
- **JWT Token Verification**: Validates token format, signature, and expiration
- **User Existence Check**: Ensures authenticated user still exists in database
- **Token Revocation Support**: Automatically denies access for deleted users

### Authorization Boundaries
- **Business Ownership Verification**: Ensures users can only access their own businesses
- **Strict Access Control**: Prevents cross-business data leakage
- **Database-Level Validation**: Validates business ownership at repository level

### Input Validation
- **Business ID Format Validation**: Regex-based validation for business ID format
- **Injection Prevention**: Protection against SQL injection and malformed inputs
- **Length Limits**: Enforces reasonable length constraints on business IDs

## Implementation Details

### Middleware Flow

1. **Token Validation**
   ```typescript
   // Extract and validate Bearer token
   const authHeader = req.headers.authorization;
   if (!authHeader || !authHeader.startsWith("Bearer ")) {
     return res.status(401).json({ code: "MISSING_AUTH" });
   }
   ```

2. **User Verification**
   ```typescript
   // Verify token and check user existence
   const user = await validateUserToken(token);
   if (!user) {
     return res.status(401).json({ code: "INVALID_TOKEN" });
   }
   ```

3. **Business ID Extraction**
   ```typescript
   // Priority-based business ID extraction
   const businessId = extractBusinessId(req);
   // 1. x-business-id header
   // 2. business_id from request body
   // 3. businessId from request body
   ```

4. **Authorization Check**
   ```typescript
   // Verify business ownership
   const business = await validateBusinessAccess(businessId, user.id);
   if (!business) {
     return res.status(403).json({ code: "BUSINESS_NOT_FOUND" });
   }
   ```

### Error Handling

The middleware provides detailed error responses with structured error codes:

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `MISSING_AUTH` | 401 | Missing or invalid Authorization header |
| `INVALID_TOKEN` | 401 | Invalid, expired, or malformed JWT token |
| `MISSING_BUSINESS_ID` | 400 | Business ID not provided or invalid format |
| `BUSINESS_NOT_FOUND` | 403 | Business not found or access denied |
| `USER_NOT_FOUND` | 401 | Authenticated user no longer exists |

## Usage

### Applying the Middleware

```typescript
import { requireBusinessAuth } from '../middleware/requireBusinessAuth.js';

// Apply to routes that require business context
router.get('/attestations', requireBusinessAuth, getAttestations);
router.post('/attestations', requireBusinessAuth, createAttestation);
router.patch('/business/:id', requireBusinessAuth, updateBusiness);
```

### Request Headers

```http
Authorization: Bearer <jwt_token>
x-business-id: <business_id>
```

### Request Body (Alternative)

```json
{
  "business_id": "business-123",
  "businessId": "business-123",  // Alternative field name
  "other_data": "value"
}
```

### Accessing Authenticated Context

```typescript
export async function handler(req: Request, res: Response) {
  // Access authenticated user
  const user = req.user; // { id, userId, email }
  
  // Access authorized business
  const business = req.business; // { id, userId, name, ... }
  
  // Both are guaranteed to exist when requireBusinessAuth passes
}
```

## Security Considerations

### Threat Model

1. **Cross-Business Data Access**: Prevented by strict ownership verification
2. **Token Manipulation**: Mitigated by cryptographic JWT validation
3. **Business ID Injection**: Prevented by input validation and regex filtering
4. **Privilege Escalation**: Blocked by database-level ownership checks

### Best Practices

1. **Always Use requireBusinessAuth**: Apply to all business-scoped endpoints
2. **Validate Business Context**: Check `req.business` exists before processing
3. **Audit Logging**: Enable logging for security monitoring
4. **Token Rotation**: Implement token refresh mechanisms
5. **Database Constraints**: Ensure foreign key constraints at database level

### Performance Considerations

- **Database Queries**: 2 queries per request (user verification + business lookup)
- **Caching Strategy**: Consider caching user and business data for high-traffic endpoints
- **Connection Pooling**: Ensure proper database connection management
- **Async Operations**: All validation is non-blocking

## Testing

### Test Coverage

The implementation includes comprehensive test coverage:

1. **Authentication Tests**
   - Missing Authorization header
   - Invalid token format
   - Expired/invalid tokens

2. **Authorization Tests**
   - Business ownership verification
   - Cross-business access attempts
   - Non-existent business access

3. **Input Validation Tests**
   - Invalid business ID formats
   - SQL injection attempts
   - Edge cases (empty, null, extremely long IDs)

4. **Security Tests**
   - Concurrent request handling
   - Race condition prevention
   - Error message consistency

### Running Tests

```bash
# Run all integration tests
npm test

# Run specific test suite
npm test -- tests/integration/attestations.test.ts

# Run with coverage
npm test -- --coverage
```

## Migration Guide

### From Basic Auth to Business Auth

1. **Replace Middleware**
   ```typescript
   // Before
   import { requireAuth } from '../middleware/auth.js';
   router.get('/endpoint', requireAuth, handler);
   
   // After
   import { requireBusinessAuth } from '../middleware/requireBusinessAuth.js';
   router.get('/endpoint', requireBusinessAuth, handler);
   ```

2. **Update Request Headers**
   ```http
   // Add business context header
   x-business-id: business-123
   ```

3. **Update Handler Logic**
   ```typescript
   // Before
   const userId = req.user.id;
   const business = await getBusinessByUserId(userId);
   
   // After
   const business = req.business; // Already validated and available
   ```

### Backward Compatibility

The legacy `requireBusinessAuthLegacy` middleware is provided for backward compatibility but should be deprecated in favor of the new implementation.

## Monitoring and Alerting

### Security Events to Monitor

1. **Failed Authentication Attempts**
   - Invalid tokens
   - Missing headers
   - Malformed requests

2. **Authorization Failures**
   - Cross-business access attempts
   - Non-existent business access
   - User not found errors

3. **Performance Metrics**
   - Middleware execution time
   - Database query performance
   - Error rates by type

### Logging Configuration

```typescript
// Enable security logging
if (process.env.NODE_ENV !== 'test') {
  console.log(`Business auth success: user=${user.id}, business=${business.id}`);
}
```

## Compliance and Standards

This implementation aligns with:

- **OWASP Authentication Guidelines**: Proper token validation and session management
- **ISO 27001**: Access control and information security policies
- **GDPR**: Data access controls and audit trails
- **SOC 2**: Security and availability controls

## Future Enhancements

1. **Role-Based Access Control (RBAC)**: Extend to support multiple user roles
2. **Multi-Tenant Support**: Add organization-level isolation
3. **API Rate Limiting**: Implement per-business rate limiting
4. **Audit Trail**: Detailed logging of all business operations
5. **Cache Layer**: Redis-based caching for improved performance

## Support and Troubleshooting

### Common Issues

1. **401 Unauthorized**: Check JWT token validity and format
2. **403 Forbidden**: Verify business ownership and existence
3. **400 Bad Request**: Validate business ID format and presence
4. **Performance Issues**: Monitor database query performance

### Debug Mode

Enable debug logging by setting:
```bash
DEBUG=business-auth:*
```

### Contact

For security issues or questions about this implementation, contact the security team at security@veritasor.com.
