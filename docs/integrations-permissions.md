# Integrations Granular Permission Mapping

## Overview

This document describes the granular permission mapping system implemented for the Veritasor Backend integrations API. The system provides fine-grained access control for integration operations based on user roles, permissions, and ownership context.

## Architecture

### Permission Types

The permission system defines granular permissions for different integration operations:

```typescript
export enum IntegrationPermission {
  // Read permissions
  READ_AVAILABLE = 'integrations:read:available',      // View available integrations
  READ_CONNECTED = 'integrations:read:connected',      // View connected integrations
  READ_OWN = 'integrations:read:own',                  // View own integration details
  
  // Write permissions
  CONNECT = 'integrations:connect',                      // Connect new integrations
  DISCONNECT_OWN = 'integrations:disconnect:own',       // Disconnect own integrations
  DISCONNECT_ANY = 'integrations:disconnect:any',       // Disconnect any integrations
  
  // Management permissions
  MANAGE_OWN = 'integrations:manage:own',              // Manage own integrations
  MANAGE_ANY = 'integrations:manage:any',              // Manage any integrations
  
  // Admin permissions
  ADMIN = 'integrations:admin',                         // Full admin access
}
```

### Role-Based Access Control

Three user roles are defined with different permission levels:

#### User Role
- Can view available and connected integrations
- Can connect new integrations
- Can disconnect their own integrations
- Cannot manage integrations belonging to others

#### Business Admin Role
- All user permissions
- Can disconnect any integration within their business
- Can manage any integration within their business
- Cannot perform system admin operations

#### Admin Role
- Full system access
- All permissions including admin operations
- Can manage any integration in the system

### Permission Mapping

| Route | Method | Required Permission | Description |
|-------|--------|-------------------|-------------|
| `/api/integrations` | GET | `READ_AVAILABLE` | List available integrations (public) |
| `/api/integrations/connected` | GET | `READ_CONNECTED` | List connected integrations |
| `/api/integrations/connect` | POST | `CONNECT` | Initiate integration connection |
| `/api/integrations/:id` | GET | `READ_OWN` | Get specific integration details |
| `/api/integrations/:id` | DELETE | `DISCONNECT_OWN` | Disconnect integration |

## Implementation Details

### Permission Middleware

The `requirePermissions` middleware enforces access control:

```typescript
// Basic permission check
router.get('/connected', 
  requireAuth,
  requirePermissions(IntegrationPermission.READ_CONNECTED),
  handler
);

// With ownership verification
router.delete('/:id',
  requireAuth,
  requirePermissions(IntegrationPermission.DISCONNECT_OWN, { 
    checkOwnership: true 
  }),
  handler
);
```

### Ownership Verification

For operations on specific integrations, the system verifies ownership:

1. **User Ownership**: Users can only access integrations they created
2. **Business Context**: Business admins can access integrations within their business
3. **System Admin**: Admins can access any integration

### Security Features

#### Data Protection
- Sensitive tokens and credentials are never exposed in API responses
- Metadata filtering removes sensitive fields before returning data
- Input validation prevents injection attacks

#### Access Control
- All protected routes require authentication
- Permission checks happen before business logic
- Ownership verification prevents unauthorized access

#### Error Handling
- Consistent error format across all endpoints
- Permission denied errors don't reveal sensitive information
- Graceful handling of malformed requests

## API Endpoints

### GET /api/integrations
**Public endpoint** - Lists available integrations
- No authentication required
- Returns connection status for authenticated users
- Filters sensitive metadata

### GET /api/integrations/connected
**Protected endpoint** - Lists user's connected integrations
- Requires `READ_CONNECTED` permission
- Returns only non-sensitive metadata
- Includes connection count

### POST /api/integrations/connect
**Protected endpoint** - Initiates integration connection
- Requires `CONNECT` permission
- Validates integration availability
- Prevents duplicate connections
- Generates OAuth state or API key instructions

### GET /api/integrations/:id
**Protected endpoint** - Gets specific integration details
- Requires `READ_OWN` permission with ownership check
- Returns safe integration details
- Filters sensitive tokens

### DELETE /api/integrations/:id
**Protected endpoint** - Disconnects integration
- Requires `DISCONNECT_OWN` permission with ownership check
- Verifies ownership before deletion
- Returns disconfirmation details

## Usage Examples

### Client-Side Integration

```javascript
// List available integrations
const response = await fetch('/api/integrations');
const { available, connected } = await response.json();

// Connect new integration (requires authentication)
const connectResponse = await fetch('/api/integrations/connect', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer <token>',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ provider: 'stripe' })
});
```

### Server-Side Permission Check

```typescript
// Custom permission middleware
const customPermissionCheck = requirePermissions(
  IntegrationPermission.MANAGE_OWN,
  {
    checkOwnership: true,
    customCheck: async (req, context) => {
      // Custom business logic
      return await verifyBusinessAccess(context.userId, req.params.id);
    }
  }
);
```

## Testing

### Test Coverage

The implementation includes comprehensive tests covering:
- Permission enforcement for all roles
- Ownership verification
- Data protection and filtering
- Error handling and edge cases
- Integration flows

### Security Tests

- Token leakage prevention
- Input validation
- Authentication bypass attempts
- Authorization boundary testing

## Migration Guide

### From Simple Auth

1. **Update Routes**: Add permission middleware to existing routes
2. **Set Headers**: Include `x-user-role` and `x-business-id` headers
3. **Handle Errors**: Update error handling for permission denied responses
4. **Test Permissions**: Verify all user roles work correctly

### Example Migration

```typescript
// Before
router.get('/connected', requireAuth, handler);

// After
router.get('/connected', 
  requireAuth,
  requirePermissions(IntegrationPermission.READ_CONNECTED),
  handler
);
```

## Best Practices

### Security
- Always filter sensitive data before returning responses
- Use ownership checks for operations on specific resources
- Validate all input parameters
- Implement proper error handling

### Performance
- Cache permission checks where appropriate
- Use efficient database queries for ownership verification
- Minimize permission overhead in hot paths

### Maintainability
- Keep permission definitions in a single source of truth
- Use descriptive permission names
- Document permission requirements for each endpoint
- Test permission boundaries thoroughly

## Future Enhancements

### Potential Improvements
1. **Dynamic Permissions**: Role-based permissions from database
2. **Resource-Based Permissions**: Permissions per integration type
3. **Time-Based Permissions**: Temporary access grants
4. **Audit Logging**: Permission check logging
5. **Permission Inheritance**: Business role inheritance

### Scalability Considerations
- Permission caching for high-traffic endpoints
- Distributed permission checking for microservices
- Real-time permission updates
- Permission analytics and monitoring
