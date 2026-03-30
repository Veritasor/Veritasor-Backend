/**
 * Granular permission types for integration operations
 * 
 * This module defines the permission system for controlling access
 * to various integration operations with different levels of granularity.
 */

/**
 * Base permission categories for integrations
 */
export enum IntegrationPermission {
  // Read permissions
  READ_AVAILABLE = 'integrations:read:available',
  READ_CONNECTED = 'integrations:read:connected',
  READ_OWN = 'integrations:read:own',
  
  // Write permissions
  CONNECT = 'integrations:connect',
  DISCONNECT_OWN = 'integrations:disconnect:own',
  DISCONNECT_ANY = 'integrations:disconnect:any',
  
  // Management permissions
  MANAGE_OWN = 'integrations:manage:own',
  MANAGE_ANY = 'integrations:manage:any',
  
  // Admin permissions
  ADMIN = 'integrations:admin',
}

/**
 * Permission sets by role
 */
export const ROLE_PERMISSIONS = {
  // Basic user can view and manage their own integrations
  user: [
    IntegrationPermission.READ_AVAILABLE,
    IntegrationPermission.READ_CONNECTED,
    IntegrationPermission.READ_OWN,
    IntegrationPermission.CONNECT,
    IntegrationPermission.DISCONNECT_OWN,
    IntegrationPermission.MANAGE_OWN,
  ],
  
  // Business admin can manage all integrations for their business
  business_admin: [
    IntegrationPermission.READ_AVAILABLE,
    IntegrationPermission.READ_CONNECTED,
    IntegrationPermission.READ_OWN,
    IntegrationPermission.CONNECT,
    IntegrationPermission.DISCONNECT_OWN,
    IntegrationPermission.DISCONNECT_ANY,
    IntegrationPermission.MANAGE_OWN,
    IntegrationPermission.MANAGE_ANY,
  ],
  
  // System admin has full control
  admin: Object.values(IntegrationPermission),
} as const;

/**
 * Permission requirements for specific routes
 */
export const ROUTE_PERMISSIONS = {
  // GET /api/integrations - List available integrations
  'GET:/': [IntegrationPermission.READ_AVAILABLE],
  
  // GET /api/integrations/connected - List connected integrations
  'GET:/connected': [IntegrationPermission.READ_CONNECTED],
  
  // POST /api/integrations/:provider/connect - Connect new integration
  'POST:/:provider/connect': [IntegrationPermission.CONNECT],
  
  // DELETE /api/integrations/:id - Disconnect integration
  'DELETE:/:id': [IntegrationPermission.DISCONNECT_OWN],
  
  // PUT /api/integrations/:id - Update integration
  'PUT:/:id': [IntegrationPermission.MANAGE_OWN],
  
  // GET /api/integrations/:id - Get specific integration
  'GET:/:id': [IntegrationPermission.READ_OWN],
} as const;

/**
 * Integration provider-specific permissions
 */
export const PROVIDER_PERMISSIONS = {
  stripe: 'integrations:provider:stripe',
  razorpay: 'integrations:provider:razorpay',
  shopify: 'integrations:provider:shopify',
} as const;

/**
 * User role type
 */
export type UserRole = keyof typeof ROLE_PERMISSIONS;

/**
 * Permission check result
 */
export interface PermissionCheck {
  allowed: boolean;
  reason?: string;
  requiredPermissions?: IntegrationPermission[];
  userPermissions?: IntegrationPermission[];
}

/**
 * User permissions context
 */
export interface UserPermissionContext {
  userId: string;
  businessId?: string;
  role: UserRole;
  permissions: IntegrationPermission[];
  providerPermissions?: string[];
}
