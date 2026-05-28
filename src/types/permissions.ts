import { z } from 'zod';

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

  // Platform Admin permissions
  ADMIN_READ_STATS = 'admin:read:stats',
  ADMIN_MANAGE_USERS = 'admin:manage:users',
  ADMIN_READ_AUDIT_LOGS = 'admin:read:audit_logs',
}

/**
 * Zod schema for runtime validation of IntegrationPermission
 */
export const IntegrationPermissionSchema = z.nativeEnum(IntegrationPermission);

/**
 * Exhaustive metadata for all permissions.
 * The use of Record<IntegrationPermission, ...> ensures that any new permission added
 * to the enum must be documented here or the code will fail to compile.
 */
export const PERMISSION_METADATA: Record<IntegrationPermission, { description: string }> = {
  [IntegrationPermission.READ_AVAILABLE]: { description: 'View available integration providers' },
  [IntegrationPermission.READ_CONNECTED]: { description: 'View currently connected integrations' },
  [IntegrationPermission.READ_OWN]: { description: 'View details of own integrations' },
  [IntegrationPermission.CONNECT]: { description: 'Connect a new integration provider' },
  [IntegrationPermission.DISCONNECT_OWN]: { description: 'Disconnect own integrations' },
  [IntegrationPermission.DISCONNECT_ANY]: { description: 'Disconnect any integration (admin)' },
  [IntegrationPermission.MANAGE_OWN]: { description: 'Manage settings for own integrations' },
  [IntegrationPermission.MANAGE_ANY]: { description: 'Manage settings for any integration (admin)' },
  [IntegrationPermission.ADMIN]: { description: 'Full administrative access to integrations' },
  [IntegrationPermission.ADMIN_READ_STATS]: { description: 'Read platform-wide integration statistics' },
  [IntegrationPermission.ADMIN_MANAGE_USERS]: { description: 'Manage platform users and their roles' },
  [IntegrationPermission.ADMIN_READ_AUDIT_LOGS]: { description: 'Read platform security and audit logs' },
};

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
  admin: [
    ...Object.values(IntegrationPermission),
  ],
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
