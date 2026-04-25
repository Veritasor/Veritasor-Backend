/**
 * Granular permission types for integration operations
 *
 * This module defines the permission system for controlling access
 * to various integration operations with different levels of granularity.
 */
/**
 * Base permission categories for integrations
 */
export var IntegrationPermission;
(function (IntegrationPermission) {
    // Read permissions
    IntegrationPermission["READ_AVAILABLE"] = "integrations:read:available";
    IntegrationPermission["READ_CONNECTED"] = "integrations:read:connected";
    IntegrationPermission["READ_OWN"] = "integrations:read:own";
    // Write permissions
    IntegrationPermission["CONNECT"] = "integrations:connect";
    IntegrationPermission["DISCONNECT_OWN"] = "integrations:disconnect:own";
    IntegrationPermission["DISCONNECT_ANY"] = "integrations:disconnect:any";
    // Management permissions
    IntegrationPermission["MANAGE_OWN"] = "integrations:manage:own";
    IntegrationPermission["MANAGE_ANY"] = "integrations:manage:any";
    // Admin permissions
    IntegrationPermission["ADMIN"] = "integrations:admin";
})(IntegrationPermission || (IntegrationPermission = {}));
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
};
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
};
/**
 * Integration provider-specific permissions
 */
export const PROVIDER_PERMISSIONS = {
    stripe: 'integrations:provider:stripe',
    razorpay: 'integrations:provider:razorpay',
    shopify: 'integrations:provider:shopify',
};
