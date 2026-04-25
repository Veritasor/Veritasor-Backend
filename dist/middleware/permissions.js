/**
 * Granular permission middleware for integration routes
 *
 * This middleware provides fine-grained access control for integration operations
 * based on user roles, permissions, and ownership context.
 */
import { ROUTE_PERMISSIONS, ROLE_PERMISSIONS } from '../types/permissions.js';
/**
 * Permission service for checking user permissions
 */
export class PermissionService {
    /**
     * Get user permissions based on role
     */
    static getUserPermissions(role) {
        return [...(ROLE_PERMISSIONS[role] || [])];
    }
    /**
     * Check if user has required permissions
     */
    static checkPermissions(userPermissions, requiredPermissions) {
        const missing = requiredPermissions.filter(permission => !userPermissions.includes(permission));
        return {
            allowed: missing.length === 0,
            reason: missing.length > 0
                ? `Missing required permissions: ${missing.join(', ')}`
                : undefined,
            requiredPermissions,
            userPermissions,
        };
    }
    /**
     * Create permission context from request
     */
    static createContext(userId, role = 'user', businessId) {
        return {
            userId,
            businessId,
            role,
            permissions: this.getUserPermissions(role),
        };
    }
}
/**
 * Middleware to require specific permissions for a route
 */
export function requirePermissions(requiredPermissions, options) {
    const permissions = Array.isArray(requiredPermissions)
        ? requiredPermissions
        : [requiredPermissions];
    return async (req, res, next) => {
        try {
            // Ensure user is authenticated
            if (!req.user || !req.user.userId) {
                res.status(401).json({
                    error: 'Unauthorized',
                    message: 'Authentication required',
                });
                return;
            }
            // Extract user role from headers or default to 'user'
            const role = req.headers['x-user-role'] || 'user';
            // Create permission context
            const context = PermissionService.createContext(req.user.userId, role, req.headers['x-business-id']);
            // Attach context to request
            req.permissionContext = context;
            // Check base permissions
            const permissionCheck = PermissionService.checkPermissions(context.permissions, permissions);
            if (!permissionCheck.allowed) {
                res.status(403).json({
                    error: 'Forbidden',
                    message: 'Insufficient permissions',
                    details: permissionCheck.reason,
                });
                return;
            }
            // Custom ownership check if required
            if (options?.checkOwnership) {
                const integrationId = req.params.id || req.params.provider;
                if (integrationId) {
                    // TODO: Implement actual ownership check against database
                    // For now, we'll assume the user owns the resource if they have basic permissions
                    const ownsResource = await checkIntegrationOwnership(req.user.userId, integrationId, context.businessId);
                    if (!ownsResource) {
                        res.status(403).json({
                            error: 'Forbidden',
                            message: 'You do not have permission to access this integration',
                        });
                        return;
                    }
                }
            }
            // Custom permission check if provided (runs after ownership check)
            if (options?.customCheck) {
                const customResult = await options.customCheck(req, context);
                if (!customResult) {
                    res.status(403).json({
                        error: 'Forbidden',
                        message: 'Custom permission check failed',
                    });
                    return;
                }
            }
            next();
        }
        catch (error) {
            console.error('Permission middleware error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                message: 'Error checking permissions',
            });
        }
    };
}
/**
 * Middleware to check permissions based on route pattern
 */
export function requireRoutePermissions(routePattern) {
    const requiredPermissions = ROUTE_PERMISSIONS[routePattern];
    if (!requiredPermissions) {
        throw new Error(`No permissions defined for route pattern: ${routePattern}`);
    }
    return requirePermissions([...requiredPermissions]);
}
/**
 * Check if user owns a specific integration
 * TODO: Implement actual database check
 */
async function checkIntegrationOwnership(userId, integrationId, businessId) {
    // This is a placeholder implementation
    // In a real implementation, you would:
    // 1. Query the database for the integration
    // 2. Check if the integration belongs to the user or their business
    // 3. Return the result
    // For now, we'll assume ownership if the integration ID contains the user ID
    // or if a business ID is provided and matches
    return !!(integrationId.includes(userId) || (businessId && integrationId.includes(businessId)));
}
/**
 * Helper middleware to add permission context to request
 */
export function addPermissionContext() {
    return (req, res, next) => {
        if (req.user && req.user.userId) {
            const role = req.headers['x-user-role'] || 'user';
            req.permissionContext = PermissionService.createContext(req.user.userId, role, req.headers['x-business-id']);
        }
        next();
    };
}
