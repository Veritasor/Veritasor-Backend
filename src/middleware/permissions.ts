/*
 * Granular permission middleware for integration routes
 * 
 * This middleware provides fine-grained access control for integration operations
 * based on user roles, permissions, and ownership context.
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';
import { createAuditLog } from '../repositories/auditLogRepository.js';
import { getById } from '../repositories/integration.js';
import {
  IntegrationPermission,
  PermissionCheck,
  UserPermissionContext,
  ROUTE_PERMISSIONS,
  ROLE_PERMISSIONS,
  UserRole
} from '../types/permissions.js';

/**
 * A compact, auditable policy DSL. Rules are evaluated in order only for
 * reporting; an applicable deny always wins over every applicable allow.
 */
export interface PolicyRule {
  id: string;
  effect: 'allow' | 'deny';
  actions: readonly string[];
  resources: readonly string[];
  roles?: readonly UserRole[];
  tenantScope?: 'same' | 'any';
}

export interface PolicyRequest {
  action: string;
  resource: string;
  role: UserRole;
  actorTenantId?: string;
  resourceTenantId?: string;
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  ruleId?: string;
}

/** Default least-privilege rules for business-scoped integration resources. */
export const DEFAULT_POLICY: readonly PolicyRule[] = [
  { id: 'integration-user-own', effect: 'allow', actions: ['read', 'create', 'update', 'delete'], resources: ['integration'], roles: ['user'], tenantScope: 'same' },
  { id: 'integration-business-admin', effect: 'allow', actions: ['*'], resources: ['integration'], roles: ['business_admin'], tenantScope: 'same' },
  { id: 'platform-admin', effect: 'allow', actions: ['*'], resources: ['*'], roles: ['admin'], tenantScope: 'any' },
];

function matches(value: string, values: readonly string[]): boolean {
  return values.includes('*') || values.includes(value);
}

function ruleMatches(rule: PolicyRule, request: PolicyRequest): boolean {
  if (!matches(request.action, rule.actions) || !matches(request.resource, rule.resources)) return false;
  if (rule.roles && !rule.roles.includes(request.role)) return false;
  if (rule.tenantScope === 'same') {
    return Boolean(request.actorTenantId) && request.actorTenantId === request.resourceTenantId;
  }
  return true;
}

/** Evaluate a policy request. Explicit denies override allows; default is deny. */
export function evaluatePolicy(
  request: PolicyRequest,
  rules: readonly PolicyRule[] = DEFAULT_POLICY,
): PolicyDecision {
  const matching = rules.filter((rule) => ruleMatches(rule, request));
  const deny = matching.find((rule) => rule.effect === 'deny');
  if (deny) return { allowed: false, ruleId: deny.id, reason: `Denied by policy rule: ${deny.id}` };

  const allow = matching.find((rule) => rule.effect === 'allow');
  if (allow) return { allowed: true, ruleId: allow.id, reason: `Allowed by policy rule: ${allow.id}` };

  const tenantMismatch = request.resourceTenantId !== undefined &&
    request.actorTenantId !== request.resourceTenantId;
  return {
    allowed: false,
    reason: tenantMismatch ? 'Denied: resource belongs to a different tenant' : 'Denied: no matching policy rule',
  };
}

async function auditPolicyDecision(
  userId: string,
  request: PolicyRequest,
  decision: PolicyDecision,
  resourceId?: string,
): Promise<void> {
  try {
    await createAuditLog({
      userId,
      action: 'POLICY_DECISION',
      resource: request.resource,
      resourceId,
      metadata: {
        action: request.action,
        allowed: decision.allowed,
        reason: decision.reason,
        ruleId: decision.ruleId,
        actorTenantId: request.actorTenantId,
        resourceTenantId: request.resourceTenantId,
      },
    });
  } catch (error) {
    // Audit availability must not convert an authorization decision into an allow.
    logger.error(JSON.stringify({ event: 'policy.audit_failed', userId, error: String(error) }));
  }
}

export interface PolicyMiddlewareOptions {
  rules?: readonly PolicyRule[];
  resourceId?: (req: Request) => string | undefined;
  resourceTenantId?: (req: Request) => string | undefined | Promise<string | undefined>;
}

/** Resolve roles only from authenticated middleware state, failing closed. */
function getAuthenticatedRole(req: Request): UserRole {
  const role = req.user?.role;
  return role && Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role)
    ? role
    : 'user';
}

/**
 * Require an explicit action-on-resource policy decision. Tenant IDs are read
 * only from the business context attached by requireBusinessAuth, never from a
 * caller-controlled header.
 */
export function requirePolicy(action: string, resource: string, options: PolicyMiddlewareOptions = {}) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user?.userId) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
      return;
    }

    const role = (req.user.role || 'user') as UserRole;
    const request: PolicyRequest = {
      action,
      resource,
      role,
      actorTenantId: req.business?.id,
      resourceTenantId: await options.resourceTenantId?.(req),
    };
    const decision = evaluatePolicy(request, options.rules);
    await auditPolicyDecision(req.user.userId, request, decision, options.resourceId?.(req));

    if (!decision.allowed) {
      res.status(403).json({ error: 'Forbidden', message: 'Policy denied', details: decision.reason });
      return;
    }
    next();
  };
}

/**
 * Extend Express Request to include permission context
 */
declare global {
  namespace Express {
    interface Request {
      permissionContext?: UserPermissionContext;
    }
  }
}

/**
 * Permission service for checking user permissions
 */
export class PermissionService {
  /**
   * Get user permissions based on role
   */
  static getUserPermissions(role: UserRole): IntegrationPermission[] {
    return [...(ROLE_PERMISSIONS[role] || [])];
  }

  /**
   * Check if user has required permissions
   */
  static checkPermissions(
    userPermissions: IntegrationPermission[],
    requiredPermissions: IntegrationPermission[]
  ): PermissionCheck {
    const missing = requiredPermissions.filter(
      permission => !userPermissions.includes(permission)
    );

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
  static createContext(
    userId: string,
    role: UserRole = 'user',
    businessId?: string
  ): UserPermissionContext {
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
export function requirePermissions(
  requiredPermissions: IntegrationPermission | IntegrationPermission[],
  options?: {
    // Check if user owns the resource (for operations on specific integrations).
    // Pass `true` to use the default `integrationId`
    // param, or a string to select a different route param.
    checkOwnership?: boolean | string;
    // Custom permission check logic
    customCheck?: (req: Request, context: UserPermissionContext) => boolean | Promise<boolean>;
  }
) {
  const permissions = Array.isArray(requiredPermissions)
    ? requiredPermissions
    : [requiredPermissions];

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Ensure user is authenticated
      if (!req.user || !req.user.userId) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      const role = getAuthenticatedRole(req);

      // Create permission context
      const context = PermissionService.createContext(
        req.user.userId,
        role,
        req.business?.id
      );

      // Attach context to request
      req.permissionContext = context;

      // Check base permissions
      const permissionCheck = PermissionService.checkPermissions(
        context.permissions,
        permissions
      );

      if (!permissionCheck.allowed) {
        logger.warn(JSON.stringify({
          event: 'permissions.denied',
          userId: context.userId,
          businessId: context.businessId,
          role: context.role,
          required: permissions,
          missing: permissionCheck.reason,
        }));

        res.status(403).json({
          error: 'Forbidden',
          message: 'Insufficient permissions',
          details: permissionCheck.reason,
        });
        return;
      }

      // Custom ownership check if required
      if (options?.checkOwnership) {
        const paramName = typeof options.checkOwnership === 'string'
          ? options.checkOwnership
          : 'integrationId';
        const integrationId = req.params?.[paramName];

        if (!integrationId) {
          // Fail closed: ownership was requested but no resource id can be resolved.
          res.status(403).json({
            error: 'Forbidden',
            message: 'You do not have permission to access this integration',
          });
          return;
        }

        const ownership = await checkIntegrationOwnership(
          req.user.userId,
          integrationId,
          req.business?.id
        );

        if (!ownership.owned) {
          res.status(ownership.status).json({
            error: ownership.status === 404 ? 'Not Found' : 'Forbidden',
            message: ownership.status === 404
              ? 'Integration not found'
              : 'You do not have permission to access this integration',
          });
          return;
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
    } catch (error) {
      console.error('Permission middleware error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Error checking permissions',
      });
    }
  };
}

/**
 * Dedicated platform-admin guard for the direct business-tier promotion route.
 * Keeping this named avoids widening the endpoint if generic user-management
 * permissions change later.
 */
export const requireBusinessTierRolePromotionPermission = requirePermissions(
  IntegrationPermission.ADMIN_MANAGE_USERS,
);

/**
 * Middleware to check permissions based on route pattern
 */
export function requireRoutePermissions(routePattern: string) {
  const requiredPermissions = ROUTE_PERMISSIONS[routePattern as keyof typeof ROUTE_PERMISSIONS];

  if (!requiredPermissions) {
    throw new Error(`No permissions defined for route pattern: ${routePattern}`);
  }

  return requirePermissions([...requiredPermissions]);
}

export interface IntegrationOwnershipResult {
  owned: boolean;
  status: 200 | 403 | 404;
  reason?: string;
}

/**
 * Determine whether the verified business context owns the integration.
 *
 * Fail closed:
 *   - No business context            -> 403 (forbidden)
 *   - Integration does not exist       -> 404 (not found)
 *   - Integration belongs to another tenant -> 403 (forbidden)
 *   - Integration belongs to this tenant  -> 200 (owned)
 */
export async function checkIntegrationOwnership(
  userId: string,
  integrationId: string,
  businessId?: string,
): Promise<IntegrationOwnershipResult> {
  if (!businessId) {
    logger.warn(JSON.stringify({
      event: 'permissions.ownership_no_business',
      userId,
      integrationId,
    }));
    return { owned: false, status: 403, reason: 'No business context' };
  }

  const integration = await getById(integrationId);
  if (!integration) {
    return { owned: false, status: 404, reason: 'Integration not found' };
  }

  if (integration.businessId !== businessId) {
    logger.warn(JSON.stringify({
      event: 'permissions.ownership_tenant_mismatch',
      userId,
      integrationId,
      actorTenantId: businessId,
      resourceTenantId: integration.businessId,
    }));
    return { owned: false, status: 403, reason: 'Integration belongs to a different tenant' };
  }

  return { owned: true, status: 200 };
}

/**
 * Helper middleware to add permission context to request
 */
export function addPermissionContext() {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.user && req.user.userId) {
      const role = getAuthenticatedRole(req);
      req.permissionContext = PermissionService.createContext(
        req.user.userId,
        role,
        req.business?.id
      );
    }
    next();
  };
}
