import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  PermissionService,
  requirePermissions
} from "../../src/middleware/permissions.js";
import { IntegrationPermission } from "../../src/types/permissions.js";
import { Request, Response, NextFunction } from "express";

describe("PermissionService", () => {
  describe("getUserPermissions", () => {
    it("should return correct permissions for user role", () => {
      const permissions = PermissionService.getUserPermissions("user");

      expect(permissions).toContain(IntegrationPermission.READ_AVAILABLE);
      expect(permissions).toContain(IntegrationPermission.READ_CONNECTED);
      expect(permissions).toContain(IntegrationPermission.CONNECT);
      expect(permissions).toContain(IntegrationPermission.DISCONNECT_OWN);
      expect(permissions).not.toContain(IntegrationPermission.ADMIN);
    });

    it("should return correct permissions for business_admin role", () => {
      const permissions = PermissionService.getUserPermissions("business_admin");

      expect(permissions).toContain(IntegrationPermission.DISCONNECT_ANY);
      expect(permissions).toContain(IntegrationPermission.MANAGE_ANY);
      expect(permissions).not.toContain(IntegrationPermission.ADMIN);
    });

    it("should return all permissions for admin role", () => {
      const permissions = PermissionService.getUserPermissions("admin");

      expect(permissions).toContain(IntegrationPermission.ADMIN);
      expect(permissions.length).toBe(Object.values(IntegrationPermission).length);
    });

    it("should return empty array for invalid role", () => {
      const permissions = PermissionService.getUserPermissions("invalid" as any);

      expect(permissions).toEqual([]);
    });
  });

  describe("checkPermissions", () => {
    const userPermissions = [
      IntegrationPermission.READ_AVAILABLE,
      IntegrationPermission.READ_CONNECTED,
      IntegrationPermission.CONNECT,
    ];

    it("should allow access when user has all required permissions", () => {
      const result = PermissionService.checkPermissions(
        userPermissions,
        [IntegrationPermission.READ_AVAILABLE]
      );

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("should allow access when user has multiple required permissions", () => {
      const result = PermissionService.checkPermissions(
        userPermissions,
        [IntegrationPermission.READ_AVAILABLE, IntegrationPermission.CONNECT]
      );

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("should deny access when user lacks required permissions", () => {
      const result = PermissionService.checkPermissions(
        userPermissions,
        [IntegrationPermission.ADMIN]
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Missing required permissions");
      expect(result.requiredPermissions).toEqual([IntegrationPermission.ADMIN]);
      expect(result.userPermissions).toEqual(userPermissions);
    });

    it("should deny access when user has some but not all required permissions", () => {
      const result = PermissionService.checkPermissions(
        userPermissions,
        [IntegrationPermission.READ_AVAILABLE, IntegrationPermission.ADMIN]
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Missing required permissions");
    });

    it("should handle empty required permissions", () => {
      const result = PermissionService.checkPermissions(userPermissions, []);

      expect(result.allowed).toBe(true);
    });

    it("should handle empty user permissions", () => {
      const result = PermissionService.checkPermissions(
        [],
        [IntegrationPermission.READ_AVAILABLE]
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Missing required permissions");
    });
  });

  describe("createContext", () => {
    it("should create permission context with all fields", () => {
      const context = PermissionService.createContext(
        "user_123",
        "user",
        "business_123"
      );

      expect(context.userId).toBe("user_123");
      expect(context.role).toBe("user");
      expect(context.businessId).toBe("business_123");
      expect(context.permissions).toContain(IntegrationPermission.READ_AVAILABLE);
    });

    it("should create context without business ID", () => {
      const context = PermissionService.createContext("user_123", "admin");

      expect(context.userId).toBe("user_123");
      expect(context.role).toBe("admin");
      expect(context.businessId).toBeUndefined();
      expect(context.permissions).toContain(IntegrationPermission.ADMIN);
    });

    it("should default role to user", () => {
      const context = PermissionService.createContext("user_123");

      expect(context.role).toBe("user");
      expect(context.permissions).toContain(IntegrationPermission.READ_AVAILABLE);
    });
  });
});

describe("requirePermissions middleware", () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      user: { userId: "user_123", email: "test@example.com" },
      headers: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
  });

  it("should call next when user has required permissions", async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_AVAILABLE);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  it("should set permission context on request", async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_AVAILABLE);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockReq.permissionContext).toBeDefined();
    expect(mockReq.permissionContext?.userId).toBe("user_123");
    expect(mockReq.permissionContext?.role).toBe("user");
  });

  it("should return 401 when user is not authenticated", async () => {
    mockReq.user = undefined;
    const middleware = requirePermissions(IntegrationPermission.READ_AVAILABLE);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: "Unauthorized",
      message: "Authentication required",
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should return 403 when user lacks permissions", async () => {
    const middleware = requirePermissions(IntegrationPermission.ADMIN);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: "Forbidden",
      message: "Insufficient permissions",
      details: expect.stringContaining("Missing required permissions"),
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should handle multiple required permissions", async () => {
    const middleware = requirePermissions([
      IntegrationPermission.READ_AVAILABLE,
      IntegrationPermission.CONNECT,
    ]);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
  });

  it("should use user role from headers", async () => {
    mockReq.headers = { "x-user-role": "admin" };
    const middleware = requirePermissions(IntegrationPermission.ADMIN);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockReq.permissionContext?.role).toBe("admin");
  });

  it("should use business ID from headers", async () => {
    mockReq.headers = { "x-business-id": "business_123" };
    const middleware = requirePermissions(IntegrationPermission.READ_AVAILABLE);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockReq.permissionContext?.businessId).toBe("business_123");
  });

  it("should handle custom ownership check", async () => {
    const customCheck = vi.fn().mockResolvedValue(false);
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
      customCheck,
    });

    mockReq.params = { id: "integration_123" };

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should pass custom ownership check", async () => {
    const customCheck = vi.fn().mockResolvedValue(true);
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
      customCheck,
    });

    mockReq.params = { id: "integration_123" };

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
  });

  it("should handle ownership check without integration ID", async () => {
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      checkOwnership: true,
    });

    // No params.id set
    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).toHaveBeenCalled(); // Should pass since no ownership check needed
  });

  it("should handle errors in custom check", async () => {
    const customCheck = vi.fn().mockRejectedValue(new Error("Custom error"));
    const middleware = requirePermissions(IntegrationPermission.READ_OWN, {
      customCheck,
    });

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: "Internal Server Error",
      message: "Error checking permissions",
    });
  });
});
