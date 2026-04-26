import { randomUUID } from 'node:crypto';

export type UserRole = 'admin' | 'business_admin' | 'user';

export interface TenantContext {
  id: string;
  userId: string;
  email: string;
  role: UserRole;
  token: string;
}

const activeTenants = new Map<string, TenantContext>();

/**
 * Creates a new isolated tenant context for tests
 * @param role The role of the user (admin, business_admin, user)
 * @param overrides Optional overrides for the generated tenant data
 */
export function createIsolatedTenant(role: UserRole = 'user', overrides?: Partial<TenantContext>): TenantContext {
  const id = overrides?.id || randomUUID();
  const token = overrides?.token || `test-token-${id}`;
  const userId = overrides?.userId || `user_${id}`;
  const tenant: TenantContext = {
    id,
    userId,
    email: overrides?.email || `tenant_${id}@example.com`,
    role,
    token,
    ...overrides,
  };
  
  activeTenants.set(token, tenant);
  return tenant;
}

/**
 * Retrieves a tenant by their token
 * Useful for auth mocks.
 */
export function getTenantByToken(token: string): TenantContext | undefined {
  return activeTenants.get(token);
}

/**
 * Clears all active tenants
 * Should be called in beforeEach or afterEach
 */
export function clearTenants(): void {
  activeTenants.clear();
}

/**
 * Generates Auth Headers for a given tenant.
 * Note: Some tests mock token parsing from Authorization,
 * while others may mock requireAuth to use x-user-role directly.
 */
export function getAuthHeaders(tenant: TenantContext): Record<string, string> {
  return {
    Authorization: `Bearer ${tenant.token}`,
    'x-user-role': tenant.role,
    'x-user-id': tenant.userId,
  };
}
