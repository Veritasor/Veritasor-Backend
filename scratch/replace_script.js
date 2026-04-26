const fs = require('fs');

let content = fs.readFileSync('tests/integration/integrations.test.ts', 'utf8');

// 1. Remove the vi.mock for auth.js and the getMockUserFromToken function
content = content.replace(/\/\/ Mock the auth middleware[\s\S]*?function getMockUserFromToken[\s\S]*?return tokenMap\[token\];\n}\n/, "import { createIsolatedTenant, getAuthHeaders, clearTenants } from '../fixtures/tenant.js';\n\nlet userTenant: any;\nlet adminTenant: any;\nlet bizAdminTenant: any;\n");

// 2. Add beforeEach and afterEach to reset tenants
content = content.replace(/beforeEach\(\(\) => \{\n  clearAll\(\);\n\}\);/, "beforeEach(() => {\n  clearAll();\n  clearTenants();\n  userTenant = createIsolatedTenant('user', { id: 'user_123', userId: 'user_123', email: 'user@example.com' });\n  adminTenant = createIsolatedTenant('admin', { id: 'admin_123', userId: 'admin_123', email: 'admin@example.com' });\n  bizAdminTenant = createIsolatedTenant('business_admin', { id: 'biz_admin_123', userId: 'biz_admin_123', email: 'bizadmin@example.com' });\n});");

// 3. Replace .set("Authorization", "Bearer user_token") and .set("x-user-role", "user") etc.
content = content.replace(/\.set\("Authorization", "Bearer user_token"\)(?:\s*\.set\("x-user-role", "user"\))?/g, ".set(getAuthHeaders(userTenant))");

content = content.replace(/\.set\("Authorization", "Bearer admin_token"\)(?:\s*\.set\("x-user-role", "admin"\))?/g, ".set(getAuthHeaders(adminTenant))");

content = content.replace(/\.set\("Authorization", "Bearer business_admin_token"\)(?:\s*\.set\("x-user-role", "business_admin"\))?/g, ".set(getAuthHeaders(bizAdminTenant))");

fs.writeFileSync('tests/integration/integrations.test.ts', content, 'utf8');
console.log("Done");
