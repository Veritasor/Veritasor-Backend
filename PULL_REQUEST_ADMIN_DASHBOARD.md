# Pull Request: Admin Dashboard API Implementation

## Description
This PR implements the Admin Dashboard API for platform health monitoring and user management. It introduces a granular Role-Based Access Control (RBAC) system, audit logging for administrative actions, and endpoints for platform-wide statistics.

## Key Changes
### 1. API Endpoints (`/api/v1/admin`)
- **Stats**: `GET /stats` provides aggregated data on user distribution and attestation volume.
- **User Management**:
    - `GET /users`: Comprehensive list of all registered users.
    - `PATCH /users/:id`: Allows role updates and profile modifications.
    - `DELETE /users/:id`: Facilitates account removal with audit tracking.
- **Audit Logs**: `GET /audit-logs` exposes the system-wide trail of administrative operations.

### 2. Security & RBAC
- Extended `IntegrationPermission` with `ADMIN_READ_STATS`, `ADMIN_MANAGE_USERS`, and `ADMIN_READ_AUDIT_LOGS`.
- Updated `requireAuth` middleware to securely fetch and attach user roles from the database.
- Enhanced `requirePermissions` middleware to prioritize database-verified roles over request headers.

### 3. Data Layer
- **Audit Log Repository**: New repository for persistent (in-memory for now) tracking of admin actions.
- **User Repository**: Added `role` support and administrative CRUD helpers.
- **Attestation Repository**: Added `listAll()` for global metrics.

### 4. Testing
- Created `tests/unit/routes/admin.test.ts` covering authentication, permission enforcement, and dashboard logic.

## Technical Notes
- The `app.ts` was restored and fixed to ensure correct router mounting and server startup reliability.
- All admin actions trigger an `AuditLog` entry for accountability.

## Checklist
- [x] Design admin API endpoints
- [x] Implement authentication and authorization
- [x] Add platform statistics endpoints
- [x] Create user management endpoints
- [x] Implement audit logging
- [x] Write admin API tests

#564
