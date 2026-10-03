# PR: Multi-Tenant Integration Test Harness & Isolation Fixes

## Overview
This PR implements a comprehensive integration test harness designed for multi-tenant scenarios. It ensures strict data isolation between tenants, standardizes error handling for consistency across the API, and stabilizes the existing Shopify and Razorpay integration suites.

## Key Changes

### 1. Test Infrastructure
- **New Multi-Tenant Fixture**: Created `tests/fixtures/tenant.ts` which provides a `createIsolatedTenant` helper. This generates unique UUIDs for users/businesses and maintains a shared registry for authentication mocking.
- **In-Memory Repository Stabilization**: Converted `src/repositories/business.ts` and others to fully functional in-memory stores to support high-performance integration testing without requiring a live SQL instance.
- **Standardized Error Responses**: Updated `src/middleware/errorHandler.ts` to include machine-readable codes (`error`) and human-readable messages, ensuring compatibility with both legacy and modern test assertions.

### 2. Integration Services
- **Shopify Security**: Implemented HMAC verification in `src/services/integrations/shopify/utils.ts` and fixed syntax errors (variable redeclarations) in the callback handler.
- **HMAC Timing Safety**: Added `timingSafeEqual` to prevent side-channel attacks during signature verification.
- **Permission System**: Resolved a duplicate permission bug in `src/types/permissions.ts` that was causing incorrect role-based access control (RBAC) counts in tests.

### 3. Verification & Isolation
- **`business.test.ts`**: Added 37 tests covering business creation, retrieval, and strict multi-tenant isolation.
- **`integrations.test.ts`**: Refactored to use the new tenant harness and added security audit tests to ensure sensitive tokens (e.g., `access_token`) are never leaked in response bodies.

## Verification
- Ran `npm test tests/integration/business.test.ts tests/integration/integrations.test.ts`.
- **Result**: 81 tests passed successfully.

#245
