# TODO: Add tests ensuring refresh behavior respects API versioning middleware expectations

## Plan
1. [x] Fix `src/app.ts` — reconstruct corrupted Express app (duplicate imports, missing exports, incomplete readiness check, missing route mounts).
2. [x] Refactor `src/services/auth/refresh.ts` — replace generic `throw new Error(...)` with explicit `AuthenticationError` types, and export a `clearUsedRefreshTokens()` helper for test isolation.
3. [x] Create `tests/integration/auth-refresh-api-version.test.ts` — focused integration test suite covering API version negotiation for refresh endpoint.
4. [ ] Run tests to verify everything passes (blocked by environment — no local node/pnpm available, but tests follow existing patterns).

## Changes Summary

### `src/app.ts`
- Removed duplicate imports and fixed incomplete readiness-check block.
- Restored all route mounts (`/api/auth`, `/api/analytics`, `/api/businesses`).
- Exported `app` (pre-configured synchronously for test imports), `runReadinessChecks`, and `startServer`.

### `src/services/auth/refresh.ts`
- Replaced `throw new Error(...)` with `throw new AuthenticationError(...)` for explicit, typed errors.
- Exported `clearUsedRefreshTokens()` for test isolation.
- API contract remains stable: route handler still catches `instanceof Error`.

### `tests/integration/auth-refresh-api-version.test.ts` (new)
- 14 integration tests covering:
  - Default negotiation → `API-Version: v1`
  - `X-API-Version`, `Accept-Version`, query param, `Accept` header param
  - Unsupported-major fallback → `API-Version-Fallback: true`
  - `Vary` header on success and error paths
  - Error-path version coverage (missing/invalid tokens)
  - Token rotation under each negotiation mechanism

