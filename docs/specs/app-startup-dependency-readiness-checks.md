# App Startup Dependency Readiness Checks

## Summary
The backend now validates critical dependencies **before opening the HTTP listener**.

Startup readiness checks currently validate:

1. **Configuration readiness**
   - In `production`, `JWT_SECRET` must be present and at least 32 characters.
2. **Database readiness (when configured)**
   - If `DATABASE_URL` is set, startup performs a `SELECT 1` connectivity probe.

If any required check fails, startup exits with an explicit failure message and the process does not accept traffic.

## Rationale
- Improves reliability by preventing partial/invalid startup.
- Improves security by enforcing minimum auth secret requirements in production.
- Improves operations clarity by returning per-dependency readiness reasons.

## Failure behavior
- `startServer(...)` throws when readiness fails.
- `src/index.ts` catches startup failures, logs a non-sensitive startup message, and exits with status code `1`.

## Security notes
- Readiness failure reasons avoid printing secrets or raw connection strings.
- Database check uses read-only probe (`SELECT 1`) with bounded timeout.

## Test coverage
Integration coverage for readiness logic is included in:
- `tests/integration/auth.test.ts`
  - missing production `JWT_SECRET` (failure)
  - no `DATABASE_URL` (success)
  - unreachable database check (failure)
