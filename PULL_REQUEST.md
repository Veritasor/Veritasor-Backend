# Pull Request

## Description
This pull request documents the expected database indexes for the hot queries in `src/repositories/userRepository.ts` to ensure scalable and performant read operations, addressing potential lock contentions and full table scans. It also introduces comprehensive tests in `tests/unit/repositories/integration.test.ts` to verify the robustness of `userRepository` queries against common edge cases like non-existent records and expired reset tokens. Additionally, the `tests/README.md` has been expanded with a detailed Operator Guide covering environment variables, failure modes, and database idempotency, building upon the existing threat model notes.

## Changes Included
* **Documentation**: Annotated `findUserByEmail`, `findUserById`, and `findUserByResetToken` in `userRepository.ts` with JSDoc `@expectedIndex` and `@migrationNote` tags specifying the required B-Tree, unique, and composite indexes.
* **Testing**: Added a new suite `User Repository - queries and indexes` in `tests/unit/repositories/integration.test.ts` to validate index behavior under lookup and expiration scenarios, ensuring robust query results.
* **Operator Guide**: Updated `tests/README.md` with detailed sections on Database Expected Indexes, Environment Variables, Failure Modes (e.g., N+1 Queries, API Outages), and Idempotency patterns to aid operators.

## Representative Test Output

Running only the touched test file:

```
> vitest run tests/unit/repositories/integration.test.ts

 RUN  v4.1.2  C:/Users/Kroman/Veritasor-Backend-1

 ✓ tests/unit/repositories/integration.test.ts (21 tests) 139ms
   ✓ Integration Repository - update function (7)
   ✓ Integration Repository - deleteById function (5)
   ✓ User Repository - partial update safety (4)
   ✓ User Repository - queries and indexes (5)
     ✓ finds user by email (testing email index behavior)
     ✓ returns null for non-existent email lookup
     ✓ finds user by reset token only if not expired
     ✓ returns null for expired reset token (simulates token + expiry index check)
     ✓ returns null for non-existent reset token

 Test Files  1 passed (1)
      Tests  21 passed (21)
   Duration  1.02s
```

> **Note:** 9 test files / 23 tests fail in `tests/integration/` and unrelated unit middleware/config suites. These failures are pre-existing on `main` (confirmed by `git stash` baseline: `9 failed | 21 passed (30)` — identical count before and after this change). No regressions were introduced.

Resolves #241
