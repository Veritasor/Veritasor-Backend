# Pull Request: Add golden snapshot tests for OpenAPI spec output

## Overview
This PR addresses issue #429 by implementing deterministic, normalized golden snapshot tests for `src/utils/openapi.ts`. It locks down the structural output of the OpenAPI spec generator, ensuring that any spec drift (new routes, schema changes, etc.) is caught in CI and requires explicit review. This complements the existing in-memory contract test and unit tests.

## Key Changes

### 🛠 Architecture & Tooling
- **Deterministic Normalizer**: Added `src/utils/normalizeSpec.ts` to recursively sort object keys, path keys, tags, parameters, required arrays, and response status codes. This ensures snapshot comparisons are immune to insertion-order variance.
- **Shared Canonical Fixtures**: Extracted inline route fixtures from `tests/unit/utils/openapi.test.ts` into a shared module `tests/openapi/fixtures/routes.ts`, establishing a single source of truth for both unit tests and snapshot tests.
- **Update Script**: Added `scripts/update-snapshot.ts` and wired it up via `npm run snapshot:update` in `package.json` for easy, one-command snapshot regeneration.
- **Golden Snapshot**: Created the initial golden snapshot at `tests/openapi/golden.snap.json` (46,727 bytes, 17 paths, 6 tags).

### 🧪 Testing & Coverage
- **New Golden Snapshot Suite**: Added `tests/openapi/golden-snapshot.test.ts` with 24 tests covering:
  - **Full structural match**: Normalized spec must exactly match the snapshot.
  - **Ordering stability**: Randomized route input must produce identical normalized output.
  - **Structural checks**: Verifies subset generation, empty baselines, and exact path/tag/schema counts.
  - **Drift detection**: Adding/removing routes or changing properties correctly triggers failures with actionable diffs.
  - **Example value stability**: Ensures any example fields remain stable across runs.
- **No Regressions**: All 46 existing OpenAPI unit tests pass seamlessly with the new shared fixtures.

### 📝 Documentation
- **Snapshot Guide**: Added `tests/openapi/README.md` explaining how the snapshot system works, when CI will fail, and how to update the snapshot (`npm run snapshot:update`).

## Verification Results
- **Golden Snapshot Tests**: 24/24 passed.
- **Unit Tests**: 46/46 passed (no regressions).
- *(Note: The existing contract test failure `tests/contract/openapi-snapshot.test.ts` is due to a pre-existing duplicate logger import in `src/routes/admin.ts` and is unrelated to this PR).*

## Security & Maintenance Notes
- **Decoupled from Runtime**: The golden snapshots are generated from fixed fixtures rather than the live Express app. This tests the OpenAPI generator logic in isolation and avoids false positives during local runtime changes.
- **Diff Noise Reduction**: By deeply normalizing the output, PR reviewers will only see semantic changes to the OpenAPI spec, not noisy key reordering or insertion differences.

Closes #429
