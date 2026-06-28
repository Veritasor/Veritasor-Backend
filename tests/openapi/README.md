# OpenAPI Golden Snapshot Tests

This directory contains golden snapshot tests that lock down the structural
output of `src/utils/openapi.ts`. Any unintentional change to the OpenAPI
spec shape — new paths, modified schemas, reordered keys — will cause CI to
fail, requiring explicit review and approval of the change.

## How it works

1. **Canonical fixtures** in [`fixtures/routes.ts`](./fixtures/routes.ts)
   define the set of routes fed to `generateOpenApiSpec()`.
2. The **normalizer** at [`src/utils/normalizeSpec.ts`](../../src/utils/normalizeSpec.ts)
   sorts all keys, paths, tags, parameters, and response codes for
   deterministic output regardless of insertion order.
3. The **golden snapshot** at [`golden.snap.json`](./golden.snap.json) stores
   the expected normalized output.
4. The **test suite** at [`golden-snapshot.test.ts`](./golden-snapshot.test.ts)
   regenerates the spec from fixtures, normalizes it, and diffs against the
   snapshot.

## When CI fails

CI will fail when:

- A **new route** is added to the fixtures but the snapshot is not updated.
- An **existing route's schema** is modified (different response codes,
  changed request body, etc.).
- The **normalizer logic** changes, producing different key ordering.
- **Path parameter names** or **tag descriptions** are changed.

## How to update the snapshot

After making intentional changes to routes or the OpenAPI generator:

```bash
npm run snapshot:update
```

This runs `scripts/update-snapshot.ts`, which:
1. Generates the spec from the canonical fixture routes
2. Normalizes it for deterministic output
3. Writes `tests/openapi/golden.snap.json`

Then commit the updated snapshot:

```bash
git add tests/openapi/golden.snap.json
git commit -m "chore: regenerate OpenAPI golden snapshot"
```

## Relationship to other tests

| Test file | What it validates |
|---|---|
| `tests/unit/utils/openapi.test.ts` | Individual operation builders — schema shapes, auth requirements, parameters |
| `tests/contract/openapi-snapshot.test.ts` | Live Express app routes match `docs/openapi.json` |
| **`tests/openapi/golden-snapshot.test.ts`** | OpenAPI generator function itself, using fixed fixtures (this directory) |

The golden snapshot tests are **independent of the runtime Express app** —
they test the generator in isolation with known inputs. This catches logic
regressions even if the router changes. The contract test at
`tests/contract/` catches drift between the live app and the committed
`docs/openapi.json`.

## File structure

```
tests/openapi/
├── README.md                    # This file
├── fixtures/
│   └── routes.ts                # Canonical route fixtures (shared)
├── golden.snap.json             # Golden snapshot (auto-generated)
└── golden-snapshot.test.ts      # Test suite
```
