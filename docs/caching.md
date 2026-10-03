# Cache-Control policy matrix

## Cache Policy Matrix

All edge-cached endpoints are defined in a **single canonical source of truth**:
`src/utils/cachePolicy.ts`. This module exports `CACHE_POLICIES`, an array of
`CachePolicyEntry` objects describing every URL pattern, HTTP method, TTL,
stale-while-revalidate window, and ETag support.

The route handlers (`src/routes/publicAttestations.ts`,
`src/routes/webhookEgressIps.ts`, `src/app.ts`) import the matrix and use
`formatCacheControl()` to build the `Cache-Control` header — never hardcode
TTLs in two places.

### Adding a new cached endpoint

1. Add an entry to `CACHE_POLICIES` in `src/utils/cachePolicy.ts`.
2. Use `formatCacheControl(policy.directives)` in your route handler.
3. Run `npm run docs:vcl` to regenerate the Fastly VCL.
4. Commit the updated `ops/fastly/edge-cache.vcl` alongside your code.

---

## Fastly VCL Export (`scripts/generate-vcl.ts`)

The script at `scripts/generate-vcl.ts` reads the same `CACHE_POLICIES` matrix
and generates `ops/fastly/edge-cache.vcl` — a Fastly VCL snippet containing
two subroutines:

- **`vcl_fetch`** — For each cache policy, sets `beresp.ttl`,
  `beresp.stale_while_revalidate`, `beresp.stale_if_error`, the
  `Cache-Control` header, and the `Vary` header.
- **`vcl_deliver`** — Strips `ETag` from responses that don't support it
  (revoked attestations, webhook egress IP manifest) and removes the
  `Server` header for security.

### Regenerating

```bash
npm run docs:vcl          # Write ops/fastly/edge-cache.vcl
npm run docs:vcl:check    # Verify committed file matches generated output (CI)
```

### CI enforcement

A `vcl-sync-check` GitHub Actions workflow runs on every PR that touches
`src/utils/cachePolicy.ts`, `scripts/generate-vcl.ts`, or
`ops/fastly/edge-cache.vcl`. It regenerates the VCL and fails if the
committed file differs from the generated output.

During **releases**, the VCL is generated and uploaded as a build artifact
named `fastly-edge-cache-vcl`, making it available for deployment
alongside the container image.

---

## Public Attestations
Public attestation responses utilize the `stale-while-revalidate` Cache-Control directive to allow edge caches to serve slightly stale content while asynchronously revalidating in the background.

The `Cache-Control` header is constructed from the canonical cache policy matrix rather than using ad hoc helper methods.

| Policy name | Endpoint | Directive | Rationale |
|---|---|---|---|
| `PUBLIC_ATTESTATION_REVOKED` | `GET /api/v1/public/attestations/:hash` (revoked) | `public, max-age=15, stale-while-revalidate=60` | Revoked attestation — short TTL so clients learn of revocation quickly |
| `PUBLIC_ATTESTATION_ACTIVE` | `GET /api/v1/public/attestations/:hash` (active) | `public, max-age=60, stale-while-revalidate=60` | Active attestation — medium TTL, paired with ETag for validation |
| `WEBHOOK_EGRESS_IPS` | `GET /.well-known/webhook-egress-ips` | `public, max-age=3600, stale-while-revalidate=60` | Egress IP manifest — long TTL since the IP set changes infrequently |
| `JWKS_DOCUMENT` | `GET /.well-known/jwks.json` | `public, max-age=<rotation-ttl>, stale-while-revalidate=60` | JWKS public keys — TTL driven by key rotation schedule |
| `DATA_EXPORT_DOWNLOAD` | `GET /api/users/me/export/:token` | `no-cache, no-store, must-revalidate` | GDPR data export — must never be cached |

### Revoked Attestations
Revoked attestations also support `stale-while-revalidate` but with a shorter TTL (15s vs 60s for active) to ensure clients are quickly informed of revocation while still benefiting from edge caching.
