# Cache-Control policy matrix

All Cache-Control directives are defined in [`src/utils/cacheControl.ts`](../src/utils/cacheControl.ts)
and applied via `setCacheControl(res, policy)` — the single source of truth.

## Policy table

| Policy name | Endpoint | Directive | Rationale |
|---|---|---|---|
| `PUBLIC_ATTESTATION_REVOKED` | `GET /api/v1/public/attestations/:hash` (revoked) | `public, max-age=15, stale-while-revalidate=60` | Revoked attestation — short TTL so clients learn of revocation quickly |
| `PUBLIC_ATTESTATION_ACTIVE` | `GET /api/v1/public/attestations/:hash` (active) | `public, max-age=60, stale-while-revalidate=60` | Active attestation — medium TTL, paired with ETag for validation |
| `WEBHOOK_EGRESS_IPS` | `GET /.well-known/webhook-egress-ips` | `public, max-age=3600, stale-while-revalidate=60` | Egress IP manifest — long TTL since the IP set changes infrequently |
| `JWKS_DOCUMENT` | `GET /.well-known/jwks.json` | `public, max-age=<rotation-ttl>, stale-while-revalidate=60` | JWKS public keys — TTL driven by key rotation schedule |
| `DATA_EXPORT_DOWNLOAD` | `GET /api/users/me/export/:token` | `no-cache, no-store, must-revalidate` | GDPR data export — must never be cached |

## Design

Each policy is a `CachePolicy` object carrying a `name`, `value`, and `description`.
Policies that accept parameters (e.g. `WEBHOOK_EGRESS_IPS(maxAge)`, `JWKS_DOCUMENT(maxAge)`)
are factory functions; invariant policies are plain objects.

The `stale-while-revalidate` seconds are configured via the
`PUBLIC_CDN_STALE_WHILE_REVALIDATE` environment variable (default `60`).
All public-cacheable endpoints use the same SWR duration so CDN edge and
enterprise proxy behaviour is consistent across the API.

## Adding a new policy

1. Add a new entry to `CachePolicies` in `src/utils/cacheControl.ts`.
2. Update this table.
3. Call `setCacheControl(res, CachePolicies.YOUR_POLICY)` in the route handler.

## Verification

To verify that a response carries the expected `Cache-Control` header:

```bash
curl -sI https://api.example.com/.well-known/webhook-egress-ips \
  | grep -i cache-control
```
