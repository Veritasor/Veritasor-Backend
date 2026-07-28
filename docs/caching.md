# Caching

## Public Attestations
Public attestation responses utilize the `stale-while-revalidate` Cache-Control directive to allow edge caches to serve slightly stale content while asynchronously revalidating in the background.

The `Cache-Control` header is constructed using a helper method to ensure consistent application of cache policies.

For observability, we emit an `Age` header. In a fresh response from the backend, the `Age` is 0. 

### Revoked Attestations
Revoked attestations also support `stale-while-revalidate` but typically have shorter or modified cache limits to ensure clients are quickly informed of the revocation, although currently we just serve them with `no-store` or a brief cache to prevent excessive backend load while maintaining security. Wait, actually, the PR requires "Revalidation on revoked attestation". So revoked attestations should also emit SWR cache headers so they can be cached at the edge but refreshed asynchronously.
