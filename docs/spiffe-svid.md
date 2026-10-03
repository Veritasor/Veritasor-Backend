# SPIFFE SVID integration for service identity

Veritasor Backend can obtain short-lived X.509 SVIDs from a SPIRE Agent
Workload API socket instead of loading long-lived static certificate files.
This reduces credential exposure and enables automatic rotation.

## Enable SPIFFE-backed mTLS

```bash
export MTLS_ENABLED=true
export MTLS_SPIFFE_ENABLED=true
export SPIFFE_TRUST_DOMAIN=example.org
export SPIFFE_WORKLOAD_API_SOCKET=unix:///tmp/spire-agent/public/api.sock

# Optional: restrict inbound client identities
export MTLS_SPIFFE_ID_ALLOWLIST="spiffe://example.org/api,spiffe://example.org/worker"
```

When `MTLS_SPIFFE_ENABLED=true`:

- The server bootstraps TLS material from the Workload API `FetchX509SVID` RPC.
- A streaming watch keeps the in-memory SVID current.
- The HTTPS listener hot-swaps credentials via `setSecureContext` on rotation.
- A TTL-based refresh timer re-fetches the SVID at 70% of certificate lifetime.

When SPIFFE mode is disabled but `MTLS_ENABLED=true`, the legacy static file
paths remain supported:

```bash
export MTLS_CA_PATH=/etc/veritasor/ca.pem
export MTLS_CERT_PATH=/etc/veritasor/cert.pem
export MTLS_KEY_PATH=/etc/veritasor/key.pem
```

## Client identity validation

With SPIFFE enabled, `src/middleware/mtls.ts` validates client certificates by
extracting the SPIFFE ID URI from the Subject Alternative Name and verifying
that it belongs to the configured trust domain. An optional allowlist can
further restrict callers.

Legacy CN allowlists continue to apply when SPIFFE mode is disabled.

## Workload API restart behavior

If the Workload API stream ends or the agent restarts, the SVID provider:

1. Clears any pending refresh timer.
2. Retries `FetchX509SVID` with exponential backoff (500 ms → 30 s cap).
3. Re-establishes the streaming watch after a successful fetch.

This keeps the process alive while SPIRE comes back and avoids serving stale
credentials after rotation.

## Security notes

- Only unix domain socket addresses are accepted for `SPIFFE_WORKLOAD_API_SOCKET`.
- `SPIFFE_TRUST_DOMAIN` is validated at boot; the process fails fast if SPIFFE
  mode is enabled without it.
- Client certificate authorization still occurs in middleware; the TLS layer
  requests client certificates but delegates rejection to application logic.
- Trust bundles returned by the Workload API are used as the server CA pool for
  mutual TLS verification.

## Local SPIRE testing

1. Run a SPIRE Agent with the Workload API socket exposed at the configured path.
2. Register a workload entry for this service.
3. Start the backend with the environment variables above.
4. Connect with a peer presenting a SPIFFE ID in the same trust domain.

## Related code

- `src/spiffe/workloadApiClient.ts` — gRPC Workload API client
- `src/spiffe/svidProvider.ts` — rotation and restart recovery
- `src/middleware/mtls.ts` — inbound identity enforcement
- `src/startup/readiness.ts` — boot-time configuration validation
