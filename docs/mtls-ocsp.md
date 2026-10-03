# OCSP stapling verification for mTLS client certificates

Veritasor Backend can enforce client-certificate revocation checks during mTLS
authorization. The revocation path prefers a stapled OCSP response and falls
back to a CRL when the staple is missing, stale, or unverifiable.

## Configuration

```bash
export MTLS_ENABLED=true
export MTLS_CA_PATH=/etc/veritasor/ca.pem
export MTLS_CERT_PATH=/etc/veritasor/server-cert.pem
export MTLS_KEY_PATH=/etc/veritasor/server-key.pem

export MTLS_OCSP_ENABLED=true
export MTLS_OCSP_CACHE_TTL_MS=300000
export MTLS_OCSP_ISSUER_PATH=/etc/veritasor/issuer.pem   # optional; defaults to MTLS_CA_PATH
export MTLS_CRL_PATH=/etc/veritasor/client-ca.crl
```

## Verification flow

1. The middleware reads the client certificate from the TLS socket.
2. If a stapled OCSP response is available on the socket, OpenSSL verifies it
   against the configured issuer and CA material.
3. Successful OCSP checks are cached until the earlier of:
   - `Next Update` from the response
   - `MTLS_OCSP_CACHE_TTL_MS`
4. If the OCSP response is missing, stale, or unverifiable, the middleware
   falls back to a CRL check using `openssl verify -crl_check`.
5. Revoked certificates are rejected with `MTLS_CERT_REVOKED`.
6. Certificates whose revocation status cannot be validated are rejected with
   `MTLS_REVOCATION_CHECK_FAILED`.

## Security notes

- Revocation checks are fail-closed when enabled.
- `MTLS_CRL_PATH` is required when OCSP verification is enabled so the backend
  always has a deterministic fallback when a staple is stale or absent.
- OCSP responses are only trusted while fresh; stale responses are not cached
  as successful validations.
- The implementation assumes the TLS stack or terminating proxy exposes the
  client's stapled OCSP response on the socket (`ocspResponse` or
  `getOCSPResponse()`), because Node does not provide a first-class Express
  middleware API for client-certificate OCSP staples.

## Tests

The unit suite covers:

- good / revoked / stale OCSP responses
- CRL fallback success and revocation rejection
- cache reuse
- missing staple handling
- middleware error and authorization paths
