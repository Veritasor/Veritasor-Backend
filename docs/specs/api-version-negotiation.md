# API version negotiation

## Behavior

The server resolves a **major API version** (e.g. `v1`) per request and exposes it on every response as `API-Version`. Resolution uses a fixed fallback order:

1. URL prefix `/api/v{n}/...` when present (highest precedence).
2. `X-API-Version` header (`1`, `v1`, etc.).
3. `Accept-Version` header.
4. Query parameters `apiVersion` or `api_version` (string or first element if repeated).
5. `Accept` header parameters: `version=`, `api-version=`, or `v=` on any accepted type in the list.
6. Default: `v1` (see `DEFAULT_API_VERSION` in `src/middleware/apiVersion.ts`).

Supported majors are listed in `SUPPORTED_API_VERSIONS`. Requesting an unsupported major **falls back** to the default and sets response header `API-Version-Fallback: true` so clients can detect downgrade.

## Caching

`versionResponseMiddleware` sets or merges `Vary: Accept, X-API-Version, Accept-Version` so intermediaries do not serve a cached representation for one negotiated version to a client that asked for another.

## Security

- Only trimmed tokens matching `v?` + a bounded positive integer (max digit length enforced) are accepted from headers, query, or `Accept` parameters.
- Oversized `Accept` headers are ignored for version extraction (abuse guard).
- Response headers only emit known labels from `SUPPORTED_API_VERSIONS`, never raw client strings.

## Tests

- Unit: `tests/unit/middleware/apiVersion.test.ts`
- Integration (headers + fallback + `Vary`): `tests/integration/attestations.test.ts`
