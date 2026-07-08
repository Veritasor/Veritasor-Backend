# Response Compression

Veritasor compresses HTTP responses with **brotli preferred, gzip as a
fallback**, implemented in [`src/middleware/compression.ts`](../src/middleware/compression.ts)
and wired into the app in [`src/app.ts`](../src/app.ts) immediately after body
parsing and CORS.

## Behaviour

For every response the middleware:

1. Reads the request `Accept-Encoding` header and selects the best supported
   encoding — `br` when offered, otherwise `gzip`. Encodings disabled with
   `;q=0` are honoured. If neither is acceptable the response is sent untouched.
2. Buffers the response body (so streamed `res.write(...)` + `res.end()` is
   reassembled and compressed as a whole) and then decides whether to compress.

A response is compressed only when **all** of these hold:

| Condition | Default |
| --- | --- |
| Uncompressed size ≥ threshold | `1024` bytes (1KB) |
| `Content-Type` is compressible | text / json / javascript / xml / svg / form |
| `Content-Encoding` not already set | — |
| Status is not `204` / `304` | — |
| `Cache-Control` does **not** contain `no-transform` | — |
| Response does **not** set a session cookie (BREACH guard) | see below |
| Response body does **not** contain a CSRF token (BREACH guard) | see below |
| Compression not disabled for the route | see `disableCompression` |

When compressed, the middleware sets `Content-Encoding`, refreshes
`Content-Length`, and always adds `Vary: Accept-Encoding` so shared caches keep
encoded and unencoded variants apart.

## BREACH / CRIME guard

BREACH-class attacks recover secrets (most importantly CSRF tokens) by observing
how the compressed size of a response changes as attacker-controlled input is
reflected into it. To remove that risk we **never compress** a response that:

- sets a session/auth cookie — any `Set-Cookie` whose name matches a configured
  session cookie name (`session`, `connect.sid`, `csrf`, `refresh_token`, …), or
- contains a CSRF/XSRF token field in its body (`csrfToken`, `_csrf`,
  `xsrf-token`, …).

These secret-bearing responses are sent uncompressed.

## Per-route opt-out

To disable compression for a single response (e.g. an endpoint that streams a
pre-compressed artefact, or one with bespoke caching needs), call
`disableCompression(res)` before sending:

```ts
import { disableCompression } from "../middleware/compression.js";

router.get("/export.tar.gz", (req, res) => {
  disableCompression(res);
  streamArchive(res);
});
```

## Configuration

`compressionMiddleware(options)` accepts:

- `threshold` — minimum uncompressed size in bytes (default `1024`).
- `sessionCookieNames` — cookie names treated as session cookies for the BREACH
  guard.
- `csrfFieldNames` — body field names treated as CSRF tokens for the BREACH
  guard.

## Tests

[`tests/unit/compression.test.ts`](../tests/unit/compression.test.ts) covers
encoding selection (brotli preference, gzip fallback, `q=0`, wildcard),
threshold behaviour, `no-transform`, non-compressible content types, the BREACH
guards (session cookie and CSRF body), the per-route opt-out, chunked/streamed
responses, and the no-double-encoding path.
