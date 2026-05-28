import { Request, Response, NextFunction } from 'express'

/**
 * @title API version negotiation
 * @notice Resolves which documented API revision applies to a request when the URL path
 *         omits `/api/v{n}` (legacy unversioned mounts) or when clients advertise a preference
 *         via headers or Accept parameters.
 * @dev Security: only bounded numeric tokens are accepted. Arbitrary strings are ignored so
 *      response headers never reflect unsanitized client input. Unsupported major versions
 *      fall back to {@link DEFAULT_API_VERSION} and set `API-Version-Fallback: true`.
 */

/** Major versions implemented by this deployment. Append entries when shipping new majors. */
export const SUPPORTED_API_VERSIONS = ['v1'] as const
export type ApiVersionString = (typeof SUPPORTED_API_VERSIONS)[number]
export const DEFAULT_API_VERSION: ApiVersionString = 'v1'

const MAX_VERSION_DIGITS = 3

export type ApiNegotiationSource =
  | 'path'
  | 'x-api-version'
  | 'accept-version'
  | 'query'
  | 'accept'
  | 'default'

declare global {
  namespace Express {
    interface Request {
      /** Resolved major version label, e.g. `v1`. */
      apiVersion?: ApiVersionString
      /** True when the requested major was unsupported and {@link DEFAULT_API_VERSION} was used. */
      apiVersionDidFallback?: boolean
      /** Which negotiation step won (for observability, not sent on the wire). */
      apiVersionSource?: ApiNegotiationSource
    }
  }
}

function isSupportedLabel(label: string): label is ApiVersionString {
  return (SUPPORTED_API_VERSIONS as readonly string[]).includes(label)
}

function majorToLabel(major: number): string {
  return `v${major}`
}

/**
 * Parses a single major version token from an untrusted string (header, query fragment, etc.).
 *
 * @param raw Raw header or query value
 * @returns Major version number, or `null` if absent or invalid
 *
 * @dev Rejects non-integers, negative numbers, zero, overlong digit strings, and values over
 *      ~999 to keep parsing deterministic and cheap (header smuggling / ReDoS hardening).
 */
export function parseVersionToken(raw: string | undefined): number | null {
  if (raw === undefined) return null
  const s = String(raw).trim()
  if (s.length === 0 || s.length > 32) return null
  const m = s.match(/^v?(\d+)$/i)
  if (!m) return null
  const digits = m[1]
  if (digits.length > MAX_VERSION_DIGITS) return null
  const n = parseInt(digits, 10)
  if (!Number.isFinite(n) || n < 1) return null
  return n
}

function resolveMajor(major: number): { version: ApiVersionString; fallback: boolean } {
  const label = majorToLabel(major)
  if (isSupportedLabel(label)) {
    return { version: label, fallback: false }
  }
  return { version: DEFAULT_API_VERSION, fallback: true }
}

const ACCEPT_HEADER_MAX = 1024

/**
 * Reads `version`, `api-version`, or `v` parameters from an `Accept` header list.
 *
 * @dev Only examines bounded input; ignores media types, only parameter keys listed above.
 */
export function extractVersionFromAccept(acceptHeader: string | undefined): number | null {
  if (acceptHeader == null || typeof acceptHeader !== 'string') return null
  if (acceptHeader.length > ACCEPT_HEADER_MAX) return null
  const segments = acceptHeader.split(',')
  for (const segment of segments) {
    const params = segment.split(';')
    for (let i = 1; i < params.length; i++) {
      const param = params[i].trim().toLowerCase()
      const eq = param.indexOf('=')
      if (eq === -1) continue
      const key = param.slice(0, eq).trim()
      let val = param.slice(eq + 1).trim()
      if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1)
      if (key === 'version' || key === 'api-version' || key === 'v') {
        const n = parseVersionToken(val)
        if (n !== null) return n
      }
    }
  }
  return null
}

/**
 * Determines API major version using static fallback order:
 * 1. Path prefix `/api/v{n}/...` (strongest signal — matches versioned mounts)
 * 2. `X-API-Version`
 * 3. `Accept-Version`
 * 4. Query `apiVersion` or `api_version`
 * 5. `Accept` parameter (`version=`, `api-version=`, `v=`)
 * 6. {@link DEFAULT_API_VERSION}
 *
 * @dev Path and header signals that disagree are not merged: path wins whenever it matches.
 */
export function negotiateApiVersion(req: Pick<Request, 'path' | 'headers' | 'query'>): {
  version: ApiVersionString
  fallback: boolean
  source: ApiNegotiationSource
} {
  const pathMatch = req.path.match(/^\/api\/v(\d+)/)
  if (pathMatch) {
    const digits = pathMatch[1]
    if (digits.length <= MAX_VERSION_DIGITS) {
      const major = parseInt(digits, 10)
      if (Number.isFinite(major) && major >= 1) {
        const { version, fallback } = resolveMajor(major)
        return { version, fallback, source: 'path' }
      }
    }
  }

  const xApi = req.headers['x-api-version']
  if (typeof xApi === 'string') {
    const major = parseVersionToken(xApi)
    if (major !== null) {
      const { version, fallback } = resolveMajor(major)
      return { version, fallback, source: 'x-api-version' }
    }
  }

  const acceptVersion = req.headers['accept-version']
  if (typeof acceptVersion === 'string') {
    const major = parseVersionToken(acceptVersion)
    if (major !== null) {
      const { version, fallback } = resolveMajor(major)
      return { version, fallback, source: 'accept-version' }
    }
  }

  const qRaw = req.query['apiVersion'] ?? req.query['api_version']
  const q =
    typeof qRaw === 'string'
      ? qRaw
      : Array.isArray(qRaw) && typeof qRaw[0] === 'string'
        ? qRaw[0]
        : undefined
  if (typeof q === 'string') {
    const major = parseVersionToken(q)
    if (major !== null) {
      const { version, fallback } = resolveMajor(major)
      return { version, fallback, source: 'query' }
    }
  }

  const fromAccept = extractVersionFromAccept(req.headers.accept)
  if (fromAccept !== null) {
    const { version, fallback } = resolveMajor(fromAccept)
    return { version, fallback, source: 'accept' }
  }

  return {
    version: DEFAULT_API_VERSION,
    fallback: false,
    source: 'default',
  }
}

/** Applies {@link negotiateApiVersion} and attaches the result to `req`. */
export function apiVersionMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const { version, fallback, source } = negotiateApiVersion(req)
  req.apiVersion = version
  req.apiVersionDidFallback = fallback
  req.apiVersionSource = source
  next()
}

function mergeVaryHeader(res: Response, extra: string): void {
  const current = res.getHeader('Vary')
  const tokens = new Set<string>()
  if (current) {
    const s = Array.isArray(current) ? current.join(', ') : String(current)
    for (const p of s.split(',')) {
      const t = p.trim()
      if (t) tokens.add(t)
    }
  }
  for (const p of extra.split(',')) {
    const t = p.trim()
    if (t) tokens.add(t)
  }
  if (tokens.size > 0) res.setHeader('Vary', [...tokens].join(', '))
}

/**
 * Emits `API-Version` (always a supported label). When an unsupported major was requested,
 * adds `API-Version-Fallback: true` so clients can detect downgrade behavior.
 *
 * @dev Adds `Vary: Accept, X-API-Version, Accept-Version` (merged with any existing `Vary`)
 *      so shared caches treat versioned representations distinctly.
 */
export function versionResponseMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const apiVersion = req.apiVersion ?? DEFAULT_API_VERSION
  res.setHeader('API-Version', apiVersion)
  if (req.apiVersionDidFallback) {
    res.setHeader('API-Version-Fallback', 'true')
  }
  mergeVaryHeader(res, 'Accept, X-API-Version, Accept-Version')
  next()
}
