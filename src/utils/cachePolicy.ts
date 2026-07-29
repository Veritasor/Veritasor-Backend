/**
 * Cache Policy Matrix
 *
 * Canonical source of truth for every edge-cached endpoint in the application.
 * Both the route handlers (which emit Cache-Control headers) and the Fastly VCL
 * generator (scripts/generate-vcl.ts) consume this matrix, ensuring that the
 * backend policy is always the single source of truth.
 *
 * When adding a new cached endpoint:
 *   1. Add an entry to CACHE_POLICIES below.
 *   2. Use `getCachePolicyForRoute(path, method)` in your route handler.
 *   3. Run `npm run docs:vcl` to regenerate the VCL.
 */

export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';

export interface CacheDirectives {
  /** public | private | no-store */
  scope: 'public' | 'private' | 'no-store';
  /** max-age in seconds (0 = no caching) */
  maxAge: number;
  /** stale-while-revalidate window in seconds (0 = disabled) */
  staleWhileRevalidate: number;
  /** stale-if-error window in seconds (0 = disabled) */
  staleIfError: number;
}

export interface CachePolicyEntry {
  /** Human-readable name for the policy (used in VCL comments) */
  name: string;
  /** URL path pattern (supports :param placeholders like Express) */
  path: string;
  /** HTTP method(s) this policy applies to */
  methods: HttpMethod[];
  /** Cache directives */
  directives: CacheDirectives;
  /** Whether this endpoint supports ETag validation */
  supportsEtag: boolean;
  /** Optional: custom VCL snippets to inject for this route */
  customVcl?: string[];
  /** Description of what this endpoint caches */
  description: string;
}

/**
 * The full matrix of edge cache policies.
 * When the route handler emits Cache-Control headers it MUST use the same
 * values defined here — never hardcode TTLs in two places.
 */
export const CACHE_POLICIES: CachePolicyEntry[] = [
  {
    name: 'public-attestations-active',
    path: '/api/v1/public/attestations/:hash',
    methods: ['GET'],
    directives: {
      scope: 'public',
      maxAge: 60,
      staleWhileRevalidate: 60,
      staleIfError: 86400,
    },
    supportsEtag: true,
    description: 'Active (non-revoked) public attestation by hash identifier',
  },
  {
    name: 'public-attestations-revoked',
    path: '/api/v1/public/attestations/:hash',
    methods: ['GET'],
    directives: {
      scope: 'public',
      maxAge: 15,
      staleWhileRevalidate: 60,
      staleIfError: 3600,
    },
    supportsEtag: false,
    description: 'Revoked public attestation — shorter TTL so revocation propagates quickly',
  },
  {
    name: 'webhook-egress-ips',
    path: '/.well-known/webhook-egress-ips',
    methods: ['GET'],
    directives: {
      scope: 'public',
      maxAge: 3600,
      staleWhileRevalidate: 60,
      staleIfError: 86400,
    },
    supportsEtag: false,
    description: 'Signed manifest of NAT egress IPs used for outbound webhooks',
  },
  {
    name: 'jwks',
    path: '/.well-known/jwks.json',
    methods: ['GET'],
    directives: {
      scope: 'public',
      maxAge: 300,
      staleWhileRevalidate: 60,
      staleIfError: 86400,
    },
    supportsEtag: true,
    description: 'JSON Web Key Set for JWT signature verification',
  },
];

/**
 * Build a Cache-Control header value string from directives.
 */
export function formatCacheControl(directives: CacheDirectives): string {
  const parts: string[] = [];

  if (directives.scope === 'no-store') {
    return 'no-store';
  }

  parts.push(directives.scope);
  parts.push(`max-age=${directives.maxAge}`);

  if (directives.staleWhileRevalidate > 0) {
    parts.push(`stale-while-revalidate=${directives.staleWhileRevalidate}`);
  }

  if (directives.staleIfError > 0) {
    parts.push(`stale-if-error=${directives.staleIfError}`);
  }

  return parts.join(', ');
}

/**
 * Find the cache policy for a given route path and method.
 * This performs simple pattern matching — it replaces :param tokens with
 * regex wildcards for comparison.
 */
export function getCachePolicyForRoute(
  path: string,
  method: HttpMethod,
): CachePolicyEntry | undefined {
  return CACHE_POLICIES.find((policy) => {
    if (!policy.methods.includes(method)) return false;
    // Convert Express-style :param patterns to a regex for matching
    const pattern = new RegExp(
      `^${policy.path.replace(/:[\w]+/g, '[^/]+')}$`,
    );
    return pattern.test(path);
  });
}
