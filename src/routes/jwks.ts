import { Request, Response, Router } from 'express';
import { jwksManager } from '../utils/jwks.js';
import { CACHE_POLICIES, formatCacheControl } from '../utils/cachePolicy.js';
import { etagHitsTotal } from '../metrics.js';

/**
 * Returns `true` when the client's `If-None-Match` header matches `etag`.
 * Handles comma-separated lists and the `W/` weak-ETag prefix per RFC 7232.
 */
function matchEtag(ifNoneMatch: string | undefined, etag: string): boolean {
  if (!ifNoneMatch) return false;
  const stripWeak = (s: string) => (s.startsWith('W/') ? s.slice(2) : s);
  const target = stripWeak(etag);
  return ifNoneMatch
    .split(',')
    .map((s) => stripWeak(s.trim()))
    .some((c) => c === target);
}

export const jwksRouter = Router();

/**
 * GET /.well-known/jwks.json
 *
 * Returns the JSON Web Key Set (JWKS) document with proper ETag caching.
 *
 * Cache semantics
 * ───────────────
 * - Cache-Control per `jwks` policy
 * - ETag for conditional requests
 *
 * Conditional requests
 * ────────────────────
 * If-None-Match — ETag comparison; responds 304 on match with no body.
 */
jwksRouter.get('/', async (_req: Request, res: Response) => {
  await jwksManager.ensureLoaded();

  const jwks = jwksManager.getJwksResponse();
  const etag = jwksManager.getEtag();
  const cacheSeconds = jwksManager.getCacheTtlSeconds();

  const jwksPolicy = CACHE_POLICIES.find((p) => p.name === 'jwks');
  const cacheControl = jwksPolicy
    ? formatCacheControl(jwksPolicy.directives)
    : `public, max-age=${cacheSeconds}, stale-while-revalidate=60`;

  // ETag conditional
  if (matchEtag(_req.headers['if-none-match'], etag)) {
    etagHitsTotal.inc({ route: 'jwks', result: 'hit' });
    res.set({
      'ETag': etag,
      'Cache-Control': cacheControl,
    });
    res.status(304).end();
    return;
  }

  etagHitsTotal.inc({ route: 'jwks', result: 'miss' });

  res.set({
    'Cache-Control': cacheControl,
    'ETag': etag,
  });
  res.status(200).json(jwks);
});
