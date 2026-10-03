import crypto from 'node:crypto';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import * as attestationRepository from '../repositories/attestationRepository.js';
import { db } from '../db/client.js';
import { AppError, VRTErrorCodes } from '../types/errors.js';
import { asyncErrorHandler } from '../middleware/errorHandler.js';
import { CACHE_POLICIES, formatCacheControl } from '../utils/cachePolicy.js';
import { etagHitsTotal } from '../metrics.js';
import { optionalAuth } from '../middleware/optionalAuth.js';
import { publicGraphqlYoga } from '../graphql/publicAttestationSchema.js';
import { rateLimiter } from '../middleware/rateLimiter.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * HMAC signing secret for public attestation payloads.
 *
 * When set, every 200 response includes an `X-Attestation-Signature` header
 * that CDN edge nodes and widget consumers can verify without a DB round-trip.
 *
 * Header format: `sha256=<lowercase hex(HMAC-SHA256(secret, canonicalJSON))>`
 *
 * When not set the header is omitted (backward-compatible with existing callers).
 */
const ATTESTATION_SIGNING_SECRET = process.env.ATTESTATION_SIGNING_SECRET ?? '';

const HASH_PARAM_SCHEMA = z.string().min(1).max(512);

// ---------------------------------------------------------------------------
// Cache policy look-up (from canonical matrix in cachePolicy.ts)
// ---------------------------------------------------------------------------

const activePolicy = CACHE_POLICIES.find(
  (p) => p.name === 'public-attestations-active',
);
const revokedPolicy = CACHE_POLICIES.find(
  (p) => p.name === 'public-attestations-revoked',
);

// ---------------------------------------------------------------------------
// Rate limiter — public, unauthenticated traffic
// ---------------------------------------------------------------------------

const publicLookupRateLimiter = rateLimiter({
  bucket: 'public-attestations:lookup',
  max: 60,
  windowMs: 60_000,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Deterministically serialises `payload` by sorting keys before JSON encoding.
 * Ensures ETag / signature values are stable regardless of insertion order.
 */
function sortedJson(payload: Record<string, unknown>): string {
  const sorted = Object.keys(payload)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = payload[key];
      return acc;
    }, {});
  return JSON.stringify(sorted);
}

/**
 * Computes a strong ETag for `payload` as a quoted SHA-256/base64 string.
 */
function computeEtag(payload: Record<string, unknown>): string {
  const hash = crypto.createHash('sha256').update(sortedJson(payload)).digest('base64');
  return `"${hash}"`;
}

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

/**
 * Returns `true` when the client's `If-Modified-Since` date is at or after the
 * resource's last-modified time (i.e., the client already has the latest version).
 *
 * Truncates to-the-second precision per RFC 7232 §2.3.  Returns `false` when
 * the header is missing or unparseable so the request falls through normally.
 */
function isNotModifiedSince(
  ifModifiedSince: string | undefined,
  lastModified: Date,
): boolean {
  if (!ifModifiedSince) return false;
  const clientDate = new Date(ifModifiedSince);
  if (isNaN(clientDate.getTime())) return false;
  return (
    Math.floor(lastModified.getTime() / 1000) <=
    Math.floor(clientDate.getTime() / 1000)
  );
}

/**
 * Signs `payload` with HMAC-SHA256 using `ATTESTATION_SIGNING_SECRET`.
 * Returns the header value string, or `null` when no secret is configured.
 *
 * Format: `sha256=<lowercase hex>`
 */
function signPayload(payload: Record<string, unknown>): string | null {
  if (!ATTESTATION_SIGNING_SECRET) return null;
  const sig = crypto
    .createHmac('sha256', ATTESTATION_SIGNING_SECRET)
    .update(sortedJson(payload))
    .digest('hex');
  return `sha256=${sig}`;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export const publicAttestationsRouter = Router();

publicAttestationsRouter.use('/graphql', optionalAuth, publicGraphqlYoga);

/**
 * GET /api/v1/public/attestations/:hash
 *
 * Returns a slim, optionally-signed attestation payload for embedding in
 * widgets and crawlers.  `:hash` resolves against the Merkle root hash first
 * (primary use-case for credential holders) and falls back to the attestation
 * UUID (backward compatibility for existing integrations).
 *
 * Cache semantics
 * ───────────────
 * Active:  Cache-Control per `public-attestations-active` policy; ETag;
 *          Last-Modified; optional X-Attestation-Signature.
 * Revoked: 410 Gone with short-TTL Cache-Control (revocation propagates fast).
 * Missing: 404 with no-store.
 *
 * Conditional requests
 * ────────────────────
 * If-None-Match      — ETag comparison; responds 304 on match.
 * If-Modified-Since  — createdAt comparison; responds 304 when current.
 *
 * Security
 * ────────
 * - Rate limited: 60 req/min per IP.
 * - Parameter bounded and sanitised (min 1, max 512 chars).
 * - No internal details, secrets, or stack traces in error responses.
 */
publicAttestationsRouter.get(
  '/:hash',
  publicLookupRateLimiter,
  asyncErrorHandler(async (req: Request, res: Response) => {
    // --- Parameter validation ------------------------------------------------
    const hashResult = HASH_PARAM_SCHEMA.safeParse(req.params.hash);
    if (!hashResult.success) {
      throw new AppError('Invalid attestation identifier', 400, VRTErrorCodes.VRT_0002);
    }

    const hash = hashResult.data;

    // --- Repository look-up --------------------------------------------------
    // Resolve by Merkle root first (credential-holder use-case), then by UUID
    // (legacy integrations that stored the internal id).
    let attestation = await attestationRepository.getByMerkleRoot(db, hash);
    if (!attestation) {
      attestation = await attestationRepository.getById(db, hash);
    }

    // --- 404 Not Found -------------------------------------------------------
    if (!attestation) {
      res.status(404).json({
        status: 'error',
        code: 'NOT_FOUND',
        message: 'Attestation not found',
      });
      return;
    }

    // --- 410 Gone (revoked) --------------------------------------------------
    if (attestation.status === 'revoked') {
      res.set({
        'Cache-Control': revokedPolicy
          ? formatCacheControl(revokedPolicy.directives)
          : 'public, max-age=15, stale-while-revalidate=60',
        'Age': '0',
      });
      res.status(410).json({
        status: 'error',
        code: 'GONE',
        message: 'Attestation has been revoked',
      });
      return;
    }

    // --- Slim public payload -------------------------------------------------
    const payload = {
      id: attestation.id,
      businessId: attestation.businessId,
      period: attestation.period,
      merkleRoot: attestation.merkleRoot,
      txHash: attestation.txHash,
      status: attestation.status,
      attestedAt: attestation.createdAt.toISOString(),
    };

    // --- Caching headers -----------------------------------------------------
    const etag = computeEtag(payload);
    const lastModified = attestation.createdAt;
    const lastModifiedStr = lastModified.toUTCString();
    const cacheControl = activePolicy
      ? formatCacheControl(activePolicy.directives)
      : 'public, max-age=60, stale-while-revalidate=60';

    // ETag conditional (takes priority over If-Modified-Since per RFC 7232 §6)
    if (matchEtag(req.headers['if-none-match'], etag)) {
      etagHitsTotal.inc({ route: 'publicAttestations', result: 'hit' });
      res.set({
        'ETag': etag,
        'Last-Modified': lastModifiedStr,
        'Cache-Control': cacheControl,
      });
      res.status(304).end();
      return;
    }

    // If-Modified-Since conditional
    if (isNotModifiedSince(req.headers['if-modified-since'], lastModified)) {
      etagHitsTotal.inc({ route: 'publicAttestations', result: 'hit' });
      res.set({
        'ETag': etag,
        'Last-Modified': lastModifiedStr,
        'Cache-Control': cacheControl,
      });
      res.status(304).end();
      return;
    }

    etagHitsTotal.inc({ route: 'publicAttestations', result: 'miss' });

    // --- 200 OK --------------------------------------------------------------
    const responseHeaders: Record<string, string> = {
      'Cache-Control': cacheControl,
      'ETag': etag,
      'Last-Modified': lastModifiedStr,
      'Age': '0',
    };

    // Attach HMAC signature when signing secret is configured
    const signature = signPayload(payload);
    if (signature) {
      responseHeaders['X-Attestation-Signature'] = signature;
    }

    res.set(responseHeaders);
    res.status(200).json({
      status: 'success',
      data: payload,
    });
  }),
);
