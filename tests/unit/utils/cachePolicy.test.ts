/**
 * Tests for src/utils/cachePolicy.ts
 * Covers the cache policy matrix, formatCacheControl, and getCachePolicyForRoute.
 */

import { describe, it, expect } from 'vitest';
import {
  CACHE_POLICIES,
  formatCacheControl,
  getCachePolicyForRoute,
  type CacheDirectives,
} from '../../../src/utils/cachePolicy';

// ─── Static Matrix Consistency ───────────────────────────────────────────

describe('CACHE_POLICIES matrix', () => {
  it('has at least the known expected entries', () => {
    const names = CACHE_POLICIES.map((p) => p.name);
    expect(names).toContain('public-attestations-active');
    expect(names).toContain('public-attestations-revoked');
    expect(names).toContain('webhook-egress-ips');
    expect(names).toContain('jwks');
  });

  it('each entry has a non-empty name, path, description, and at least one method', () => {
    for (const policy of CACHE_POLICIES) {
      expect(policy.name).toBeTruthy();
      expect(policy.path).toMatch(/^\//);
      expect(policy.description).toBeTruthy();
      expect(policy.methods.length).toBeGreaterThan(0);
    }
  });

  it('each entry has valid CacheDirectives (maxAge >= 0, staleWhileRevalidate >= 0, staleIfError >= 0)', () => {
    for (const policy of CACHE_POLICIES) {
      expect(policy.directives.maxAge).toBeGreaterThanOrEqual(0);
      expect(policy.directives.staleWhileRevalidate).toBeGreaterThanOrEqual(0);
      expect(policy.directives.staleIfError).toBeGreaterThanOrEqual(0);
    }
  });

  it('revoked attestations have a shorter max-age than active attestations', () => {
    const active = CACHE_POLICIES.find((p) => p.name === 'public-attestations-active');
    const revoked = CACHE_POLICIES.find((p) => p.name === 'public-attestations-revoked');
    expect(active).toBeDefined();
    expect(revoked).toBeDefined();
    expect(revoked!.directives.maxAge).toBeLessThan(active!.directives.maxAge);
  });

  it('JWKS TTL is distinct and reasonable (<= 300s)', () => {
    const policy = CACHE_POLICIES.find((p) => p.name === 'jwks');
    expect(policy).toBeDefined();
    expect(policy!.directives.maxAge).toBeLessThanOrEqual(300);
  });

  it('all entries use "public" scope', () => {
    for (const policy of CACHE_POLICIES) {
      expect(policy.directives.scope).toBe('public');
    }
  });
});

// ─── formatCacheControl ──────────────────────────────────────────────────

describe('formatCacheControl', () => {
  it('formats public scope with max-age and stale-while-revalidate', () => {
    const result = formatCacheControl({
      scope: 'public',
      maxAge: 60,
      staleWhileRevalidate: 30,
      staleIfError: 0,
    });
    expect(result).toBe('public, max-age=60, stale-while-revalidate=30');
  });

  it('includes stale-if-error when non-zero', () => {
    const result = formatCacheControl({
      scope: 'public',
      maxAge: 300,
      staleWhileRevalidate: 60,
      staleIfError: 86400,
    });
    expect(result).toBe(
      'public, max-age=300, stale-while-revalidate=60, stale-if-error=86400',
    );
  });

  it('omits stale-while-revalidate when zero', () => {
    const result = formatCacheControl({
      scope: 'public',
      maxAge: 60,
      staleWhileRevalidate: 0,
      staleIfError: 0,
    });
    expect(result).toBe('public, max-age=60');
  });

  it('returns "no-store" when scope is no-store', () => {
    const result = formatCacheControl({
      scope: 'no-store',
      maxAge: 0,
      staleWhileRevalidate: 0,
      staleIfError: 0,
    });
    expect(result).toBe('no-store');
  });

  it('handles private scope correctly', () => {
    const result = formatCacheControl({
      scope: 'private',
      maxAge: 0,
      staleWhileRevalidate: 0,
      staleIfError: 0,
    });
    expect(result).toBe('private, max-age=0');
  });
});

// ─── getCachePolicyForRoute ──────────────────────────────────────────────

describe('getCachePolicyForRoute', () => {
  it('finds the active attestation policy by path and GET method', () => {
    const policy = getCachePolicyForRoute(
      '/api/v1/public/attestations/abc123',
      'GET',
    );
    expect(policy).toBeDefined();
    expect(policy!.name).toBe('public-attestations-active');
  });

  it('finds the jwks policy by path', () => {
    const policy = getCachePolicyForRoute(
      '/.well-known/jwks.json',
      'GET',
    );
    expect(policy).toBeDefined();
    expect(policy!.name).toBe('jwks');
  });

  it('finds the webhook egress IPs policy', () => {
    const policy = getCachePolicyForRoute(
      '/.well-known/webhook-egress-ips',
      'GET',
    );
    expect(policy).toBeDefined();
    expect(policy!.name).toBe('webhook-egress-ips');
  });

  it('returns undefined for an unknown route', () => {
    const policy = getCachePolicyForRoute('/api/v1/unknown', 'GET');
    expect(policy).toBeUndefined();
  });

  it('returns undefined when method does not match', () => {
    const policy = getCachePolicyForRoute(
      '/.well-known/jwks.json',
      'POST',
    );
    expect(policy).toBeUndefined();
  });

  it('matches routes with query strings', () => {
    const policy = getCachePolicyForRoute(
      '/api/v1/public/attestations/xyz789?foo=bar',
      'GET',
    );
    expect(policy).toBeDefined();
    expect(policy!.name).toBe('public-attestations-active');
  });
});
