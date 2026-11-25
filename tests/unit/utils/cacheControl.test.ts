/**
 * Tests for src/utils/cacheControl.ts
 * Covers CachePolicies, setCacheControl, and env-derived stale-while-revalidate
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Response } from 'express';
import {
  CachePolicies,
  setCacheControl,
} from '../../../src/utils/cacheControl';

// ─── Static Policy Values ────────────────────────────────────────────────

describe('CachePolicies static values', () => {
  it('PUBLIC_ATTESTATION_REVOKED has correct value with default stale-while-revalidate', () => {
    const policy = CachePolicies.PUBLIC_ATTESTATION_REVOKED;
    expect(policy.name).toBe('public_attestation_revoked');
    expect(policy.value).toBe('public, max-age=15, stale-while-revalidate=60');
    expect(policy.description).toBe('Revoked attestation — short TTL so clients learn of revocation quickly');
  });

  it('PUBLIC_ATTESTATION_ACTIVE has correct value with default stale-while-revalidate', () => {
    const policy = CachePolicies.PUBLIC_ATTESTATION_ACTIVE;
    expect(policy.name).toBe('public_attestation_active');
    expect(policy.value).toBe('public, max-age=60, stale-while-revalidate=60');
    expect(policy.description).toBe('Active attestation — medium TTL, paired with ETag for validation');
  });

  it('DATA_EXPORT_DOWNLOAD has correct value (no caching)', () => {
    const policy = CachePolicies.DATA_EXPORT_DOWNLOAD;
    expect(policy.name).toBe('data_export_download');
    expect(policy.value).toBe('no-cache, no-store, must-revalidate');
    expect(policy.description).toBe('GDPR data export — must never be cached');
  });
});

// ─── Dynamic Policy Functions ─────────────────────────────────────────────

describe('CachePolicies dynamic functions', () => {
  it('WEBHOOK_EGRESS_IPS interpolates max-age correctly', () => {
    const policy = CachePolicies.WEBHOOK_EGRESS_IPS(300);
    expect(policy.name).toBe('webhook_egress_ips');
    expect(policy.value).toBe('public, max-age=300, stale-while-revalidate=60');
    expect(policy.description).toBe('Egress IP manifest — long TTL since the IP set changes infrequently');
  });

  it('WEBHOOK_EGRESS_IPS with different max-age values', () => {
    expect(CachePolicies.WEBHOOK_EGRESS_IPS(120).value).toBe('public, max-age=120, stale-while-revalidate=60');
    expect(CachePolicies.WEBHOOK_EGRESS_IPS(600).value).toBe('public, max-age=600, stale-while-revalidate=60');
  });

  it('JWKS_DOCUMENT interpolates max-age correctly', () => {
    const policy = CachePolicies.JWKS_DOCUMENT(300);
    expect(policy.name).toBe('jwks_document');
    expect(policy.value).toBe('public, max-age=300, stale-while-revalidate=60');
    expect(policy.description).toBe('JWKS public keys — TTL driven by key rotation schedule');
  });

  it('JWKS_DOCUMENT with different max-age values', () => {
    expect(CachePolicies.JWKS_DOCUMENT(180).value).toBe('public, max-age=180, stale-while-revalidate=60');
    expect(CachePolicies.JWKS_DOCUMENT(600).value).toBe('public, max-age=600, stale-while-revalidate=60');
  });
});

// ─── setCacheControl ─────────────────────────────────────────────────────

describe('setCacheControl', () => {
  it('sets Cache-Control header on Response', () => {
    const mockRes = {
      set: vi.fn(),
    } as unknown as Response;

    const policy = CachePolicies.PUBLIC_ATTESTATION_ACTIVE;
    setCacheControl(mockRes, policy);

    expect(mockRes.set).toHaveBeenCalledWith('Cache-Control', policy.value);
  });

  it('works with dynamic policies', () => {
    const mockRes = {
      set: vi.fn(),
    } as unknown as Response;

    const policy = CachePolicies.WEBHOOK_EGRESS_IPS(300);
    setCacheControl(mockRes, policy);

    expect(mockRes.set).toHaveBeenCalledWith('Cache-Control', policy.value);
  });
});

// ─── readStaleWhileRevalidate (internal function) ────────────────────────

// We need to import the internal function for testing
// Since it's not exported, we'll test the observable behavior through the policies
// by documenting that the env var is read at module initialization time

describe('stale-while-revalidate behavior', () => {
  it('default value is 60 seconds when PUBLIC_CDN_STALE_WHILE_REVALIDATE is not set', () => {
    // This is tested implicitly by the static policy tests above
    // which all use the default value of 60
    const active = CachePolicies.PUBLIC_ATTESTATION_ACTIVE;
    expect(active.value).toContain('stale-while-revalidate=60');
  });

  it('the value is consistent across all policies that use it', () => {
    const active = CachePolicies.PUBLIC_ATTESTATION_ACTIVE;
    const revoked = CachePolicies.PUBLIC_ATTESTATION_REVOKED;
    const webhook = CachePolicies.WEBHOOK_EGRESS_IPS(300);
    const jwks = CachePolicies.JWKS_DOCUMENT(300);

    // Extract the stale-while-revalidate value from each policy
    const extractSwr = (value: string) => {
      const match = value.match(/stale-while-revalidate=(\d+)/);
      return match ? match[1] : null;
    };

    const activeSwr = extractSwr(active.value);
    const revokedSwr = extractSwr(revoked.value);
    const webhookSwr = extractSwr(webhook.value);
    const jwksSwr = extractSwr(jwks.value);

    expect(activeSwr).toBe(revokedSwr);
    expect(activeSwr).toBe(webhookSwr);
    expect(activeSwr).toBe(jwksSwr);
  });

  it('DATA_EXPORT_DOWNLOAD does not use stale-while-revalidate', () => {
    const policy = CachePolicies.DATA_EXPORT_DOWNLOAD;
    expect(policy.value).not.toContain('stale-while-revalidate');
    expect(policy.value).toBe('no-cache, no-store, must-revalidate');
  });
});
