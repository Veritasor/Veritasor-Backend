import type { Response } from "express";

export interface CachePolicy {
  readonly name: string;
  readonly value: string;
  readonly description: string;
}

const DEFAULT_STALE_WHILE_REVALIDATE = 60;

function readStaleWhileRevalidate(env?: Record<string, string | undefined>): number {
  const raw = env?.PUBLIC_CDN_STALE_WHILE_REVALIDATE;
  if (raw) {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return DEFAULT_STALE_WHILE_REVALIDATE;
}

const staleWhileRevalidate = readStaleWhileRevalidate(
  typeof process !== "undefined" ? process.env : undefined,
);

export const CachePolicies = {
  PUBLIC_ATTESTATION_REVOKED: {
    name: "public_attestation_revoked",
    value: `public, max-age=15, stale-while-revalidate=${staleWhileRevalidate}`,
    description: "Revoked attestation — short TTL so clients learn of revocation quickly",
  } satisfies CachePolicy,

  PUBLIC_ATTESTATION_ACTIVE: {
    name: "public_attestation_active",
    value: `public, max-age=60, stale-while-revalidate=${staleWhileRevalidate}`,
    description: "Active attestation — medium TTL, paired with ETag for validation",
  } satisfies CachePolicy,

  WEBHOOK_EGRESS_IPS: (maxAge: number): CachePolicy => ({
    name: "webhook_egress_ips",
    value: `public, max-age=${maxAge}, stale-while-revalidate=${staleWhileRevalidate}`,
    description: "Egress IP manifest — long TTL since the IP set changes infrequently",
  }),

  JWKS_DOCUMENT: (maxAge: number): CachePolicy => ({
    name: "jwks_document",
    value: `public, max-age=${maxAge}, stale-while-revalidate=${staleWhileRevalidate}`,
    description: "JWKS public keys — TTL driven by key rotation schedule",
  }),

  DATA_EXPORT_DOWNLOAD: {
    name: "data_export_download",
    value: "no-cache, no-store, must-revalidate",
    description: "GDPR data export — must never be cached",
  } satisfies CachePolicy,
} as const;

export function setCacheControl(res: Response, policy: CachePolicy): void {
  res.set("Cache-Control", policy.value);
}
