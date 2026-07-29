/**
 * Webhook Egress IP Allow-List  (issue #534)
 *
 * Enterprise consumers need a stable, machine-readable list of source IPs that
 * Veritasor uses when dispatching outbound webhooks.  This module:
 *
 *  1. Maintains the canonical IP list and a monotonic manifest version.
 *  2. Produces a signed manifest (HMAC-SHA256 over a canonical JSON payload)
 *     so consumers can verify authenticity without a public PKI dependency.
 *  3. Exposes `getSignedManifest()` consumed by the /.well-known endpoint.
 *
 * Rotation:
 *   Update `WEBHOOK_EGRESS_IPS` and bump `MANIFEST_VERSION`.  The signing key
 *   is loaded via the shared SecretAdapter so it can be rotated through the
 *   same Vault / AWS-SM / GSM pipelines used for all other secrets.
 *
 * Security notes:
 *  • The signing key should be at least 32 bytes of random data.
 *  • The manifest payload is deterministically serialised (keys sorted) so the
 *    signature is stable for a given set of IPs + version.
 *  • `signedAt` is included in the signed payload so replay of an old manifest
 *    can be detected by comparing the timestamp to the present time.
 */

import crypto from "node:crypto";
import { createSecretLoader } from "../../utils/secret-loader.js";
import { logger } from "../../utils/logger.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Known NAT egress IPs for outbound webhook traffic.
 *
 * Operators: update this list (and bump MANIFEST_VERSION) whenever IP
 * allocation changes.  The list is sorted for deterministic serialisation.
 */
export const WEBHOOK_EGRESS_IPS: readonly string[] = Object.freeze([
  "203.0.113.10",
  "203.0.113.11",
  "203.0.113.12",
]);

/**
 * Monotonic version number for the manifest.  Increment whenever IPs are
 * added, removed, or changed so consumers can detect staleness.
 */
export const MANIFEST_VERSION = 1;

/**
 * Cache TTL in seconds advertised to HTTP caches via Cache-Control.
 * Consumers should re-fetch before this window expires.
 */
export const MANIFEST_CACHE_TTL_SECONDS = 3600; // 1 hour

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EgressIpManifest {
  /** Monotonic version – bump on every IP list change. */
  version: number;
  /** Sorted list of CIDR or IPv4 addresses used as webhook egress IPs. */
  ips: string[];
  /** ISO-8601 timestamp when this manifest was generated. */
  signedAt: string;
}

export interface SignedEgressIpManifest {
  manifest: EgressIpManifest;
  /**
   * Hex-encoded HMAC-SHA256 over the canonical JSON serialisation of
   * `manifest` (keys sorted, no extra whitespace).
   */
  signature: string;
  /** Algorithm identifier – always "hmac-sha256" for this implementation. */
  algorithm: "hmac-sha256";
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Produce a canonical (stable) JSON string from the manifest.
 *
 * Keys are sorted to ensure the serialisation is deterministic regardless of
 * insertion order, so the HMAC remains stable for a given logical manifest.
 */
export function canonicaliseManifest(manifest: EgressIpManifest): string {
  // Sort ips list for determinism
  const stable: EgressIpManifest = {
    ips: [...manifest.ips].sort(),
    signedAt: manifest.signedAt,
    version: manifest.version,
  };
  return JSON.stringify(stable, Object.keys(stable).sort());
}

/**
 * Compute HMAC-SHA256 signature over `data` using `signingKey`.
 */
export function computeManifestSignature(
  data: string,
  signingKey: string
): string {
  return crypto.createHmac("sha256", signingKey).update(data).digest("hex");
}

/**
 * Verify that a `SignedEgressIpManifest` carries a valid signature.
 *
 * @param signed       - The manifest + signature to verify.
 * @param signingKey   - The HMAC key used when the manifest was signed.
 * @returns `true` if the signature is valid; `false` otherwise.
 */
export function verifyManifestSignature(
  signed: SignedEgressIpManifest,
  signingKey: string
): boolean {
  const canonical = canonicaliseManifest(signed.manifest);
  const expected = computeManifestSignature(canonical, signingKey);
  const expectedBuf = Buffer.from(expected, "hex");
  let providedBuf: Buffer;
  try {
    providedBuf = Buffer.from(signed.signature, "hex");
  } catch {
    return false;
  }
  if (expectedBuf.length !== providedBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, providedBuf);
}

// ---------------------------------------------------------------------------
// Primary API
// ---------------------------------------------------------------------------

/**
 * Build and sign the current egress IP manifest.
 *
 * The signing key is sourced from the secret loader under the key
 * `WEBHOOK_EGRESS_SIGNING_KEY`.  In production this should be a random
 * 256-bit hex string; in development the loader falls back to the env var of
 * the same name.
 *
 * @param now - Injectable clock (defaults to `new Date()`).
 */
export async function getSignedManifest(
  now: Date = new Date()
): Promise<SignedEgressIpManifest> {
  const loader = createSecretLoader();
  let signingKey: string;

  try {
    signingKey = await loader.get("WEBHOOK_EGRESS_SIGNING_KEY");
  } catch {
    // Fall back to a dev-only placeholder so local development still works;
    // production deployments must supply the secret.
    const fallback = process.env["WEBHOOK_EGRESS_SIGNING_KEY"];
    if (fallback) {
      signingKey = fallback;
    } else {
      logger.warn(
        "WEBHOOK_EGRESS_SIGNING_KEY not configured – using insecure fallback. " +
          "Set this secret in production."
      );
      signingKey = "dev-insecure-signing-key-do-not-use-in-production";
    }
  }

  const manifest: EgressIpManifest = {
    version: MANIFEST_VERSION,
    ips: [...WEBHOOK_EGRESS_IPS].sort(),
    signedAt: now.toISOString(),
  };

  const canonical = canonicaliseManifest(manifest);
  const signature = computeManifestSignature(canonical, signingKey);

  return {
    manifest,
    signature,
    algorithm: "hmac-sha256",
  };
}
