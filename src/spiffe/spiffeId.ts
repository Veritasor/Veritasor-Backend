import type { PeerCertificate } from "node:tls";

const SPIFFE_URI_PREFIX = "URI:spiffe://";

/**
 * Returns true when `id` is a SPIFFE ID belonging to `trustDomain`.
 */
export function isSpiffeIdInTrustDomain(id: string, trustDomain: string): boolean {
  const normalizedDomain = trustDomain.trim();
  if (!normalizedDomain) {
    return false;
  }
  return id.startsWith(`spiffe://${normalizedDomain}/`);
}

/**
 * Extract the first SPIFFE ID from a peer certificate's Subject Alternative Name
 * that matches the configured trust domain.
 */
export function extractSpiffeIdFromCert(
  cert: PeerCertificate,
  trustDomain: string,
): string | undefined {
  const subjectAltName = cert.subjectaltname;
  if (!subjectAltName || !trustDomain.trim()) {
    return undefined;
  }

  for (const entry of subjectAltName.split(", ")) {
    if (!entry.startsWith(SPIFFE_URI_PREFIX)) {
      continue;
    }
    const spiffeId = entry.slice(4);
    if (isSpiffeIdInTrustDomain(spiffeId, trustDomain)) {
      return spiffeId;
    }
  }

  return undefined;
}

/**
 * Parse a comma-separated SPIFFE ID allowlist from configuration.
 */
export function parseSpiffeIdAllowlist(raw: string | undefined): string[] {
  if (!raw?.trim()) {
    return [];
  }
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}
