import type { PeerCertificate } from "node:tls";

const SAN_URI_PREFIX = "URI:";
const SPIFFE_URI_PREFIX = "URI:spiffe://";

/**
 * Structural validation for a SPIFFE ID parsed out of a URI SAN.
 *
 * SPIFFE IDs are strictly hierarchical URIs: query strings and fragments are
 * not part of the grammar, and ".." path segments would allow traversal-style
 * confusion when IDs are compared or logged. Returns false for anything that
 * does not look like a plain hierarchical SPIFFE ID — callers must treat that
 * as "no SPIFFE ID" (fail closed), never fall back to another identity.
 */
function isWellFormedSpiffeId(id: string): boolean {
  if (id.includes("..") || id.includes("?") || id.includes("#")) {
    return false;
  }
  return true;
}

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

  // SAN entries are comma-separated, but do not rely on an exact ", "
  // separator — trim each entry so "a,URI:x" and "a, URI:x" both parse.
  for (const rawEntry of subjectAltName.split(",")) {
    const entry = rawEntry.trim();
    if (!entry.startsWith(SPIFFE_URI_PREFIX)) {
      continue;
    }
    const spiffeId = entry.slice(SAN_URI_PREFIX.length);
    if (!isWellFormedSpiffeId(spiffeId)) {
      continue;
    }
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
