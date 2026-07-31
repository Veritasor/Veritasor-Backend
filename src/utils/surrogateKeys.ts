import crypto from 'node:crypto';

// Use an environment variable for the secret salt, fallback to a safe random string if not present
// so that internal IDs are not easily reversed.
const SECRET_SALT = process.env.SURROGATE_KEY_SALT || 'veritasor_default_surrogate_salt';

/**
 * Computes a secure, hashed surrogate key to avoid leaking internal identifiers.
 * 
 * @param type The type of entity (e.g., 'biz' or 'att')
 * @param id The internal identifier
 * @returns A safe string to use as a CDN surrogate key tag
 */
export function computeSurrogateKey(type: string, id: string): string {
  const hash = crypto.createHash('sha256').update(`${type}:${id}:${SECRET_SALT}`).digest('base64url');
  // Return the first 16 chars for efficiency while maintaining enough entropy to prevent collisions
  return `${type}_${hash.substring(0, 16)}`;
}

/**
 * Generates the surrogate key header value containing multiple tags (e.g., for an attestation and its business).
 */
export function generateSurrogateKeys(businessId: string, attestationId: string): string {
  const bizKey = computeSurrogateKey('biz', businessId);
  const attKey = computeSurrogateKey('att', attestationId);
  return `${bizKey} ${attKey}`;
}
