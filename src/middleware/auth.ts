/**
 * Legacy module retained only so stale imports fail safely at build time.
 *
 * Authentication middleware lives in `requireAuth.ts`; this module must never
 * derive an authenticated identity from request headers.
 */

export {};
