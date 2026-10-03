/**
 * Canonical route fixtures for OpenAPI golden snapshot tests.
 *
 * These fixture arrays are the single source of truth for route inputs used
 * by both the unit tests in `tests/unit/utils/openapi.test.ts` and the golden
 * snapshot tests in `tests/openapi/golden-snapshot.test.ts`.
 *
 * When adding or removing API routes, update these fixtures and then run:
 *   npm run snapshot:update
 *
 * @module tests/openapi/fixtures/routes
 */

import type { RouteInfo } from '../../../src/utils/routeMap.js';

export const AUTH_ROUTES: RouteInfo[] = [
  { method: 'POST', path: '/api/auth/login' },
  { method: 'POST', path: '/api/auth/signup' },
  { method: 'POST', path: '/api/auth/refresh' },
  { method: 'POST', path: '/api/auth/forgot-password' },
  { method: 'POST', path: '/api/auth/reset-password' },
  { method: 'GET',  path: '/api/auth/me' },
  { method: 'GET',  path: '/api/auth/signup/availability' },
];

export const HEALTH_ROUTES: RouteInfo[] = [
  { method: 'GET', path: '/api/health' },
];

export const ANALYTICS_ROUTES: RouteInfo[] = [
  { method: 'GET', path: '/api/analytics/periods' },
  { method: 'GET', path: '/api/analytics/revenue' },
];

export const ATTESTATIONS_ROUTES: RouteInfo[] = [
  { method: 'GET',  path: '/api/attestations' },
  { method: 'POST', path: '/api/attestations' },
  { method: 'GET',  path: '/api/attestations/:id' },
  { method: 'POST', path: '/api/attestations/:id/revoke' },
];

export const BUSINESSES_ROUTES: RouteInfo[] = [
  { method: 'POST',  path: '/api/businesses' },
  { method: 'GET',   path: '/api/businesses/me' },
  { method: 'PATCH', path: '/api/businesses/me' },
  { method: 'GET',   path: '/api/businesses/:id' },
];

export const WEBHOOK_ROUTES: RouteInfo[] = [
  { method: 'POST', path: '/api/webhooks/razorpay' },
];

export const ALL_ROUTES: RouteInfo[] = [
  ...AUTH_ROUTES,
  ...HEALTH_ROUTES,
  ...ANALYTICS_ROUTES,
  ...ATTESTATIONS_ROUTES,
  ...BUSINESSES_ROUTES,
  ...WEBHOOK_ROUTES,
];
