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

export const USERS_ROUTES: RouteInfo[] = [
  { method: 'PATCH', path: '/api/users/me' },
  { method: 'POST', path: '/api/users/me/export' },
  { method: 'GET', path: '/api/users/me/export/:token' },
  { method: 'GET', path: '/api/users/me/export/:exportId/status' },
];

export const WEBHOOK_SUBSCRIPTIONS_ROUTES: RouteInfo[] = [
  { method: 'GET', path: '/api/v1/webhook-subscriptions' },
  { method: 'POST', path: '/api/v1/webhook-subscriptions' },
  { method: 'GET', path: '/api/v1/webhook-subscriptions/:id' },
  { method: 'PATCH', path: '/api/v1/webhook-subscriptions/:id' },
  { method: 'DELETE', path: '/api/v1/webhook-subscriptions/:id' },
];

export const PUBLIC_ATTESTATIONS_ROUTES: RouteInfo[] = [
  { method: 'GET', path: '/api/v1/public/attestations/:hash' },
];

export const INTEGRATIONS_ROUTES: RouteInfo[] = [
  { method: 'GET', path: '/api/integrations' },
  { method: 'POST', path: '/api/integrations/razorpay' },
  { method: 'GET', path: '/api/integrations/shopify' },
  { method: 'GET', path: '/api/integrations/stripe/connect' },
];

export const ADMIN_ROUTES: RouteInfo[] = [
  { method: 'POST', path: '/api/admin/role-requests' },
  { method: 'POST', path: '/api/v1/admin/role-requests' },
];

export const ALL_ROUTES: RouteInfo[] = [
  ...AUTH_ROUTES,
  ...HEALTH_ROUTES,
  ...ANALYTICS_ROUTES,
  ...ATTESTATIONS_ROUTES,
  ...BUSINESSES_ROUTES,
  ...WEBHOOK_ROUTES,
  ...USERS_ROUTES,
  ...WEBHOOK_SUBSCRIPTIONS_ROUTES,
  ...PUBLIC_ATTESTATIONS_ROUTES,
  ...INTEGRATIONS_ROUTES,
  ...ADMIN_ROUTES,
];
