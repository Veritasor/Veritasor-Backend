/**
 * Route-table and dispatch tests for the integrations endpoints.
 *
 * Regression guard for the mount-order bug where the generic
 * `DELETE /api/integrations/:integrationId` route shadowed the provider
 * disconnect routes (`DELETE /api/integrations/razorpay` and
 * `DELETE /api/integrations/shopify`).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import type { Router } from 'express';

vi.mock('../../services/integrations/shopify/disconnect.js', () => ({ default: vi.fn() }));
vi.mock('../../services/integrations/razorpay/disconnect.js', () => ({ default: vi.fn() }));

import { app } from '../../app.js';
import integrationsRouter from '../integrations.js';
import integrationsRazorpayRouter from '../integrations-razorpay.js';
import { integrationsShopifyRouter } from '../integrations-shopify.js';
import disconnectShopify from '../../services/integrations/shopify/disconnect.js';
import disconnectRazorpay from '../../services/integrations/razorpay/disconnect.js';
import { generateRouteMap } from '../../utils/routeMap.js';
import * as jwt from '../../utils/jwt.js';
import * as userRepository from '../../repositories/userRepository.js';
import * as businessRepo from '../../repositories/business.js';
import { clearAll, create, getById } from '../../repositories/integration.js';

const mockedDisconnectShopify = vi.mocked(disconnectShopify);
const mockedDisconnectRazorpay = vi.mocked(disconnectRazorpay);

const UUID_PATTERN = '[0-9a-fA-F-]{36}';

const USER = {
  id: 'routing-user',
  userId: 'routing-user',
  email: 'routing@example.com',
};

const BUSINESS = {
  id: 'routing-business',
  userId: USER.id,
  name: 'Routing Business',
  industry: null,
  description: null,
  website: null,
  createdAt: '2024-01-01T00:00:00.000Z',
  updatedAt: '2024-01-01T00:00:00.000Z',
  suspended: false,
};

const AUTH_HEADERS = {
  Authorization: 'Bearer routing-test-token',
  'x-business-id': BUSINESS.id,
};

interface RouteDescriptor {
  path: string;
  methods: Record<string, boolean>;
  stack: Array<{ handle: unknown }>;
}

function findRoute(router: Router, method: string, path: string): RouteDescriptor | undefined {
  const layers = router.stack as unknown as Array<{ route?: RouteDescriptor }>;
  return layers.find(
    (layer) => layer.route?.path === path && layer.route.methods[method],
  )?.route;
}

beforeEach(() => {
  vi.clearAllMocks();
  clearAll();

  mockedDisconnectShopify.mockImplementation(async (_req, res) =>
    res.status(200).json({ disconnected: 'shopify' }),
  );
  mockedDisconnectRazorpay.mockImplementation(async (_req, res) =>
    res.status(200).json({ disconnected: 'razorpay' }),
  );

  vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: USER.id, email: USER.email });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue(USER as any);
  vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(BUSINESS as any);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('integrations route table', () => {
  it('mounts provider routers before the generic integrations router', () => {
    const table = generateRouteMap(app)
      .filter(({ path }) => path.startsWith('/api/integrations'))
      .map(({ method, path }) => `${method} ${path.replace(/\/+$/, '')}`);

    expect(table).toEqual([
      'POST /api/integrations/razorpay',
      'DELETE /api/integrations/razorpay',
      'POST /api/integrations/shopify/connect',
      'GET /api/integrations/shopify/callback',
      'DELETE /api/integrations/shopify',
      'POST /api/integrations/stripe/connect',
      'GET /api/integrations/stripe/callback',
      'GET /api/integrations',
      'GET /api/integrations/connected',
      'POST /api/integrations/connect',
      `DELETE /api/integrations/:integrationId(${UUID_PATTERN})`,
      `GET /api/integrations/:integrationId(${UUID_PATTERN})`,
    ]);
  });

  it('maps the documented disconnect routes to their handlers', () => {
    const providerRoutes = [
      { router: integrationsRazorpayRouter, path: '/', handler: mockedDisconnectRazorpay },
      { router: integrationsShopifyRouter, path: '/', handler: mockedDisconnectShopify },
    ];

    for (const entry of providerRoutes) {
      const route = findRoute(entry.router, 'delete', entry.path);

      expect(route, `missing DELETE ${entry.path} on provider router`).toBeDefined();
      expect(route!.stack.at(-1)?.handle).toBe(entry.handler);
    }

    for (const method of ['delete', 'get']) {
      const route = findRoute(integrationsRouter, method, `/:integrationId(${UUID_PATTERN})`);

      expect(route, `missing ${method.toUpperCase()} UUID route`).toBeDefined();
      expect(typeof route!.stack.at(-1)?.handle).toBe('function');
    }
  });
});

describe('DELETE /api/integrations provider disconnects', () => {
  it('reaches disconnectShopify for DELETE /api/integrations/shopify', async () => {
    const response = await request(app)
      .delete('/api/integrations/shopify')
      .set(AUTH_HEADERS);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ disconnected: 'shopify' });
    expect(mockedDisconnectShopify).toHaveBeenCalledTimes(1);
    expect(mockedDisconnectRazorpay).not.toHaveBeenCalled();
  });

  it('reaches disconnectRazorpay for DELETE /api/integrations/razorpay', async () => {
    const response = await request(app)
      .delete('/api/integrations/razorpay')
      .set(AUTH_HEADERS);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ disconnected: 'razorpay' });
    expect(mockedDisconnectRazorpay).toHaveBeenCalledTimes(1);
    expect(mockedDisconnectShopify).not.toHaveBeenCalled();
  });

  it('still reaches the generic handler for DELETE /api/integrations/:integrationId', async () => {
    const integration = await create({
      userId: USER.id,
      businessId: BUSINESS.id,
      provider: 'stripe',
      externalId: 'acct_routing',
      token: {},
      metadata: {},
    });

    const response = await request(app)
      .delete(`/api/integrations/${integration.id}`)
      .set(AUTH_HEADERS);

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      message: 'Integration disconnected successfully',
      integrationId: integration.id,
      provider: 'stripe',
    });
    expect(await getById(integration.id)).toBeNull();
    expect(mockedDisconnectShopify).not.toHaveBeenCalled();
    expect(mockedDisconnectRazorpay).not.toHaveBeenCalled();
  });

  it('does not route non-UUID paths through the generic handler', async () => {
    const response = await request(app)
      .delete('/api/integrations/not-a-real-provider')
      .set(AUTH_HEADERS);

    expect(response.status).toBe(404);
    expect(mockedDisconnectShopify).not.toHaveBeenCalled();
    expect(mockedDisconnectRazorpay).not.toHaveBeenCalled();
  });
});
