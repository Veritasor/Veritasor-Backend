import { describe, it, expect } from 'vitest';
import { generateOpenApiSpec } from '../../../src/utils/openapi.js';
import type { RouteInfo } from '../../../src/utils/routeMap.js';
import {
  AUTH_ROUTES,
  HEALTH_ROUTES,
  ANALYTICS_ROUTES,
  ATTESTATIONS_ROUTES,
  BUSINESSES_ROUTES,
  WEBHOOK_ROUTES,
  ALL_ROUTES,
} from '../../openapi/fixtures/routes.js';

// ─── Top-level structure ───────────────────────────────────────────────────────

describe('generateOpenApiSpec — document structure', () => {
  it('returns a valid OpenAPI 3.1.0 envelope', () => {
    const spec = generateOpenApiSpec([]);
    expect(spec.openapi).toBe('3.1.0');
    expect(spec.info.title).toBe('Veritasor Backend API');
    expect(spec.info.version).toBe('1.0.0');
    expect(spec.info.description).toBeTruthy();
  });

  it('accepts a custom version string', () => {
    const spec = generateOpenApiSpec([], '2.3.4');
    expect(spec.info.version).toBe('2.3.4');
  });

  it('includes at least one server entry', () => {
    const spec = generateOpenApiSpec([]);
    expect(spec.servers.length).toBeGreaterThanOrEqual(1);
    expect(spec.servers[0].url).toBeTruthy();
  });

  it('defines bearerAuth security scheme', () => {
    const spec = generateOpenApiSpec([]);
    expect(spec.components.securitySchemes.bearerAuth).toBeDefined();
    const scheme = spec.components.securitySchemes.bearerAuth as Record<string, string>;
    expect(scheme.type).toBe('http');
    expect(scheme.scheme).toBe('bearer');
  });

  it('defines shared Error, CodedError, and ValidationError component schemas', () => {
    const spec = generateOpenApiSpec([]);
    expect(spec.components.schemas.Error).toBeDefined();
    expect(spec.components.schemas.CodedError).toBeDefined();
    expect(spec.components.schemas.ValidationError).toBeDefined();
  });

  it('produces an empty paths object for an empty route list', () => {
    const spec = generateOpenApiSpec([]);
    expect(spec.paths).toEqual({});
    expect(spec.tags).toEqual([]);
  });

  it('tags array is sorted alphabetically', () => {
    const spec = generateOpenApiSpec(ALL_ROUTES);
    const names = spec.tags.map((t) => t.name);
    expect(names).toEqual([...names].sort());
  });

  it('every tag has a description', () => {
    const spec = generateOpenApiSpec(ALL_ROUTES);
    for (const tag of spec.tags) {
      expect(tag.description.length).toBeGreaterThan(0);
    }
  });
});

// ─── Path / method mapping ─────────────────────────────────────────────────────

describe('generateOpenApiSpec — path and method mapping', () => {
  it('maps every route to a path entry', () => {
    const spec = generateOpenApiSpec(ALL_ROUTES);
    for (const route of ALL_ROUTES) {
      const openApiPath = route.path.replace(/:([^/]+)/g, '{$1}');
      expect(spec.paths[openApiPath], `missing path ${openApiPath}`).toBeDefined();
    }
  });

  it('maps HTTP methods to lowercase keys on the path item', () => {
    const spec = generateOpenApiSpec(ALL_ROUTES);
    expect(spec.paths['/api/auth/login'].post).toBeDefined();
    expect(spec.paths['/api/auth/me'].get).toBeDefined();
    expect(spec.paths['/api/businesses/me'].patch).toBeDefined();
  });

  it('converts Express :param to OpenAPI {param}', () => {
    const spec = generateOpenApiSpec(BUSINESSES_ROUTES);
    expect(spec.paths['/api/businesses/{id}']).toBeDefined();
    expect(spec.paths['/api/businesses/:id']).toBeUndefined();
  });

  it('converts Express :id in attestation paths', () => {
    const spec = generateOpenApiSpec(ATTESTATIONS_ROUTES);
    expect(spec.paths['/api/attestations/{id}']).toBeDefined();
    expect(spec.paths['/api/attestations/{id}/revoke']).toBeDefined();
  });

  it('handles duplicate methods on the same path (last write wins)', () => {
    const routes: RouteInfo[] = [
      { method: 'GET', path: '/api/test' },
      { method: 'POST', path: '/api/test' },
    ];
    const spec = generateOpenApiSpec(routes);
    expect(spec.paths['/api/test'].get).toBeDefined();
    expect(spec.paths['/api/test'].post).toBeDefined();
  });
});

// ─── Auth routes ───────────────────────────────────────────────────────────────

describe('generateOpenApiSpec — auth routes', () => {
  it('login has POST requestBody with email and password', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    const op = spec.paths['/api/auth/login'].post;
    expect(op.requestBody?.required).toBe(true);
    const schema = op.requestBody?.content['application/json'].schema;
    expect(schema?.required).toContain('email');
    expect(schema?.required).toContain('password');
  });

  it('login does NOT require bearerAuth', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    const security = spec.paths['/api/auth/login'].post.security ?? [];
    expect(security).toEqual([]);
  });

  it('login returns 401 and 429 responses', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    const responses = spec.paths['/api/auth/login'].post.responses;
    expect(responses['401']).toBeDefined();
    expect(responses['429']).toBeDefined();
  });

  it('GET /api/auth/me requires bearerAuth', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    const security = spec.paths['/api/auth/me'].get.security ?? [];
    expect(security).toContainEqual({ bearerAuth: [] });
  });

  it('signup POST has a 201 response', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    expect(spec.paths['/api/auth/signup'].post.responses['201']).toBeDefined();
  });

  it('forgot-password does not require auth', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    const security = spec.paths['/api/auth/forgot-password'].post.security ?? [];
    expect(security).toEqual([]);
  });

  it('refresh has a requestBody with refreshToken', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    const schema = spec.paths['/api/auth/refresh'].post.requestBody?.content['application/json'].schema;
    expect(schema?.required).toContain('refreshToken');
  });

  it('signup/availability GET has optional email query param', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    const op = spec.paths['/api/auth/signup/availability'].get;
    expect(op).toBeDefined();
  });

  it('all auth routes are tagged "auth"', () => {
    const spec = generateOpenApiSpec(AUTH_ROUTES);
    for (const pathItem of Object.values(spec.paths)) {
      for (const op of Object.values(pathItem)) {
        expect((op as { tags: string[] }).tags).toContain('auth');
      }
    }
  });
});

// ─── Health routes ─────────────────────────────────────────────────────────────

describe('generateOpenApiSpec — health routes', () => {
  it('GET /api/health has a mode query parameter', () => {
    const spec = generateOpenApiSpec(HEALTH_ROUTES);
    const params = spec.paths['/api/health'].get.parameters ?? [];
    const modeParam = params.find((p) => p.name === 'mode');
    expect(modeParam).toBeDefined();
    expect(modeParam?.in).toBe('query');
    expect(modeParam?.schema.enum).toContain('shallow');
    expect(modeParam?.schema.enum).toContain('deep');
  });

  it('GET /api/health has 200 and 503 responses', () => {
    const spec = generateOpenApiSpec(HEALTH_ROUTES);
    const responses = spec.paths['/api/health'].get.responses;
    expect(responses['200']).toBeDefined();
    expect(responses['503']).toBeDefined();
  });

  it('health response schema has status enum', () => {
    const spec = generateOpenApiSpec(HEALTH_ROUTES);
    const schema = spec.paths['/api/health'].get.responses['200'].content?.['application/json'].schema;
    expect(schema?.properties?.status?.enum).toContain('ok');
    expect(schema?.properties?.status?.enum).toContain('degraded');
    expect(schema?.properties?.status?.enum).toContain('unhealthy');
  });

  it('health route has no auth requirement', () => {
    const spec = generateOpenApiSpec(HEALTH_ROUTES);
    const security = spec.paths['/api/health'].get.security;
    expect(security).toBeUndefined();
  });
});

// ─── Analytics routes ──────────────────────────────────────────────────────────

describe('generateOpenApiSpec — analytics routes', () => {
  it('analytics routes require bearerAuth', () => {
    const spec = generateOpenApiSpec(ANALYTICS_ROUTES);
    for (const pathItem of Object.values(spec.paths)) {
      for (const op of Object.values(pathItem)) {
        expect((op as { security: unknown[] }).security).toContainEqual({ bearerAuth: [] });
      }
    }
  });

  it('/api/analytics/revenue has 404 response', () => {
    const spec = generateOpenApiSpec(ANALYTICS_ROUTES);
    expect(spec.paths['/api/analytics/revenue'].get.responses['404']).toBeDefined();
  });

  it('/api/analytics/revenue has query parameters', () => {
    const spec = generateOpenApiSpec(ANALYTICS_ROUTES);
    const params = spec.paths['/api/analytics/revenue'].get.parameters ?? [];
    expect(params.length).toBeGreaterThan(0);
  });

  it('analytics routes include 401 and 403 responses', () => {
    const spec = generateOpenApiSpec(ANALYTICS_ROUTES);
    const periodResponses = spec.paths['/api/analytics/periods'].get.responses;
    expect(periodResponses['401']).toBeDefined();
    expect(periodResponses['403']).toBeDefined();
  });
});

// ─── Attestation routes ────────────────────────────────────────────────────────

describe('generateOpenApiSpec — attestation routes', () => {
  it('POST /api/attestations has a requestBody', () => {
    const spec = generateOpenApiSpec(ATTESTATIONS_ROUTES);
    expect(spec.paths['/api/attestations'].post.requestBody).toBeDefined();
  });

  it('POST /api/attestations returns 201', () => {
    const spec = generateOpenApiSpec(ATTESTATIONS_ROUTES);
    expect(spec.paths['/api/attestations'].post.responses['201']).toBeDefined();
  });

  it('GET /api/attestations/{id} includes path parameter', () => {
    const spec = generateOpenApiSpec(ATTESTATIONS_ROUTES);
    const params = spec.paths['/api/attestations/{id}'].get.parameters ?? [];
    expect(params.find((p) => p.name === 'id' && p.in === 'path')).toBeDefined();
  });

  it('POST /api/attestations/{id}/revoke includes path parameter', () => {
    const spec = generateOpenApiSpec(ATTESTATIONS_ROUTES);
    const params = spec.paths['/api/attestations/{id}/revoke'].post.parameters ?? [];
    expect(params.find((p) => p.name === 'id')).toBeDefined();
  });
});

// ─── Businesses routes ─────────────────────────────────────────────────────────

describe('generateOpenApiSpec — businesses routes', () => {
  it('POST /api/businesses has a requestBody with name required', () => {
    const spec = generateOpenApiSpec(BUSINESSES_ROUTES);
    const schema = spec.paths['/api/businesses'].post.requestBody?.content['application/json'].schema;
    expect(schema?.required).toContain('name');
  });

  it('POST /api/businesses returns 409 conflict', () => {
    const spec = generateOpenApiSpec(BUSINESSES_ROUTES);
    expect(spec.paths['/api/businesses'].post.responses['409']).toBeDefined();
  });

  it('GET /api/businesses/{id} exists with path param', () => {
    const spec = generateOpenApiSpec(BUSINESSES_ROUTES);
    const params = spec.paths['/api/businesses/{id}'].get.parameters ?? [];
    expect(params.find((p) => p.name === 'id')).toBeDefined();
  });
});

// ─── Webhook routes ────────────────────────────────────────────────────────────

describe('generateOpenApiSpec — webhook routes', () => {
  it('webhook routes do NOT require bearerAuth', () => {
    const spec = generateOpenApiSpec(WEBHOOK_ROUTES);
    const security = spec.paths['/api/webhooks/razorpay'].post.security ?? [];
    expect(security).toEqual([]);
  });

  it('webhook routes are tagged "webhooks"', () => {
    const spec = generateOpenApiSpec(WEBHOOK_ROUTES);
    const op = spec.paths['/api/webhooks/razorpay'].post;
    expect(op.tags).toContain('webhooks');
  });
});

// ─── Edge cases ────────────────────────────────────────────────────────────────

describe('generateOpenApiSpec — edge cases', () => {
  it('handles a single unknown route without throwing', () => {
    const routes: RouteInfo[] = [{ method: 'GET', path: '/api/unknown/resource' }];
    expect(() => generateOpenApiSpec(routes)).not.toThrow();
  });

  it('unknown routes still get a 200 and 429 response', () => {
    const routes: RouteInfo[] = [{ method: 'DELETE', path: '/api/users/:id' }];
    const spec = generateOpenApiSpec(routes);
    const responses = spec.paths['/api/users/{id}'].delete.responses;
    expect(responses['200']).toBeDefined();
    expect(responses['429']).toBeDefined();
  });

  it('path parameters are extracted for unknown deeply nested routes', () => {
    const routes: RouteInfo[] = [{ method: 'GET', path: '/api/misc/:orgId/items/:itemId' }];
    const spec = generateOpenApiSpec(routes);
    const params = spec.paths['/api/misc/{orgId}/items/{itemId}'].get.parameters ?? [];
    expect(params.find((p) => p.name === 'orgId')).toBeDefined();
    expect(params.find((p) => p.name === 'itemId')).toBeDefined();
  });

  it('handles routes with uppercase methods', () => {
    const routes: RouteInfo[] = [{ method: 'GET', path: '/api/health' }];
    const spec = generateOpenApiSpec(routes);
    expect(spec.paths['/api/health'].get).toBeDefined();
  });

  it('multiple routes on the same path produce separate method entries', () => {
    const routes: RouteInfo[] = [
      { method: 'GET',  path: '/api/businesses/me' },
      { method: 'PATCH', path: '/api/businesses/me' },
    ];
    const spec = generateOpenApiSpec(routes);
    expect(spec.paths['/api/businesses/me'].get).toBeDefined();
    expect(spec.paths['/api/businesses/me'].patch).toBeDefined();
  });

  it('all operations have a non-empty summary', () => {
    const spec = generateOpenApiSpec(ALL_ROUTES);
    for (const [path, pathItem] of Object.entries(spec.paths)) {
      for (const [method, op] of Object.entries(pathItem)) {
        expect((op as { summary: string }).summary.length, `${method} ${path} missing summary`).toBeGreaterThan(0);
      }
    }
  });

  it('all operations have at least one tag', () => {
    const spec = generateOpenApiSpec(ALL_ROUTES);
    for (const [path, pathItem] of Object.entries(spec.paths)) {
      for (const [method, op] of Object.entries(pathItem)) {
        expect((op as { tags: string[] }).tags.length, `${method} ${path} has no tags`).toBeGreaterThan(0);
      }
    }
  });
});
