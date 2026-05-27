import { RouteInfo } from './routeMap.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface OpenApiSchema {
  type?: string;
  properties?: Record<string, OpenApiSchema>;
  required?: string[];
  items?: OpenApiSchema;
  enum?: string[];
  format?: string;
  description?: string;
  example?: unknown;
  additionalProperties?: boolean | OpenApiSchema;
  oneOf?: OpenApiSchema[];
  nullable?: boolean;
}

export interface OpenApiResponse {
  description: string;
  content?: Record<string, { schema: OpenApiSchema }>;
}

export interface OpenApiOperation {
  summary: string;
  description?: string;
  tags: string[];
  security?: Record<string, string[]>[];
  parameters?: OpenApiParameter[];
  requestBody?: {
    required: boolean;
    content: Record<string, { schema: OpenApiSchema }>;
  };
  responses: Record<string, OpenApiResponse>;
}

export interface OpenApiParameter {
  name: string;
  in: 'path' | 'query' | 'header';
  required: boolean;
  schema: OpenApiSchema;
  description?: string;
}

export interface OpenApiPathItem {
  [method: string]: OpenApiOperation;
}

export interface OpenApiSpec {
  openapi: '3.1.0';
  info: {
    title: string;
    version: string;
    description: string;
  };
  servers: { url: string; description: string }[];
  components: {
    securitySchemes: Record<string, unknown>;
    schemas: Record<string, OpenApiSchema>;
  };
  paths: Record<string, OpenApiPathItem>;
  tags: { name: string; description: string }[];
}

// ─── Shared schema fragments ──────────────────────────────────────────────────

const ERROR_SCHEMA: OpenApiSchema = {
  type: 'object',
  properties: {
    error: { type: 'string', description: 'Human-readable error message' },
  },
  required: ['error'],
};

const CODED_ERROR_SCHEMA: OpenApiSchema = {
  type: 'object',
  properties: {
    error: { type: 'string' },
    code: { type: 'string' },
  },
  required: ['error', 'code'],
};

const VALIDATION_ERROR_SCHEMA: OpenApiSchema = {
  type: 'object',
  properties: {
    error: { type: 'string' },
    type: { type: 'string' },
    details: { type: 'object', additionalProperties: true },
  },
  required: ['error'],
};

const RATE_LIMIT_RESPONSE: OpenApiResponse = {
  description: 'Too many requests',
  content: { 'application/json': { schema: ERROR_SCHEMA } },
};

const UNAUTHORIZED_RESPONSE: OpenApiResponse = {
  description: 'Unauthorized',
  content: { 'application/json': { schema: CODED_ERROR_SCHEMA } },
};

// ─── Tag registry ─────────────────────────────────────────────────────────────

const TAG_DESCRIPTIONS: Record<string, string> = {
  auth: 'Authentication — login, signup, token refresh, and password reset',
  analytics: 'Analytics — revenue reports and attested billing periods',
  attestations: 'Attestations — on-chain attestation submission and revocation',
  businesses: 'Businesses — business profile management',
  health: 'Health — liveness and readiness probes',
  integrations: 'Integrations — third-party platform connections (Shopify, Stripe, Razorpay)',
  users: 'Users — user profile and account management',
  admin: 'Admin — administrative operations (restricted)',
  webhooks: 'Webhooks — inbound webhook receivers',
};

function tagFromPath(path: string): string {
  // /api/integrations/shopify → integrations
  // /api/webhooks/razorpay   → webhooks
  const segment = path.split('/').find((s, i) => i > 0 && s.length > 0 && s !== 'api') ?? 'misc';
  // Normalise "integrations-shopify" etc. to "integrations"
  return segment.replace(/-.*$/, '');
}

// ─── Per-route operation builders ─────────────────────────────────────────────

/**
 * Returns a minimal but meaningful OpenAPI operation for a given route.
 * Routes that require authentication get a Bearer security requirement.
 */
function buildOperation(method: string, path: string): OpenApiOperation {
  const tag = tagFromPath(path);
  const httpMethod = method.toLowerCase();

  // Convert Express :param segments to {param} for OpenAPI
  const openApiPath = path.replace(/:([^/]+)/g, '{$1}');

  // Extract path parameters
  const pathParams: OpenApiParameter[] = [];
  const paramMatches = path.matchAll(/:([^/]+)/g);
  for (const match of paramMatches) {
    pathParams.push({
      name: match[1],
      in: 'path',
      required: true,
      schema: { type: 'string' },
    });
  }

  // Auth routes
  if (tag === 'auth') {
    return buildAuthOperation(httpMethod, openApiPath, pathParams);
  }

  // Health routes
  if (tag === 'health') {
    return buildHealthOperation(httpMethod, openApiPath, pathParams);
  }

  // Analytics routes
  if (tag === 'analytics') {
    return buildAnalyticsOperation(httpMethod, openApiPath, pathParams);
  }

  // Attestations routes
  if (tag === 'attestations') {
    return buildAttestationsOperation(httpMethod, openApiPath, pathParams);
  }

  // Businesses routes
  if (tag === 'businesses') {
    return buildBusinessesOperation(httpMethod, openApiPath, pathParams);
  }

  // Default operation for all other routes
  return buildDefaultOperation(httpMethod, openApiPath, tag, pathParams);
}

function buildAuthOperation(
  method: string,
  path: string,
  pathParams: OpenApiParameter[],
): OpenApiOperation {
  const requiresAuth = path.includes('/me') || path.includes('/refresh');
  const security = requiresAuth ? [{ bearerAuth: [] }] : [];

  const operationMap: Record<string, Partial<OpenApiOperation>> = {
    '/api/auth/login': {
      summary: 'Login with email and password',
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['email', 'password'],
              properties: {
                email: { type: 'string', format: 'email' },
                password: { type: 'string', format: 'password' },
              },
            },
          },
        },
      },
      responses: {
        '200': {
          description: 'Login successful',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  accessToken: { type: 'string' },
                  refreshToken: { type: 'string' },
                },
              },
            },
          },
        },
        '401': { description: 'Invalid credentials', content: { 'application/json': { schema: ERROR_SCHEMA } } },
        '429': RATE_LIMIT_RESPONSE,
      },
    },
    '/api/auth/signup': {
      summary: 'Create a new user account',
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['email', 'password'],
              properties: {
                email: { type: 'string', format: 'email' },
                password: { type: 'string', format: 'password' },
                website: { type: 'string', description: 'Honeypot field — must be empty' },
              },
            },
          },
        },
      },
      responses: {
        '201': { description: 'Account created', content: { 'application/json': { schema: { type: 'object', properties: { userId: { type: 'string' } } } } } },
        '400': { description: 'Validation error', content: { 'application/json': { schema: VALIDATION_ERROR_SCHEMA } } },
        '429': RATE_LIMIT_RESPONSE,
      },
    },
    '/api/auth/refresh': {
      summary: 'Refresh access token',
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['refreshToken'],
              properties: { refreshToken: { type: 'string' } },
            },
          },
        },
      },
      responses: {
        '200': { description: 'Token refreshed', content: { 'application/json': { schema: { type: 'object', properties: { accessToken: { type: 'string' } } } } } },
        '401': UNAUTHORIZED_RESPONSE,
        '429': RATE_LIMIT_RESPONSE,
      },
    },
    '/api/auth/forgot-password': {
      summary: 'Request password reset link',
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['email'],
              properties: { email: { type: 'string', format: 'email' } },
            },
          },
        },
      },
      responses: {
        '200': { description: 'Reset email sent (if account exists)', content: { 'application/json': { schema: { type: 'object', properties: { message: { type: 'string' } } } } } },
        '400': { description: 'Bad request', content: { 'application/json': { schema: CODED_ERROR_SCHEMA } } },
        '429': RATE_LIMIT_RESPONSE,
      },
    },
    '/api/auth/reset-password': {
      summary: 'Reset password with reset token',
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['token', 'newPassword'],
              properties: {
                token: { type: 'string' },
                newPassword: { type: 'string', format: 'password' },
              },
            },
          },
        },
      },
      responses: {
        '200': { description: 'Password reset successful', content: { 'application/json': { schema: { type: 'object', properties: { message: { type: 'string' } } } } } },
        '400': { description: 'Invalid or expired token', content: { 'application/json': { schema: ERROR_SCHEMA } } },
        '429': RATE_LIMIT_RESPONSE,
      },
    },
    '/api/auth/me': {
      summary: 'Get current authenticated user',
      responses: {
        '200': { description: 'User info', content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string' }, email: { type: 'string', format: 'email' } } } } } },
        '401': UNAUTHORIZED_RESPONSE,
        '429': RATE_LIMIT_RESPONSE,
      },
    },
    '/api/auth/signup/availability': {
      summary: 'Check signup availability for current IP',
      parameters: [{ name: 'email', in: 'query', required: false, schema: { type: 'string', format: 'email' } }],
      responses: {
        '200': { description: 'Availability status', content: { 'application/json': { schema: { type: 'object', properties: { available: { type: 'boolean' } } } } } },
      },
    },
  };

  const known = operationMap[path] ?? {};
  return {
    summary: known.summary ?? `${method.toUpperCase()} ${path}`,
    tags: ['auth'],
    security,
    parameters: [...pathParams, ...(known.parameters ?? [])],
    requestBody: known.requestBody,
    responses: known.responses ?? { '200': { description: 'Success' }, '429': RATE_LIMIT_RESPONSE },
  };
}

function buildHealthOperation(
  method: string,
  path: string,
  pathParams: OpenApiParameter[],
): OpenApiOperation {
  return {
    summary: 'Health check',
    description: 'Liveness and readiness probe. Use ?mode=deep for full dependency check.',
    tags: ['health'],
    parameters: [
      ...pathParams,
      {
        name: 'mode',
        in: 'query',
        required: false,
        schema: { type: 'string', enum: ['shallow', 'deep'] },
        description: 'shallow (default) or deep dependency check',
      },
    ],
    responses: {
      '200': {
        description: 'Service healthy or degraded',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              required: ['status', 'service', 'timestamp'],
              properties: {
                status: { type: 'string', enum: ['ok', 'degraded', 'unhealthy'] },
                service: { type: 'string', example: 'veritasor-backend' },
                timestamp: { type: 'string', format: 'date-time' },
                mode: { type: 'string', enum: ['shallow', 'deep'] },
                db: { type: 'string', enum: ['ok', 'down'] },
                redis: { type: 'string', enum: ['ok', 'down'] },
                soroban: { type: 'string', enum: ['ok', 'down'] },
                email: { type: 'string', enum: ['ok', 'down'] },
              },
            },
          },
        },
      },
      '503': {
        description: 'Service unhealthy (deep mode only)',
        content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string' } } } } },
      },
    },
  };
}

function buildAnalyticsOperation(
  method: string,
  path: string,
  pathParams: OpenApiParameter[],
): OpenApiOperation {
  const operationMap: Record<string, Partial<OpenApiOperation>> = {
    '/api/analytics/periods': {
      summary: 'List attested billing periods',
      responses: {
        '200': { description: 'List of attested periods', content: { 'application/json': { schema: { type: 'array', items: { type: 'object', properties: { period: { type: 'string' }, attestedAt: { type: 'string', format: 'date-time' } } } } } } },
        '400': { description: 'Missing business ID', content: { 'application/json': { schema: CODED_ERROR_SCHEMA } } },
        '401': UNAUTHORIZED_RESPONSE,
        '403': { description: 'Business not found or suspended', content: { 'application/json': { schema: CODED_ERROR_SCHEMA } } },
        '429': RATE_LIMIT_RESPONSE,
      },
    },
    '/api/analytics/revenue': {
      summary: 'Get revenue report for a period',
      parameters: [
        { name: 'period', in: 'query', required: false, schema: { type: 'string' }, description: 'Billing period identifier' },
        { name: 'from', in: 'query', required: false, schema: { type: 'string', format: 'date' } },
        { name: 'to', in: 'query', required: false, schema: { type: 'string', format: 'date' } },
      ],
      responses: {
        '200': { description: 'Revenue report', content: { 'application/json': { schema: { type: 'object', properties: { total: { type: 'number' }, currency: { type: 'string' } } } } } },
        '400': { description: 'Bad query params or time-window error', content: { 'application/json': { schema: ERROR_SCHEMA } } },
        '401': UNAUTHORIZED_RESPONSE,
        '403': { description: 'Business not found or suspended', content: { 'application/json': { schema: CODED_ERROR_SCHEMA } } },
        '404': { description: 'No data for the given window', content: { 'application/json': { schema: ERROR_SCHEMA } } },
        '429': RATE_LIMIT_RESPONSE,
      },
    },
  };

  const known = operationMap[path] ?? {};
  return {
    summary: known.summary ?? `${method.toUpperCase()} ${path}`,
    tags: ['analytics'],
    security: [{ bearerAuth: [] }],
    parameters: [...pathParams, ...(known.parameters ?? [])],
    responses: known.responses ?? { '200': { description: 'Success' }, '401': UNAUTHORIZED_RESPONSE, '429': RATE_LIMIT_RESPONSE },
  };
}

function buildAttestationsOperation(
  method: string,
  path: string,
  pathParams: OpenApiParameter[],
): OpenApiOperation {
  const isSubmit = method === 'post' && !path.includes('{');
  const isRevoke = method === 'post' && path.includes('/revoke');
  const isList = method === 'get' && !path.includes('{');
  const isGet = method === 'get' && path.includes('{');

  let summary = `${method.toUpperCase()} ${path}`;
  let requestBody: OpenApiOperation['requestBody'] | undefined;
  let responses: Record<string, OpenApiResponse> = { '200': { description: 'Success' }, '401': UNAUTHORIZED_RESPONSE, '429': RATE_LIMIT_RESPONSE };

  if (isRevoke) {
    summary = 'Revoke an attestation';
    responses = {
      '200': { description: 'Attestation revoked' },
      '401': UNAUTHORIZED_RESPONSE,
      '404': { description: 'Attestation not found', content: { 'application/json': { schema: ERROR_SCHEMA } } },
      '429': RATE_LIMIT_RESPONSE,
    };
  } else if (isSubmit) {
    summary = 'Submit a new attestation';
    requestBody = {
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['business', 'period', 'merkleRoot', 'timestamp', 'version'],
            properties: {
              business: { type: 'string' },
              period: { type: 'string' },
              merkleRoot: { type: 'string' },
              timestamp: { type: 'number' },
              version: { type: 'string' },
            },
          },
        },
      },
    };
    responses = {
      '201': { description: 'Attestation submitted', content: { 'application/json': { schema: { type: 'object', properties: { txHash: { type: 'string' } } } } } },
      '400': { description: 'Validation error', content: { 'application/json': { schema: ERROR_SCHEMA } } },
      '401': UNAUTHORIZED_RESPONSE,
      '429': RATE_LIMIT_RESPONSE,
    };
  } else if (isList) {
    summary = 'List attestations';
    responses = {
      '200': { description: 'List of attestations', content: { 'application/json': { schema: { type: 'array', items: { type: 'object' } } } } },
      '401': UNAUTHORIZED_RESPONSE,
      '429': RATE_LIMIT_RESPONSE,
    };
  } else if (isGet) {
    summary = 'Get attestation by ID';
    responses = {
      '200': { description: 'Attestation details', content: { 'application/json': { schema: { type: 'object' } } } },
      '401': UNAUTHORIZED_RESPONSE,
      '404': { description: 'Not found', content: { 'application/json': { schema: ERROR_SCHEMA } } },
      '429': RATE_LIMIT_RESPONSE,
    };
  }

  return {
    summary,
    tags: ['attestations'],
    security: [{ bearerAuth: [] }],
    parameters: pathParams,
    requestBody,
    responses,
  };
}

function buildBusinessesOperation(
  method: string,
  path: string,
  pathParams: OpenApiParameter[],
): OpenApiOperation {
  const operationMap: Record<string, Record<string, Partial<OpenApiOperation>>> = {
    'post:/api/businesses': {
      post: {
        summary: 'Create a new business',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['name'],
                properties: {
                  name: { type: 'string' },
                  industry: { type: 'string' },
                  description: { type: 'string' },
                  website: { type: 'string', format: 'uri' },
                },
              },
            },
          },
        },
        responses: {
          '201': { description: 'Business created' },
          '400': { description: 'Validation error', content: { 'application/json': { schema: ERROR_SCHEMA } } },
          '401': UNAUTHORIZED_RESPONSE,
          '409': { description: 'Business already exists for user', content: { 'application/json': { schema: ERROR_SCHEMA } } },
          '429': RATE_LIMIT_RESPONSE,
        },
      },
    },
  };

  const key = `${method}:${path}`;
  const known = operationMap[key]?.[method] ?? {};
  return {
    summary: known.summary ?? `${method.toUpperCase()} ${path}`,
    tags: ['businesses'],
    security: [{ bearerAuth: [] }],
    parameters: [...pathParams, ...(known.parameters ?? [])],
    requestBody: known.requestBody,
    responses: known.responses ?? {
      '200': { description: 'Success' },
      '401': UNAUTHORIZED_RESPONSE,
      '429': RATE_LIMIT_RESPONSE,
    },
  };
}

function buildDefaultOperation(
  method: string,
  path: string,
  tag: string,
  pathParams: OpenApiParameter[],
): OpenApiOperation {
  const isWebhook = tag === 'webhooks';
  const security = isWebhook ? [] : [{ bearerAuth: [] }];

  return {
    summary: `${method.toUpperCase()} ${path}`,
    tags: [tag],
    security,
    parameters: pathParams,
    responses: {
      '200': { description: 'Success' },
      '401': isWebhook ? undefined as unknown as OpenApiResponse : UNAUTHORIZED_RESPONSE,
      '429': RATE_LIMIT_RESPONSE,
    },
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Generate an OpenAPI 3.1 specification document from an array of RouteInfo
 * objects produced by `generateRouteMap`.
 *
 * @param routes   - Route list from `generateRouteMap(app)`
 * @param version  - API version string (default `"1.0.0"`)
 * @returns        OpenAPI 3.1 spec object
 */
export function generateOpenApiSpec(routes: RouteInfo[], version = '1.0.0'): OpenApiSpec {
  const paths: Record<string, OpenApiPathItem> = {};
  const tagSet = new Set<string>();

  for (const route of routes) {
    const method = route.method.toLowerCase();
    // Convert Express :param to OpenAPI {param}
    const openApiPath = route.path.replace(/:([^/]+)/g, '{$1}');

    if (!paths[openApiPath]) {
      paths[openApiPath] = {};
    }

    const operation = buildOperation(method, route.path);
    paths[openApiPath][method] = operation;
    operation.tags.forEach((t) => tagSet.add(t));
  }

  const tags = [...tagSet].sort().map((name) => ({
    name,
    description: TAG_DESCRIPTIONS[name] ?? name,
  }));

  return {
    openapi: '3.1.0',
    info: {
      title: 'Veritasor Backend API',
      version,
      description:
        'Machine-readable OpenAPI 3.1 specification for the Veritasor Backend. ' +
        'Generated automatically from the Express router stack. Do not edit manually.',
    },
    servers: [
      { url: '/api', description: 'Current server (relative)' },
      { url: 'https://api.veritasor.com/api', description: 'Production' },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      schemas: {
        Error: ERROR_SCHEMA,
        CodedError: CODED_ERROR_SCHEMA,
        ValidationError: VALIDATION_ERROR_SCHEMA,
      },
    },
    paths,
    tags,
  };
}
