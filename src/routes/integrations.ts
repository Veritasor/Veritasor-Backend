import { Router, Request, Response } from 'express';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireBusinessAuth } from '../middleware/requireBusinessAuth.js';
import { requirePermissions, requirePolicy } from '../middleware/permissions.js';
import { IntegrationPermission } from '../types/permissions.js';
import { getById, listByUserId, listByBusinessId, deleteById } from '../repositories/integration.js';
import { z } from 'zod';
import crypto from 'cypto';
import { setOAuthState, consumeOAuthState } from '../services/integrations/stripe/store.js';
import { generateAuthUrl } from '../services/integrations/oauth.js';

const router = Router();

// Integration records are keyed by UUID (see repositories/integration.ts).
// Constraining the dynamic segment keeps provider paths such as `/razorpay`
// and `/shopify` from being captured by the generic handlers below.
const INTEGRATION_ID_PATTERN = '[0-9a-fA-F-]{36}';

interface IntegrationType {
  name: string;
  slug: 'stripe' | 'razorpay' | 'shopify';
  description?: string;
  authType: 'oauth2' | 'api_key';
  status: 'available' | 'coming_soon' | 'deprecated';
}

const AVAILABLE_INTEGRATIONS: IntegrationType[] = [
  {
    name: 'Stripe',
    slug: 'stripe',
    description: 'Connect your Stripe account to attest payment data',
    authType: 'oauth2',
    status: 'available'
  },
  {
    name: 'Razorpay',
    slug: 'razorpay',
    description: 'Connect Razorpay to attest payment data',
    authType: 'api_key',
    status: 'available'
  },
  {
    name: 'Shopify',
    slug: 'shopify',
    description: 'Connect your Shopify store to attest sales data',
    authType: 'oauth2',
    status: 'available'
  },
];

// Validation schemas
const connectIntegrationSchema = z.object({
  provider: z.enum(['stripe', 'razorpay', 'shopify']),
  redirectUri: z.string.url().optional(),
});

const disconnectIntegrationSchema = z.object({
  integrationId: z.string.uuid(),
});

/**
 * Resolve the set of allowed redirect URIs for the generic connect flow.
 * Configured via INTEGRATION_REDIRECT_ALLOWLIST (comma-separated).
 */
export function getAllowedRedirectUris(): string[] {
  const raw = process.env.INTEGRATION_REDIRECT_ALLOWLIST
  if (!raw) return []
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

/**
 * Return true if the supplied redirect URI is on the configured allowlist.
 * Fails closed when the allowlist is empty.
 */
export function isAllowedRedirectUri(redirectUri: string): boolean {
  const allowed = getAllowedRedirectUris()
  return allowed.includes(redirectUri)
}

/**
 * @notice Consume and validate a generic integration OAuth state for the caller.
 * @returns true only if the state exists, has not expired, and is bound to the caller's user/business.
 */
export function consumeGenericOAuthState(state: string, userId: string, businessId: string): boolean {
  const record = consumeOAuthState(state)
  if (!record) return false
  if (record.userId !== userId || record.businessId !== businessId) return false
  return true
}

/**
 * @notice Generate a random OAuth state for the generic connect flow.
 */
export function generateGenericOAuthState(): string {
  return crypto.randomBytes(32).toString('hex')
}

/**
 * @notice Persist the generic OAuth state bound to the initiating user/business.
 */
export function storeGenericOAuthState(state: string, userId: string, businessId: string, expiresAt: number): void {
  setOAuthState(state, { userId, businessId, expiresAt })
}

/**
 * GET /api/integrations/callback
 * Handles the generic OAuth callback for providers that use the generic connect flow.
 * Verifies the state is bound to the calling user/business and has not been replayed.
 */
router.get('/callback',
  requireBusinessAuth,
  async (req: Request, res: Response) => {
    const state = (typeof req.query.state === 'string' ? req.query.state : '').trim()
    if (!state) {
      return res.status(400).json({ error: 'Bad Request', message: 'Invalid or expired state' })
    }

    const ok = consumeGenericOAuthState(state, req.user!.userId, req.business!.id)
    if (!ok) {
      return res.status(400).json({ error: 'Bad Request', message: 'Invalid or expired state' })
    }

    return res.json({ success: true })
  }
);

/**
 * GET /api/integrations
 * List all available integrations (public endpoint)
 * @access Public - no authentication required for browsing available integrations
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    const available = AVAILABLE_INTEGRATIONS.map((integration) => ({
      ...integration,
      isConnected: false, // Will be updated for authenticated users
    }));

    // If user is authenticated, check which integrations they have connected
    if (req.user?.userId) {
      const connected = await listByUserId(req.user.userId);
      const connectedSlugs = new Set(connected.map((i) => i.provider));

      const availableWithStatus = available.map((integration) => ({
        ...integration,
        isConnected: connectedSlugs.has(integration.slug),
      }));

      return res.json({
        available: availableWithStatus,
        connected: connected.map((i) => ({
          id: i.id,
          type: i.provider,
          externalId: i.externalId,
          connectedAt: i.createdAt,
          metadata: {
            // Only include safe metadata, exclude sensitive tokens
            ...i.metadata,
            token: undefined,
            accessToken: undefined,
            refreshToken: undefined,
          },
        })),
      });
    }

    res.json({ available });
  } catch (error) {
    console.error('Error fetching integrations:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch integrations',
    });
  }
});

/**
 * GET /api/integrations/connected
 * List connected integrations for authenticated business
 * @access Private - requires business authentication and read permissions
 */
router.get('/connected',
  requireBusinessAuth,
  requirePermissions(IntegrationPermission.READ_CONNECTED),
  requirePolicy('read', 'integration', { resourceTenantId: (req) => req.business?.id }),
  async (req: Request, res: Response) => {
    try {
      const businessId = req.business!.id;
      const connected = await listByBusinessId(businessId);

      const connectedSafe = connected.map((i) => ({
        id: i.id,
        type: i.provider,
        externalId: i.externalId,
        connectedAt: i.createdAt,
        updatedAt: i.updatedAt,
        metadata: {
          // Only include non-sensitive metadata
          ...Object.fromEntries(
            Object.entries(i.metadata).filter(([key]) =>
              !key.includes('token') && !key.includes('secret') && !key.includes('key')
            )
          ),
        },
      }));

      res.json({
        integrations: connectedSafe,
        count: connectedSafe.length,
      });
    } catch (error) {
      console.error('Error fetching connected integrations:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to fetch connected integrations',
      });
    }
  }
);

/**
 * POST /api/integrations/connect
 * Initiate connection process for an integration provider
 * @access Private - requires business authentication and connect permissions
 */
router.post('/connect',
  requireBusinessAuth,
  requirePermissions(IntegrationPermission.CONNECT),
  requirePolicy('create', 'integration', { resourceTenantId: (req) => req.business?.id }),
  async (req: Request, res: Response) => {
    try {
      const { provider, redirectUri } = connectIntegrationSchema.parse(req.body);

      // Check if integration is available
      const integration = AVAILABLE_INTEGRATIONS.find(i => i.slug === provider);
      if (!integration) {
        return res.status(404).json({
          error: 'Not Found',
          message: `Integration provider '${provider}' not found`,
        });
      }

      if (integration.status !== 'available') {
        return res.status(400).json({
          error: 'Bad Request',
          message: `Integration '${provider}' is ${integration.status}`,
        });
      }

      // Restrict client-supplied redirect URIs to the configured allowlist.
      if (redirectUri !== undefined && !isAllowedRedirectUri(redirectUri)) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'redirectUri is not allowed',
        });
      }

      // Check if user already has this integration connected
      const existingIntegrations = await listByBusinessId(req.business!.id);
      const existingConnection = existingIntegrations.find(i => i.provider === provider);

      if (existingConnection) {
        return res.status(409).json({
          error: 'Conflict',
          message: `Integration '${provider}' is already connected`,
          existingConnection: {
            id: existingConnection.id,
            connectedAt: existingConnection.createdAt,
          },
        });
      }

      // Generate a random OAuth state bound to the initiating user/business.
      const state = generateGenericOAuthState();
      const expiresAt = Date.now() + 10 * 60 * 1000;
      storeGenericOAuthState(state, req.user!.userId, req.business!.id, expiresAt);

      const authUrl = generateAuthUrl(provider, state, redirectUri);

      return res.json({
        state: state,
        redirectUri: redirectUri,
        authUrl,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid request data',
          details: error.errors,
        });
      }
      console.error('Error initiating integration connection', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to initiate connection',
      });
    }
  }
);

/**
 * DELETE /api/integrations/:id
 * Disconnect an integration
 * @access Private - requires business authentication and delete permissions
 */
router.delete('/:id',
  requireBusinessAuth,
  requirePermissions(IntegrationPermission.DISCONNECT),
  requirePolicy('delete', 'integration', { resourceTenantId: (req) => req.business?.id }),
  async (req: Request, res: Response) => {
    try {
      const { integrationId } = disconnectIntegrationSchema.parse({ integrationId: req.params.id });

      const existing = await getById(integrationId);
      if (!existing || existing.businessId !== req.business!.id) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Integration not found',
        });
      }

      const deleted = await deleteById(req.business!.id, integrationId);
      if (!deleted) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Integration not found',
        });
      }

      return res.json({ success: true });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid integration ID',
          details: error.errors,
        });
      }
      console.error('Error disconnecting integration:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to disconnect integration',
      });
    }
  }
);

export default router;
