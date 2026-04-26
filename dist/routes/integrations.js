import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { requirePermissions, IntegrationPermission } from '../middleware/permissions.js';
import { listByUserId, deleteById } from '../repositories/integration.js';
import { z } from 'zod';
const router = Router();
const AVAILABLE_INTEGRATIONS = [
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
    redirectUri: z.string().url().optional(),
});
const disconnectIntegrationSchema = z.object({
    integrationId: z.string().uuid(),
});
/**
 * @route GET /api/integrations
 * @desc List all available integrations (public endpoint)
 * @access Public - no authentication required for browsing available integrations
 */
router.get('/', async (req, res) => {
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
    }
    catch (error) {
        console.error('Error fetching integrations:', error);
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to fetch integrations',
        });
    }
});
/**
 * @route GET /api/integrations/connected
 * @desc List connected integrations for authenticated user
 * @access Private - requires authentication and read permissions
 */
router.get('/connected', requireAuth, requirePermissions(IntegrationPermission.READ_CONNECTED), async (req, res) => {
    try {
        const userId = req.user.userId;
        const connected = await listByUserId(userId);
        const connectedSafe = connected.map((i) => ({
            id: i.id,
            type: i.provider,
            externalId: i.externalId,
            connectedAt: i.createdAt,
            updatedAt: i.updatedAt,
            metadata: {
                // Only include non-sensitive metadata
                ...Object.fromEntries(Object.entries(i.metadata).filter(([key]) => !key.includes('token') && !key.includes('secret') && !key.includes('key'))),
            },
        }));
        res.json({
            integrations: connectedSafe,
            count: connectedSafe.length,
        });
    }
    catch (error) {
        console.error('Error fetching connected integrations:', error);
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to fetch connected integrations',
        });
    }
});
/**
 * @route POST /api/integrations/connect
 * @desc Initiate connection process for an integration provider
 * @access Private - requires authentication and connect permissions
 */
router.post('/connect', requireAuth, requirePermissions(IntegrationPermission.CONNECT), async (req, res) => {
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
        // Check if user already has this integration connected
        const existingIntegrations = await listByUserId(req.user.userId);
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
        // Generate OAuth state or API key connection details
        const state = `${provider}_${req.user.userId}_${Date.now()}`;
        const authUrl = generateAuthUrl(provider, state, redirectUri);
        res.json({
            provider,
            authType: integration.authType,
            authUrl,
            state,
            expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(), // 10 minutes
        });
    }
    catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({
                error: 'Validation Error',
                message: 'Invalid request body',
                details: error.errors,
            });
        }
        console.error('Error initiating integration connection:', error);
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to initiate connection',
        });
    }
});
/**
 * @route DELETE /api/integrations/:integrationId
 * @desc Disconnect a specific integration
 * @access Private - requires authentication and disconnect permissions with ownership check
 */
router.delete('/:integrationId', requireAuth, requirePermissions(IntegrationPermission.DISCONNECT_OWN, { checkOwnership: true }), async (req, res) => {
    try {
        const { integrationId } = req.params;
        if (!integrationId) {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Integration ID is required',
            });
        }
        // Verify ownership before deletion
        const userIntegrations = await listByUserId(req.user.userId);
        const integration = userIntegrations.find(i => i.id === integrationId);
        if (!integration) {
            return res.status(404).json({
                error: 'Not Found',
                message: 'Integration not found or access denied',
            });
        }
        // Delete the integration
        const deleted = await deleteById(integrationId);
        if (!deleted) {
            return res.status(500).json({
                error: 'Internal Server Error',
                message: 'Failed to disconnect integration',
            });
        }
        res.json({
            message: 'Integration disconnected successfully',
            integrationId,
            provider: integration.provider,
            disconnectedAt: new Date().toISOString(),
        });
    }
    catch (error) {
        console.error('Error disconnecting integration:', error);
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to disconnect integration',
        });
    }
});
/**
 * @route GET /api/integrations/:integrationId
 * @desc Get details of a specific integration
 * @access Private - requires authentication and read permissions with ownership check
 */
router.get('/:integrationId', requireAuth, requirePermissions(IntegrationPermission.READ_OWN, { checkOwnership: true }), async (req, res) => {
    try {
        const { integrationId } = req.params;
        if (!integrationId) {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Integration ID is required',
            });
        }
        const userIntegrations = await listByUserId(req.user.userId);
        const integration = userIntegrations.find(i => i.id === integrationId);
        if (!integration) {
            return res.status(404).json({
                error: 'Not Found',
                message: 'Integration not found or access denied',
            });
        }
        // Return safe integration details (exclude sensitive tokens)
        const safeIntegration = {
            id: integration.id,
            provider: integration.provider,
            externalId: integration.externalId,
            createdAt: integration.createdAt,
            updatedAt: integration.updatedAt,
            metadata: {
                // Only include non-sensitive metadata
                ...Object.fromEntries(Object.entries(integration.metadata).filter(([key]) => !key.includes('token') && !key.includes('secret') && !key.includes('key'))),
            },
        };
        res.json(safeIntegration);
    }
    catch (error) {
        console.error('Error fetching integration details:', error);
        res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to fetch integration details',
        });
    }
});
/**
 * Helper function to generate authentication URLs for different providers
 */
function generateAuthUrl(provider, state, redirectUri) {
    const baseUrl = redirectUri || 'http://localhost:3000/integrations/callback';
    switch (provider) {
        case 'stripe':
            return `https://connect.stripe.com/oauth/authorize?client_id=mock_stripe_client_id&state=${state}&redirect_uri=${encodeURIComponent(baseUrl)}&scope=read_write`;
        case 'shopify':
            return `https://${process.env.SHOPIFY_SHOP_DOMAIN || 'example'}.myshopify.com/admin/oauth/authorize?client_id=mock_shopify_client_id&state=${state}&redirect_uri=${encodeURIComponent(baseUrl)}&scope=read_products,read_orders`;
        case 'razorpay':
            // Razorpay uses API key flow, return mock instructions
            return `${baseUrl}?provider=razorpay&state=${state}`;
        default:
            throw new Error(`Unsupported provider: ${provider}`);
    }
}
export default router;
