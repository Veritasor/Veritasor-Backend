import { Router } from 'express';
import { startConnect } from '../services/integrations/stripe/connect.js';
import { handleCallback } from '../services/integrations/stripe/callback.js';
import { requireAuth } from '../middleware/auth.js';
export const integrationsStripeRouter = Router();
export const path = '/integrations/stripe';
/**
 * POST /api/integrations/stripe/connect
 * Initiates Stripe OAuth flow by redirecting to Stripe authorization screen.
 * Requires authentication.
 */
integrationsStripeRouter.post('/connect', requireAuth, (req, res) => {
    // Validate environment configuration
    const clientId = process.env.STRIPE_CLIENT_ID;
    const redirectUri = process.env.STRIPE_REDIRECT_URI;
    if (!clientId || !redirectUri) {
        res.status(400).json({ error: 'Missing STRIPE_CLIENT_ID or STRIPE_REDIRECT_URI' });
        return;
    }
    try {
        const { redirectUrl } = startConnect();
        res.redirect(302, redirectUrl);
    }
    catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : 'Connect failed' });
    }
});
/**
 * GET /api/integrations/stripe/callback
 * Query: code, state (from Stripe redirect)
 * Exchanges code for access token and stores it; redirects to success URL or returns JSON.
 * Requires authentication.
 */
integrationsStripeRouter.get('/callback', requireAuth, async (req, res) => {
    const code = req.query.code;
    const state = req.query.state;
    const userId = req.user.userId;
    const result = await handleCallback({ code: code ?? '', state: state ?? '' }, userId);
    // Handle network errors (502)
    if (!result.success && result.error === 'Failed to reach Stripe API') {
        res.status(502).json({ success: false, error: result.error });
        return;
    }
    // Handle success with redirect or JSON response
    const successRedirect = process.env.STRIPE_SUCCESS_REDIRECT;
    if (result.success && successRedirect) {
        res.redirect(302, successRedirect);
        return;
    }
    if (result.success) {
        res.status(200).json({ success: true, stripeAccountId: result.stripeAccountId });
        return;
    }
    // Handle validation and token exchange errors (400)
    res.status(400).json({ success: false, error: result.error });
});
