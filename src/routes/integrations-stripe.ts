import { Router, type Request, type Response } from 'express'
import { startConnect } from '../services/integrations/stripe/connect.js'
import {
  handleCallback,
  verifyStripeWebhook,
} from '../services/integrations/stripe/callback.js'
import { requireAuth } from '../middleware/auth.js'
import { logger } from '../utils/logger.js'

export const integrationsStripeRouter = Router()
export const path = '/integrations/stripe'

/**
 * POST /api/integrations/stripe/connect
 * Initiates Stripe OAuth flow by redirecting to Stripe authorization screen.
 * Requires authentication.
 */
integrationsStripeRouter.post('/connect', requireAuth, (req: Request, res: Response) => {
  const clientId = process.env.STRIPE_CLIENT_ID
  const redirectUri = process.env.STRIPE_REDIRECT_URI

  if (!clientId || !redirectUri) {
    res.status(400).json({ error: 'Missing STRIPE_CLIENT_ID or STRIPE_REDIRECT_URI' })
    return
  }

  try {
    const { redirectUrl } = startConnect()
    res.redirect(302, redirectUrl)
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Connect failed' })
  }
})

/**
 * GET /api/integrations/stripe/callback
 * Query: code, state (from Stripe redirect)
 * Exchanges code for access token and stores it; redirects to success URL or returns JSON.
 * Requires authentication.
 */
integrationsStripeRouter.get('/callback', requireAuth, async (req: Request, res: Response) => {
  const code = req.query.code as string | undefined
  const state = req.query.state as string | undefined
  const userId = req.user!.userId

  const result = await handleCallback(
    { code: code ?? '', state: state ?? '' },
    userId,
  )

  if (!result.success && result.error === 'Failed to reach Stripe API') {
    res.status(502).json({ success: false, error: result.error })
    return
  }

  const successRedirect = process.env.STRIPE_SUCCESS_REDIRECT
  if (result.success && successRedirect) {
    res.redirect(302, successRedirect)
    return
  }
  if (result.success) {
    res.status(200).json({ success: true, stripeAccountId: result.stripeAccountId })
    return
  }

  res.status(400).json({ success: false, error: result.error })
})

/**
 * POST /api/integrations/stripe/webhook
 *
 * Receives Stripe webhook events.  The route must receive the **raw** request
 * body (Buffer/string) so that the HMAC signature can be verified against the
 * exact bytes Stripe signed.  Mount this route *before* any `express.json()`
 * middleware, or use the `express.raw()` middleware scoped to this path.
 *
 * Required env var: STRIPE_WEBHOOK_SECRET  (whsec_... from the Stripe dashboard)
 *
 * Responses:
 *   200 – event accepted (or intentionally ignored event type)
 *   400 – payload could not be parsed after a valid signature
 *   401 – signature missing, malformed, or timestamp out of tolerance
 *   409 – duplicate event ID (already processed)
 *   500 – missing server configuration
 */
integrationsStripeRouter.post(
  '/webhook',
  // Parse body as raw Buffer so we can verify the HMAC signature.
  // express.json() must NOT run before this handler.
  (req: Request, res: Response, next) => {
    // If the body was already parsed as a Buffer by a parent raw middleware, pass through.
    if (Buffer.isBuffer(req.body)) {
      next()
      return
    }
    // Otherwise collect the raw bytes ourselves.
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      req.body = Buffer.concat(chunks)
      next()
    })
    req.on('error', (err) => {
      logger.error(JSON.stringify({ event: 'stripe_webhook_body_read_error', message: err.message }))
      res.status(400).json({ error: 'Failed to read request body' })
    })
  },
  (req: Request, res: Response) => {
    const secret = process.env.STRIPE_WEBHOOK_SECRET
    if (!secret) {
      logger.error(JSON.stringify({ event: 'stripe_webhook_config_error', reason: 'STRIPE_WEBHOOK_SECRET not set' }))
      res.status(500).json({ error: 'Webhook endpoint not configured' })
      return
    }

    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body)
    const signature = req.headers['stripe-signature'] as string | undefined

    const result = verifyStripeWebhook(rawBody, signature, secret)

    if (!result.success) {
      switch (result.reason) {
        case 'duplicate_event':
          // Return 200 so Stripe does not keep retrying a duplicate
          res.status(200).json({ received: true, note: 'duplicate' })
          return
        case 'invalid_payload':
          res.status(400).json({ error: 'Invalid webhook payload' })
          return
        default:
          // missing_signature | invalid_signature_format | timestamp_too_old |
          // timestamp_in_future | signature_mismatch
          res.status(401).json({ error: 'Webhook signature verification failed' })
          return
      }
    }

    const event = result.event!

    // Dispatch to per-event-type handlers.
    // Extend this switch as new event types are supported.
    switch (event.type) {
      case 'account.updated':
        logger.info(JSON.stringify({ event: 'stripe_event_handled', type: event.type, id: event.id }))
        break
      case 'account.application.deauthorized':
        logger.info(JSON.stringify({ event: 'stripe_event_handled', type: event.type, id: event.id }))
        break
      default:
        // Unknown event types are acknowledged but not acted upon.
        logger.info(JSON.stringify({ event: 'stripe_event_ignored', type: event.type, id: event.id }))
    }

    res.status(200).json({ received: true })
  },
)
