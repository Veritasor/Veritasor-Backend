import { Router, type Request, type Response } from 'express'
import { startConnect } from '../services/integrations/shopify/connect.js'
import { handleCallback } from '../services/integrations/shopify/callback.js'
import { requireAuth } from '../middleware/auth.js'
import disconnectShopify from '../services/integrations/shopify/disconnect.js'

export const integrationsShopifyRouter = Router()

/**
 * POST /api/integrations/shopify/connect
 * Body: { shop: string } (e.g. "mystore" or "mystore.myshopify.com")
 * Redirects to Shopify OAuth authorization screen.
 */
integrationsShopifyRouter.post('/connect', (req: Request, res: Response) => {
  const shop = req.body?.shop
  if (!shop || typeof shop !== 'string') {
    res.status(400).json({ error: 'Missing or invalid shop' })
    return
  }
  try {
    const { redirectUrl } = startConnect(shop)
    res.redirect(302, redirectUrl)
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Connect failed' })
  }
})

/**
 * GET /api/integrations/shopify/callback
 * Query: code, shop, state (from Shopify redirect)
 * Exchanges code for access token and stores it; redirects to success URL or returns JSON error.
 */
integrationsShopifyRouter.get('/callback', async (req: Request, res: Response) => {
  const code = req.query.code as string | undefined
  const shop = req.query.shop as string | undefined
  const state = req.query.state as string | undefined

  const result = await handleCallback({ code: code ?? '', shop: shop ?? '', state: state ?? '' })

  const successRedirect = process.env.SHOPIFY_SUCCESS_REDIRECT
  if (result.success && successRedirect) {
    res.redirect(302, successRedirect)
    return
  }
  if (result.success) {
    res.status(200).json({ success: true, shop: result.shop })
    return
  }
  res.status(400).json({ success: false, error: result.error })
})

integrationsShopifyRouter.delete('/', requireAuth, disconnectShopify)
