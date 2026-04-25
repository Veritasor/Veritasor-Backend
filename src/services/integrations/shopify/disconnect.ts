import { Request, Response } from 'express'
import { deleteById, listByUserId } from '../../../repositories/integration.js'
import { deleteToken, isValidShopHost, normalizeShop } from './store.js'

const SHOPIFY_UNINSTALL_PATH = '/admin/api_permissions/current.json'
const ALREADY_REVOKED_STATUSES = new Set([401, 403, 404])

async function revokeShopifyAccess(shop: string, accessToken: string): Promise<{
  success: boolean
  alreadyRevoked?: boolean
  error?: string
}> {
  try {
    const response = await fetch(`https://${shop}${SHOPIFY_UNINSTALL_PATH}`, {
      method: 'DELETE',
      headers: {
        Accept: 'application/json',
        'X-Shopify-Access-Token': accessToken,
      },
    })

    if (response.ok) {
      return { success: true }
    }

    if (ALREADY_REVOKED_STATUSES.has(response.status)) {
      return { success: true, alreadyRevoked: true }
    }

    return { success: false, error: 'Failed to revoke Shopify access' }
  } catch {
    return { success: false, error: 'Failed to reach Shopify API' }
  }
}

export default async function disconnectShopify(req: Request, res: Response) {
  const userId = req.user?.userId ?? req.user?.id
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const rec = (await listByUserId(userId)).find((integration) => integration.provider === 'shopify')
  if (!rec) {
    return res.status(404).json({ error: 'Shopify integration not found' })
  }

  const shop = normalizeShop(
    typeof rec.externalId === 'string'
      ? rec.externalId
      : typeof rec.metadata?.shop === 'string'
        ? rec.metadata.shop
        : '',
  )
  const accessToken = rec.token?.accessToken

  if (!shop || !isValidShopHost(shop) || typeof accessToken !== 'string' || !accessToken) {
    return res.status(500).json({ error: 'Shopify integration is missing revocation metadata' })
  }

  const revocation = await revokeShopifyAccess(shop, accessToken)
  if (!revocation.success) {
    return res.status(502).json({ error: revocation.error })
  }

  const ok = await deleteById(rec.id)
  if (!ok) {
    return res.status(500).json({ error: 'Failed to disconnect Shopify integration' })
  }

  deleteToken(shop)

  return res.status(200).json({
    message: 'ok',
    revoked: true,
    alreadyRevoked: Boolean(revocation.alreadyRevoked),
  })
}
