import { Request, Response } from 'express'
import { deleteById, listByBusinessId } from '../../../repositories/integration.js'
import { deleteToken, isValidShopHost, normalizeShop } from './store.js'
import { logger } from '../../../utils/logger.js'

const SHOPIFY_UNINSTALL_PATH = '/admin/api_permissions/current.json'
const ALREADY_REVOKED_STATUSES = new Set([401, 403, 404])

type RevokeResult = {
  success: boolean
  alreadyRevoked?: boolean
  errorCode?: 'revocation_failed' | 'network_error'
  error?: string
}

async function revokeShopifyAccess(shop: string, accessToken: string): Promise<RevokeResult> {
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

    return { success: false, errorCode: 'revocation_failed', error: 'Failed to revoke Shopify access' }
  } catch {
    return { success: false, errorCode: 'network_error', error: 'Failed to reach Shopify API' }
  }
}

export default async function disconnectShopify(req: Request, res: Response) {
  const userId = req.user?.userId ?? req.user?.id
  const businessId = req.business?.id
  if (!userId || !businessId) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const rec = (await listByBusinessId(businessId)).find((integration) => integration.provider === 'shopify')
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
    logger.warn(
      JSON.stringify({
        type: 'shopify_disconnect_invalid_metadata',
        userId,
        integrationId: rec.id,
        shop,
      }),
    )
    return res.status(500).json({ error: 'Shopify integration is missing revocation metadata' })
  }

  const revocation = await revokeShopifyAccess(shop, accessToken)
  logger.info(
    JSON.stringify({
      type: 'shopify_disconnect_revocation',
      userId,
      integrationId: rec.id,
      shop,
      success: revocation.success,
      alreadyRevoked: Boolean(revocation.alreadyRevoked),
      errorCode: revocation.errorCode,
    }),
  )

  if (!revocation.success) {
    return res.status(502).json({ error: revocation.error })
  }

  const ok = await deleteById(businessId, rec.id)
  if (!ok) {
    return res.status(500).json({ error: 'Failed to disconnect Shopify integration' })
  }

  deleteToken(shop)
  logger.info(
    JSON.stringify({
      type: 'shopify_disconnect_completed',
      userId,
      integrationId: rec.id,
      shop,
      alreadyRevoked: Boolean(revocation.alreadyRevoked),
    }),
  )

  return res.status(200).json({
    message: 'ok',
    revoked: true,
    alreadyRevoked: Boolean(revocation.alreadyRevoked),
  })
}
