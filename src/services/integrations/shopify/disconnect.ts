import { Request, Response } from 'express'
import { integrationRepository } from '../../../repositories/integrations.js'

export default async function disconnectShopify(req: Request, res: Response) {
  const userId = req.user?.id
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const rec = integrationRepository.findByUserAndProvider(userId, 'shopify')
  if (!rec) {
    return res.status(404).json({ error: 'Shopify integration not found' })
  }

  const ok = integrationRepository.deleteById(rec.id)
  if (!ok) {
    return res.status(500).json({ error: 'Failed to disconnect Shopify integration' })
  }

  return res.status(200).json({ message: 'ok' })
}

