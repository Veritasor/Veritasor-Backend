import { Request, Response } from 'express'
import { integrationRepository } from '../../../repositories/integrations.js'

/**
 * Connect Razorpay account using API key pair.
 * Expects { apiKeyId, apiKeySecret } in the JSON body.
 * Verifies credentials by calling a lightweight Razorpay endpoint before storing.
 */
export async function connectRazorpay(req: Request, res: Response) {
  const userId = req.user?.userId
  if (!userId) return res.status(401).json({ error: 'Unauthorized' })

  const { apiKeyId, apiKeySecret } = req.body ?? {}
  if (!apiKeyId || !apiKeySecret) {
    return res.status(400).json({ error: 'apiKeyId and apiKeySecret are required' })
  }

  // Test credentials against Razorpay by making a simple authenticated request
  const auth = Buffer.from(`${apiKeyId}:${apiKeySecret}`).toString('base64')
  const url = new URL('https://api.razorpay.com/v1/payments')
  url.searchParams.set('count', '1')

  try {
    const resp = await fetch(url.toString(), {
      headers: { Authorization: `Basic ${auth}`, Accept: 'application/json' },
    })

    if (!resp.ok) {
      const text = await resp.text()
      return res.status(400).json({ error: 'Invalid Razorpay credentials', details: text })
    }
  } catch (err: any) {
    return res.status(502).json({ error: 'Failed to reach Razorpay API', details: String(err) })
  }

  // Persist the credentials (in-memory for now)
  const record = integrationRepository.create({
    provider: 'razorpay',
    userId,
    meta: { apiKeyId, apiKeySecret },
  })

  // Mask secret in response
  const safe = { ...record, meta: { apiKeyId: record.meta.apiKeyId, apiKeySecret: '*****' } }

  return res.status(201).json(safe)
}

export default connectRazorpay
