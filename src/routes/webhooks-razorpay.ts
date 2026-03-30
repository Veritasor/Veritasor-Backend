import { Router, Request, Response } from 'express'
import { verifyRazorpaySignature, handleRazorpayEvent, RazorpayEvent } from '../services/webhooks/razorpayHandler.js'

export const razorpayWebhookRouter = Router()

razorpayWebhookRouter.post('/', (req: Request, res: Response) => {
  const signature = req.headers['x-razorpay-signature'] as string

  if (!signature) {
    return res.status(400).json({ error: 'Missing Razorpay signature header' })
  }

  const secret = process.env.RAZORPAY_WEBHOOK_SECRET
  if (!secret) {
    return res.status(500).json({ error: 'Webhook secret not configured' })
  }

  const rawBody = JSON.stringify(req.body)
  const isValid = verifyRazorpaySignature(rawBody, signature, secret)

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' })
  }

  const result = handleRazorpayEvent(req.body as RazorpayEvent)
  return res.status(200).json(result)
})