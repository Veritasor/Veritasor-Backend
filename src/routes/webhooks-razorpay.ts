import { Router, Request, Response } from 'express'
import express from 'express'
import {
  handleRazorpayEvent,
  parseRazorpayEvent,
  RazorpayWebhookError,
  verifyRazorpaySignatureWithRotation,
} from '../services/webhooks/razorpayHandler.js'
import { logger } from '../utils/logger.js'

export const razorpayWebhookRouter = Router()

razorpayWebhookRouter.use(express.raw({ type: 'application/json' }))

razorpayWebhookRouter.post('/', async (req: Request, res: Response) => {
  const correlationId = (req as Request & { correlationId?: string }).correlationId

  try {
    const signature = req.headers['x-razorpay-signature']
    if (typeof signature !== 'string' || signature.length === 0) {
      throw new RazorpayWebhookError('missing_signature', 400, 'Missing Razorpay signature header')
    }

    const primary = process.env.RAZORPAY_WEBHOOK_SECRET
    if (!primary) {
      throw new RazorpayWebhookError('secret_not_configured', 500, 'Webhook secret not configured')
    }

    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      throw new RazorpayWebhookError('invalid_payload', 400, 'Invalid webhook payload')
    }

    // Support overlapping primary + secondary secrets for zero-downtime rotation.
    // RAZORPAY_WEBHOOK_SECRET_NEXT is optional; set it while Razorpay transitions
    // to the new secret, then promote it to RAZORPAY_WEBHOOK_SECRET once stable.
    const secondary = process.env.RAZORPAY_WEBHOOK_SECRET_NEXT || undefined
    const { valid, keyLabel } = verifyRazorpaySignatureWithRotation(
      req.body,
      signature,
      primary,
      secondary,
    )

    if (!valid) {
      throw new RazorpayWebhookError('invalid_signature', 401, 'Invalid signature')
    }

    // Log which key matched so rotation progress is observable without leaking secrets.
    logger.info(
      JSON.stringify({
        type: 'razorpay_webhook_signature_verified',
        keyLabel,
        correlationId,
      }),
    )

    const event = parseRazorpayEvent(req.body)
    const result = await handleRazorpayEvent(event)
    return res.status(200).json(result)
  } catch (error) {
    if (error instanceof RazorpayWebhookError) {
      logger.warn(
        JSON.stringify({
          type: 'razorpay_webhook_rejected',
          code: error.code,
          statusCode: error.httpStatus,
          correlationId,
        }),
      )

      return res.status(error.httpStatus).json({ error: error.message, code: error.code })
    }

    logger.error(
      JSON.stringify({
        type: 'razorpay_webhook_failure',
        correlationId,
        message: error instanceof Error ? error.message : 'Unknown webhook failure',
      }),
    )

    return res.status(500).json({ error: 'Internal Server Error' })
  }
})
