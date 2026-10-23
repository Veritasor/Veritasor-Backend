import { Router, Request, Response } from 'express'
import express from 'express'
import {
  handleRazorpayEvent,
  parseRazorpayEvent,
  RazorpayWebhookError,
  verifyRazorpaySignatureWithRotation,
} from '../services/webhooks/razorpayHandler.js'
import { logger } from '../utils/logger.js'
import { secretLoader, SecretNotFoundError } from '../utils/secret-loader.js'
import { hasForbiddenKeys } from '../middleware/prototypePollution.js'
import { BackoffError } from '../utils/backoff.js'

export const razorpayWebhookRouter = Router()

razorpayWebhookRouter.use(express.raw({ type: 'application/json' }))

razorpayWebhookRouter.post('/', async (req: Request, res: Response) => {
  const correlationId = (req as Request & { correlationId?: string }).correlationId

  try {
    const signature = req.headers['x-razorpay-signature']
    if (typeof signature !== 'string' || signature.length === 0) {
      throw new RazorpayWebhookError('missing_signature', 400, 'Missing Razorpay signature header')
    }

    let primary: string
    try {
      primary = secretLoader.get('RAZORPAY_WEBHOOK_SECRET')
    } catch (error) {
      if (error instanceof SecretNotFoundError) {
        throw new RazorpayWebhookError('secret_not_configured', 500, 'Webhook secret not configured')
      }
      throw error
    }

    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      throw new RazorpayWebhookError('invalid_payload', 400, 'Invalid webhook payload')
    }

    let secondary: string | undefined
    try {
      const secondaryCandidate = secretLoader.get('RAZORPAY_WEBHOOK_SECRET_NEXT')
      secondary = secondaryCandidate || undefined
    } catch (error) {
      if (!(error instanceof SecretNotFoundError)) {
        throw error
      }
      secondary = undefined
    }

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

    let rawJson: unknown
    try {
      rawJson = JSON.parse(req.body.toString('utf8'))
    } catch {
      throw new RazorpayWebhookError('invalid_payload', 400, 'Invalid webhook payload')
    }

    if (hasForbiddenKeys(rawJson)) {
      return res.status(400).json({
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Invalid body fields',
      })
    }

    const event = parseRazorpayEvent(req.body)
    const result = await handleRazorpayEvent(event)
    return res.status(200).json(result)
  } catch (error) {
    let actualError: unknown = error
    while (actualError instanceof BackoffError && actualError.cause) {
      actualError = actualError.cause
    }

    if (actualError instanceof RazorpayWebhookError) {
      logger.warn(
        JSON.stringify({
          type: 'razorpay_webhook_rejected',
          code: actualError.code,
          statusCode: actualError.httpStatus,
          correlationId,
        }),
      )

      return res.status(actualError.httpStatus).json({ error: actualError.message, code: actualError.code })
    }

    logger.error(
      JSON.stringify({
        type: 'razorpay_webhook_failure',
        correlationId,
        message: actualError instanceof Error ? actualError.message : 'Unknown webhook failure',
      }),
    )

    return res.status(500).json({ error: 'Internal Server Error' })
  }
})
