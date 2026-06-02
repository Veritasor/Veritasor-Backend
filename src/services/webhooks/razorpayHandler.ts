import crypto from 'node:crypto'
import { z } from 'zod'
import { logger } from '../../utils/logger.js'
import { isEventProcessed, markEventProcessed, checkTimestampTolerance } from './idempotency.js'
import { saveDeadLetter } from './deadLetterQueue.js'

const HANDLED_EVENT_TYPES = new Set(['payment.captured', 'payment.failed', 'order.paid'])
const DEFAULT_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000

const paymentEntitySchema = z
  .object({
    id: z.string().min(1),
    order_id: z.string().min(1),
    status: z.string().min(1),
    amount: z.number(),
    currency: z.string().min(1),
  })
  .passthrough()

const razorpayEventSchema = z
  .object({
    id: z.string().min(1),
    event: z.string().min(1),
    created_at: z.number().int().positive().optional(),
    payload: z
      .object({
        payment: z.object({ entity: paymentEntitySchema }).optional(),
      })
      .optional()
      .default({}),
  })
  .passthrough()
  .superRefine((event, ctx) => {
    if (HANDLED_EVENT_TYPES.has(event.event) && !event.payload.payment?.entity) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Handled Razorpay events require payload.payment.entity',
        path: ['payload', 'payment', 'entity'],
      })
    }
  })

export type RazorpayEvent = z.infer<typeof razorpayEventSchema>

export class RazorpayWebhookError extends Error {
  constructor(
    public readonly code:
      | 'missing_signature'
      | 'invalid_signature'
      | 'invalid_payload'
      | 'invalid_event'
      | 'invalid_timestamp'
      | 'secret_not_configured',
    public readonly httpStatus: number,
    message: string,
  ) {
    super(message)
    this.name = 'RazorpayWebhookError'
  }
}

export function verifyRazorpaySignature(
  rawBody: Buffer | string,
  signature: string,
  secret: string,
): boolean {
  if (!secret || !/^[a-f0-9]{64}$/i.test(signature)) {
    return false
  }

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest()
  const providedSignature = Buffer.from(signature, 'hex')

  if (expectedSignature.length !== providedSignature.length) {
    return false
  }

  return crypto.timingSafeEqual(expectedSignature, providedSignature)
}

/**
 * Result of a rotation-aware signature verification attempt.
 *
 * @property valid   - Whether any candidate secret produced a matching signature.
 * @property keyLabel - Which key matched: `'primary'` | `'secondary'` | `null` when no match.
 *                      Never contains the secret value itself — safe to log.
 */
export interface VerifyWithRotationResult {
  valid: boolean
  keyLabel: 'primary' | 'secondary' | null
}

/**
 * Verifies a Razorpay webhook signature against one or two candidate secrets,
 * enabling zero-downtime secret rotation.
 *
 * Rotation workflow:
 *   1. Generate the new secret in Razorpay and set it as `RAZORPAY_WEBHOOK_SECRET_NEXT`.
 *   2. Deploy — both old (`RAZORPAY_WEBHOOK_SECRET`) and new secrets are accepted.
 *   3. Once Razorpay has fully switched to the new secret, promote it:
 *      set `RAZORPAY_WEBHOOK_SECRET=<new>` and unset `RAZORPAY_WEBHOOK_SECRET_NEXT`.
 *
 * Security properties:
 *   - Each candidate is compared with `crypto.timingSafeEqual` to prevent timing attacks.
 *   - The secondary is only tried when the primary fails, so the common path (primary match)
 *     does not leak timing information about the secondary secret's existence.
 *   - `keyLabel` in the return value is a fixed string (`'primary'` / `'secondary'`),
 *     never the secret itself, so it is safe to include in structured logs.
 *
 * @param rawBody   - Raw request body bytes (must be the exact bytes Razorpay signed).
 * @param signature - Hex-encoded HMAC-SHA256 from the `x-razorpay-signature` header.
 * @param primary   - Value of `RAZORPAY_WEBHOOK_SECRET` (required).
 * @param secondary - Value of `RAZORPAY_WEBHOOK_SECRET_NEXT` (optional, for rotation).
 */
export function verifyRazorpaySignatureWithRotation(
  rawBody: Buffer | string,
  signature: string,
  primary: string,
  secondary?: string,
): VerifyWithRotationResult {
  if (verifyRazorpaySignature(rawBody, signature, primary)) {
    return { valid: true, keyLabel: 'primary' }
  }

  if (secondary && verifyRazorpaySignature(rawBody, signature, secondary)) {
    return { valid: true, keyLabel: 'secondary' }
  }

  return { valid: false, keyLabel: null }
}

export function parseRazorpayEvent(
  rawBody: Buffer | string,
  options?: { nowMs?: number; maxFutureSkewMs?: number },
): RazorpayEvent {
  let payload: unknown

  try {
    const body = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8')
    payload = JSON.parse(body)
  } catch {
    throw new RazorpayWebhookError('invalid_payload', 400, 'Invalid webhook payload')
  }

  const parsedEvent = razorpayEventSchema.safeParse(payload)
  if (!parsedEvent.success) {
    throw new RazorpayWebhookError('invalid_event', 400, 'Invalid event structure')
  }

  const event = parsedEvent.data
  if (typeof event.created_at === 'number') {
    const nowMs = options?.nowMs ?? Date.now()
    const maxFutureSkewMs = options?.maxFutureSkewMs ?? DEFAULT_MAX_FUTURE_SKEW_MS
    const eventTimeMs = event.created_at * 1000

    if (eventTimeMs > nowMs + maxFutureSkewMs) {
      throw new RazorpayWebhookError('invalid_timestamp', 400, 'Invalid webhook timestamp')
    }
  }

  return event
}

// In-memory store for processed events (for simplicity; in production, use DB)
const processedEvents = new Set<string>()

export function resetProcessedRazorpayEvents(): void {
  processedEvents.clear()
}

export async function handleRazorpayEvent(event: RazorpayEvent): Promise<{ status: string; message: string }> {
  try {
    if (processedEvents.has(event.id)) {
      logger.info(
        JSON.stringify({
          type: 'razorpay_webhook_duplicate',
          eventId: event.id,
          eventType: event.event,
        }),
      )

      return {
        status: 'ok',
        message: `Event ${event.id} already processed`,
      }
    }

    const tsCheck = checkTimestampTolerance(event.created_at)
    if (!tsCheck.valid) {
      throw new RazorpayWebhookError('invalid_timestamp', 400, tsCheck.reason ?? 'Event timestamp out of tolerance')
    }
    if (isEventProcessed(event.id)) {
      logger.info(JSON.stringify({ type: 'razorpay_webhook_duplicate', eventId: event.id, eventType: event.event }))
      return { status: 'duplicate', message: `Event ${event.id} already processed` }
    }
    markEventProcessed(event.id)
    logger.info(
      JSON.stringify({
        type: 'razorpay_webhook_processing',
        eventId: event.id,
        eventType: event.event,
      }),
    )

    switch (event.event) {
      case 'payment.captured':
        return {
          status: 'ok',
          message: `Payment ${event.payload.payment?.entity.id} captured successfully`,
        }
      case 'payment.failed':
        return {
          status: 'ok',
          message: `Payment ${event.payload.payment?.entity.id} failed`,
        }
      case 'order.paid':
        return {
          status: 'ok',
          message: `Order ${event.payload.payment?.entity.order_id} marked as paid`,
        }
      default:
        logger.info(
          JSON.stringify({
            type: 'razorpay_webhook_ignored',
            eventId: event.id,
            eventType: event.event,
          }),
        )

        return {
          status: 'ignored',
          message: `Unhandled event type: ${event.event}`,
        }
    }
  } catch (error) {
    if (event.id) {
      try {
        await saveDeadLetter('razorpay', event.id, event, error)
      } catch (dlqError) {
        logger.error(
          JSON.stringify({
            type: 'razorpay_webhook_dlq_failed',
            eventId: event.id,
            error: dlqError instanceof Error ? dlqError.message : String(dlqError),
          }),
        )
      }
    }
    throw error
  }
}
