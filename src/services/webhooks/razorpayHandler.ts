import crypto from 'crypto'

export type RazorpayEvent = {
  event: string
  payload: {
    payment?: {
      entity: {
        id: string
        order_id: string
        status: string
        amount: number
        currency: string
      }
    }
  }
}

export function verifyRazorpaySignature(
  rawBody: string,
  signature: string,
  secret: string,
): boolean {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex')
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature),
    Buffer.from(signature),
  )
}

export function handleRazorpayEvent(event: RazorpayEvent): { status: string; message: string } {
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
      return {
        status: 'ignored',
        message: `Unhandled event type: ${event.event}`,
      }
  }
}