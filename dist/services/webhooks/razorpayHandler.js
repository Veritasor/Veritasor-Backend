import crypto from 'node:crypto';
import { z } from 'zod';
import { logger } from '../../utils/logger.js';
const HANDLED_EVENT_TYPES = new Set(['payment.captured', 'payment.failed', 'order.paid']);
const DEFAULT_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const paymentEntitySchema = z
    .object({
    id: z.string().min(1),
    order_id: z.string().min(1),
    status: z.string().min(1),
    amount: z.number(),
    currency: z.string().min(1),
})
    .passthrough();
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
        });
    }
});
export class RazorpayWebhookError extends Error {
    code;
    httpStatus;
    constructor(code, httpStatus, message) {
        super(message);
        this.code = code;
        this.httpStatus = httpStatus;
        this.name = 'RazorpayWebhookError';
    }
}
export function verifyRazorpaySignature(rawBody, signature, secret) {
    if (!secret || !/^[a-f0-9]{64}$/i.test(signature)) {
        return false;
    }
    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(rawBody)
        .digest();
    const providedSignature = Buffer.from(signature, 'hex');
    if (expectedSignature.length !== providedSignature.length) {
        return false;
    }
    return crypto.timingSafeEqual(expectedSignature, providedSignature);
}
export function parseRazorpayEvent(rawBody, options) {
    let payload;
    try {
        const body = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8');
        payload = JSON.parse(body);
    }
    catch {
        throw new RazorpayWebhookError('invalid_payload', 400, 'Invalid webhook payload');
    }
    const parsedEvent = razorpayEventSchema.safeParse(payload);
    if (!parsedEvent.success) {
        throw new RazorpayWebhookError('invalid_event', 400, 'Invalid event structure');
    }
    const event = parsedEvent.data;
    if (typeof event.created_at === 'number') {
        const nowMs = options?.nowMs ?? Date.now();
        const maxFutureSkewMs = options?.maxFutureSkewMs ?? DEFAULT_MAX_FUTURE_SKEW_MS;
        const eventTimeMs = event.created_at * 1000;
        if (eventTimeMs > nowMs + maxFutureSkewMs) {
            throw new RazorpayWebhookError('invalid_timestamp', 400, 'Invalid webhook timestamp');
        }
    }
    return event;
}
// In-memory store for processed events (for simplicity; in production, use DB)
const processedEvents = new Set();
export function resetProcessedRazorpayEvents() {
    processedEvents.clear();
}
export function handleRazorpayEvent(event) {
    if (processedEvents.has(event.id)) {
        logger.info(JSON.stringify({
            type: 'razorpay_webhook_duplicate',
            eventId: event.id,
            eventType: event.event,
        }));
        return {
            status: 'ok',
            message: `Event ${event.id} already processed`,
        };
    }
    processedEvents.add(event.id);
    logger.info(JSON.stringify({
        type: 'razorpay_webhook_processing',
        eventId: event.id,
        eventType: event.event,
    }));
    switch (event.event) {
        case 'payment.captured':
            return {
                status: 'ok',
                message: `Payment ${event.payload.payment?.entity.id} captured successfully`,
            };
        case 'payment.failed':
            return {
                status: 'ok',
                message: `Payment ${event.payload.payment?.entity.id} failed`,
            };
        case 'order.paid':
            return {
                status: 'ok',
                message: `Order ${event.payload.payment?.entity.order_id} marked as paid`,
            };
        default:
            logger.info(JSON.stringify({
                type: 'razorpay_webhook_ignored',
                eventId: event.id,
                eventType: event.event,
            }));
            return {
                status: 'ignored',
                message: `Unhandled event type: ${event.event}`,
            };
    }
}
