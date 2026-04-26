import crypto from 'crypto';
export function verifyRazorpaySignature(rawBody, signature, secret) {
    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(rawBody)
        .digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature));
}
export function handleRazorpayEvent(event) {
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
            return {
                status: 'ignored',
                message: `Unhandled event type: ${event.event}`,
            };
    }
}
