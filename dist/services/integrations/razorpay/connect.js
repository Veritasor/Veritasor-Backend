import { createHash } from 'node:crypto';
import { integrationRepository } from '../../../repositories/integrations.js';
const RAZORPAY_VERIFY_URL = 'https://api.razorpay.com/v1/payments';
const MAX_CREDENTIAL_LENGTH = 256;
const CREDENTIAL_TIMEOUT_MS = 10_000;
/**
 * Validate and return a Razorpay credential value without mutating it.
 * Rejecting padded or control-character input helps preserve credential integrity.
 */
function parseCredential(value) {
    if (typeof value !== 'string') {
        return null;
    }
    if (value.length === 0 || value.length > MAX_CREDENTIAL_LENGTH) {
        return null;
    }
    if (value.trim() !== value) {
        return null;
    }
    if (/[\u0000-\u001f\u007f]/.test(value)) {
        return null;
    }
    return value;
}
function isRazorpayVerificationPayload(value) {
    if (!value || typeof value !== 'object') {
        return false;
    }
    const payload = value;
    return payload.entity === 'collection' && Array.isArray(payload.items);
}
function fingerprintCredentials(apiKeyId, apiKeySecret) {
    return createHash('sha256')
        .update(`${apiKeyId}:${apiKeySecret}`)
        .digest('hex');
}
/**
 * Connect Razorpay account using API key pair.
 * Expects { apiKeyId, apiKeySecret } in the JSON body.
 * Verifies credentials by calling a lightweight Razorpay endpoint before storing.
 *
 * Security notes:
 * - Rejects malformed or padded credentials instead of normalizing them silently.
 * - Refuses duplicate provider connections for the same user.
 * - Never returns upstream Razorpay response bodies or secrets to the client.
 */
export async function connectRazorpay(req, res) {
    const userId = req.user?.userId;
    if (!userId)
        return res.status(401).json({ error: 'Unauthorized' });
    const apiKeyId = parseCredential(req.body?.apiKeyId);
    const apiKeySecret = parseCredential(req.body?.apiKeySecret);
    if (!apiKeyId || !apiKeySecret) {
        return res.status(400).json({
            error: 'apiKeyId and apiKeySecret must be non-empty strings without surrounding whitespace',
        });
    }
    const existingIntegration = integrationRepository.findByUserAndProvider(userId, 'razorpay');
    if (existingIntegration) {
        return res.status(409).json({ error: 'Razorpay integration already connected' });
    }
    const auth = Buffer.from(`${apiKeyId}:${apiKeySecret}`).toString('base64');
    const url = new URL(RAZORPAY_VERIFY_URL);
    url.searchParams.set('count', '1');
    try {
        const resp = await fetch(url.toString(), {
            headers: { Authorization: `Basic ${auth}`, Accept: 'application/json' },
            signal: AbortSignal.timeout(CREDENTIAL_TIMEOUT_MS),
        });
        if (!resp.ok) {
            if (resp.status === 401 || resp.status === 403) {
                return res.status(400).json({ error: 'Invalid Razorpay credentials' });
            }
            return res.status(502).json({ error: 'Razorpay credential verification failed' });
        }
        const responseBody = await resp.json().catch(() => null);
        if (!isRazorpayVerificationPayload(responseBody)) {
            return res.status(502).json({ error: 'Unexpected Razorpay verification response' });
        }
    }
    catch {
        return res.status(502).json({ error: 'Failed to reach Razorpay API' });
    }
    const record = integrationRepository.create({
        provider: 'razorpay',
        userId,
        meta: {
            apiKeyId,
            apiKeySecret,
            credentialFingerprint: fingerprintCredentials(apiKeyId, apiKeySecret),
            verifiedAt: new Date().toISOString(),
        },
    });
    const safe = {
        ...record,
        meta: {
            apiKeyId: record.meta.apiKeyId,
            apiKeySecret: '*****',
            credentialFingerprint: record.meta.credentialFingerprint,
            verifiedAt: record.meta.verifiedAt,
        },
    };
    return res.status(201).json(safe);
}
export default connectRazorpay;
