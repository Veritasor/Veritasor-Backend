import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { idempotencyMiddleware } from '../middleware/idempotency.js';
import { validateBody, validateQuery } from '../middleware/validate.js';
import { attestationRepository } from '../repositories/attestation.js';
import { businessRepository } from '../repositories/business.js';
import { AppError } from '../types/errors.js';
const localAttestationStore = [];
export const attestationsRouter = Router();
/**
 * @notice NatSpec: Schema for listing attestations.
 * @dev Enforces strict query parameters and sets maximum bounds to prevent DoS.
 */
const listQuerySchema = z.object({
    businessId: z.string().min(1).max(255).optional(),
    period: z.string().min(1).max(50).optional(),
    status: z.enum(['submitted', 'revoked']).optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
}).strict();
/**
 * @notice NatSpec: Schema for submitting an attestation.
 * @dev Enforces strict body payload to prevent prototype pollution and arbitrary field injection.
 */
const submitBodySchema = z.object({
    businessId: z.string().min(1).max(255).optional(),
    period: z.string().min(1).max(50),
    merkleRoot: z.string().min(1).max(1024),
    timestamp: z.coerce.number().int().nonnegative().optional(),
    version: z.string().min(1).max(50).default('1.0.0'),
}).strict();
/**
 * @notice NatSpec: Schema for revoking an attestation.
 * @dev Limits reason length and strictly prevents extra fields.
 */
const revokeBodySchema = z.object({
    reason: z.string().trim().min(1).max(1000).optional(),
}).strict();
function createHttpError(status, code, message) {
    return new AppError(message, status, code);
}
function asyncHandler(handler) {
    return (req, res, next) => {
        void handler(req, res, next).catch(next);
    };
}
function parseIdParam(id) {
    const parsed = z.string().min(1).safeParse(id);
    if (!parsed.success) {
        throw createHttpError(400, 'VALIDATION_ERROR', 'Invalid attestation id');
    }
    return parsed.data;
}
async function resolveBusinessIdForUser(userId) {
    const repo = businessRepository;
    if (typeof repo.getByUserId === 'function') {
        const business = await repo.getByUserId(userId);
        return business?.id ?? null;
    }
    if (typeof repo.findByUserId === 'function') {
        const business = repo.findByUserId(userId);
        return business?.id ?? null;
    }
    return null;
}
async function listByBusinessId(businessId) {
    const repo = attestationRepository;
    let repositoryItems = [];
    if (typeof repo.listByBusiness === 'function') {
        repositoryItems = repo.listByBusiness(businessId);
    }
    else if (typeof repo.list === 'function') {
        repositoryItems = await repo.list({ businessId });
    }
    const localItems = localAttestationStore.filter((item) => item.businessId === businessId);
    const merged = [...repositoryItems, ...localItems];
    const deduped = new Map();
    for (const item of merged) {
        deduped.set(item.id, item);
    }
    return Array.from(deduped.values()).sort((a, b) => b.attestedAt.localeCompare(a.attestedAt));
}
async function getById(id, businessId) {
    const repo = attestationRepository;
    if (typeof repo.getById === 'function') {
        const found = await repo.getById(id);
        if (!found || found.businessId !== businessId) {
            return null;
        }
        return found;
    }
    const items = await listByBusinessId(businessId);
    return items.find((item) => item.id === id) ?? null;
}
async function saveAttestation(record) {
    const repo = attestationRepository;
    if (typeof repo.create === 'function') {
        return repo.create(record);
    }
    localAttestationStore.push(record);
    return record;
}
async function revokeAttestation(id, reason) {
    const repo = attestationRepository;
    if (typeof repo.revoke === 'function') {
        return repo.revoke(id, { reason });
    }
    const index = localAttestationStore.findIndex((item) => item.id === id);
    if (index === -1) {
        return null;
    }
    localAttestationStore[index] = {
        ...localAttestationStore[index],
        status: 'revoked',
        revokedAt: new Date().toISOString(),
    };
    return localAttestationStore[index];
}
async function submitOnChain(params) {
    const modulePath = '../services/soroban/submitAttestation.js';
    let module;
    try {
        module = (await import(modulePath));
    }
    catch (_error) {
        // Service is optional at route layer while other issue lands.
        return {
            txHash: `pending_${randomUUID()}`,
        };
    }
    if (typeof module.submitAttestation !== 'function') {
        return {
            txHash: `pending_${randomUUID()}`,
        };
    }
    try {
        return await module.submitAttestation(params);
    }
    catch (error) {
        const sorobanError = error;
        if (sorobanError?.code === 'VALIDATION_ERROR') {
            throw createHttpError(400, sorobanError.code, sorobanError.message);
        }
        if (sorobanError?.code === 'MISSING_SIGNER' ||
            sorobanError?.code === 'SIGNER_MISMATCH') {
            throw createHttpError(503, sorobanError.code, 'Soroban submission is not available right now.');
        }
        if (sorobanError?.code === 'SUBMIT_FAILED' ||
            sorobanError?.code === 'SOROBAN_NETWORK_ERROR') {
            throw createHttpError(502, sorobanError.code, 'Soroban RPC request failed after applying the retry policy.');
        }
        throw error;
    }
}
attestationsRouter.get('/', requireAuth, validateQuery(listQuerySchema), asyncHandler(async (req, res) => {
    const query = req.query;
    const businessId = query.businessId ?? (await resolveBusinessIdForUser(req.user.id));
    if (!businessId) {
        throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }
    const allItems = await listByBusinessId(businessId);
    const filtered = allItems.filter((item) => {
        if (query.period && item.period !== query.period) {
            return false;
        }
        if (query.status && (item.status ?? 'submitted') !== query.status) {
            return false;
        }
        return true;
    });
    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / query.limit));
    const start = (query.page - 1) * query.limit;
    const items = filtered.slice(start, start + query.limit);
    res.status(200).json({
        status: 'success',
        data: items,
        pagination: {
            page: query.page,
            limit: query.limit,
            total,
            totalPages,
        },
    });
}));
attestationsRouter.get('/:id', requireAuth, asyncHandler(async (req, res) => {
    const id = parseIdParam(req.params.id);
    const businessId = await resolveBusinessIdForUser(req.user.id);
    if (!businessId) {
        throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }
    const attestation = await getById(id, businessId);
    if (!attestation) {
        throw createHttpError(404, 'ATTESTATION_NOT_FOUND', 'Attestation not found');
    }
    res.status(200).json({
        status: 'success',
        data: attestation,
    });
}));
attestationsRouter.post('/', requireAuth, idempotencyMiddleware({ scope: 'attestations' }), validateBody(submitBodySchema), asyncHandler(async (req, res) => {
    const payload = req.body;
    const userBusinessId = await resolveBusinessIdForUser(req.user.id);
    const businessId = payload.businessId ?? userBusinessId;
    if (!businessId) {
        throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }
    if (payload.businessId && userBusinessId && payload.businessId !== userBusinessId) {
        throw createHttpError(403, 'FORBIDDEN', 'Cannot submit attestation for another business');
    }
    const onChain = await submitOnChain({
        business: businessId,
        period: payload.period,
        merkleRoot: payload.merkleRoot,
        timestamp: payload.timestamp ?? Date.now(),
        version: payload.version,
    });
    const now = new Date().toISOString();
    const record = {
        id: randomUUID(),
        businessId,
        period: payload.period,
        merkleRoot: payload.merkleRoot,
        timestamp: payload.timestamp ?? Date.now(),
        version: payload.version,
        txHash: onChain.txHash,
        status: 'submitted',
        revokedAt: null,
        attestedAt: now,
    };
    const saved = await saveAttestation(record);
    res.status(201).json({
        status: 'success',
        data: saved,
        txHash: onChain.txHash,
    });
}));
async function handleRevoke(req, res) {
    const id = parseIdParam(req.params.id);
    const businessId = await resolveBusinessIdForUser(req.user.id);
    if (!businessId) {
        throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }
    const attestation = await getById(id, businessId);
    if (!attestation) {
        throw createHttpError(404, 'ATTESTATION_NOT_FOUND', 'Attestation not found');
    }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : undefined;
    const revoked = await revokeAttestation(id, reason);
    if (!revoked) {
        throw createHttpError(500, 'REVOKE_FAILED', 'Failed to revoke attestation');
    }
    res.status(200).json({
        status: 'success',
        data: revoked,
    });
}
attestationsRouter.post('/:id/revoke', requireAuth, validateBody(revokeBodySchema), asyncHandler(handleRevoke));
attestationsRouter.delete('/:id/revoke', requireAuth, asyncHandler(handleRevoke));
