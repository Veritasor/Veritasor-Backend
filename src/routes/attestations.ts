import { randomUUID } from 'node:crypto';
import { NextFunction, Request, Response, Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { idempotencyMiddleware } from '../middleware/idempotency.js';
import { validateBody, validateQuery } from '../middleware/validate.js';
import { attestationRepository } from '../repositories/attestation.js';
import { businessRepository } from '../repositories/business.js';
import { AppError } from '../types/errors.js';

type RouteAttestation = {
  id: string;
  businessId: string;
  period: string;
  attestedAt: string;
  merkleRoot?: string;
  timestamp?: number;
  version?: string;
  txHash?: string;
  status?: 'submitted' | 'revoked';
  revokedAt?: string | null;
};

type SubmitAttestationParams = {
  business: string;
  period: string;
  merkleRoot: string;
  timestamp: number;
  version: string;
};

type SubmitAttestationResult = {
  txHash: string;
};

type SorobanServiceError = Error & {
  code?: string;
};

const localAttestationStore: RouteAttestation[] = [];
export const attestationsRouter = Router();

/**
 * Maximum byte length allowed for a route :id parameter.
 *
 * Express does not enforce parameter length; an unbounded parameter could cause
 * DoS by forcing a full DB scan or log-line overflow. 512 chars covers any
 * reasonable UUID, slug, or hash while staying well under typical DB index limits.
 */
const ATTESTATION_ID_MAX_LENGTH = 512;

/**
 * Regex that rejects null bytes and ASCII control characters in the :id param.
 * Control characters in IDs can confuse log aggregators and some DB drivers.
 */
const SAFE_ID_PATTERN = /^[^\u0000-\u001F\u007F]+$/;

/**
 * @notice NatSpec: Schema for listing attestations.
 * @dev Enforces strict query parameters and sets maximum bounds to prevent DoS.
 *
 * Security notes:
 * - `.strict()` rejects unknown keys (prevents prototype-pollution via query params).
 * - `page` and `limit` use `z.coerce` to handle query-string strings, but integer
 *   and range checks prevent NaN/Infinity/float/negative inputs from reaching the
 *   pagination logic silently.
 */
const listQuerySchema = z.object({
  businessId: z.string().min(1).max(255).optional(),
  period: z.string().min(1).max(50).optional(),
  status: z.enum(['submitted', 'revoked']).optional(),
  page: z.coerce.number().int('page must be an integer').min(1, 'page must be ≥ 1').default(1),
  limit: z.coerce
    .number()
    .int('limit must be an integer')
    .min(1, 'limit must be ≥ 1')
    .max(100, 'limit must be ≤ 100')
    .default(20),
}).strict();

/**
 * @notice NatSpec: Schema for submitting an attestation.
 * @dev Enforces strict body payload to prevent prototype pollution and arbitrary
 *      field injection.
 *
 * Security notes:
 * - `timestamp` uses `z.coerce.number().int().nonnegative()` — rejects NaN strings,
 *   negative values, and floats that would survive a plain `Number()` conversion.
 * - `.strict()` rejects extra fields including `__proto__`, `constructor`, etc.
 */
const submitBodySchema = z.object({
  businessId: z.string().min(1).max(255).optional(),
  period: z.string().min(1).max(50),
  merkleRoot: z.string().min(1).max(1024),
  timestamp: z.coerce.number().int('timestamp must be an integer').nonnegative('timestamp must be ≥ 0').optional(),
  version: z.string().min(1).max(50).default('1.0.0'),
}).strict();

/**
 * @notice NatSpec: Schema for revoking an attestation.
 * @dev Limits reason length and strictly prevents extra fields.
 */
const revokeBodySchema = z.object({
  reason: z.string().trim().min(1).max(1000).optional(),
}).strict();

function createHttpError(status: number, code: string, message: string): AppError {
  return new AppError(message, status, code);
}

function asyncHandler(handler: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    void handler(req, res, next).catch(next);
  };
}

/**
 * Parse and validate the :id route parameter.
 *
 * Guards:
 * 1. Must be a non-empty string (Express always provides a string, but be explicit).
 * 2. Must not contain null bytes or control characters — these can confuse DB
 *    drivers, log parsers, and upstream cache keys.
 * 3. Bounded to ATTESTATION_ID_MAX_LENGTH characters to prevent DoS via oversized
 *    index lookups or log-line inflation.
 *
 * @throws AppError 400 VALIDATION_ERROR on any violation.
 */
function parseIdParam(id: string): string {
  const lengthResult = z.string().min(1).safeParse(id);
  if (!lengthResult.success) {
    throw createHttpError(400, 'VALIDATION_ERROR', 'Invalid attestation id');
  }

  if (id.length > ATTESTATION_ID_MAX_LENGTH) {
    throw createHttpError(400, 'VALIDATION_ERROR', `Attestation id must be at most ${ATTESTATION_ID_MAX_LENGTH} characters`);
  }

  if (!SAFE_ID_PATTERN.test(id)) {
    throw createHttpError(400, 'VALIDATION_ERROR', 'Attestation id contains invalid characters');
  }

  return id;
}

async function resolveBusinessIdForUser(userId: string): Promise<string | null> {
  const repo = businessRepository as Record<string, unknown>;

  if (typeof repo.getByUserId === 'function') {
    const business = await (repo.getByUserId as (id: string) => Promise<{ id: string } | null>)(userId);
    return business?.id ?? null;
  }

  if (typeof repo.findByUserId === 'function') {
    const business = (repo.findByUserId as (id: string) => { id: string } | null)(userId);
    return business?.id ?? null;
  }

  return null;
}

async function listByBusinessId(businessId: string): Promise<RouteAttestation[]> {
  const repo = attestationRepository as Record<string, unknown>;

  let repositoryItems: RouteAttestation[] = [];

  if (typeof repo.listByBusiness === 'function') {
    repositoryItems = (repo.listByBusiness as (id: string) => RouteAttestation[])(businessId);
  } else if (typeof repo.list === 'function') {
    repositoryItems = await (repo.list as (filters: { businessId: string }) => Promise<RouteAttestation[]>)({ businessId });
  }

  const localItems = localAttestationStore.filter((item) => item.businessId === businessId);
  const merged = [...repositoryItems, ...localItems];
  const deduped = new Map<string, RouteAttestation>();

  for (const item of merged) {
    deduped.set(item.id, item);
  }

  return Array.from(deduped.values()).sort((a, b) => b.attestedAt.localeCompare(a.attestedAt));
}

async function getById(id: string, businessId: string): Promise<RouteAttestation | null> {
  const repo = attestationRepository as Record<string, unknown>;

  if (typeof repo.getById === 'function') {
    const found = await (repo.getById as (value: string) => Promise<RouteAttestation | null>)(id);
    if (!found || found.businessId !== businessId) {
      return null;
    }
    return found;
  }

  const items = await listByBusinessId(businessId);
  return items.find((item) => item.id === id) ?? null;
}

async function saveAttestation(record: RouteAttestation): Promise<RouteAttestation> {
  const repo = attestationRepository as Record<string, unknown>;

  if (typeof repo.create === 'function') {
    return (repo.create as (value: RouteAttestation) => Promise<RouteAttestation>)(record);
  }

  localAttestationStore.push(record);
  return record;
}

async function revokeAttestation(id: string, reason?: string): Promise<RouteAttestation | null> {
  const repo = attestationRepository as Record<string, unknown>;

  if (typeof repo.revoke === 'function') {
    return (repo.revoke as (value: string, data?: { reason?: string }) => Promise<RouteAttestation | null>)(id, { reason });
  }

  const index = localAttestationStore.findIndex((item) => item.id === id);
  if (index === -1) {
    console.log(`Attestation ${id} not found in local store. Available IDs:`,
      localAttestationStore.map(i => i.id));
    return null;
  }

  if (localAttestationStore[index].status === 'revoked') {
    console.log(`Attestation ${id} is already revoked`);
    return localAttestationStore[index];
  }

  const updated: RouteAttestation = {
    ...localAttestationStore[index],
    status: 'revoked',
    revokedAt: new Date().toISOString(),
  };

  localAttestationStore[index] = updated;
  console.log(`Successfully revoked attestation ${id}`, updated);
  return updated;
}

async function submitOnChain(params: SubmitAttestationParams): Promise<SubmitAttestationResult> {
  const modulePath = '../services/soroban/submitAttestation.js';
  let module: {
    submitAttestation?: (value: SubmitAttestationParams) => Promise<SubmitAttestationResult>;
  };

  try {
    module = (await import(modulePath)) as typeof module;
  } catch (_error) {
    return { txHash: `pending_${randomUUID()}` };
  }

  if (typeof module.submitAttestation !== 'function') {
    return { txHash: `pending_${randomUUID()}` };
  }

  try {
    return await module.submitAttestation(params);
  } catch (error) {
    const sorobanError = error as SorobanServiceError;

    if (sorobanError?.code === 'VALIDATION_ERROR') {
      throw createHttpError(400, sorobanError.code, sorobanError.message);
    }

    if (
      sorobanError?.code === 'MISSING_SIGNER' ||
      sorobanError?.code === 'SIGNER_MISMATCH'
    ) {
      throw createHttpError(503, sorobanError.code, 'Soroban submission is not available right now.');
    }

    if (
      sorobanError?.code === 'SUBMIT_FAILED' ||
      sorobanError?.code === 'SOROBAN_NETWORK_ERROR'
    ) {
      throw createHttpError(502, sorobanError.code, 'Soroban RPC request failed after applying the retry policy.');
    }

    throw error;
  }
}

attestationsRouter.get(
  '/',
  requireAuth,
  validateQuery(listQuerySchema),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as z.infer<typeof listQuerySchema>;
    const businessId = query.businessId ?? (await resolveBusinessIdForUser(req.user!.id));

    if (!businessId) {
      throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }

    const allItems = await listByBusinessId(businessId);
    const filtered = allItems.filter((item) => {
      if (query.period && item.period !== query.period) return false;
      if (query.status && (item.status ?? 'submitted') !== query.status) return false;
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
  }),
);

attestationsRouter.get(
  '/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const id = parseIdParam(req.params.id);
    const businessId = await resolveBusinessIdForUser(req.user!.id);

    if (!businessId) {
      throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }

    const attestation = await getById(id, businessId);
    if (!attestation) {
      throw createHttpError(404, 'ATTESTATION_NOT_FOUND', 'Attestation not found');
    }

    res.status(200).json({ status: 'success', data: attestation });
  }),
);

attestationsRouter.post(
  '/',
  requireAuth,
  idempotencyMiddleware({ scope: 'attestations' }),
  validateBody(submitBodySchema),
  asyncHandler(async (req, res) => {
    const payload = req.body as z.infer<typeof submitBodySchema>;
    const userBusinessId = await resolveBusinessIdForUser(req.user!.id);
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
    const record: RouteAttestation = {
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
  }),
);

async function handleRevoke(req: Request, res: Response): Promise<void> {
  try {
    const id = parseIdParam(req.params.id);
    const businessId = await resolveBusinessIdForUser(req.user!.id);

    if (!businessId) {
      throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }

    const attestation = await getById(id, businessId);
    if (!attestation) {
      throw createHttpError(404, 'ATTESTATION_NOT_FOUND', 'Attestation not found');
    }

    if (attestation.status === 'revoked') {
      throw createHttpError(400, 'ALREADY_REVOKED', 'Attestation is already revoked');
    }

    const reason = typeof req.body?.reason === 'string' ? req.body.reason : undefined;
    const revoked = await revokeAttestation(id, reason);

    if (!revoked) {
      throw createHttpError(500, 'REVOKE_FAILED', 'Failed to revoke attestation');
    }

    res.status(200).json({ status: 'success', data: revoked });
  } catch (error) {
    if (error instanceof AppError) {
      throw error;
    }
    console.error('Revoke error:', error);
    throw createHttpError(500, 'REVOKE_FAILED', 'Internal server error during revocation');
  }
}

attestationsRouter.post(
  '/:id/revoke',
  requireAuth,
  validateBody(revokeBodySchema),
  asyncHandler(handleRevoke)
);

attestationsRouter.delete(
  '/:id/revoke',
  requireAuth,
  asyncHandler(handleRevoke)
);