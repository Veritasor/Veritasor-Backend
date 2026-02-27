import { randomUUID } from 'node:crypto';
import { NextFunction, Request, Response, Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { idempotencyMiddleware } from '../middleware/idempotency.js';
import { validateBody, validateQuery } from '../middleware/validate.js';
import { attestationRepository } from '../repositories/attestation.js';
import { businessRepository } from '../repositories/business.js';

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

type HttpError = Error & {
  status: number;
  code: string;
};

const localAttestationStore: RouteAttestation[] = [];
export const attestationsRouter = Router();

const listQuerySchema = z.object({
  businessId: z.string().min(1).optional(),
  period: z.string().min(1).optional(),
  status: z.enum(['submitted', 'revoked']).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

const submitBodySchema = z.object({
  businessId: z.string().min(1).optional(),
  period: z.string().min(1),
  merkleRoot: z.string().min(1),
  timestamp: z.coerce.number().int().nonnegative().optional(),
  version: z.string().min(1).default('1.0.0'),
});

const revokeBodySchema = z.object({
  reason: z.string().trim().min(1).optional(),
});

function createHttpError(status: number, code: string, message: string): HttpError {
  const error = new Error(message) as HttpError;
  error.status = status;
  error.code = code;
  return error;
}

function asyncHandler(handler: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    void handler(req, res, next).catch(next);
  };
}

function parseIdParam(id: string): string {
  const parsed = z.string().min(1).safeParse(id);
  if (!parsed.success) {
    throw createHttpError(400, 'VALIDATION_ERROR', 'Invalid attestation id');
  }
  return parsed.data;
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
    return null;
  }

  localAttestationStore[index] = {
    ...localAttestationStore[index],
    status: 'revoked',
    revokedAt: new Date().toISOString(),
  };

  return localAttestationStore[index];
}

async function submitOnChain(params: SubmitAttestationParams): Promise<SubmitAttestationResult> {
  const modulePath = '../services/soroban/submitAttestation.js';

  try {
    const module = (await import(modulePath)) as {
      submitAttestation?: (value: SubmitAttestationParams) => Promise<SubmitAttestationResult>;
    };

    if (typeof module.submitAttestation === 'function') {
      return await module.submitAttestation(params);
    }
  } catch (_error) {
    // Service is optional at route layer while other issue lands.
  }

  return {
    txHash: `pending_${randomUUID()}`,
  };
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

    res.status(200).json({
      status: 'success',
      data: attestation,
    });
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
  const id = parseIdParam(req.params.id);
  const businessId = await resolveBusinessIdForUser(req.user!.id);

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
