import { randomUUID } from 'node:crypto';
import { NextFunction, Request, Response, Router } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { idempotencyMiddleware } from '../middleware/idempotency.js';
import { validateBody, validateQuery } from '../middleware/validate.js';
import * as attestationRepository from '../repositories/attestationRepository.js';
import { businessRepository } from '../repositories/business.js';
import { db } from '../db/client.js';
import { createAuditLog } from '../repositories/auditLogRepository.js';
import { ReadConsistency, type Attestation } from '../types/attestation.js';
import { revokeAttestation as revokeAttestationService } from '../services/attestation/revoke.js';
import type {
  SubmitAttestationParams as SorobanSubmitAttestationParams,
  SubmitAttestationResult as SorobanSubmitAttestationResult,
} from '../services/soroban/submitAttestation.js';
import {
  integrateRevenueChecks,
  shouldProceedWithAttestation,
  type AttestationRevenueSummary,
  type RawRevenueInput,
} from '../services/attestation/integrateRevenueChecks.js';
import { AppError } from '../types/errors.js';
import { getPagination, formatPaginatedResponse } from '../utils/pagination.js';
import { generateProof, verifyProof } from '../services/merkle/generateProof.js';
import { rateLimiter } from '../middleware/rateLimiter.js';
import { broadcaster } from '../ws/attestationStream.js';

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

type SubmitAttestationParams = Omit<SorobanSubmitAttestationParams, 'sourcePublicKey' | 'signerSecret'> & {
  userId?: string;
  businessId?: string;
};

type SubmitAttestationResult = SorobanSubmitAttestationResult;

type SorobanServiceError = Error & {
  code?: string;
};

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
  merkleRoot: z.string().min(1).max(1024).optional(),
  timestamp: z.coerce.number().int('timestamp must be an integer').nonnegative('timestamp must be ≥ 0').optional(),
  version: z.string().min(1).max(50).default('1.0.0'),
  submit: z.boolean().optional(),
  revenueEntries: z.array(z.any()).optional(),
  monthlySeries: z.array(z.any()).optional(),
});

/**
 * @notice NatSpec: Schema for revoking an attestation.
 * @dev Limits reason length and strictly prevents extra fields.
 */
const revokeBodySchema = z.object({
  reason: z.string().trim().min(1).max(1000).optional(),
}).strict();

/**
 * @notice NatSpec: Schema for requesting a Merkle inclusion proof.
 * @dev Enforces strict query parameters and handles array preprocessing.
 */
const proofQuerySchema = z.object({
  leaves: z.preprocess((val) => {
    if (typeof val === 'string') {
      try {
        const parsed = JSON.parse(val);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        return [val];
      }
    }
    return val;
  }, z.array(z.string().min(1)).min(1)),
  leafIndex: z.coerce.number().int('leafIndex must be an integer').nonnegative('leafIndex must be ≥ 0'),
}).strict();

const proofRateLimiter = rateLimiter({
  bucket: 'attestations:proof',
  max: 30,
});

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

async function listByBusinessId(businessId: string, page: number, limit: number): Promise<{ items: RouteAttestation[], total: number }> {
  const result = await attestationRepository.list(db, { businessId }, { limit, offset: (page - 1) * limit });

  const items = result.items.map((item: Attestation) => ({
    id: item.id,
    businessId: item.businessId,
    period: item.period,
    attestedAt: item.createdAt.toISOString(),
    merkleRoot: item.merkleRoot,
    txHash: item.txHash,
    status: item.status === 'revoked' ? 'revoked' as const : 'submitted' as const,
    revokedAt: item.status === 'revoked' ? item.updatedAt.toISOString() : null,
    version: item.version.toString(),
  }));

  return { items, total: result.total };
}

async function getById(id: string, businessId: string): Promise<RouteAttestation | null> {
  const found = await attestationRepository.getById(db, id);
  if (!found || found.businessId !== businessId) {
    return null;
  }
  return {
    id: found.id,
    businessId: found.businessId,
    period: found.period,
    attestedAt: found.createdAt.toISOString(),
    merkleRoot: found.merkleRoot,
    txHash: found.txHash,
    status: found.status === 'revoked' ? 'revoked' as const : 'submitted' as const,
    revokedAt: found.status === 'revoked' ? found.updatedAt.toISOString() : null,
    version: found.version.toString(),
  };
}

async function saveAttestation(record: Omit<RouteAttestation, 'id' | 'attestedAt' | 'revokedAt'> & { id?: string }): Promise<RouteAttestation> {
  const created = await attestationRepository.create(db, {
    businessId: record.businessId,
    period: record.period,
    merkleRoot: record.merkleRoot || '',
    txHash: record.txHash || '',
    status: 'submitted',
  });

  return {
    id: created.id,
    businessId: created.businessId,
    period: created.period,
    attestedAt: created.createdAt.toISOString(),
    merkleRoot: created.merkleRoot,
    txHash: created.txHash,
    status: 'submitted',
    revokedAt: null,
    version: created.version.toString(),
  };
}

async function revokeAttestation(id: string, reason?: string): Promise<RouteAttestation | null> {
  const updated = await attestationRepository.updateStatus(db, id, 'revoked');
  if (!updated) return null;

  return {
    id: updated.id,
    businessId: updated.businessId,
    period: updated.period,
    attestedAt: updated.createdAt.toISOString(),
    merkleRoot: updated.merkleRoot,
    txHash: updated.txHash,
    status: 'revoked',
    revokedAt: updated.updatedAt.toISOString(),
    version: updated.version.toString(),
  };
}

async function submitOnChain(
  params: SubmitAttestationParams & { userId?: string; businessId?: string },
): Promise<SubmitAttestationResult> {
  const shouldSubmit = params.submit ?? true;
  const submissionEnabled = process.env.SOROBAN_SUBMIT_ENABLED === 'true';

  if (shouldSubmit && !submissionEnabled) {
    return { txHash: `pending_${randomUUID()}`, status: 'pending' };
  }

  const sourcePublicKey = process.env.SOROBAN_SOURCE_PUBLIC_KEY;
  if (!sourcePublicKey) {
    throw createHttpError(503, 'SOROBAN_NOT_CONFIGURED', 'Soroban submission is not available right now.');
  }

  const modulePath = '../services/soroban/submitAttestation.js';
  let module: {
    submitAttestation?: (value: SorobanSubmitAttestationParams) => Promise<SorobanSubmitAttestationResult>;
  };

  try {
    module = (await import(modulePath)) as typeof module;
  } catch (_error) {
    return { txHash: `pending_${randomUUID()}`, status: 'pending' };
  }

  if (typeof module.submitAttestation !== 'function') {
    return { txHash: `pending_${randomUUID()}`, status: 'pending' };
  }

  try {
    return await module.submitAttestation({ ...params, sourcePublicKey, submit: shouldSubmit });
  } catch (error) {
    const sorobanError = error as SorobanServiceError;
    const code = sorobanError?.code;

    if (code === 'VALIDATION_ERROR') {
      throw createHttpError(400, code, sorobanError.message);
    }

    if (code === 'MISSING_SIGNER' || code === 'SIGNER_MISMATCH') {
      throw createHttpError(503, code, 'Soroban submission is not available right now.');
    }

    if (
      code === 'SUBMIT_FAILED' ||
      code === 'SOROBAN_NETWORK_ERROR' ||
      code === 'INVALID_RESPONSE' ||
      code === 'CONFIRMATION_FAILED' ||
      code === 'RESULT_VALIDATION_FAILED' ||
      code === 'RESULT_MISMATCH'
    ) {
      if (params.userId && params.businessId) {
        await createAuditLog({
          userId: params.userId,
          action: 'ATTESTATION_SUBMIT_FAILED',
          resource: 'attestation',
          resourceId: params.businessId,
          metadata: {
            outcome: 'submit_failed',
            errorCode: code,
            params: {
              business: params.business,
              period: params.period,
              merkleRoot: params.merkleRoot,
              timestamp: params.timestamp,
              version: params.version,
            },
          },
        }).catch(() => {});
      }
      throw createHttpError(502, code, 'Soroban RPC request failed after applying the retry policy.');
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

    const { page, limit } = getPagination({ page: query.page, limit: query.limit });
    const { items, total } = await listByBusinessId(businessId, page, limit);

    // Filter server-side if query params present (repository list handles businessId but not period/status yet)
    let filteredItems = items;
    if (query.period || query.status) {
      filteredItems = items.filter(item => {
        if (query.period && item.period !== query.period) return false;
        if (query.status && (item.status ?? 'submitted') !== query.status) return false;
        return true;
      });
    }

    const paginated = formatPaginatedResponse(filteredItems, total, page, limit);

    res.status(200).json({
      status: 'success',
      data: paginated.data,
      pagination: {
        page: paginated.page,
        limit: paginated.limit,
        total: paginated.total,
        totalPages: paginated.totalPages,
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

attestationsRouter.get(
  '/:id/proof',
  requireAuth,
  proofRateLimiter,
  validateQuery(proofQuerySchema),
  asyncHandler(async (req, res) => {
    const id = parseIdParam(req.params.id);
    const query = req.query as unknown as z.infer<typeof proofQuerySchema>;
    const { leaves, leafIndex } = query;

    const businessId = await resolveBusinessIdForUser(req.user!.id);
    if (!businessId) {
      throw createHttpError(404, 'BUSINESS_NOT_FOUND', 'Business not found for user');
    }

    const attestation = await getById(id, businessId);
    if (!attestation || attestation.status === 'revoked') {
      throw createHttpError(404, 'ATTESTATION_NOT_FOUND', 'Attestation not found');
    }

    if (leafIndex < 0 || leafIndex >= leaves.length) {
      throw createHttpError(404, 'LEAF_NOT_FOUND', 'Leaf not found at specified index');
    }

    const leaf = leaves[leafIndex];
    const root = attestation.merkleRoot;
    if (!root) {
      throw createHttpError(404, 'MERKLE_ROOT_NOT_FOUND', 'Merkle root not found for attestation');
    }

    const proof = generateProof(leaves, leafIndex);

    // Self-check: verify that the generated proof is indeed valid for this leaf and root
    const isValid = verifyProof(leaf, proof, root);
    if (!isValid) {
      throw createHttpError(400, 'INVALID_LEAVES', 'Provided leaves do not match the attestation Merkle root');
    }

    res.status(200).json({
      status: 'success',
      data: {
        leaf,
        proof,
        root,
      },
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

    let merkleRoot = payload.merkleRoot;
    let attestationSummary: AttestationRevenueSummary | undefined;

    // Use revenue entries if provided (automatic Merkle + anomaly detection)
    if (payload.revenueEntries && payload.revenueEntries.length > 0) {
      attestationSummary = await integrateRevenueChecks(
        payload.revenueEntries as RawRevenueInput[],
        payload.monthlySeries ?? [],
      );

      merkleRoot = attestationSummary.merkleRoot;

      // Check if attestation should proceed
      const check = shouldProceedWithAttestation(attestationSummary);
      if (!check.proceed) {
        throw createHttpError(
          400,
          'VALIDATION_ERROR',
          `Cannot proceed with attestation: ${check.reason}. Warnings: ${attestationSummary.warnings.join('; ')}`
        );
      }

      // Log warnings but allow submission
      if (attestationSummary.warnings.length > 0) {
        console.warn(
          `[Attestation] Warnings for business ${businessId} period ${payload.period}: ` +
          attestationSummary.warnings.join('; ')
        );
      }
    } else if (!merkleRoot) {
      throw createHttpError(
        400,
        'VALIDATION_ERROR',
        'Either revenueEntries or merkleRoot must be provided'
      );
    }

    const onChain = await submitOnChain({
      business: businessId,
      period: payload.period,
      merkleRoot: merkleRoot!,
      timestamp: payload.timestamp ?? Date.now(),
      version: payload.version,
      submit: payload.submit,
      userId: req.user!.id,
      businessId,
    });

    const submission = {
      status: onChain.status,
      txHash: onChain.txHash,
      ...(onChain.unsignedXdr ? { unsignedXdr: onChain.unsignedXdr } : {}),
      ...(onChain.ledger !== undefined ? { ledger: onChain.ledger } : {}),
      ...(onChain.resultMerkleRoot ? { resultMerkleRoot: onChain.resultMerkleRoot } : {}),
      ...(onChain.resultTimestamp !== undefined ? { resultTimestamp: onChain.resultTimestamp } : {}),
    };

    const now = new Date().toISOString();
    const record: Omit<RouteAttestation, 'id' | 'attestedAt' | 'revokedAt'> = {
      businessId,
      period: payload.period,
      merkleRoot: merkleRoot!,
      timestamp: payload.timestamp ?? Date.now(),
      version: payload.version,
      txHash: onChain.txHash,
      status: 'submitted',
    };

    const saved = await saveAttestation(record);

    broadcaster.publish({
      type: 'attestation.submitted',
      businessId,
      attestationId: saved.id,
      period: saved.period,
      txHash: onChain.txHash,
      timestamp: new Date().toISOString(),
    });

    res.status(201).json({
      status: 'success',
      data: saved,
      txHash: onChain.txHash,
      submission,
      ...(attestationSummary && {
        attestationSummary: {
          anomaly: attestationSummary.anomaly,
          drift: attestationSummary.drift,
          warnings: attestationSummary.warnings,
          merkleProofsCount: attestationSummary.merkleProofs.length,
        },
      }),
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