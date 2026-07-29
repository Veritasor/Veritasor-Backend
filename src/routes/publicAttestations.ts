import crypto from 'node:crypto';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import * as attestationRepository from '../repositories/attestationRepository.js';
import { db } from '../db/client.js';
import { AppError } from '../types/errors.js';
import { formatCacheControl, CACHE_POLICIES } from '../utils/cachePolicy.js';
import { etagHitsTotal } from '../metrics.js';

const hashParamSchema = z.string().min(1).max(512);

export const publicAttestationsRouter = Router();

const activePolicy = CACHE_POLICIES.find(
  (p) => p.name === 'public-attestations-active',
);
const revokedPolicy = CACHE_POLICIES.find(
  (p) => p.name === 'public-attestations-revoked',
);

function sortObjectKeys(obj: Record<string, unknown>): Record<string, unknown> {
  return Object.keys(obj).sort().reduce<Record<string, unknown>>((acc, key) => {
    acc[key] = obj[key];
    return acc;
  }, {});
}

function computeEtag(payload: Record<string, unknown>): string {
  const sorted = sortObjectKeys(payload);
  const hash = crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('base64');
  return `"${hash}"`;
}

function matchEtag(ifNoneMatch: string | undefined, etag: string): boolean {
  if (!ifNoneMatch) return false;
  const candidates = ifNoneMatch.split(',').map((s) => s.trim());
  const stripWeak = (s: string) => (s.startsWith('W/') ? s.slice(2) : s);
  const target = stripWeak(etag);
  return candidates.some((c) => stripWeak(c) === target);
}

publicAttestationsRouter.get(
  '/:hash',
  async (req: Request, res: Response) => {
    const hashResult = hashParamSchema.safeParse(req.params.hash);
    if (!hashResult.success) {
      throw new AppError('Invalid attestation identifier', 400, 'VALIDATION_ERROR');
    }

    const hash = hashResult.data;
    const attestation = await attestationRepository.getById(db, hash);

    if (!attestation) {
      res.status(404).json({
        status: 'error',
        code: 'NOT_FOUND',
        message: 'Attestation not found',
      });
      return;
    }

    if (attestation.status === 'revoked') {
      res.set({
        'Cache-Control': revokedPolicy
          ? formatCacheControl(revokedPolicy.directives)
          : 'public, max-age=15, stale-while-revalidate=60',
        'Age': '0',
      });
      res.status(410).json({
        status: 'error',
        code: 'GONE',
        message: 'Attestation has been revoked',
      });
      return;
    }

    const payload = {
      id: attestation.id,
      businessId: attestation.businessId,
      period: attestation.period,
      merkleRoot: attestation.merkleRoot,
      txHash: attestation.txHash,
      status: attestation.status,
      attestedAt: attestation.createdAt.toISOString(),
    };

    const etag = computeEtag(payload);
    const lastModified = attestation.createdAt.toUTCString();

    if (matchEtag(req.headers['if-none-match'], etag)) {
      etagHitsTotal.inc({ route: 'publicAttestations', result: 'hit' });
      res.status(304).end();
      return;
    }

    etagHitsTotal.inc({ route: 'publicAttestations', result: 'miss' });

    res.set({
      'Cache-Control': activePolicy
        ? formatCacheControl(activePolicy.directives)
        : 'public, max-age=60, stale-while-revalidate=60',
      'ETag': etag,
      'Last-Modified': lastModified,
      'Age': '0',
    });

    res.status(200).json({
      status: 'success',
      data: payload,
    });
  },
);
