import { Request, Response, Router } from 'express';
import { z } from 'zod';
import * as attestationRepository from '../repositories/attestationRepository.js';
import { db } from '../db/client.js';
import { AppError } from '../types/errors.js';

const STALE_WHILE_REVALIDATE = Number(process.env.PUBLIC_CDN_STALE_WHILE_REVALIDATE) || 60;

const hashParamSchema = z.string().min(1).max(512);

export const publicAttestationsRouter = Router();

function getSwrCacheControl(maxAge: number) {
  return `public, max-age=${maxAge}, stale-while-revalidate=${STALE_WHILE_REVALIDATE}`;
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
        'Cache-Control': getSwrCacheControl(15),
        'Age': '0'
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

    const etag = `"${Buffer.from(JSON.stringify(payload)).toString('base64').slice(0, 32)}"`;
    const lastModified = attestation.createdAt.toUTCString();

    if (req.headers['if-none-match'] === etag) {
      res.status(304).end();
      return;
    }

    res.set({
      'Cache-Control': getSwrCacheControl(60),
      'ETag': etag,
      'Last-Modified': lastModified,
      'Age': '0'
    });

    res.status(200).json({
      status: 'success',
      data: payload,
    });
  },
);
