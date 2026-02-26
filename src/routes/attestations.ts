import { Router } from 'express'
import { idempotencyMiddleware } from '../middleware/idempotency.js'

export const attestationsRouter = Router()

attestationsRouter.use(requireAuth)

// Placeholder: list attestations (will integrate DB + Horizon later)
attestationsRouter.get('/', (_req, res) => {
  res.json({
    attestations: [],
    message: 'Attestation list will be populated from DB + Stellar',
  })
})

// Placeholder: submit attestation (will call Merkle engine + Soroban later). Idempotent by Idempotency-Key.
attestationsRouter.post(
  '/',
  idempotencyMiddleware({ scope: 'attestations' }),
  (req, res) => {
    res.status(201).json({
      message: 'Attestation submission will invoke Merkle generator and Soroban contract',
      business_id: req.body?.business_id ?? null,
      period: req.body?.period ?? null,
    })
  }
)
