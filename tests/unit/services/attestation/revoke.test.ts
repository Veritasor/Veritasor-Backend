import { describe, expect, it, vi } from 'vitest'
import { revokeAttestation } from '../../../../src/services/attestation/revoke.js'

// Mock repositories
vi.mock('../../../../src/repositories/attestation.js', () => ({
  attestationRepository: {
    findById: vi.fn(),
    update: vi.fn(),
  },
}))

vi.mock('../../../../src/repositories/business.js', () => ({
  businessRepository: {
    findById: vi.fn(),
  },
}))

vi.mock('../../../../src/services/features/flags.js', () => ({
  FlagKeys: {
    SOROBAN_ATTESTATION_REVOCATION: 'soroban_attestation_revocation',
  },
  getBooleanFlag: vi.fn(),
}))

vi.mock('../../../../src/services/soroban/submitAttestation.js', () => ({
  revokeAttestationOnChain: vi.fn(),
}))

vi.mock('../../../../src/repositories/auditLogRepository.js', () => ({
  createAuditLog: vi.fn(),
}))

import { attestationRepository } from '../../../../src/repositories/attestation.js'
import { businessRepository } from '../../../../src/repositories/business.js'
import { getBooleanFlag } from '../../../../src/services/features/flags.js'
import { revokeAttestationOnChain } from '../../../../src/services/soroban/submitAttestation.js'
import { createAuditLog } from '../../../../src/repositories/auditLogRepository.js'

describe('revokeAttestation', () => {
  const mockAttestationRepository = vi.mocked(attestationRepository)
  const mockBusinessRepository = vi.mocked(businessRepository)
  const mockGetBooleanFlag = vi.mocked(getBooleanFlag)
  const mockRevokeAttestationOnChain = vi.mocked(revokeAttestationOnChain)
  const mockCreateAuditLog = vi.mocked(createAuditLog)

  beforeEach(() => {
    vi.clearAllMocks()
    mockGetBooleanFlag.mockResolvedValue(false)
    mockCreateAuditLog.mockResolvedValue({} as Awaited<ReturnType<typeof createAuditLog>>)
  })

  it('does not call Soroban when on-chain revocation is disabled', async () => {
    mockAttestationRepository.findById.mockReturnValue({
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'submitted',
    })
    mockBusinessRepository.findById.mockResolvedValue({ id: 'biz_1', userId: 'user_1' })
    mockAttestationRepository.update.mockReturnValue({
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'revoked',
    })

    await expect(revokeAttestation('att_1', 'user_1')).resolves.toBeUndefined()

    expect(mockRevokeAttestationOnChain).not.toHaveBeenCalled()
    expect(mockAttestationRepository.update).toHaveBeenCalledWith('att_1', {
      status: 'revoked',
      revokedAt: expect.any(String),
    })
  })

  it('persists the Soroban transaction hash when on-chain revocation succeeds', async () => {
    mockGetBooleanFlag.mockResolvedValue(true)
    mockAttestationRepository.findById.mockReturnValue({
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'submitted',
    })
    mockBusinessRepository.findById.mockResolvedValue({ id: 'biz_1', userId: 'user_1' })
    mockAttestationRepository.update.mockReturnValue({
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'revoked',
    })
    mockRevokeAttestationOnChain.mockResolvedValue('tx-hash')

    await expect(revokeAttestation('att_1', 'user_1')).resolves.toBeUndefined()

    expect(mockRevokeAttestationOnChain).toHaveBeenCalledWith({
      business: 'biz_1',
      period: '2025-10',
    })
    expect(mockAttestationRepository.update).toHaveBeenLastCalledWith('att_1', {
      revokeTxHash: 'tx-hash',
    })
  })

  it('keeps the local revocation and queues a retry when Soroban fails', async () => {
    mockGetBooleanFlag.mockResolvedValue(true)
    mockAttestationRepository.findById.mockReturnValue({
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'submitted',
    })
    mockBusinessRepository.findById.mockResolvedValue({ id: 'biz_1', userId: 'user_1' })
    mockAttestationRepository.update.mockReturnValue({
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'revoked',
    })
    mockRevokeAttestationOnChain.mockRejectedValue(new Error('RPC unavailable'))

    await expect(revokeAttestation('att_1', 'user_1')).resolves.toBeUndefined()

    expect(mockAttestationRepository.update).toHaveBeenCalledWith('att_1', {
      status: 'revoked',
      revokedAt: expect.any(String),
    })
    expect(mockCreateAuditLog).toHaveBeenCalledWith({
      userId: 'user_1',
      action: 'ATTESTATION_REVOKE_RETRY_QUEUED',
      resource: 'attestation',
      resourceId: 'att_1',
      metadata: {
        businessId: 'biz_1',
        period: '2025-10',
        reason: 'RPC unavailable',
      },
    })
  })

  it('successfully revokes an attestation', async () => {
    const attestationId = 'att_1'
    const userId = 'user_1'
    const reason = 'Test reason'

    const mockAttestation = {
      id: attestationId,
      businessId: 'biz_1',
      status: 'submitted',
    }

    const mockBusiness = {
      id: 'biz_1',
      userId: userId,
    }

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)
    mockAttestationRepository.update.mockReturnValue(mockAttestation)

    await expect(revokeAttestation(attestationId, userId, reason)).resolves.toBeUndefined()

    expect(mockAttestationRepository.findById).toHaveBeenCalledWith(attestationId)
    expect(mockBusinessRepository.findById).toHaveBeenCalledWith('biz_1')
    expect(mockAttestationRepository.update).toHaveBeenCalledWith(attestationId, {
      status: 'revoked',
      revokedAt: expect.any(String),
      revokeReason: reason,
    })
  })

  it('throws error if attestation not found', async () => {
    mockAttestationRepository.findById.mockReturnValue(null)

    await expect(revokeAttestation('nonexistent', 'user_1')).rejects.toThrow('Attestation not found: nonexistent')

    expect(mockAttestationRepository.findById).toHaveBeenCalledWith('nonexistent')
  })

  it('throws error if business not found', async () => {
    const mockAttestation = { id: 'att_1', businessId: 'biz_1', status: 'submitted' }

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(null)

    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Unauthorized: attestation does not belong to your business')
  })

  it('throws error if user does not own business', async () => {
    const mockAttestation = { id: 'att_1', businessId: 'biz_1', status: 'submitted' }
    const mockBusiness = { id: 'biz_1', userId: 'other_user' }

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)

    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Unauthorized: attestation does not belong to your business')
  })

  it('throws error if attestation already revoked', async () => {
    const mockAttestation = { id: 'att_1', businessId: 'biz_1', status: 'revoked' }
    const mockBusiness = { id: 'biz_1', userId: 'user_1' }

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)

    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Attestation att_1 is already revoked')
  })

  it('handles revoke without reason', async () => {
    const mockAttestation = { id: 'att_1', businessId: 'biz_1', status: 'submitted' }
    const mockBusiness = { id: 'biz_1', userId: 'user_1' }

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)
    mockAttestationRepository.update.mockReturnValue(mockAttestation)

    await expect(revokeAttestation('att_1', 'user_1')).resolves.toBeUndefined()

    expect(mockAttestationRepository.update).toHaveBeenCalledWith('att_1', {
      status: 'revoked',
      revokedAt: expect.any(String),
    })
  })
})