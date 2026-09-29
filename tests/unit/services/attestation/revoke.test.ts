import { beforeEach, describe, expect, it, vi } from 'vitest'
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

vi.mock('../../../../src/services/cdn/cdnClientAdapter.js', () => ({
  cdnClient: { purge: vi.fn().mockResolvedValue(undefined) },
}))

vi.mock('../../../../src/services/audit/auditLog.js', () => ({
  recordCdnPurgeStatus: vi.fn(),
}))

vi.mock('../../../../src/utils/logger.js', () => ({
  logger: { info: vi.fn(), error: vi.fn() },
}))

import { attestationRepository } from '../../../../src/repositories/attestation.js'
import { businessRepository } from '../../../../src/repositories/business.js'
import { cdnClient } from '../../../../src/services/cdn/cdnClientAdapter.js'
import { recordCdnPurgeStatus } from '../../../../src/services/audit/auditLog.js'

describe('revokeAttestation', () => {
  const mockAttestationRepository = vi.mocked(attestationRepository)
  const mockBusinessRepository = vi.mocked(businessRepository)
  const makeAttestation = (status: 'active' | 'revoked' = 'active') => ({
    id: 'att_1',
    businessId: 'biz_1',
    status,
    period: '2025-01',
    attestedAt: '2025-02-01T00:00:00.000Z',
  })
  const makeBusiness = (userId = 'user_1') => ({
    id: 'biz_1',
    userId,
    name: 'Example business',
    email: 'owner@example.com',
    reportingPeriod: 'monthly' as const,
    reportingTimezone: 'UTC',
    lastReminderSentAt: null,
    createdAt: '2025-01-01T00:00:00.000Z',
    updatedAt: '2025-01-01T00:00:00.000Z',
  })

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('successfully revokes an attestation', async () => {
    const attestationId = 'att_1'
    const userId = 'user_1'
    const reason = 'Test reason'

    const mockAttestation = { ...makeAttestation(), id: attestationId }
    const mockBusiness = makeBusiness(userId)

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
    expect(cdnClient.purge).toHaveBeenCalledWith([
      `${process.env.CDN_BASE_URL ?? ''}/attestations/${attestationId}`,
    ])
    expect(recordCdnPurgeStatus).toHaveBeenCalledWith(
      attestationId,
      'success',
      { url: `${process.env.CDN_BASE_URL ?? ''}/attestations/${attestationId}` },
    )
  })

  it('throws error if attestation not found', async () => {
    mockAttestationRepository.findById.mockReturnValue(null)

    await expect(revokeAttestation('nonexistent', 'user_1')).rejects.toThrow('Attestation not found: nonexistent')

    expect(mockAttestationRepository.findById).toHaveBeenCalledWith('nonexistent')
    expect(mockAttestationRepository.update).not.toHaveBeenCalled()
    expect(cdnClient.purge).not.toHaveBeenCalled()
  })

  it('throws error if business not found', async () => {
    const mockAttestation = makeAttestation()

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(null)

    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Unauthorized: attestation does not belong to your business')
    expect(mockAttestationRepository.update).not.toHaveBeenCalled()
  })

  it('throws error if user does not own business', async () => {
    const mockAttestation = makeAttestation()
    const mockBusiness = makeBusiness('other_user')

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)

    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Unauthorized: attestation does not belong to your business')
    expect(mockAttestationRepository.update).not.toHaveBeenCalled()
  })

  it('throws error if attestation already revoked', async () => {
    const mockAttestation = makeAttestation('revoked')
    const mockBusiness = makeBusiness()

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)

    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Attestation att_1 is already revoked')
    expect(mockAttestationRepository.update).not.toHaveBeenCalled()
  })

  it('handles revoke without reason', async () => {
    const mockAttestation = makeAttestation()
    const mockBusiness = makeBusiness()

    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)
    mockAttestationRepository.update.mockReturnValue(mockAttestation)

    await expect(revokeAttestation('att_1', 'user_1')).resolves.toBeUndefined()

    expect(mockAttestationRepository.update).toHaveBeenCalledWith('att_1', {
      status: 'revoked',
      revokedAt: expect.any(String),
    })
  })

  it('does not purge the CDN when the repository update fails', async () => {
    const mockAttestation = makeAttestation()
    const mockBusiness = makeBusiness()
    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)
    mockAttestationRepository.update.mockReturnValue(null)

    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow(
      'Failed to revoke attestation: att_1',
    )
    expect(cdnClient.purge).not.toHaveBeenCalled()
    expect(recordCdnPurgeStatus).not.toHaveBeenCalled()
  })

  it('records CDN purge failure without undoing the persisted revocation', async () => {
    const mockAttestation = makeAttestation()
    const mockBusiness = makeBusiness()
    const purgeError = new Error('CDN unavailable')
    mockAttestationRepository.findById.mockReturnValue(mockAttestation)
    mockBusinessRepository.findById.mockResolvedValue(mockBusiness)
    mockAttestationRepository.update.mockReturnValue(mockAttestation)
    vi.mocked(cdnClient.purge).mockRejectedValueOnce(purgeError)

    await expect(revokeAttestation('att_1', 'user_1')).resolves.toBeUndefined()
    expect(mockAttestationRepository.update).toHaveBeenCalledOnce()
    expect(recordCdnPurgeStatus).toHaveBeenCalledWith(
      'att_1',
      'failed',
      { error: 'CDN unavailable' },
    )
  })
})
