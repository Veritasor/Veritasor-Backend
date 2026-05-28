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

import { attestationRepository } from '../../../../src/repositories/attestation.js'
import { businessRepository } from '../../../../src/repositories/business.js'

describe('revokeAttestation', () => {
  const mockAttestationRepository = vi.mocked(attestationRepository)
  const mockBusinessRepository = vi.mocked(businessRepository)

  beforeEach(() => {
    vi.clearAllMocks()
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