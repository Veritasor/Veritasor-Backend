import { describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { revokeAttestation } from '../../../../src/services/attestation/revoke.js'

const { mockCdnPurge, mockRecordCdnPurgeStatus } = vi.hoisted(() => ({
  mockCdnPurge: vi.fn(),
  mockRecordCdnPurgeStatus: vi.fn(),
}))

vi.mock('../../../../src/services/cdn/cdnClientAdapter.js', () => ({
  cdnClient: { purge: mockCdnPurge },
}))

vi.mock('../../../../src/services/audit/auditLog.js', () => ({
  recordCdnPurgeStatus: mockRecordCdnPurgeStatus,
}))

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
    mockCdnPurge.mockResolvedValue(undefined)
    mockGetBooleanFlag.mockResolvedValue(false)
    mockCreateAuditLog.mockResolvedValue({} as Awaited<ReturnType<typeof createAuditLog>>)
  })

  function seedRevocableAttestation() {
    let current: Record<string, unknown> = {
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'submitted',
    }
    mockAttestationRepository.findById.mockImplementation(() => current)
    mockAttestationRepository.update.mockImplementation(
      (_id: string, data: Record<string, unknown>) => {
        current = { ...current, ...data }
        return current
      },
    )
    return () => current
  }

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
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { revokeAttestation } from '../../../../src/services/attestation/revoke.js';
import * as repository from '../../../../src/repositories/attestationRepository.js';
import { businessRepository } from '../../../../src/repositories/business.js';
import { db } from '../../../../src/db/client.js';
import { cdnClient } from '../../../../src/services/cdn/cdnClientAdapter.js';
import { recordCdnPurgeStatus } from '../../../../src/services/audit/auditLog.js';
import type { Attestation } from '../../../../src/types/attestation.js';
import type { Business } from '../../../../src/repositories/business.js';

vi.mock('../../../../src/repositories/attestationRepository.js', () => ({ getById: vi.fn(), updateStatus: vi.fn() }));
vi.mock('../../../../src/repositories/business.js', () => ({ businessRepository: { findById: vi.fn() } }));
vi.mock('../../../../src/db/client.js', () => ({ db: {} }));
vi.mock('../../../../src/services/cdn/cdnClientAdapter.js', () => ({ cdnClient: { purge: vi.fn() } }));
vi.mock('../../../../src/services/audit/auditLog.js', () => ({ recordCdnPurgeStatus: vi.fn() }));
vi.mock('../../../../src/utils/logger.js', () => ({ logger: { info: vi.fn(), error: vi.fn() } }));

const attestation: Attestation = {
  id: 'att_1', businessId: 'biz_1', period: '2025-11', status: 'submitted',
  merkleRoot: 'root', txHash: 'tx', version: 3,
  createdAt: new Date('2025-12-01T00:00:00Z'), updatedAt: new Date('2025-12-01T00:00:00Z'),
};
const business: Business = {
  id: 'biz_1', userId: 'user_1', name: 'Business', email: 'owner@example.com',
  reportingPeriod: 'monthly', reportingTimezone: 'UTC', lastReminderSentAt: null,
  createdAt: '2025-01-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z',
};

describe('revokeAttestation', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(repository.getById).mockResolvedValue(attestation);
    vi.mocked(businessRepository.findById).mockResolvedValue(business);
    vi.mocked(repository.updateStatus).mockResolvedValue({ ...attestation, status: 'revoked', version: 4 });
    vi.mocked(cdnClient.purge).mockResolvedValue(undefined);
  });

  it.each([undefined, 'Test reason'])('persists revocation before purging, reason=%s', async reason => {
    await expect(revokeAttestation('att_1', 'user_1', reason)).resolves.toBeUndefined();
    expect(repository.getById).toHaveBeenCalledWith(db, 'att_1');
    expect(businessRepository.findById).toHaveBeenCalledWith('biz_1');
    expect(repository.updateStatus).toHaveBeenCalledWith(db, 'att_1', 'revoked', 3);
    expect(vi.mocked(repository.updateStatus).mock.invocationCallOrder[0])
      .toBeLessThan(vi.mocked(cdnClient.purge).mock.invocationCallOrder[0]);
    expect(recordCdnPurgeStatus).toHaveBeenCalledWith('att_1', 'success', expect.objectContaining({ reason }));
  });

  it('rejects a missing attestation', async () => {
    vi.mocked(repository.getById).mockResolvedValue(null);
    await expect(revokeAttestation('missing', 'user_1')).rejects.toThrow('Attestation not found: missing');
    expect(repository.updateStatus).not.toHaveBeenCalled();
    expect(cdnClient.purge).not.toHaveBeenCalled();
  });

  it.each([null, { ...business, userId: 'other_user' }])('rejects missing or foreign ownership', async owner => {
    vi.mocked(businessRepository.findById).mockResolvedValue(owner);
    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Unauthorized: attestation does not belong to your business');
    expect(repository.updateStatus).not.toHaveBeenCalled();
    expect(cdnClient.purge).not.toHaveBeenCalled();
  });

  it('rejects an already revoked attestation', async () => {
    vi.mocked(repository.getById).mockResolvedValue({ ...attestation, status: 'revoked' });
    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Attestation att_1 is already revoked');
    expect(repository.updateStatus).not.toHaveBeenCalled();
  });

  it('propagates a read failure without purging', async () => {
    vi.mocked(repository.getById).mockRejectedValue(new Error('read failed'));
    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('read failed');
    expect(repository.updateStatus).not.toHaveBeenCalled();
    expect(cdnClient.purge).not.toHaveBeenCalled();
  });

  it.each(['write failed', 'version conflict'])('propagates %s without purging', async message => {
    vi.mocked(repository.updateStatus).mockRejectedValue(new Error(message));
    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow(message);
    expect(cdnClient.purge).not.toHaveBeenCalled();
  });

  it('rejects an attestation removed between read and update', async () => {
    vi.mocked(repository.updateStatus).mockResolvedValue(null);
    await expect(revokeAttestation('att_1', 'user_1')).rejects.toThrow('Attestation not found: att_1');
    expect(cdnClient.purge).not.toHaveBeenCalled();
  });

  it('records a purge failure after the persisted revocation', async () => {
    vi.mocked(cdnClient.purge).mockRejectedValue(new Error('CDN unavailable'));
    await expect(revokeAttestation('att_1', 'user_1')).resolves.toBeUndefined();
    expect(repository.updateStatus).toHaveBeenCalledTimes(1);
    expect(recordCdnPurgeStatus).toHaveBeenCalledWith('att_1', 'failed', { error: 'CDN unavailable' });
  });
});

  it('stores the revoked status, timestamp and reason before purging the CDN', async () => {
    const stored = seedRevocableAttestation()
    mockBusinessRepository.findById.mockResolvedValue({ id: 'biz_1', userId: 'user_1' })

    await revokeAttestation('att_1', 'user_1', 'leaked secret')

    expect(stored()).toMatchObject({
      status: 'revoked',
      revokedAt: expect.any(String),
      revokeReason: 'leaked secret',
    })
    expect(mockAttestationRepository.findById('att_1')).toMatchObject({
      status: 'revoked',
      revokedAt: expect.any(String),
      revokeReason: 'leaked secret',
    })
    expect(mockCdnPurge).toHaveBeenCalledWith([
      expect.stringContaining('/attestations/att_1'),
    ])
    expect(mockAttestationRepository.update.mock.invocationCallOrder[0]).toBeLessThan(
      mockCdnPurge.mock.invocationCallOrder[0],
    )
  })

  it('does not purge the CDN when the repository update fails', async () => {
    mockAttestationRepository.findById.mockReturnValue({
      id: 'att_1',
      businessId: 'biz_1',
      period: '2025-10',
      status: 'submitted',
    })
    mockBusinessRepository.findById.mockResolvedValue({ id: 'biz_1', userId: 'user_1' })
    mockAttestationRepository.update.mockReturnValue(null)

    await expect(revokeAttestation('att_1', 'user_1', 'leaked secret')).rejects.toThrow(
      'Failed to update attestation att_1',
    )

    expect(mockCdnPurge).not.toHaveBeenCalled()
    expect(mockRecordCdnPurgeStatus).not.toHaveBeenCalled()
  })

  it('does not cast the typed update payload through any', () => {
    const source = readFileSync(
      new URL('../../../../src/services/attestation/revoke.ts', import.meta.url),
      'utf8',
    )

    expect(source).not.toContain('(updateData as any)')
    expect(source).not.toMatch(/revokeReason[^\n]*as any/)
  })
})
