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
