import { describe, expect, it, vi } from 'vitest';
import { listByBusiness, listPeriods } from '../../../src/repositories/attestationRepository.js';
import type { DbClient } from '../../../src/types/attestation.js';

vi.mock('../../../src/services/soroban/getAttestation.js', () => ({ getAttestation: vi.fn() }));
vi.mock('../../../src/utils/logger.js', () => ({ logger: { warn: vi.fn() } }));

describe('SQL attestation analytics reads', () => {
  it('binds the business ID and delegates distinct descending periods to SQL', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ period: '2026-02' }, { period: '2026-01' }] });
    const client: DbClient = { query };
    const businessId = "business' OR TRUE --";
    await expect(listPeriods(client, businessId)).resolves.toEqual(['2026-02', '2026-01']);
    expect(query).toHaveBeenCalledWith(
      'SELECT DISTINCT period FROM attestations WHERE business_id = $1 ORDER BY period DESC',
      [businessId],
    );
  });

  it('maps persisted records and reads all matching rows in deterministic order', async () => {
    const row = {
      id: 'id', business_id: 'business', period: '2026-01', merkle_root: 'root',
      tx_hash: 'tx', status: 'confirmed', version: 2,
      created_at: '2026-02-01T00:00:00Z', updated_at: '2026-02-02T00:00:00Z',
    };
    const query = vi.fn().mockResolvedValue({ rows: [row] });
    await expect(listByBusiness({ query }, 'business')).resolves.toEqual([{
      id: 'id', businessId: 'business', period: '2026-01', merkleRoot: 'root', txHash: 'tx',
      status: 'confirmed', version: 2, createdAt: new Date(row.created_at), updatedAt: new Date(row.updated_at),
    }]);
    expect(query).toHaveBeenCalledWith(
      'SELECT * FROM attestations WHERE business_id = $1 ORDER BY created_at DESC, id DESC', ['business'],
    );
  });

  it('returns empty results for a business with no persisted attestations', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [] });
    await expect(listPeriods({ query }, 'missing')).resolves.toEqual([]);
    await expect(listByBusiness({ query }, 'missing')).resolves.toEqual([]);
  });

  it('propagates database errors', async () => {
    const failure = new Error('connection failed');
    const query = vi.fn().mockRejectedValue(failure);
    await expect(listPeriods({ query }, 'business')).rejects.toBe(failure);
    await expect(listByBusiness({ query }, 'business')).rejects.toBe(failure);
  });
});
