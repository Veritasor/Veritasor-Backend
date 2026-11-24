import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { listPeriods, listByBusiness } = vi.hoisted(() => ({
  listPeriods: vi.fn(), listByBusiness: vi.fn(),
}));
vi.mock('../../../../src/db/client.js', () => ({ db: { query: vi.fn() } }));
vi.mock('../../../../src/repositories/attestationRepository.js', () => ({
  listPeriods, listByBusiness,
}));
import { db } from '../../../../src/db/client.js';
import { listAttestedPeriodsForBusiness } from '../../../../src/services/analytics/periods.js';
import { getRevenueReport } from '../../../../src/services/analytics/revenueReports.js';

describe('persistent attestation analytics', () => {
  beforeEach(() => vi.resetAllMocks());

  it('reads periods from the SQL repository for the requested business', async () => {
    listPeriods.mockResolvedValue(['2026-02', '2026-01']);
    await expect(listAttestedPeriodsForBusiness('business-db')).resolves.toEqual(['2026-02', '2026-01']);
    expect(listPeriods).toHaveBeenCalledWith(db, 'business-db');
  });

  it('preserves revenue response fields using persisted creation timestamps', async () => {
    listByBusiness.mockResolvedValue([{
      id: 'persisted-id', period: '2026-01', createdAt: new Date('2026-02-01T00:00:00Z'),
    }]);
    await expect(getRevenueReport('business-db', '2026-01')).resolves.toEqual({
      period: '2026-01', total: 100, net: 95, currency: 'USD',
      breakdown: [{ attestationId: 'persisted-id', attestedAt: '2026-02-01T00:00:00.000Z' }],
    });
    expect(listByBusiness).toHaveBeenCalledWith(db, 'business-db');
  });

  it('propagates database failures instead of returning seeded data', async () => {
    const failure = new Error('database unavailable');
    listPeriods.mockRejectedValue(failure);
    listByBusiness.mockRejectedValue(failure);
    await expect(listAttestedPeriodsForBusiness('biz_1')).rejects.toBe(failure);
    await expect(getRevenueReport('biz_1', '2025-11')).rejects.toBe(failure);
  });

  it('has no production imports of the legacy in-memory repository', () => {
    const root = fileURLToPath(new URL('../../../../src/', import.meta.url));
    const offenders: string[] = [];
    function inspect(directory: string): void {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) inspect(path);
        else if (/\.[cm]?[jt]s$/.test(entry.name) && !/\.(test|spec)\./.test(entry.name)) {
          if (/(?:from\s*|import\s*\(|require\s*\()["'][^"']*repositories\/attestation\.[jt]s["']/.test(readFileSync(path, 'utf8'))) {
            offenders.push(path);
          }
        }
      }
    }
    inspect(root);
    expect(offenders).toEqual([]);
  });
});
