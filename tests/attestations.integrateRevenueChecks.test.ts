import { describe, it, expect, beforeEach } from 'vitest';
import {
  integrateRevenueChecks,
  shouldProceedWithAttestation,
  type AttestationRevenueSummary,
} from '../src/services/attestation/integrateRevenueChecks.js';
import { MERKLE_MAX_LEAVES } from '../src/services/merkle/index.js';

describe('integrateRevenueChecks', () => {
  describe('Core Functionality', () => {
    it('should normalize, detect anomalies, and generate Merkle proofs', async () => {
      const entries = [
        {
          id: '1',
          amount: 100,
          currency: 'USD',
          date: '2026-01-15',
          source: 'stripe',
        },
        {
          id: '2',
          amount: 150,
          currency: 'USD',
          date: '2026-01-16',
          source: 'stripe',
        },
        {
          id: '3',
          amount: -50,
          currency: 'usd',
          date: '2026-01-17',
        },
      ];

      const result = await integrateRevenueChecks(entries);

      expect(result).toBeDefined();
      expect(result.normalizedEntries).toHaveLength(3);
      expect(result.merkleRoot).toMatch(/^[a-f0-9]{64}$/);
      expect(result.merkleProofs).toHaveLength(3);
      expect(result.warnings).toBeDefined();
    });

    it('should normalize currency codes to uppercase', async () => {
      const entries = [
        { id: '1', amount: 100, currency: 'usd', date: '2026-01-15' },
        { id: '2', amount: 200, currency: 'EUR', date: '2026-01-16' },
        { id: '3', amount: 300, date: '2026-01-17' }, // no currency
      ];

      const result = await integrateRevenueChecks(entries);

      expect(result.normalizedEntries[0].currency).toBe('USD');
      expect(result.normalizedEntries[1].currency).toBe('EUR');
      expect(result.normalizedEntries[2].currency).toBe('USD'); // default
    });

    it('should classify negative amounts as refunds', async () => {
      const entries = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: -50, date: '2026-01-16' },
        { id: '3', amount: 0, date: '2026-01-17' },
      ];

      const result = await integrateRevenueChecks(entries);

      expect(result.normalizedEntries[0].type).toBe('payment');
      expect(result.normalizedEntries[1].type).toBe('refund');
      expect(result.normalizedEntries[2].type).toBe('payment'); // zero is payment
    });

    it('should handle missing source fields by setting to "unknown"', async () => {
      const entries = [
        { id: '1', amount: 100, source: 'stripe', date: '2026-01-15' },
        { id: '2', amount: 200, date: '2026-01-16' }, // no source
      ];

      const result = await integrateRevenueChecks(entries);

      expect(result.normalizedEntries[0].source).toBe('stripe');
      expect(result.normalizedEntries[1].source).toBe('unknown');
    });
  });

  describe('Edge Cases', () => {
    it('should throw on empty entries array', async () => {
      await expect(integrateRevenueChecks([])).rejects.toThrow('No revenue entries to process');
    });

    it('should throw when entry count exceeds MERKLE_MAX_LEAVES', async () => {
      const entries = Array.from({ length: MERKLE_MAX_LEAVES + 1 }, (_, i) => ({
        id: `entry_${i}`,
        amount: 100,
        date: `2026-01-${String((i % 28) + 1).padStart(2, '0')}`,
      }));

      await expect(integrateRevenueChecks(entries)).rejects.toThrow(
        `Entry count ${MERKLE_MAX_LEAVES + 1} exceeds MERKLE_MAX_LEAVES`
      );
    });

    it('should handle single leaf (boundary case)', async () => {
      const entries = [{ id: '1', amount: 100, date: '2026-01-15' }];

      const result = await integrateRevenueChecks(entries);

      expect(result.normalizedEntries).toHaveLength(1);
      expect(result.merkleProofs).toHaveLength(1);
      expect(result.merkleProofs[0].proof).toHaveLength(0); // single leaf has no proof steps
    });

    it('should handle odd number of leaves (duplication)', async () => {
      const entries = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: 200, date: '2026-01-16' },
        { id: '3', amount: 300, date: '2026-01-17' },
      ];

      const result = await integrateRevenueChecks(entries);

      expect(result.normalizedEntries).toHaveLength(3);
      expect(result.merkleProofs).toHaveLength(3);
      // Verify proofs are valid by checking structure
      result.merkleProofs.forEach((p) => {
        expect(p.leafIndex).toBeGreaterThanOrEqual(0);
        expect(Array.isArray(p.proof)).toBe(true);
        p.proof.forEach((step) => {
          expect(step.position).toMatch(/^(left|right)$/);
          expect(step.sibling).toMatch(/^[a-f0-9]{64}$/);
        });
      });
    });

    it('should handle currency drift detection', async () => {
      const entries = Array.from({ length: 10 }, (_, i) => ({
        id: `entry_${i}`,
        amount: 100 + i * 10,
        currency: i < 5 ? 'USD' : 'EUR', // 50% USD, 50% EUR
        date: `2026-01-${String((i % 28) + 1).padStart(2, '0')}`,
      }));

      const result = await integrateRevenueChecks(entries, [], {
        refundRate: 0.05,
        unknownSourceRate: 0.02,
        usdRate: 0.9, // expect 90% USD, but we have 50%
        meanAmount: 150,
      });

      expect(result.drift.hasDrift).toBe(true);
      const usdCheck = result.drift.checks.find((c) => c.metric === 'usd_rate');
      expect(usdCheck?.flag).not.toBe('ok');
    });

    it('should handle refund spike detection', async () => {
      const entries = Array.from({ length: 10 }, (_, i) => ({
        id: `entry_${i}`,
        amount: i < 7 ? 100 : -100, // 70% refunds (high)
        date: `2026-01-${String((i % 28) + 1).padStart(2, '0')}`,
      }));

      const result = await integrateRevenueChecks(entries, [], {
        refundRate: 0.05, // expect only 5% refunds
        unknownSourceRate: 0.02,
        usdRate: 0.8,
        meanAmount: 100,
      });

      expect(result.drift.hasDrift).toBe(true);
      const refundCheck = result.drift.checks.find((c) => c.metric === 'refund_rate');
      expect(refundCheck?.flag).toBe('refund_rate_drift');
    });

    it('should skip anomaly detection when no monthly series provided', async () => {
      const entries = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: 200, date: '2026-01-16' },
      ];

      const result = await integrateRevenueChecks(entries, []);

      expect(result.anomaly.flag).toBe('ok');
      expect(result.warnings).toContain(
        'No historical monthly series provided; anomaly detection skipped'
      );
    });

    it('should detect revenue anomalies when series provided', async () => {
      const entries = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: 200, date: '2026-01-16' },
      ];

      const monthlySeries = [
        { period: '2025-12', amount: 10_000 },
        { period: '2026-01', amount: 3_000 }, // 70% drop
      ];

      const result = await integrateRevenueChecks(entries, monthlySeries);

      expect(result.anomaly.flag).not.toBe('ok');
      expect(result.anomaly.detail).toContain('dropped');
      expect(result.warnings).toContainEqual(
        expect.stringContaining('Anomaly detected')
      );
    });

    it('should handle insufficient data warning', async () => {
      const entries = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: 200, date: '2026-01-16' },
      ];

      const monthlySeries = [{ period: '2026-01', amount: 1_000 }]; // only 1 data point

      const result = await integrateRevenueChecks(entries, monthlySeries);

      expect(result.anomaly.flag).toBe('insufficient_data');
      expect(result.warnings).toContainEqual(
        expect.stringContaining('Anomaly detected')
      );
    });
  });

  describe('Merkle Proof Verification', () => {
    it('should generate consistent Merkle roots for same entries', async () => {
      const entries = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: 200, date: '2026-01-16' },
      ];

      const result1 = await integrateRevenueChecks(entries);
      const result2 = await integrateRevenueChecks(entries);

      expect(result1.merkleRoot).toBe(result2.merkleRoot);
    });

    it('should generate different Merkle root for different entries', async () => {
      const entries1 = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: 200, date: '2026-01-16' },
      ];

      const entries2 = [
        { id: '1', amount: 100, date: '2026-01-15' },
        { id: '2', amount: 201, date: '2026-01-16' }, // slightly different
      ];

      const result1 = await integrateRevenueChecks(entries1);
      const result2 = await integrateRevenueChecks(entries2);

      expect(result1.merkleRoot).not.toBe(result2.merkleRoot);
    });

    it('should generate valid proof structure for each leaf', async () => {
      const entries = Array.from({ length: 5 }, (_, i) => ({
        id: `entry_${i}`,
        amount: (i + 1) * 100,
        date: `2026-01-${String((i % 28) + 1).padStart(2, '0')}`,
      }));

      const result = await integrateRevenueChecks(entries);

      result.merkleProofs.forEach((proof, idx) => {
        expect(proof.leafIndex).toBe(idx);
        expect(Array.isArray(proof.proof)).toBe(true);
        proof.proof.forEach((step) => {
          expect(step).toHaveProperty('sibling');
          expect(step).toHaveProperty('position');
          expect(step.sibling).toMatch(/^[a-f0-9]{64}$/);
          expect(['left', 'right']).toContain(step.position);
        });
      });
    });
  });
});

describe('shouldProceedWithAttestation', () => {
  let baseSummary: AttestationRevenueSummary;

  beforeEach(() => {
    baseSummary = {
      id: 'test',
      anomaly: { score: 0, flag: 'ok', detail: 'OK' },
      drift: { hasDrift: false, overallScore: 0, checks: [], summary: 'OK' },
      normalizedEntries: [],
      merkleRoot: 'abc123',
      merkleProofs: [],
      warnings: [],
    };
  });

  it('should proceed when all checks pass', () => {
    const result = shouldProceedWithAttestation(baseSummary);

    expect(result.proceed).toBe(true);
    expect(result.reason).toBe('All checks passed');
  });

  it('should reject when anomaly score exceeds 0.7', () => {
    baseSummary.anomaly = {
      score: 0.8,
      flag: 'unusual_drop',
      detail: 'Revenue dropped 80%',
    };

    const result = shouldProceedWithAttestation(baseSummary);

    expect(result.proceed).toBe(false);
    expect(result.reason).toContain('High anomaly score');
  });

  it('should allow anomaly score ≤ 0.7', () => {
    baseSummary.anomaly = {
      score: 0.7,
      flag: 'unusual_drop',
      detail: 'Revenue dropped 70%',
    };

    const result = shouldProceedWithAttestation(baseSummary);

    expect(result.proceed).toBe(true);
  });

  it('should reject when drift score exceeds 0.5', () => {
    baseSummary.drift = {
      hasDrift: true,
      overallScore: 0.6,
      checks: [],
      summary: 'High drift',
    };

    const result = shouldProceedWithAttestation(baseSummary);

    expect(result.proceed).toBe(false);
    expect(result.reason).toContain('High drift score');
  });

  it('should allow drift score ≤ 0.5', () => {
    baseSummary.drift = {
      hasDrift: true,
      overallScore: 0.5,
      checks: [],
      summary: 'Moderate drift',
    };

    const result = shouldProceedWithAttestation(baseSummary);

    expect(result.proceed).toBe(true);
  });

  it('should provide clear error reasons', () => {
    baseSummary.anomaly = {
      score: 0.85,
      flag: 'unusual_spike',
      detail: 'Revenue spiked 300%',
    };

    const result = shouldProceedWithAttestation(baseSummary);

    expect(result.reason).toContain('Revenue spiked 300%');
  });
});
