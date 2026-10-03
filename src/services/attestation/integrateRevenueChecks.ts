import { detectRevenueAnomaly, AnomalyResult } from '../revenue/anomalyDetection.js';
import {
  detectNormalizationDrift,
  normalizeRevenueEntry,
  NormalizedRevenue,
  NormalizationDriftResult,
  NormalizationBaseline,
} from '../revenue/normalize.js';
import {
  buildTree,
  generateProof,
  getRoot,
  MERKLE_MAX_LEAVES,
} from '../merkle/index.js';
import { MERKLE_PROOF_MAX_STEPS } from '../merkle/generateProof.js';

export type RawRevenueInput = {
  id: string;
  amount: number;
  currency?: string;
  date?: string | number;
  source?: string;
  [key: string]: unknown;
};

export type AttestationRevenueSummary = {
  id: string;
  anomaly: AnomalyResult;
  drift: NormalizationDriftResult;
  normalizedEntries: NormalizedRevenue[];
  merkleRoot: string;
  merkleProofs: Array<{ leafIndex: number; proof: Array<{ sibling: string; position: 'left' | 'right' }> }>;
  warnings: string[];
};

/**
 * Comprehensive revenue attestation pipeline:
 * 1. Normalize raw revenue entries
 * 2. Detect anomalies in monthly revenue series
 * 3. Detect drift in the current batch
 * 4. Build Merkle tree from normalized leaves
 * 5. Generate proofs for each entry
 *
 * @param rawEntries Raw revenue data from ingestion source
 * @param monthlySeries Historical monthly revenue for anomaly detection
 * @param baseline Expected normalization baseline for drift detection
 * @returns Complete attestation package with all validations and proofs
 * @throws Error if leaf count exceeds MERKLE_MAX_LEAVES or other guards fail
 */
export async function integrateRevenueChecks(
  rawEntries: RawRevenueInput[],
  monthlySeries: Array<{ period: string; amount: number }> = [],
  baseline: NormalizationBaseline = {
    refundRate: 0.05,
    unknownSourceRate: 0.02,
    usdRate: 0.8,
    meanAmount: 150,
  }
): Promise<AttestationRevenueSummary> {
  const warnings: string[] = [];

  // Step 1: Normalize entries
  const normalizedEntries = rawEntries.map((raw) => normalizeRevenueEntry(raw));

  if (normalizedEntries.length === 0) {
    throw new Error('No revenue entries to process');
  }

  if (normalizedEntries.length > MERKLE_MAX_LEAVES) {
    throw new Error(
      `Entry count ${normalizedEntries.length} exceeds MERKLE_MAX_LEAVES (${MERKLE_MAX_LEAVES})`
    );
  }

  // Step 2: Detect anomalies in monthly revenue series
  let anomaly: AnomalyResult = {
    score: 0,
    flag: 'ok',
    detail: 'No historical data for anomaly detection',
  };

  if (monthlySeries.length > 0) {
    anomaly = detectRevenueAnomaly(monthlySeries);
    if (anomaly.flag !== 'ok') {
      warnings.push(`Anomaly detected: ${anomaly.detail} (score: ${anomaly.score.toFixed(2)})`);
    }
  } else {
    warnings.push('No historical monthly series provided; anomaly detection skipped');
  }

  // Step 3: Detect drift in current batch
  const drift = detectNormalizationDrift(normalizedEntries, baseline);
  if (drift.hasDrift) {
    warnings.push(
      `Normalization drift detected: ${drift.summary} (score: ${drift.overallScore.toFixed(2)})`
    );
  }

  // Step 4: Build Merkle tree from normalized entries
  // Create leaf representations: JSON serialization of key fields
  const leaves = normalizedEntries.map((entry) =>
    JSON.stringify({
      id: entry.id,
      amount: entry.amount,
      currency: entry.currency,
      date: entry.date,
      type: entry.type,
      source: entry.source,
    })
  );

  let tree: string[] = [];
  try {
    tree = buildTree(leaves);
  } catch (error) {
    throw new Error(
      `Failed to build Merkle tree: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const merkleRoot = getRoot(tree);

  // Step 5: Generate proofs for each entry
  const merkleProofs: Array<{
    leafIndex: number;
    proof: Array<{ sibling: string; position: 'left' | 'right' }>;
  }> = [];

  for (let i = 0; i < leaves.length; i++) {
    try {
      const proof = generateProof(leaves, i);

      if (proof.length > MERKLE_PROOF_MAX_STEPS) {
        throw new Error(
          `Proof length ${proof.length} exceeds MERKLE_PROOF_MAX_STEPS (${MERKLE_PROOF_MAX_STEPS})`
        );
      }

      merkleProofs.push({
        leafIndex: i,
        proof,
      });
    } catch (error) {
      throw new Error(
        `Failed to generate proof for entry ${i}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  // Return comprehensive attestation package
  return {
    id: `attestation_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`,
    anomaly,
    drift,
    normalizedEntries,
    merkleRoot,
    merkleProofs,
    warnings,
  };
}

/**
 * Flag whether the attestation should proceed given the results.
 * Returns false if anomalies or drift exceed acceptable thresholds.
 */
export function shouldProceedWithAttestation(summary: AttestationRevenueSummary): {
  proceed: boolean;
  reason: string;
} {
  // Allow anomaly score up to 0.7 (severe anomaly starts at 0.7)
  if (summary.anomaly.flag !== 'ok' && summary.anomaly.score > 0.7) {
    return {
      proceed: false,
      reason: `High anomaly score (${summary.anomaly.score.toFixed(2)}): ${summary.anomaly.detail}`,
    };
  }

  // Allow drift score up to 0.5
  if (summary.drift.hasDrift && summary.drift.overallScore > 0.5) {
    return {
      proceed: false,
      reason: `High drift score (${summary.drift.overallScore.toFixed(2)}): ${summary.drift.summary}`,
    };
  }

  return {
    proceed: true,
    reason: 'All checks passed',
  };
}
