import {
  fetchRazorpayRevenue,
  RevenueEntry,
} from "../revenue/razorpayFetch.js";
import { MerkleTree } from "../merkle.js";
import { attestationRepository } from "../../repositories/attestation.js";

/**
 * Parses a period string (e.g. "2025-10" or "2025-Q4") into ISO start and end dates.
 */
function parsePeriod(period: string): { startDate: string; endDate: string } {
  if (period.includes("-Q")) {
    const [year, q] = period.split("-Q");
    const startMonth = (parseInt(q) - 1) * 3 + 1;
    const endMonth = startMonth + 2;
    const endDay = new Date(parseInt(year), endMonth, 0).getDate();
    return {
      startDate: `${year}-${String(startMonth).padStart(2, "0")}-01T00:00:00Z`,
      endDate: `${year}-${String(endMonth).padStart(2, "0")}-${String(endDay).padStart(2, "0")}T23:59:59Z`,
    };
  } else {
    // Treat as YYYY-MM
    const [year, month] = period.split("-");
    const endDay = new Date(parseInt(year), parseInt(month), 0).getDate();
    return {
      startDate: `${year}-${month}-01T00:00:00Z`,
      endDate: `${year}-${month}-${String(endDay).padStart(2, "0")}T23:59:59Z`,
    };
  }
}

type NormalizedRevenue = {
  date: string;
  month: string;
  amount: number;
  currency: string;
};

/**
 * Normalizes raw revenue entries into a unified format.
 */
function normalizeRevenue(entries: RevenueEntry[]): NormalizedRevenue[] {
  return entries.map((e) => ({
    date: e.date,
    month: e.date.substring(0, 7), // YYYY-MM
    amount: e.amount,
    currency: e.currency,
  }));
}

/**
 * Aggregates normalized revenue grouping by month.
 */
function aggregateByMonth(
  normalized: NormalizedRevenue[],
): Record<string, number> {
  const aggregated: Record<string, number> = {};
  for (const entry of normalized) {
    if (!aggregated[entry.month]) {
      aggregated[entry.month] = 0;
    }
    aggregated[entry.month] += entry.amount;
  }
  return aggregated;
}

/**
 * Mock interface for submitting the attestation root to Soroban.
 */
async function submitToSoroban(
  merkleRoot: string,
  businessId: string,
  period: string,
): Promise<string> {
  // Simulated call to a Soroban contract
  return `tx_${merkleRoot.substring(0, 8)}_${Date.now()}`;
}

/**
 * Orchestrates the full attestation submission flow.
 *
 * @param userId - The user initiating the request
 * @param businessId - The business ID
 * @param period - The period e.g. "2025-10" or "2025-Q4"
 * @returns Attestation ID and the mock transaction hash.
 */
export async function submitAttestation(
  userId: string,
  businessId: string,
  period: string,
): Promise<{ attestationId: string; txHash: string }> {
  try {
    const { startDate, endDate } = parsePeriod(period);

    // 1. Fetch Revenue
    // Using Razorpay for now, as it's the only implemented fetch service.
    // In a real scenario, this would loop over connected integrations from `integrationRepository`.
    let rawRevenue: RevenueEntry[];
    try {
      rawRevenue = await fetchRazorpayRevenue(startDate, endDate);
    } catch (err: any) {
      throw new Error(`Failed to fetch revenue: ${err.message}`);
    }

    if (rawRevenue.length === 0) {
      throw new Error(`No revenue found for the period ${period}`);
    }

    // 2. Normalize
    const normalized = normalizeRevenue(rawRevenue);

    // 3. Aggregate
    const aggregated = aggregateByMonth(normalized);

    // 4. Build Merkle tree
    const leaves = Object.entries(aggregated)
      .sort(([m1], [m2]) => m1.localeCompare(m2))
      .map(([month, amount]) => `${month}:${amount.toFixed(2)}`);

    const tree = new MerkleTree(leaves);
    const root = tree.getRoot();

    if (!root) {
      throw new Error("Failed to generate Merkle root from aggregated data.");
    }

    // 5. Submit to Soroban
    let txHash: string;
    try {
      txHash = await submitToSoroban(root, businessId, period);
    } catch (err: any) {
      throw new Error(`Soroban contract execution failed: ${err.message}`);
    }

    // 6. Save Attestation Record
    const attestation = attestationRepository.create({
      businessId,
      period,
    });

    return {
      attestationId: attestation.id,
      txHash,
    };
  } catch (err: any) {
    // Rethrow wrapped error preserving original message
    throw new Error(`Attestation submission failed: ${err.message}`);
  }
}
