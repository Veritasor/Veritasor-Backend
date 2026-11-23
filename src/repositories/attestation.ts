import crypto from "crypto";
import { logger } from "../utils/logger.js";

export type Attestation = {
  id: string;
  businessId: string;
  period: string;
  attestedAt: string;
  status?: "active" | "revoked";
  revokedAt?: string;
  revokeReason?: string;
  revokeTxHash?: string;
};

/**
 * Fixture rows used exclusively by tests. They are never loaded into the store
 * automatically; call `seedForTests()` to opt in.
 *
 * `biz_1` has two `2025-11` rows to model a revoked-then-reissued attestation:
 * `att_2` is the original (revoked) record and `att_4` is its active
 * replacement. `listAttestedPeriodsForBusiness` still dedupes the period.
 */
const SEED_ATTESTATIONS: readonly Attestation[] = [
  {
    id: "att_1",
    businessId: "biz_1",
    period: "2025-10",
    attestedAt: "2025-11-01T12:00:00.000Z",
    status: "active",
  },
  {
    id: "att_2",
    businessId: "biz_1",
    period: "2025-11",
    attestedAt: "2025-12-01T12:00:00.000Z",
    status: "revoked",
    revokedAt: "2025-12-10T12:00:00.000Z",
    revokeReason: "Reissued after correction",
  },
  {
    id: "att_3",
    businessId: "biz_2",
    period: "2025-Q4",
    attestedAt: "2026-01-05T12:00:00.000Z",
    status: "active",
  },
  {
    id: "att_4",
    businessId: "biz_1",
    period: "2025-11",
    attestedAt: "2025-12-15T12:00:00.000Z",
    status: "active",
  },
];

// Temporary in-memory records until DB integration lands. The store starts
// empty in every environment; fixtures must be opted into via seedForTests().
const attestationStore: Attestation[] = [];

let productionWarningEmitted = false;

/**
 * Warn once when the in-memory fallback repository is actually used in
 * production, where attestations are expected to be persisted.
 */
function warnIfInMemoryInProduction(): void {
  if (process.env.NODE_ENV !== "production" || productionWarningEmitted) {
    return;
  }
  productionWarningEmitted = true;
  logger.warn(
    "In-memory attestation repository is in use in production; attestation records will not be persisted.",
  );
}

/**
 * Remove every attestation from the in-memory store.
 */
export const reset = (): void => {
  attestationStore.length = 0;
};

/**
 * Load the deterministic test fixtures into the store. Intended for tests only
 * and safe to call repeatedly: each call starts from a clean slate.
 */
export const seedForTests = (): void => {
  reset();
  attestationStore.push(...SEED_ATTESTATIONS.map((attestation) => ({ ...attestation })));
};

export const attestationRepository = {
  seedForTests,
  reset,
  listByBusiness(businessId: string): Attestation[] {
    warnIfInMemoryInProduction();
    return attestationStore
      .filter((attestation) => attestation.businessId === businessId)
      .sort((a, b) => b.attestedAt.localeCompare(a.attestedAt));
  },
  listByBusinessIds(businessIds: readonly string[]): Attestation[][] {
    return businessIds.map(id => this.listByBusiness(id));
  },
  create(data: Omit<Attestation, "id" | "attestedAt">): Attestation {
    warnIfInMemoryInProduction();
    const newAttestation: Attestation = {
      ...data,
      id: `att_${crypto.randomUUID()}`,
      attestedAt: new Date().toISOString(),
    };
    attestationStore.push(newAttestation);
    return newAttestation;
  },

  findById(id: string): Attestation | null {
    warnIfInMemoryInProduction();
    return attestationStore.find((a) => a.id === id) ?? null;
  },

  update(id: string, data: Partial<Attestation>): Attestation | null {
    warnIfInMemoryInProduction();
    const idx = attestationStore.findIndex((a) => a.id === id);
    if (idx === -1) return null;
    attestationStore[idx] = { ...attestationStore[idx], ...data };
    return attestationStore[idx];
  },
};
