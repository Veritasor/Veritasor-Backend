import crypto from "crypto";
// Temporary in-memory records until DB integration lands.
const attestationStore = [
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
        status: "active",
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
export const attestationRepository = {
    listByBusiness(businessId) {
        return attestationStore
            .filter((attestation) => attestation.businessId === businessId)
            .sort((a, b) => b.attestedAt.localeCompare(a.attestedAt));
    },
    create(data) {
        const newAttestation = {
            ...data,
            id: `att_${crypto.randomUUID()}`,
            attestedAt: new Date().toISOString(),
        };
        attestationStore.push(newAttestation);
        return newAttestation;
    },
    findById(id) {
        return attestationStore.find((a) => a.id === id) ?? null;
    },
    update(id, data) {
        const idx = attestationStore.findIndex((a) => a.id === id);
        if (idx === -1)
            return null;
        attestationStore[idx] = { ...attestationStore[idx], ...data };
        return attestationStore[idx];
    },
};
