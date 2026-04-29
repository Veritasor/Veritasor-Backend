import crypto from 'crypto';
// In-memory storage using Map data structure
const integrations = new Map();
function cloneObject(value) {
    return structuredClone(value);
}
function cloneIntegration(integration) {
    return {
        ...integration,
        token: cloneObject(integration.token),
        metadata: cloneObject(integration.metadata),
    };
}
/**
 * Retrieve all integration records for a specific user
 *
 * @param userId - The unique identifier of the user
 * @returns Array of Integration objects (empty array if no integrations exist)
 */
export async function listByUserId(userId) {
    const userIntegrations = [];
    for (const integration of integrations.values()) {
        if (integration.userId === userId) {
            userIntegrations.push(cloneIntegration(integration));
        }
    }
    return userIntegrations;
}
/**
 * Retrieve all integration records for a specific business
 *
 * @param businessId - The unique identifier of the business
 * @returns Array of Integration objects (empty array if no integrations exist)
 */
export async function listByBusinessId(businessId) {
    const businessIntegrations = [];
    for (const integration of integrations.values()) {
        if (integration.businessId === businessId) {
            businessIntegrations.push(cloneIntegration(integration));
        }
    }
    return businessIntegrations;
}
/**
 * Create a new integration record
 *
 * @param data - Object containing all required fields for a new integration
 * @returns The created Integration object with generated id, createdAt, and updatedAt fields
 */
export async function create(data) {
    const now = new Date().toISOString();
    const integration = {
        id: crypto.randomUUID(),
        userId: data.userId,
        businessId: data.businessId,
        provider: data.provider,
        externalId: data.externalId,
        token: cloneObject(data.token),
        metadata: cloneObject(data.metadata),
        createdAt: now,
        updatedAt: now,
    };
    integrations.set(integration.id, integration);
    return cloneIntegration(integration);
}
/**
 * Update token and/or metadata for an existing integration.
 * The caller must provide the owning business ID so writes cannot cross tenant boundaries.
 *
 * @param businessId - The unique identifier of the owning business/tenant
 * @param id - The unique identifier of the integration to update
 * @param data - Object containing fields to update (token and/or metadata)
 * @returns The updated Integration object if the record exists within the caller scope, null otherwise
 */
export async function update(businessId, id, data) {
    const integration = integrations.get(id);
    if (!integration || integration.businessId !== businessId) {
        return null;
    }
    // Update only the fields provided in data
    if (data.token !== undefined) {
        integration.token = cloneObject(data.token);
    }
    if (data.metadata !== undefined) {
        integration.metadata = cloneObject(data.metadata);
    }
    // Update the updatedAt timestamp
    integration.updatedAt = new Date().toISOString();
    return cloneIntegration(integration);
}
/**
 * Permanently remove an integration record inside the caller's tenant scope.
 *
 * @param businessId - The unique identifier of the owning business/tenant
 * @param id - The unique identifier of the integration to delete
 * @returns true if a record was deleted from the caller scope, false otherwise
 */
export async function deleteById(businessId, id) {
    const integration = integrations.get(id);
    if (!integration || integration.businessId !== businessId) {
        return false;
    }
    return integrations.delete(id);
}
/**
 * Clear all integrations from storage (for testing purposes)
 * @internal
 */
export function clearAll() {
    integrations.clear();
}
