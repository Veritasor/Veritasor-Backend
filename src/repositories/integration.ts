import crypto from 'crypto'

export interface Integration {
  id: string
  userId: string
  provider: string
  externalId: string
  token: Record<string, any>
  metadata: Record<string, any>
  createdAt: string
  updatedAt: string
}

/**
 * Data required to create a new integration
 */
export interface CreateIntegrationData {
  userId: string
  provider: string
  externalId: string
  token: Record<string, any>
  metadata: Record<string, any>
}

/**
 * Data that can be updated on an existing integration
 */
export interface UpdateIntegrationData {
  token?: Record<string, any>
  metadata?: Record<string, any>
}

// In-memory storage using Map data structure
const integrations: Map<string, Integration> = new Map()

function cloneObject<T extends Record<string, any>>(value: T): T {
  return structuredClone(value)
}

function cloneIntegration(integration: Integration): Integration {
  return {
    ...integration,
    token: cloneObject(integration.token),
    metadata: cloneObject(integration.metadata),
  }
}

/**
 * Retrieve all integration records for a specific user
 * 
 * @param userId - The unique identifier of the user
 * @returns Array of Integration objects (empty array if no integrations exist)
 */
export async function listByUserId(userId: string): Promise<Integration[]> {
  const userIntegrations: Integration[] = []
  
  for (const integration of integrations.values()) {
    if (integration.userId === userId) {
      userIntegrations.push(cloneIntegration(integration))
    }
  }
  
  return userIntegrations
}

/**
 * Create a new integration record
 * 
 * @param data - Object containing all required fields for a new integration
 * @returns The created Integration object with generated id, createdAt, and updatedAt fields
 */
export async function create(data: CreateIntegrationData): Promise<Integration> {
  const now = new Date().toISOString()
  
  const integration: Integration = {
    id: crypto.randomUUID(),
    userId: data.userId,
    provider: data.provider,
    externalId: data.externalId,
    token: cloneObject(data.token),
    metadata: cloneObject(data.metadata),
    createdAt: now,
    updatedAt: now,
  }
  
  integrations.set(integration.id, integration)
  
  return cloneIntegration(integration)
}

/**
 * Update token and/or metadata for an existing integration.
 * The caller must provide the owning user ID so writes cannot cross tenant boundaries.
 * 
 * @param userId - The unique identifier of the owning user/tenant
 * @param id - The unique identifier of the integration to update
 * @param data - Object containing fields to update (token and/or metadata)
 * @returns The updated Integration object if the record exists within the caller scope, null otherwise
 */
export async function update(
  userId: string,
  id: string,
  data: UpdateIntegrationData
): Promise<Integration | null> {
  const integration = integrations.get(id)
  
  if (!integration || integration.userId !== userId) {
    return null
  }
  
  // Update only the fields provided in data
  if (data.token !== undefined) {
    integration.token = cloneObject(data.token)
  }
  
  if (data.metadata !== undefined) {
    integration.metadata = cloneObject(data.metadata)
  }
  
  // Update the updatedAt timestamp
  integration.updatedAt = new Date().toISOString()
  
  return cloneIntegration(integration)
}

/**
 * Permanently remove an integration record inside the caller's tenant scope.
 * 
 * @param userId - The unique identifier of the owning user/tenant
 * @param id - The unique identifier of the integration to delete
 * @returns true if a record was deleted from the caller scope, false otherwise
 */
export async function deleteById(userId: string, id: string): Promise<boolean> {
  const integration = integrations.get(id)
  if (!integration || integration.userId !== userId) {
    return false
  }

  return integrations.delete(id)
}

/**
 * Clear all integrations from storage (for testing purposes)
 * @internal
 */
export function clearAll(): void {
  integrations.clear()
}
