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
      // Return copies to prevent external mutations
      userIntegrations.push({ ...integration })
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
    token: data.token,
    metadata: data.metadata,
    createdAt: now,
    updatedAt: now,
  }
  
  integrations.set(integration.id, integration)
  
  // Return a copy to prevent external mutations
  return { ...integration }
}

/**
 * Update token and/or metadata for an existing integration
 * 
 * @param id - The unique identifier of the integration to update
 * @param data - Object containing fields to update (token and/or metadata)
 * @returns The updated Integration object if the record exists, null otherwise
 */
export async function update(
  id: string,
  data: UpdateIntegrationData
): Promise<Integration | null> {
  const integration = integrations.get(id)
  
  if (!integration) {
    return null
  }
  
  // Update only the fields provided in data
  if (data.token !== undefined) {
    integration.token = data.token
  }
  
  if (data.metadata !== undefined) {
    integration.metadata = data.metadata
  }
  
  // Update the updatedAt timestamp
  integration.updatedAt = new Date().toISOString()
  
  // Return a copy to prevent external mutations
  return { ...integration }
}

/**
 * Permanently remove an integration record
 * 
 * @param id - The unique identifier of the integration to delete
 * @returns true if a record was deleted, false if no record with the given ID exists
 */
export async function deleteById(id: string): Promise<boolean> {
  return integrations.delete(id)
}

/**
 * Clear all integrations from storage (for testing purposes)
 * @internal
 */
export function clearAll(): void {
  integrations.clear()
}
