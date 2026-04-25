import crypto from 'crypto'

export interface Business {
  id: string
  userId: string
  name: string
  email: string
  industry?: string | null
  description?: string | null
  website?: string | null
  createdAt: string
  updatedAt: string
}

export type CreateBusinessData = {
  userId: string
  name: string
  email: string
  industry?: string | null
  description?: string | null
  website?: string | null
}

export type UpdateBusinessData = Partial<Omit<CreateBusinessData, 'userId'>>

// In-memory storage for businesses
const businesses: Map<string, Business> = new Map()

export async function create(data: CreateBusinessData): Promise<Business> {
  const now = new Date().toISOString()
  const business: Business = {
    id: crypto.randomUUID(),
    userId: data.userId,
    name: data.name,
    email: data.email,
    industry: data.industry ?? null,
    description: data.description ?? null,
    website: data.website ?? null,
    createdAt: now,
    updatedAt: now,
  }

  businesses.set(business.id, business)
  return { ...business }
}

export async function getById(id: string): Promise<Business | null> {
  const business = businesses.get(id)
  return business ? { ...business } : null
}

export async function getByUserId(userId: string): Promise<Business | null> {
  for (const business of businesses.values()) {
    if (business.userId === userId) {
      return { ...business }
    }
  }
  return null
}

export async function getAll(): Promise<Business[]> {
  return Array.from(businesses.values()).map(b => ({ ...b }))
}

export async function update(id: string, data: UpdateBusinessData): Promise<Business | null> {
  const business = businesses.get(id)
  if (!business) return null

  if (data.name !== undefined) business.name = data.name
  if (data.industry !== undefined) business.industry = data.industry
  if (data.description !== undefined) business.description = data.description
  if (data.website !== undefined) business.website = data.website
  
  business.updatedAt = new Date().toISOString()
  return { ...business }
}

/**
 * Clear all businesses from storage (for testing purposes)
 */
export function clearAll(): void {
  businesses.clear()
}

export const businessRepository = {
  create,
  getById,
  getByUserId,
  getAll,
  update,
  findById: getById,
  findByUserId: getByUserId,
  clearAll,
}
