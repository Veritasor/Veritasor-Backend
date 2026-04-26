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

export interface BusinessListOptions {
  limit: number;
  cursor?: string;
  sortBy: 'createdAt' | 'name';
  sortOrder: 'asc' | 'desc';
  industry?: string;
}

export interface PaginatedBusinessResult {
  items: Business[];
  nextCursor?: string;
}

export async function list(options: BusinessListOptions): Promise<PaginatedBusinessResult> {
  const { limit, cursor, sortBy, sortOrder, industry } = options;
  
  const sortColumn = sortBy === 'createdAt' ? 'created_at' : 'name';
  const op = sortOrder === 'asc' ? '>' : '<';
  
  const values: unknown[] = [];
  const conditions: string[] = [];
  
  if (industry !== undefined) {
    values.push(industry);
    conditions.push(`industry = $${values.length}`);
  }
  
  if (cursor) {
    try {
      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString('utf-8'));
      if (decoded.value !== undefined && decoded.id !== undefined) {
        values.push(decoded.value);
        values.push(decoded.id);
        const valIdx = values.length - 1;
        const idIdx = values.length;
        conditions.push(`(${sortColumn}, id) ${op} ($${valIdx}, $${idIdx})`);
      }
    } catch (e) {
      // Ignore invalid cursor
    }
  }
  
  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const orderClause = `ORDER BY ${sortColumn} ${sortOrder === 'asc' ? 'ASC' : 'DESC'}, id ${sortOrder === 'asc' ? 'ASC' : 'DESC'}`;
  
  values.push(limit + 1);
  const limitIdx = values.length;
  
  const result = await dbClient.query<BusinessRow>(
    `
      SELECT id, user_id, name, email, industry, description, website, created_at, updated_at
      FROM businesses
      ${whereClause}
      ${orderClause}
      LIMIT $${limitIdx}
    `,
    values
  );
  
  const hasMore = result.rows.length > limit;
  const rowsToReturn = hasMore ? result.rows.slice(0, limit) : result.rows;
  const items = rowsToReturn.map(toBusiness);
  
  let nextCursor: string | undefined;
  if (hasMore) {
    const lastItem = items[items.length - 1];
    const sortValue = sortBy === 'createdAt' ? lastItem.createdAt : lastItem.name;
    nextCursor = Buffer.from(JSON.stringify({ value: sortValue, id: lastItem.id })).toString('base64');
  }
  
  return { items, nextCursor };
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
  list,
  update,
  findById: getById,
  findByUserId: getByUserId,
  clearAll,
}
