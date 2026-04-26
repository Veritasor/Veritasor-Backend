import crypto from 'crypto'

type QueryResult<T> = {
  rows: T[]
}

type DbClient = {
  query<T>(text: string, values?: readonly unknown[]): Promise<QueryResult<T>>
}

const dbClient: DbClient = {
  async query() {
    throw new Error('DB client is not configured')
  },
}

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

type BusinessRow = {
  id: string
  user_id: string
  name: string
  email: string
  industry: string | null
  description: string | null
  website: string | null
  created_at: string
  updated_at: string
}

function toBusiness(row: BusinessRow): Business {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    email: row.email,
    industry: row.industry,
    description: row.description,
    website: row.website,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

export async function create(data: CreateBusinessData): Promise<Business> {
  const result = await dbClient.query<BusinessRow>(
    `
      INSERT INTO businesses (user_id, name, email, industry, description, website)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, user_id, name, email, industry, description, website, created_at, updated_at
    `,
    [
      data.userId,
      data.name,
      data.email,
      data.industry ?? null,
      data.description ?? null,
      data.website ?? null,
    ],
  )

  return toBusiness(result.rows[0])
}

export async function getById(id: string): Promise<Business | null> {
  const result = await dbClient.query<BusinessRow>(
    `
      SELECT id, user_id, name, email, industry, description, website, created_at, updated_at
      FROM businesses
      WHERE id = $1
      LIMIT 1
    `,
    [id],
  )

  return result.rows[0] ? toBusiness(result.rows[0]) : null
}

export async function getByUserId(userId: string): Promise<Business | null> {
  const result = await dbClient.query<BusinessRow>(
    `
      SELECT id, user_id, name, email, industry, description, website, created_at, updated_at
      FROM businesses
      WHERE user_id = $1
      LIMIT 1
    `,
    [userId],
  )

  return result.rows[0] ? toBusiness(result.rows[0]) : null
}

export async function getAll(): Promise<Business[]> {
  const result = await dbClient.query<BusinessRow>(
    `
      SELECT id, user_id, name, email, industry, description, website, created_at, updated_at
      FROM businesses
    `,
  )

  return result.rows.map(toBusiness)
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
  const updates: string[] = []
  const values: unknown[] = []

  if (data.name !== undefined) {
    values.push(data.name)
    updates.push(`name = $${values.length}`)
  }
  if (data.industry !== undefined) {
    values.push(data.industry)
    updates.push(`industry = $${values.length}`)
  }
  if (data.description !== undefined) {
    values.push(data.description)
    updates.push(`description = $${values.length}`)
  }
  if (data.website !== undefined) {
    values.push(data.website)
    updates.push(`website = $${values.length}`)
  }

  if (updates.length === 0) {
    return getById(id)
  }

  values.push(id)

  const result = await dbClient.query<BusinessRow>(
    `
      UPDATE businesses
      SET ${updates.join(", ")}, updated_at = NOW()
      WHERE id = $${values.length}
      RETURNING id, user_id, name, email, industry, description, website, created_at, updated_at
    `,
    values,
  )

  return result.rows[0] ? toBusiness(result.rows[0]) : null
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
}
