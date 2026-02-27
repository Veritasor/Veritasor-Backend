type QueryResult<T> = {
  rows: T[];
};

type DbClient = {
  query<T>(text: string, values?: readonly unknown[]): Promise<QueryResult<T>>;
};

const dbClient: DbClient = {
  async query() {
    throw new Error('DB client is not configured');
  },
};

export interface Business {
  id: string;
  userId: string;
  name: string;
  industry: string | null;
  description: string | null;
  website: string | null;
  createdAt: string;
  updatedAt: string;
}

export type CreateBusinessData = {
  userId: string;
  name: string;
  industry?: string | null;
  description?: string | null;
  website?: string | null;
};

export type UpdateBusinessData = Partial<Omit<CreateBusinessData, 'userId'>>;

type BusinessRow = {
  id: string;
  user_id: string;
  name: string;
  industry: string | null;
  description: string | null;
  website: string | null;
  created_at: string;
  updated_at: string;
};

function toBusiness(row: BusinessRow): Business {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    industry: row.industry,
    description: row.description,
    website: row.website,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function create(data: CreateBusinessData): Promise<Business> {
  const result = await dbClient.query<BusinessRow>(
    `
      INSERT INTO businesses (user_id, name, industry, description, website)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, user_id, name, industry, description, website, created_at, updated_at
    `,
    [data.userId, data.name, data.industry ?? null, data.description ?? null, data.website ?? null],
  );

  return toBusiness(result.rows[0]);
}

export async function getById(id: string): Promise<Business | null> {
  const result = await dbClient.query<BusinessRow>(
    `
      SELECT id, user_id, name, industry, description, website, created_at, updated_at
      FROM businesses
      WHERE id = $1
      LIMIT 1
    `,
    [id],
  );

  return result.rows[0] ? toBusiness(result.rows[0]) : null;
}

export async function getByUserId(userId: string): Promise<Business | null> {
  const result = await dbClient.query<BusinessRow>(
    `
      SELECT id, user_id, name, industry, description, website, created_at, updated_at
      FROM businesses
      WHERE user_id = $1
      LIMIT 1
    `,
    [userId],
  );

  return result.rows[0] ? toBusiness(result.rows[0]) : null;
}

export async function update(id: string, data: UpdateBusinessData): Promise<Business | null> {
  const updates: string[] = [];
  const values: unknown[] = [];

  if (data.name !== undefined) {
    values.push(data.name);
    updates.push(`name = $${values.length}`);
  }
  if (data.industry !== undefined) {
    values.push(data.industry);
    updates.push(`industry = $${values.length}`);
  }
  if (data.description !== undefined) {
    values.push(data.description);
    updates.push(`description = $${values.length}`);
  }
  if (data.website !== undefined) {
    values.push(data.website);
    updates.push(`website = $${values.length}`);
  }

  if (updates.length === 0) {
    return getById(id);
  }

  values.push(id);

  const result = await dbClient.query<BusinessRow>(
    `
      UPDATE businesses
      SET ${updates.join(', ')}, updated_at = NOW()
      WHERE id = $${values.length}
      RETURNING id, user_id, name, industry, description, website, created_at, updated_at
    `,
    values,
  );

  return result.rows[0] ? toBusiness(result.rows[0]) : null;
}

export const businessRepository = {
  create,
  getById,
  getByUserId,
  update,
  findById: getById,
  findByUserId: getByUserId,
};
