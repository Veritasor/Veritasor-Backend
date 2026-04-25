const dbClient = {
    async query() {
        throw new Error('DB client is not configured');
    },
};
function toBusiness(row) {
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
    };
}
export async function create(data) {
    const result = await dbClient.query(`
      INSERT INTO businesses (user_id, name, email, industry, description, website)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, user_id, name, email, industry, description, website, created_at, updated_at
    `, [
        data.userId,
        data.name,
        data.email,
        data.industry ?? null,
        data.description ?? null,
        data.website ?? null,
    ]);
    return toBusiness(result.rows[0]);
}
export async function getById(id) {
    const result = await dbClient.query(`
      SELECT id, user_id, name, email, industry, description, website, created_at, updated_at
      FROM businesses
      WHERE id = $1
      LIMIT 1
    `, [id]);
    return result.rows[0] ? toBusiness(result.rows[0]) : null;
}
export async function getByUserId(userId) {
    const result = await dbClient.query(`
      SELECT id, user_id, name, email, industry, description, website, created_at, updated_at
      FROM businesses
      WHERE user_id = $1
      LIMIT 1
    `, [userId]);
    return result.rows[0] ? toBusiness(result.rows[0]) : null;
}
export async function getAll() {
    const result = await dbClient.query(`
      SELECT id, user_id, name, email, industry, description, website, created_at, updated_at
      FROM businesses
    `);
    return result.rows.map(toBusiness);
}
export async function update(id, data) {
    const updates = [];
    const values = [];
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
    const result = await dbClient.query(`
      UPDATE businesses
      SET ${updates.join(", ")}, updated_at = NOW()
      WHERE id = $${values.length}
      RETURNING id, user_id, name, email, industry, description, website, created_at, updated_at
    `, values);
    return result.rows[0] ? toBusiness(result.rows[0]) : null;
}
export const businessRepository = {
    create,
    getById,
    getByUserId,
    getAll,
    update,
    findById: getById,
    findByUserId: getByUserId,
};
