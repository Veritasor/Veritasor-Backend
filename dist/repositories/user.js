import { db } from '../db/client.js';
import { AppError } from '../types/errors.js';
/**
 * Get user by ID
 */
export async function getById(id) {
    try {
        const result = await db.query('SELECT id, email, name, created_at as "createdAt", updated_at as "updatedAt" FROM users WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return null;
        }
        return result.rows[0];
    }
    catch (error) {
        console.error('Error in getById:', error);
        throw new AppError('Failed to fetch user', 500, 'DB_ERROR');
    }
}
/**
 * Create a new user
 */
export async function create(data) {
    const { email, passwordHash, name = '' } = data;
    try {
        const result = await db.query(`INSERT INTO users (email, password_hash, name)
       VALUES ($1, $2, $3)
       RETURNING id, email, name, created_at as "createdAt", updated_at as "updatedAt"`, [email, passwordHash, name]);
        return result.rows[0];
    }
    catch (error) {
        console.error('Error in create user:', error);
        if (error.code === '23505') {
            throw new AppError('Email already exists', 400, 'USER_ALREADY_EXISTS');
        }
        throw new AppError('Failed to create user', 500, 'DB_ERROR');
    }
}
/**
 * Update user profile fields
 */
export async function update(id, data) {
    const fields = [];
    const values = [];
    let placeholderIndex = 1;
    if (data.email !== undefined) {
        fields.push(`email = $${placeholderIndex++}`);
        values.push(data.email);
    }
    if (data.name !== undefined) {
        fields.push(`name = $${placeholderIndex++}`);
        values.push(data.name);
    }
    if (fields.length === 0) {
        const user = await getById(id);
        if (!user)
            throw new AppError('User not found', 404, 'USER_NOT_FOUND');
        return user;
    }
    fields.push(`updated_at = now()`);
    values.push(id);
    try {
        const result = await db.query(`UPDATE users
       SET ${fields.join(', ')}
       WHERE id = $${placeholderIndex}
       RETURNING id, email, name, created_at as "createdAt", updated_at as "updatedAt"`, values);
        if (result.rows.length === 0) {
            throw new AppError('User not found', 404, 'USER_NOT_FOUND');
        }
        return result.rows[0];
    }
    catch (error) {
        console.error('Error in update user:', error);
        if (error.code === '23505') {
            throw new AppError('Email already exists', 400, 'USER_ALREADY_EXISTS');
        }
        throw new AppError('Failed to update user', 500, 'DB_ERROR');
    }
}
