import pg from 'pg';
const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
    throw new Error('DATABASE_URL environment variable is required');
}
export const pool = new pg.Pool({
    connectionString,
});
export const db = {
    query: (text, params) => pool.query(text, params),
};
