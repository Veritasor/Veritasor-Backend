import bcrypt from "bcryptjs";

const DEFAULT_SALT_ROUNDS = 10;

function getSaltRounds(): number {
  const envRounds = process.env.BCRYPT_SALT_ROUNDS;
  if (envRounds) {
    const parsed = parseInt(envRounds, 10);
    if (!Number.isNaN(parsed) && parsed > 0) return parsed;
  }
  return DEFAULT_SALT_ROUNDS;
}

/**
 * Hash a plain-text password using bcrypt.
 * Salt rounds can be configured via the `BCRYPT_SALT_ROUNDS` environment variable.
 */
export async function hash(plain: string): Promise<string> {
  const saltRounds = getSaltRounds();
  return bcrypt.hash(plain, saltRounds);
}

/** Alias kept for backward compatibility. */
export const hashPassword = hash;

/**
 * Verify a plain-text password against a bcrypt hash.
 * Returns `true` if the password matches, `false` otherwise.
 */
export async function verify(plain: string, hashed: string): Promise<boolean> {
  return bcrypt.compare(plain, hashed);
}

/** Alias kept for backward compatibility. */
export const verifyPassword = verify;

export default { hash, verify, hashPassword, verifyPassword };
