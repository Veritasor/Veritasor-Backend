import bcrypt from "bcryptjs";
import { logger } from "./logger.js";

const DEFAULT_SALT_ROUNDS = 10;
const MIN_SALT_ROUNDS = 4;
const MAX_SALT_ROUNDS = 31;

function getSaltRounds(): number {
  const envRounds = process.env.BCRYPT_SALT_ROUNDS?.trim();
  if (!envRounds || !/^-?\d+$/.test(envRounds)) {
    return DEFAULT_SALT_ROUNDS;
  }

  const parsed = Number.parseInt(envRounds, 10);
  if (
    Number.isNaN(parsed) ||
    parsed < MIN_SALT_ROUNDS ||
    parsed > MAX_SALT_ROUNDS
  ) {
    return DEFAULT_SALT_ROUNDS;
  }

  if (parsed < DEFAULT_SALT_ROUNDS) {
    logger.warn(
      {
        event: "password_salt_rounds_below_recommended",
        rounds: parsed,
        recommendedRounds: DEFAULT_SALT_ROUNDS,
      },
      "[password] BCRYPT_SALT_ROUNDS is below the recommended minimum."
    );
  }

  return parsed;
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
