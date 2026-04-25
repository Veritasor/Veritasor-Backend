import { randomBytes } from 'crypto'

export interface User {
  id: string
  email: string
  passwordHash: string
  createdAt: Date
  updatedAt: Date
  resetToken?: string
  resetTokenExpiry?: Date
  role: 'user' | 'admin' | 'business_admin'
}

/**
 * Fields that are permitted to be updated on a user record.
 * Any omitted fields are left untouched to preserve partial update safety.
 */
export interface UpdateUserData {
  email?: string
  passwordHash?: string
  resetToken?: string | null
  resetTokenExpiry?: Date | null
  role?: 'user' | 'admin' | 'business_admin'
}

// In-memory user storage
const users: Map<string, User> = new Map()
const emailIndex: Map<string, string> = new Map() // email -> userId

function cloneDate(date: Date): Date {
  return new Date(date.getTime())
}

function cloneUser(user: User): User {
  return {
    ...user,
    createdAt: cloneDate(user.createdAt),
    updatedAt: cloneDate(user.updatedAt),
    ...(user.resetTokenExpiry
      ? { resetTokenExpiry: cloneDate(user.resetTokenExpiry) }
      : {}),
  }
}

function saveUser(user: User): User {
  const sanitized = cloneUser(user)
  users.set(sanitized.id, sanitized)
  emailIndex.set(sanitized.email, sanitized.id)
  return sanitized
}

/**
 * Generate a simple ID
 */
function generateId(): string {
  return randomBytes(16).toString('hex')
}

/**
 * Create a new user
 */
export async function createUser(
  email: string,
  passwordHash: string
): Promise<User> {
  const now = new Date()
  const user: User = {
    id: generateId(),
    email,
    passwordHash,
    createdAt: now,
    updatedAt: now,
    role: 'user', // Default role
  }

  const stored = saveUser(user)
  return cloneUser(stored)
}

/**
 * Find user by email
 * 
 * @expectedIndex `email` (Unique)
 * @migrationNote Ensure a unique B-tree index exists on the `email` column
 * to prevent duplicate signups and allow fast exact-match lookups during login.
 */
export async function findUserByEmail(email: string): Promise<User | null> {
  const userId = emailIndex.get(email)
  if (!userId) return null

  const user = users.get(userId)
  return user ? cloneUser(user) : null
}

/**
 * Find user by ID
 * 
 * @expectedIndex `id` (Primary Key)
 * @migrationNote The `id` column should be the primary key of the users table
 * with an implicit unique index for O(1) or O(log N) lookups.
 */
export async function findUserById(id: string): Promise<User | null> {
  const user = users.get(id)
  return user ? cloneUser(user) : null
}

/**
 * Partially update a user while keeping immutable fields intact.
 * Only properties explicitly provided in `updates` are touched.
 */
export async function updateUser(
  userId: string,
  updates: UpdateUserData
): Promise<User | null> {
  const current = users.get(userId)
  if (!current) return null

  const next: User = {
    ...current,
    email: updates.email ?? current.email,
    passwordHash: updates.passwordHash ?? current.passwordHash,
    resetToken:
      updates.resetToken === null
        ? undefined
        : updates.resetToken !== undefined
        ? updates.resetToken
        : current.resetToken,
    resetTokenExpiry:
      updates.resetTokenExpiry === null
        ? undefined
        : updates.resetTokenExpiry !== undefined
        ? updates.resetTokenExpiry
        : current.resetTokenExpiry,
    role: updates.role ?? current.role,
    updatedAt: new Date(),
  }

  if (current.email !== next.email) {
    emailIndex.delete(current.email)
  }

  const stored = saveUser(next)
  return cloneUser(stored)
}

/**
 * Update user's password
 */
export async function updateUserPassword(
  userId: string,
  passwordHash: string
): Promise<User | null> {
  return updateUser(userId, {
    passwordHash,
    resetToken: null,
    resetTokenExpiry: null,
  })
}

/**
 * Set password reset token
 */
export async function setResetToken(
  userId: string,
  token: string,
  expiryMinutes: number = 30
): Promise<User | null> {
  return updateUser(userId, {
    resetToken: token,
    resetTokenExpiry: new Date(Date.now() + expiryMinutes * 60 * 1000),
  })
}

/**
 * Find user by reset token
 * 
 * @expectedIndex `resetToken` (or composite `(resetToken, resetTokenExpiry)`)
 * @migrationNote A standard index on `resetToken` is required. For high-volume 
 * systems, a composite index on `(resetToken, resetTokenExpiry)` can optimize 
 * queries that filter out expired tokens. Also, consider partial indexes if 
 * the database supports them (e.g. `WHERE resetToken IS NOT NULL`).
 */
export async function findUserByResetToken(
  token: string
): Promise<User | null> {
  for (const user of users.values()) {
    if (
      user.resetToken === token &&
      user.resetTokenExpiry &&
      user.resetTokenExpiry > new Date()
    ) {
      return cloneUser(user)
    }
  }
  return null
}

/**
 * Delete user (for testing/cleanup)
 */
export async function deleteUser(userId: string): Promise<boolean> {
  const user = users.get(userId)
  if (!user) return false

  emailIndex.delete(user.email)
  users.delete(userId)

  return true
}

/**
 * Get all users (admin only)
 */
export async function getAllUsers(): Promise<User[]> {
  return Array.from(users.values()).map(cloneUser)
}

/**
 * Clear all users (testing/cleanup only)
 * @internal
 */
export function clearAllUsers(): void {
  users.clear()
  emailIndex.clear()
}
