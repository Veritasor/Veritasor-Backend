import { randomBytes } from 'crypto';
// In-memory user storage
const users = new Map();
const emailIndex = new Map(); // email -> userId
function cloneDate(date) {
    return new Date(date.getTime());
}
function cloneUser(user) {
    return {
        ...user,
        createdAt: cloneDate(user.createdAt),
        updatedAt: cloneDate(user.updatedAt),
        ...(user.resetTokenExpiry
            ? { resetTokenExpiry: cloneDate(user.resetTokenExpiry) }
            : {}),
    };
}
function saveUser(user) {
    const sanitized = cloneUser(user);
    users.set(sanitized.id, sanitized);
    emailIndex.set(sanitized.email, sanitized.id);
    return sanitized;
}
/**
 * Generate a simple ID
 */
function generateId() {
    return randomBytes(16).toString('hex');
}
/**
 * Create a new user
 */
export async function createUser(email, passwordHash) {
    const now = new Date();
    const user = {
        id: generateId(),
        email,
        passwordHash,
        createdAt: now,
        updatedAt: now,
    };
    const stored = saveUser(user);
    return cloneUser(stored);
}
/**
 * Find user by email
 */
export async function findUserByEmail(email) {
    const userId = emailIndex.get(email);
    if (!userId)
        return null;
    const user = users.get(userId);
    return user ? cloneUser(user) : null;
}
/**
 * Find user by ID
 */
export async function findUserById(id) {
    const user = users.get(id);
    return user ? cloneUser(user) : null;
}
/**
 * Partially update a user while keeping immutable fields intact.
 * Only properties explicitly provided in `updates` are touched.
 */
export async function updateUser(userId, updates) {
    const current = users.get(userId);
    if (!current)
        return null;
    const next = {
        ...current,
        email: updates.email ?? current.email,
        passwordHash: updates.passwordHash ?? current.passwordHash,
        resetToken: updates.resetToken === null
            ? undefined
            : updates.resetToken !== undefined
                ? updates.resetToken
                : current.resetToken,
        resetTokenExpiry: updates.resetTokenExpiry === null
            ? undefined
            : updates.resetTokenExpiry !== undefined
                ? updates.resetTokenExpiry
                : current.resetTokenExpiry,
        updatedAt: new Date(),
    };
    if (current.email !== next.email) {
        emailIndex.delete(current.email);
    }
    const stored = saveUser(next);
    return cloneUser(stored);
}
/**
 * Update user's password
 */
export async function updateUserPassword(userId, passwordHash) {
    return updateUser(userId, {
        passwordHash,
        resetToken: null,
        resetTokenExpiry: null,
    });
}
/**
 * Set password reset token
 */
export async function setResetToken(userId, token, expiryMinutes = 30) {
    return updateUser(userId, {
        resetToken: token,
        resetTokenExpiry: new Date(Date.now() + expiryMinutes * 60 * 1000),
    });
}
/**
 * Find user by reset token
 */
export async function findUserByResetToken(token) {
    for (const user of users.values()) {
        if (user.resetToken === token &&
            user.resetTokenExpiry &&
            user.resetTokenExpiry > new Date()) {
            return cloneUser(user);
        }
    }
    return null;
}
/**
 * Delete user (for testing/cleanup)
 */
export async function deleteUser(userId) {
    const user = users.get(userId);
    if (!user)
        return false;
    emailIndex.delete(user.email);
    users.delete(userId);
    return true;
}
/**
 * Clear all users (testing/cleanup only)
 * @internal
 */
export function clearAllUsers() {
    users.clear();
    emailIndex.clear();
}
