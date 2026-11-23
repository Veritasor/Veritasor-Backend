import {
  updateUserProfile,
  type User,
  type UserProfileUpdate,
} from '../../repositories/userRepository.js'
import { NotFoundError } from '../../types/errors.js'

/**
 * Sanitized user profile DTO returned by `updateProfile`.
 * Never includes `passwordHash` or any auth/refresh/reset tokens.
 */
export type SanitizedUserProfile = Omit<
  User,
  'passwordHash' | 'resetToken' | 'resetTokenExpiry'
>

/**
 * Update the authenticated user's profile.
 *
 * Persists only the validated/allowlisted profile fields through the user
 * repository and returns the sanitized user record. Throws `NotFoundError`
 * when the repository reports that the user does not exist.
 */
export async function updateProfile(
  userId: string,
  updates: UserProfileUpdate
): Promise<SanitizedUserProfile> {
  if (!userId) throw new Error('userId required')

  const updated = await updateUserProfile(userId, updates)
  if (!updated) throw new NotFoundError('User not found')

  return {
    id: updated.id,
    email: updated.email,
    role: updated.role,
    createdAt: updated.createdAt,
    updatedAt: updated.updatedAt,
    name: updated.name,
    profile: updated.profile,
  }
}

export default updateProfile
