import { findUserById } from '../../repositories/userRepository.js'
import { AuthenticationError, NotFoundError } from '../../types/errors.js'

export interface MeResponse {
  user: {
    id: string
    email: string
    createdAt: Date
    updatedAt: Date
  }
}

export async function me(userId: string): Promise<MeResponse> {
  if (!userId) {
    throw new AuthenticationError('User ID is required')
  }

  const user = await findUserById(userId)
  if (!user) {
    throw new NotFoundError('User not found')
  }

  return {
    user: {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    },
  }
}
