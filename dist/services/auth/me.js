import { findUserById } from '../../repositories/userRepository.js';
import { AuthenticationError, NotFoundError } from '../../types/errors.js';
export async function me(userId) {
    if (!userId) {
        throw new AuthenticationError('User ID is required');
    }
    const user = await findUserById(userId);
    if (!user) {
        throw new NotFoundError('User not found');
    }
    return {
        user: {
            id: user.id,
            email: user.email,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        },
    };
}
