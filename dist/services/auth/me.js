import { findUserById } from '../../repositories/userRepository.js';
export async function me(userId) {
    if (!userId) {
        throw new Error('User ID is required');
    }
    const user = await findUserById(userId);
    if (!user) {
        throw new Error('User not found');
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
