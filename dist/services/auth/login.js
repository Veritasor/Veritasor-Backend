import { findUserByEmail, } from '../../repositories/userRepository.js';
import { verifyPassword } from '../../utils/password.js';
import { generateToken, generateRefreshToken, } from '../../utils/jwt.js';
export async function login(request) {
    const { email, password } = request;
    if (!email || !password) {
        throw new Error('Email and password are required');
    }
    const user = await findUserByEmail(email);
    if (!user) {
        throw new Error('Invalid email or password');
    }
    const isPasswordValid = await verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
        throw new Error('Invalid email or password');
    }
    const accessToken = generateToken({
        userId: user.id,
        email: user.email,
    });
    const refreshToken = generateRefreshToken({
        userId: user.id,
        email: user.email,
    });
    return {
        accessToken,
        refreshToken,
        user: {
            id: user.id,
            email: user.email,
        },
    };
}
