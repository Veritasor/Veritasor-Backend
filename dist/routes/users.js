import { Router } from 'express';
import updateProfile from '../services/user/updateProfile.js';
export const usersRouter = Router();
// Very small auth guard for example purposes: requires `Authorization: Bearer <token>`
function requireAuth(req, res, next) {
    const header = req.headers?.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    // In a real app we'd verify the token and load the user from DB.
    // Here we stub a user onto the request for the route to consume.
    req.user = {
        id: 'user_123',
        email: 'alice@example.com',
        name: 'Alice',
    };
    return next();
}
// PATCH /api/users/me - update current user's profile
usersRouter.patch('/me', requireAuth, async (req, res) => {
    try {
        const body = req.body ?? {};
        // Validate allowed fields
        const allowed = ['name', 'profile'];
        const updates = {};
        for (const k of allowed) {
            if (k in body)
                updates[k] = body[k];
        }
        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: 'No updatable fields provided' });
        }
        const userId = req.user.id;
        const updated = await updateProfile(userId, updates);
        return res.json(updated);
    }
    catch (err) {
        return res.status(400).json({ message: err?.message ?? 'Invalid input' });
    }
});
export default usersRouter;
