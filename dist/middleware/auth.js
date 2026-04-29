import { AuthenticationError } from "../types/errors.js";
export function requireAuth(req, res, next) {
    const userId = req.headers["x-user-id"];
    if (!userId) {
        return next(new AuthenticationError());
    }
    req.user = { id: userId, userId, email: "" };
    next();
}
