import { Router } from "express";
import { login } from "../services/auth/login.js";
import { refresh } from "../services/auth/refresh.js";
import { signup, SignupError, getSignupRateLimitHeaders, checkSignupAvailability, } from "../services/auth/signup.js";
import { forgotPassword } from "../services/auth/forgotPassword.js";
import { resetPassword } from "../services/auth/resetPassword.js";
import { me } from "../services/auth/me.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { rateLimiter } from "../middleware/rateLimiter.js";
import { validateBody } from "../middleware/validate.js";
import { asyncErrorHandler } from "../middleware/errorHandler.js";
import { loginInputSchema } from "../schemas/auth.js";
import { resetPasswordSchema } from "../schemas/resetPasswordSchema.js";
import { AppError, ConflictError, RateLimitError, } from "../types/errors.js";
export const authRouter = Router();
const authRouteRateLimiters = {
    login: rateLimiter({ bucket: "auth:login", max: 10, algorithm: "sliding" }),
    forgotPassword: rateLimiter({
        bucket: "auth:forgot-password",
        max: 5,
        algorithm: "sliding",
    }),
    refresh: rateLimiter({ bucket: "auth:refresh", max: 20 }),
    resetPassword: rateLimiter({ bucket: "auth:reset-password", max: 5 }),
    me: rateLimiter({ bucket: "auth:me", max: 60 }),
};
/**
 * Maps signup-specific failures to typed errors handled by the global errorHandler.
 */
export function signupErrorToAppError(err) {
    switch (err.type) {
        case "RATE_LIMITED":
            return new RateLimitError(err.message);
        case "EMAIL_EXISTS":
            return new ConflictError(err.message);
        default:
            return new AppError(err.message, err.statusCode, err.type);
    }
}
function getClientIp(req) {
    const forwarded = req.headers["x-forwarded-for"];
    if (typeof forwarded === "string") {
        return forwarded.split(",")[0].trim();
    }
    return req.ip || req.socket.remoteAddress || "unknown";
}
function applySignupRateLimitHeaders(res, clientIp, email) {
    const headers = getSignupRateLimitHeaders(clientIp, email);
    for (const [key, value] of Object.entries(headers)) {
        res.setHeader(key, value);
    }
}
async function handleLogin(req, res) {
    const { email, password } = req.body;
    const result = await login({ email, password });
    res.json(result);
}
async function handleRefresh(req, res) {
    const { refreshToken } = req.body;
    const result = await refresh({ refreshToken });
    res.json(result);
}
async function handleForgotPassword(req, res) {
    const { email } = req.body;
    const result = await forgotPassword({ email });
    res.json(result);
}
async function handleResetPassword(req, res) {
    const { token, newPassword } = req.body;
    const result = await resetPassword({ token, newPassword });
    res.json(result);
}
async function handleSignup(req, res) {
    const clientIp = getClientIp(req);
    const { email, password, website } = req.body;
    const emailForHeaders = typeof email === "string" ? email : "";
    try {
        const result = await signup({
            email,
            password,
            ipAddress: clientIp,
            website,
        });
        applySignupRateLimitHeaders(res, clientIp, emailForHeaders);
        res.status(201).json(result);
    }
    catch (error) {
        applySignupRateLimitHeaders(res, clientIp, emailForHeaders);
        if (error instanceof SignupError) {
            throw signupErrorToAppError(error);
        }
        throw error;
    }
}
async function handleMe(req, res) {
    const result = await me(req.user.id);
    res.json(result);
}
authRouter.post("/login", authRouteRateLimiters.login, validateBody(loginInputSchema), asyncErrorHandler(handleLogin));
authRouter.post("/refresh", authRouteRateLimiters.refresh, asyncErrorHandler(handleRefresh));
authRouter.post("/signup", asyncErrorHandler(handleSignup));
authRouter.get("/signup/availability", (req, res) => {
    const clientIp = getClientIp(req);
    const email = req.query.email;
    res.json(checkSignupAvailability(clientIp, email));
});
authRouter.post("/forgot-password", authRouteRateLimiters.forgotPassword, asyncErrorHandler(handleForgotPassword));
authRouter.post("/reset-password", authRouteRateLimiters.resetPassword, validateBody(resetPasswordSchema), asyncErrorHandler(handleResetPassword));
authRouter.get("/me", authRouteRateLimiters.me, requireAuth, asyncErrorHandler(handleMe));
