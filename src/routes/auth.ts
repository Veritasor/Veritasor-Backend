import { Router, Request, Response } from "express";
import { login } from "../services/auth/login.js";
import { refresh } from "../services/auth/refresh.js";
import {
  signup,
  SignupError,
  getSignupRateLimitHeaders,
  checkSignupAvailability,
} from "../services/auth/signup.js";
import { forgotPassword } from "../services/auth/forgotPassword.js";
import { resetPassword } from "../services/auth/resetPassword.js";
import { me } from "../services/auth/me.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { rateLimiter } from "../middleware/rateLimiter.js";

export const authRouter = Router();

const authRouteRateLimiters = {
  login: rateLimiter({ bucket: "auth:login", max: 10 }),
  refresh: rateLimiter({ bucket: "auth:refresh", max: 20 }),
  forgotPassword: rateLimiter({ bucket: "auth:forgot-password", max: 5 }),
  resetPassword: rateLimiter({ bucket: "auth:reset-password", max: 5 }),
  me: rateLimiter({ bucket: "auth:me", max: 60 }),
};

/**
 * Extract client IP address from request.
 * Handles proxied requests with X-Forwarded-For header.
 */
function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    // Take the first IP in the chain (original client)
    return forwarded.split(",")[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "unknown";
}

/**
 * POST /api/v1/auth/login
 * Login with email and password
 */
authRouter.post("/login", authRouteRateLimiters.login, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const result = await login({ email, password });
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Login failed";
    res.status(401).json({ error: message });
  }
});

/**
 * POST /api/v1/auth/refresh
 * Refresh access token using refresh token
 */
authRouter.post("/refresh", authRouteRateLimiters.refresh, async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;
    const result = await refresh({ refreshToken });
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Refresh failed";
    res.status(401).json({ error: message });
  }
});

/**
 * POST /api/v1/auth/signup
 * Create a new user account
 *
 * Implements abuse prevention:
 * - Email validation and disposable email blocking
 * - Password strength requirements
 * - Rate limiting per IP and email
 * - Timing attack prevention
 */
authRouter.post("/signup", async (req: Request, res: Response) => {
  const clientIp = getClientIp(req);

  try {
    const { email, password, website } = req.body;

    // Pass IP and honeypot field to signup service
    const result = await signup({
      email,
      password,
      ipAddress: clientIp,
      website, // Honeypot field - should be empty
    });

    // Add rate limit headers to successful response
    const headers = getSignupRateLimitHeaders(clientIp, email);
    Object.entries(headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    res.status(201).json(result);
  } catch (error) {
    // Handle SignupError with appropriate status codes
    if (error instanceof SignupError) {
      // Add rate limit headers even on error
      const email = req.body.email || "";
      const headers = getSignupRateLimitHeaders(clientIp, email);
      Object.entries(headers).forEach(([key, value]) => {
        res.setHeader(key, value);
      });

      res.status(error.statusCode).json({
        error: error.message,
        type: error.type,
        details: error.details,
      });
      return;
    }

    const message = error instanceof Error ? error.message : "Signup failed";
    res.status(400).json({ error: message });
  }
});

/**
 * GET /api/v1/auth/signup/availability
 * Check if signup is available for the current IP
 * Useful for pre-validation before showing signup form
 */
authRouter.get("/signup/availability", (req: Request, res: Response) => {
  const clientIp = getClientIp(req);
  const email = req.query.email as string | undefined;

  const availability = checkSignupAvailability(clientIp, email);

  res.json(availability);
});

/**
 * POST /api/v1/auth/forgot-password
 * Request password reset link
 */
authRouter.post("/forgot-password", authRouteRateLimiters.forgotPassword, async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const result = await forgotPassword({ email });
    res.json(result);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Forgot password request failed";
    res.status(400).json({ error: message });
  }
});

/**
 * POST /api/v1/auth/reset-password
 * Reset password with reset token
 */
authRouter.post("/reset-password", authRouteRateLimiters.resetPassword, async (req: Request, res: Response) => {
  try {
    const { token, newPassword } = req.body;
    const result = await resetPassword({ token, newPassword });
    res.json(result);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Password reset failed";
    res.status(400).json({ error: message });
  }
});

/**
 * GET /api/v1/auth/me
 * Get current user info (protected route)
 */
authRouter.get("/me", authRouteRateLimiters.me, requireAuth, async (req: Request, res: Response) => {
  try {
    if (!req.user) {
      res.status(401).json({ error: "User not authenticated" });
      return;
    }
    const result = await me(req.user.id);
    res.json(result);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to get user";
    res.status(400).json({ error: message });
  }
});
